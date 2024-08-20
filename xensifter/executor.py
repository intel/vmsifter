# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: MIT

import logging
import os
import shutil
import signal
import socket
import subprocess
from collections import deque
from concurrent.futures import Future, ProcessPoolExecutor, as_completed
from contextlib import suppress
from itertools import count
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Type

from attrs import asdict

from xensifter.config import dump_config, settings
from xensifter.fuzzer import get_selected_gen
from xensifter.fuzzer.types import AbstractInsnGenerator
from xensifter.injector import get_selected_injector
from xensifter.injector.types import AbstractInjector
from xensifter.utils import get_available_pcpus, pformat
from xensifter.utils.protected_manager import ProtectedContextManager
from xensifter.worker import Worker, WorkerStats


class SifterExecutor(ProtectedContextManager):
    """Manages the lifecycle of the xensifter XTF VM and C helper xensifter program"""

    def __init__(self):
        super().__init__()
        self._logger = logging.getLogger(f"{self.__module__}.{self.__class__.__name__}")
        # ensure workdir exists
        self.workdir_path = Path(settings.workdir)
        self.workdir_path.mkdir(parents=True, exist_ok=True)
        # dump current config
        dump_config(self.workdir_path)
        # dump cpuinfo
        shutil.copyfile("/proc/cpuinfo", self.workdir_path / "cpuinfo")
        # dump dmidecode
        output = subprocess.check_output(["sudo", "dmidecode"])
        with open(self.workdir_path / "dmidecode", "wb") as f:
            f.write(output)

        self._sock_path = self.workdir_path / settings.SOCKET_NAME

        self._client_id_count_gen = count()

        # list of available PCPUs to be allocated
        self._av_pcpu: deque = deque()

        # ProcessPool [Future] <-> [Client]
        self._fut_to_client: Dict[Future, Tuple[Worker, AbstractInjector]] = {}

    def _safe_enter(self):
        super()._safe_enter()

        # 1. create socket
        self._sock = self._ex.enter_context(socket.socket(socket.AF_UNIX, socket.SOCK_STREAM))

        # 2. bind socket
        self._logger.debug("Bind socket: %s", self._sock_path)

        with suppress(FileNotFoundError):
            os.unlink(self._sock_path)
        self._sock.bind(str(self._sock_path))

        # 3. set socket listen state
        self._sock.listen(settings.jobs)

        # 4. set available CPUs
        av_pcpu_list = [x for x in get_available_pcpus()]
        max_pcpu = min(settings.jobs, len(av_pcpu_list))
        self._logger.info("PCPU available: %s <=> Max jobs: %s => %s", len(av_pcpu_list), settings.jobs, max_pcpu)
        # shrink to min of either jobs of len(av_pcpu_list)
        self._av_pcpu = deque(av_pcpu_list, max_pcpu)

        def cancel_sigint():
            """Ignore CTRL+C in the worker process."""
            # https://stackoverflow.com/a/44869451/3017219
            signal.signal(signal.SIGINT, signal.SIG_IGN)

        self.pool_clients = self._ex.enter_context(
            ProcessPoolExecutor(max_workers=settings.jobs, initializer=cancel_sigint)
        )

        # on CTRL-C, ensure we deallocate everything
        def ensure_deallocate(future_to_clients: Dict[Future, Tuple[Worker, AbstractInjector]]):
            """Ensure Worker and injector's __exit__ have been called"""
            for future, (worker, injector) in future_to_clients.items():
                self._deallocate_client(worker, injector)

        self._ex.callback(ensure_deallocate, self._fut_to_client)

        # Show any exceptions raised in the Workers
        def show_future_exception(future_to_clients: Dict[Future, Tuple[Worker, AbstractInjector]]):
            for future, (worker, injector) in future_to_clients.items():
                exc = future.exception()
                if exc is not None and exc is not KeyboardInterrupt:
                    self._logger.exception("Worker %s failed", worker.id)

        self._ex.callback(show_future_exception, self._fut_to_client)

        return self

    def _allocate_pcpu(self, pcpu_id: int, sub_fuzzer: AbstractInsnGenerator, inj_cls: Type[AbstractInjector]):
        # create new injector
        injector = inj_cls(self._sock_path, pcpu_id)
        injector.__enter__()
        # accept injector client
        cli_sock, cli_addr = self._sock.accept()
        # create Worker
        cli_id = next(self._client_id_count_gen)
        cli = Worker(cli_id, sub_fuzzer)
        cli.__enter__()
        self._logger.info("Assign Worker ID %s => PCPU %s", cli_id, pcpu_id)
        future = self.pool_clients.submit(cli.handle_client, cli_sock, cli_addr)
        self._fut_to_client[future] = cli, injector

    def _deallocate_client(self, client: Worker, injector: AbstractInjector) -> int:
        """Deallocate a Client / Injector and return the PCPU ressource"""
        pcpu = injector.pinned_cpu
        client.__exit__(None, None, None)
        injector.__exit__(None, None, None)
        return pcpu

    def run(self, extra_params: Optional[List[str]]):
        # get injector cls
        inj_cls = get_selected_injector()
        # get fuzzer
        fuzz_cls = get_selected_gen()
        fuzzer = fuzz_cls(extra_params=extra_params)
        # initial partitioning over deque size
        fuzzer_parts_gen = fuzzer.partition(len(self._av_pcpu))
        for next_pcpu, sub_fuzzer in zip(self._av_pcpu, fuzzer_parts_gen):
            self._allocate_pcpu(next_pcpu, sub_fuzzer, inj_cls)

        for future in as_completed(self._fut_to_client.keys()):
            client, injector = self._fut_to_client[future]
            self._logger.info("Worker %s fuzzing complete.", client.id)
            try:
                result: WorkerStats = future.result()
            except Exception:
                self._logger.exception(f"Worker {client.id} failed")
            else:
                # display stats
                self._logger.info("Worker %s Stats: %s", client.id, pformat(asdict(result)))
            finally:
                pcpu = self._deallocate_client(client, injector)
                # put it back in available queue
                self._av_pcpu.append(pcpu)
                # cleanup
                del self._fut_to_client[future]

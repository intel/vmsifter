# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: MIT

import logging
from datetime import datetime
from itertools import count
from pathlib import Path
from typing import Counter

from attr import asdict, define, field

from vmsifter.config import settings
from vmsifter.fuzzer.types import AbstractInsnGenerator, FuzzerExecResult
from vmsifter.injector.types import ExitReasonEnum, InjectorResultMessage
from vmsifter.output import CSVOutput
from vmsifter.utils import pformat
from vmsifter.utils.protected_manager import ProtectedContextManager


@define(slots=True)
class WorkerStats:
    nb_insn: int
    total_seconds: float
    general: Counter = field(factory=Counter)
    exitstats: Counter = field(factory=Counter)
    interruptstats: Counter = field(factory=Counter)

    @property
    def exec_speed(self) -> int:
        return int(self.nb_insn / self.total_seconds)


class Worker(ProtectedContextManager):
    def __init__(self, id: int, fuzzer: AbstractInsnGenerator) -> None:
        super().__init__()
        self._id = id
        self._fuzzer = fuzzer

        # stats
        self._stats: Counter = Counter()
        self._exitstats: Counter = Counter()
        self._interruptstats: Counter = Counter()
        # workaround dynaconf perf issue
        self._cache_dyna_insn_buf_size = settings.insn_buf_size
        self._cache_dyna_refresh_frequency = settings.refresh_frequency

    def init_logger_worker(self):
        """Remove exiting stdout logging and log to a file"""
        self._logger = logging.getLogger()
        # remove existing stdout handler
        while self._logger.handlers:
            self._logger.handlers.pop()
        # add File handler
        self._workdir_path = Path(settings.workdir)
        file_handler = logging.FileHandler(self._workdir_path / f"worker_{self._id}.log")
        file_handler.setFormatter(settings.logging.format)
        self._logger.addHandler(file_handler)

    @property
    def id(self):
        return self._id

    @property
    def fuzzer(self):
        return self._fuzzer

    @staticmethod
    def _recv_injector_result(cli_sock, view) -> InjectorResultMessage:
        num_bytes: int = cli_sock.recv_into(view[:])
        if num_bytes == 0:
            raise EOFError("Injector has closed the communication")
        cli_msg = InjectorResultMessage.from_buffer(view)
        return cli_msg

    def handle_client(self, cli_sock, cli_addr) -> WorkerStats:
        self.init_logger_worker()
        self._logger.debug("Injector connected: %s", cli_addr)
        with CSVOutput(self._id) as csvlog:
            self._logger.info("Fuzzing range: %s", self.fuzzer.str_fuzzing_range())

            gen = self.fuzzer.gen()

            # wait for first message from injector
            cli_msg_bytes: bytearray = bytearray(InjectorResultMessage.size())
            cli_msg_view = memoryview(cli_msg_bytes)
            cli_msg = self._recv_injector_result(cli_sock, cli_msg_view)

            result = None
            # store error if any
            # since we want to always display Client statistics in the finally block
            # but returning from finally erases the exception
            error = None

            try:
                begin = datetime.now()
                cur_begin = begin
                for index in count(start=1):
                    try:
                        new_insn = gen.send(result)
                    except StopIteration:
                        if result:
                            csvlog.log(result.final)  # type: ignore[unreachable]
                        break

                    if len(new_insn) > self._cache_dyna_insn_buf_size:
                        self._logger.debug(
                            "[%d]Fuzzer generated instruction larger then our current limit, "
                            "forgot to increase INSN_BUF_SIZE?",
                            index,
                        )
                        break

                    # previous execution result has been processed by fuzzer
                    # check for final and log
                    if result:
                        # mypy issue: https://github.com/python/mypy/issues/8721
                        csvlog.log(result.final)  # type: ignore[unreachable]
                    # print current insn
                    if not index % self._cache_dyna_refresh_frequency:
                        cur_end = datetime.now()
                        total_sec = (cur_end - cur_begin).total_seconds()
                        cur_speed = int(self._cache_dyna_refresh_frequency / total_sec)
                        self._logger.info("[%d]insn: %s | %s exec/sec", index, self.fuzzer, cur_speed)
                        # update current
                        cur_begin = datetime.now()

                    # send new insn to injector
                    if self._logger.isEnabledFor(logging.DEBUG):
                        self._logger.debug("[%d]Sending buffer %s", index, new_insn.hex())
                    cli_sock.send(new_insn)

                    # get execution result
                    cli_msg = self._recv_injector_result(cli_sock, cli_msg_view)

                    # display received data
                    if self._logger.isEnabledFor(logging.DEBUG):
                        self._logger.debug("[%d]Recv msg %s", index, pformat(cli_msg.repr_recv()))

                    result = FuzzerExecResult.factory_from_injector_message(cli_msg)
                    # sanity check
                    if result.rep_length is None:
                        self._logger.info(
                            "[%d]Impossible length recorded by CPU on VMEXIT for %s: %i",
                            index,
                            new_insn.hex(),
                            cli_msg.insn_length,
                        )
                    if self._logger.isEnabledFor(logging.DEBUG):
                        self._logger.debug("[%d]FuzzerExecResult: %s", index, pformat(asdict(result)))
                    # update exitstats
                    if result.exit_reason == ExitReasonEnum.UNKNOWN:
                        self._exitstats[f"unknown_exit_{cli_msg.reason}"] += 1
                    else:
                        self._exitstats[result.exit_reason] += 1
                    # update stats
                    self._stats[result.type_str()] += 1
            except Exception as e:
                error = e
            else:
                self._logger.info("Fuzzing complete.")
            finally:
                end = datetime.now()
                final_stats = WorkerStats(
                    general=self._stats,
                    exitstats=self._exitstats,
                    interruptstats=self._interruptstats,
                    nb_insn=index,
                    total_seconds=(end - begin).total_seconds(),
                )
                self._logger.info("VMEXIT Stats: %s", pformat(self._exitstats))
                self._logger.info("Interrupt Stats: %s", pformat(self._interruptstats))
                self._logger.info("Sifter Stats: %s", pformat(self._stats))
                self._logger.info("Speed: %s insn/sec", final_stats.exec_speed)
                # return will omit raising the exception if any
                if error is not None:
                    raise error
                return final_stats

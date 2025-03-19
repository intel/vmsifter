# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: MIT

import signal
import subprocess
import threading
from contextlib import suppress
from pathlib import Path
from typing import Optional, Type

from vmsifter.config import InjectorType, get_injector_settings, settings
from vmsifter.utils.xen import gen_tmp_xenvm_configfile, xtf_vm

from .types import AbstractInjector


class XenVMInjector(AbstractInjector):
    LOCK = threading.Lock()
    PARENT_DOMID: Optional[int] = None
    ID: int = 1

    def __init__(self, socket_path: Path, pinned_cpu: int):
        super().__init__(socket_path, pinned_cpu)
        self._domid: Optional[int] = None
        self._proc: Optional[subprocess.Popen] = None

    @staticmethod
    def get_type() -> InjectorType:
        return InjectorType.XENVM

    def _safe_enter(self):
        super()._safe_enter()
        with self.__class__.LOCK:
            if self.__class__.PARENT_DOMID is None:
                self._set_cpu_perf_state()
                domid: int = self._create_parent_vm()
                self.__class__.PARENT_DOMID = domid
            domid = self.__class__.PARENT_DOMID
        self._fork_vm(domid)
        return self

    def __exit__(
        self, __exc_type: Optional[Type[BaseException]], __exc_value: Optional[BaseException], __traceback
    ) -> None:
        self.logger.debug("Cleaning up !")
        # send SIGKILL to injector
        # pypy: with SIGINT the injector doesn't terminate somehow
        if self._proc is not None:
            with suppress(ProcessLookupError):
                self._proc.send_signal(signal.SIGKILL)
        super().__exit__(__exc_type, __exc_value, __traceback)
        self.logger.debug("Cleanup done")

    def _set_cpu_perf_state(self):
        """Set CPU performance state

        (only needed when hwp is used, otherwise its already set from the Xen command line)
        """

        cmd = ["sudo", "xenpm", "set-cpufreq-cppc", "performance"]
        self.logger.info("Setting CPU frequency: %s", cmd)
        subprocess.call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def _create_parent_vm(self) -> int:
        """Create parent Xen VM

        Returns:
            The parent VM Xen domain ID"""
        # gen temporary file
        tmp_file_path = self._ex.enter_context(gen_tmp_xenvm_configfile())
        domid: int = self._ex.enter_context(xtf_vm(tmp_file_path))
        # setup parent
        self.logger.info("Setup parent")

        cmd = [
            "sudo",
            f"{self._inj_settings.INJECTOR_PATH}",
            "--setup",
            "--domid",
            str(domid),
            "--perfcts",
            f"{self._inj_settings.perfcts}",
        ]

        if settings.debug:
            cmd += ["--debug"]

        if self._inj_settings.sse:
            cmd += ["--sse"]

        if self._inj_settings.syscall:
            cmd += ["--syscall"]

        if self._inj_settings.fpu_emulation:
            cmd += ["--fpu-emulation"]

        self.logger.debug("Launching injector: %s", cmd)
        subprocess.check_call(cmd)
        self.logger.info("Parent VM: %s", domid)
        return domid

    def _fork_vm(self, domid):
        """fork VM"""
        self.logger.info("Setup child")
        cmd = [
            "sudo",
            f"{self._inj_settings.INJECTOR_PATH}",
            "--socket",
            str(self._socket_path),
            "--domid",
            str(domid),
            "--insn-buf-size",
            f"{settings.insn_buf_size}",
            "--pin-cpu",
            str(self._pinned_cpu),
            get_injector_settings(),
        ]

        if settings.debug:
            cmd += ["--debug"]

        self.logger.debug("Setup child: %s", cmd)
        self._proc = self._ex.enter_context(subprocess.Popen(cmd, stdout=None, stderr=subprocess.STDOUT))

        self.logger.info("Child ID: %s", self.__class__.ID)
        self.__class__.ID += 1

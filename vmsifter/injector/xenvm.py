# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: MIT

import logging
import subprocess
from contextlib import contextmanager
from pathlib import Path
from typing import Generator, Optional, Type

from vmsifter.config import InjectorType, get_injector_settings, settings
from vmsifter.utils.xen import gen_tmp_xenvm_configfile, xtf_vm

from .types import AbstractInjector

# seconds given to the injector to clean up after SIGTERM
INJECTOR_STOP_TIMEOUT = 5

logger = logging.getLogger(__name__)


class XenVMInjector(AbstractInjector):
    PARENT_DOMID: Optional[int] = None
    ID: int = 1

    def __init__(self, socket_path: Path, pinned_cpu: int):
        super().__init__(socket_path, pinned_cpu)
        self._domid: Optional[int] = None
        self._proc: Optional[subprocess.Popen] = None

    @staticmethod
    def get_type() -> InjectorType:
        return InjectorType.XENVM

    @classmethod
    @contextmanager
    def shared_setup(cls) -> Generator[None, None, None]:
        """Create the parent VM, destroyed on exit: it has to outlive every fork"""
        cls._set_cpu_perf_state()
        with gen_tmp_xenvm_configfile() as tmp_file_path, xtf_vm(tmp_file_path) as domid:
            cls._setup_parent_vm(domid)
            cls.PARENT_DOMID = domid
            try:
                yield
            finally:
                cls.PARENT_DOMID = None

    def _safe_enter(self):
        super()._safe_enter()
        if self.__class__.PARENT_DOMID is None:
            raise RuntimeError("No parent VM to fork: shared_setup() must be entered first")
        self._fork_vm(self.__class__.PARENT_DOMID)
        return self

    def __exit__(
        self, __exc_type: Optional[Type[BaseException]], __exc_value: Optional[BaseException], __traceback
    ) -> None:
        self.logger.debug("Cleaning up !")
        # SIGTERM lets the injector destroy its fork VM, SIGKILL only if it doesn't stop
        # pypy: with SIGINT the injector doesn't terminate somehow
        if self._proc is not None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=INJECTOR_STOP_TIMEOUT)
            except subprocess.TimeoutExpired:
                self.logger.warning("Injector did not stop, killing it: its fork VM may be left behind")
                self._proc.kill()
        super().__exit__(__exc_type, __exc_value, __traceback)
        self.logger.debug("Cleanup done")

    @staticmethod
    def _set_cpu_perf_state():
        """Set CPU performance state

        (only needed when hwp is used, otherwise its already set from the Xen command line)
        """

        cmd = ["sudo", "xenpm", "set-cpufreq-cppc", "performance"]
        logger.info("Setting CPU frequency: %s", cmd)
        subprocess.call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    @classmethod
    def _setup_parent_vm(cls, domid: int):
        """Run the parent Xen VM until it is ready to be forked"""
        inj_settings = settings.injector[cls.get_type().name]
        logger.info("Setup parent")

        cmd = [
            "sudo",
            f"{inj_settings.INJECTOR_PATH}",
            "--setup",
            "--domid",
            str(domid),
            "--perfcts",
            f"{inj_settings.perfcts}",
        ]

        if settings.debug:
            cmd += ["--debug"]

        if inj_settings.sse:
            cmd += ["--sse"]

        if inj_settings.syscall:
            cmd += ["--syscall"]

        if inj_settings.fpu_emulation:
            cmd += ["--fpu-emulation"]

        logger.debug("Launching injector: %s", cmd)
        subprocess.check_call(cmd)
        logger.info("Parent VM: %s", domid)

    def _fork_vm(self, domid):
        """fork VM"""
        self.logger.info("Setup child")
        # Note: we cannot use "sudo" here, since it will corrupt Python's console output if used with Popen
        cmd = [
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

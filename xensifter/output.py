import csv
import logging
from pathlib import Path
from typing import Optional

from xensifter.config import settings
from xensifter.fuzzer.types import NMI, FinalLogResult
from xensifter.injector.types import InjInterruptEnum
from xensifter.utils.protected_manager import ProtectedContextManager


class CSVOutput(ProtectedContextManager):
    CSV_HEADER = [
        "insn",
        "length",
        "exit-type",
        "misc",
        "pfct1",
        "pfct2",
        "pfct3",
        "pfct4",
        "pfct5",
        "pfct6",
        "pfct7",
        "reg-delta",
    ]
    RESULTS_CSV_BASENAME = "results"
    INVALID_INSN_CSV_BASENAME = "invalid_instructions"

    def __init__(self, id: int) -> None:
        super().__init__()
        self._logger = logging.getLogger(f"{self.__module__}.{self.__class__.__name__}[{id}]")
        self._workdir_path = Path(settings.workdir)
        self._results_path = self._workdir_path / f"{self.__class__.RESULTS_CSV_BASENAME}_{id}.csv"
        self._invalid_path = self._workdir_path / f"{self.__class__.INVALID_INSN_CSV_BASENAME}_{id}.csv"

        self._results_f = self._ex.enter_context(open(self._results_path, "a", newline=""))
        self._invalid_f = self._ex.enter_context(open(self._invalid_path, "a", newline=""))

        self._results_writer = csv.writer(self._results_f)
        self._invalid_writer = csv.writer(self._invalid_f)

        # write headers
        self._results_writer.writerow(self.__class__.CSV_HEADER)
        self._invalid_writer.writerow(self.__class__.CSV_HEADER)

    def log(self, final: Optional[FinalLogResult]):
        if final is None:
            return

        self._logger.debug("Logging results for %s", final.insn)

        if isinstance(final.exec_res, NMI) and final.exec_res.interrupt == InjInterruptEnum.INVALID_OPCODE:
            # invalid insn
            self._invalid_writer.writerow(
                [
                    final.insn,
                    final.len,
                    final.exec_res.type_str(),
                    final.exec_res.misc_str() + final.misc,
                    *final.exec_res.perfct,
                    final.exec_res.reg_delta_str(),
                ]
            )
        else:
            # valid
            self._results_writer.writerow(
                [
                    final.insn,
                    final.len,
                    final.exec_res.type_str(),
                    final.exec_res.misc_str() + final.misc,
                    *final.exec_res.perfct,
                    final.exec_res.reg_delta_str(),
                ]
            )

# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: MIT

from __future__ import annotations

import csv
import itertools
from collections.abc import Generator
from pathlib import Path
from typing import List, Optional

from attrs import define

from vmsifter.config import settings
from vmsifter.fuzzer.types import AbstractInsnGenerator, FinalLogResult, FuzzerExecResult, Interrupted


@define(slots=False, auto_attribs=True, auto_detect=True)
class CsvFuzzer(AbstractInsnGenerator):
    def __init__(self, insn_buffer: Optional[bytearray] = None, extra_params: Optional[List[str]] = None):
        super().__init__(None, extra_params=extra_params)
        # check for extra params
        if not self.extra_params:
            raise ValueError("CSVFuzzer requires a CSV file parameter. Use -e <csv_file> to specify it.")
        # check if CSV file exists
        csv_input = Path(self.extra_params[0])

        self.logger.info("Opening %s as input", csv_input)
        if settings.csv_log_diff_only:
            self.logger.info("Logging only results that differ from information in the input")

        f = open(csv_input, mode="r", newline="")
        self.reader = csv.DictReader(f)
        self.row = next(self.reader)
        insn = bytearray.fromhex(self.row["insn"])
        self.init_buffer(buffer=insn)

        if settings.extra_byte != 0:
            self.insn_length += settings.extra_byte

        self.prefix_len = 0
        if settings.min_prefix_count != 0:
            self.prefix_list = []

            for i in range(settings.min_prefix_count, settings.max_prefix_count + 1):
                self.prefix_list += list(itertools.product(settings.mode_prefix, repeat=i))

            self.prefix_iterator = itertools.tee(self.prefix_list, 1)[0]
            prefix = next(self.prefix_iterator)
            self.prefix_len = len(prefix)
            self.insn_buffer[: self.prefix_len] = prefix
            self.insn_length += self.prefix_len

        if self.insn_length > settings.insn_buf_size:
            raise Exception("Instruction length is too long, should increase INSN_BUF_SIZE")

        for i in range(len(insn)):
            self.insn_buffer[self.prefix_len + i] = insn[i]

    def prefix_prepender(self):
        if settings.min_prefix_count == 0:
            return 0

        try:
            prefix = next(self.prefix_iterator)

            if len(prefix) != self.prefix_len:
                new_length = self.insn_length + len(prefix) - self.prefix_len
                if new_length > settings.insn_buf_size:
                    # no space to add this many prefixes
                    # reset iterator for next instruction
                    self.prefix_iterator = itertools.tee(self.prefix_list, 1)[0]
                    return 0

                # shift the rest of the buffer to the right to make space
                tmp = self.insn_buffer[self.prefix_len : self.insn_length]
                for i in range(len(tmp) - settings.extra_byte):
                    self.insn_buffer[len(prefix) + i] = tmp[i]

                self.insn_length = new_length

            for i in range(self.insn_length - settings.extra_byte, self.insn_length):
                self.insn_buffer[i] = 0

            self.prefix_len = len(prefix)
            for i in range(self.prefix_len):
                self.insn_buffer[i] = prefix[i]

            return 1
        except StopIteration:
            # reset iterator for next instruction
            self.prefix_iterator = itertools.tee(self.prefix_list, 1)[0]
            return 0

    def check_result(self, result):
        if settings.csv_log_diff_only == 0:
            result.final = FinalLogResult(
                exec_res=result, insn=self.view[: self.insn_length].hex(), len=self.insn_length
            )
            return

        exit_type = self.row["exit-type"]
        reg_delta = self.row["reg-delta"]

        if result.type_str() != exit_type or result.reg_delta_str() != reg_delta:
            result.final = FinalLogResult(
                exec_res=result, insn=self.view[: self.insn_length].hex(), len=self.insn_length
            )

    def gen(self) -> Generator[memoryview, FuzzerExecResult, None]:
        while True:
            result: FuzzerExecResult = yield self.current_insn
            if isinstance(result, Interrupted):
                continue

            # Log results of previous execution
            self.check_result(result)

            # Onto the next instruction
            if settings.extra_byte != 0 and self.insn_buffer[self.insn_length - 1] < 0xFF:
                self.insn_buffer[self.insn_length - 1] += 1
                continue

            if self.prefix_prepender() != 0:
                continue

            try:
                self.row = next(self.reader)
                insn = bytearray.fromhex(self.row["insn"])
                self.insn_length = len(insn)

                for i in range(self.insn_length):
                    self.insn_buffer[i] = insn[i]

                if settings.extra_byte != 0:
                    for i in range(settings.extra_byte):
                        self.insn_buffer[self.insn_length + i] = 0

                    self.insn_length += settings.extra_byte

                self.prefix_len = 0
                self.prefix_prepender()

            except StopIteration:
                return

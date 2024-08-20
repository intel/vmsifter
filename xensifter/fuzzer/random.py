# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: MIT

from __future__ import annotations

import os
import random
from collections.abc import Generator

from attrs import define

from xensifter.fuzzer.types import AbstractInsnGenerator, FuzzerExecResult


# keep slots disabled, too complicated with inheritance
# also we need to inherit from superclass __getstate__ / __setstate__ definitions
# and slots=True automatically inserts attrs generated methods
@define(slots=True, auto_attribs=True, auto_detect=True)
class RandomFuzzer(AbstractInsnGenerator):
    def _randbytes(self):
        self.insn_length = random.randint(1, self.cache_dyna_insn_buf_size)
        self.view[: self.insn_length] = os.urandom(self.insn_length)

    def gen(self) -> Generator[memoryview, FuzzerExecResult, None]:
        while True:
            yield self.current_insn
            self._randbytes()

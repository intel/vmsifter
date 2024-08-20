# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: MIT

from contextlib import suppress
from itertools import islice

import pytest
from xensifter.disasm.yaxpeax import YaxpeaxDisasmAdaptee
from xensifter.fuzzer.random import random_fuzzer_gen


@pytest.fixture
def yaxpeax():
    return YaxpeaxDisasmAdaptee()


@pytest.mark.parametrize("count", [10**3, 10**4, 10**5, 10**6])
def test_yaxpeax_disasm(yaxpeax, count):
    for next_buff in islice(random_fuzzer_gen(), count):
        yaxpeax.disasm(next_buff)

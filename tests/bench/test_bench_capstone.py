from contextlib import suppress
from itertools import islice

import pytest
from capstone import CS_ARCH_X86, CS_MODE_64, Cs

from xensifter.fuzzer.random import random_fuzzer_gen


@pytest.fixture
def cap_disasm():
    return Cs(CS_ARCH_X86, CS_MODE_64)


@pytest.mark.parametrize("count", [10**3, 10**4, 10**5, 10**6])
def test_capstone_disasm(cap_disasm, count):
    md = cap_disasm
    for next_buff in islice(random_fuzzer_gen(), count):
        with suppress(StopIteration):
            next(md.disasm(next_buff, 0x0))

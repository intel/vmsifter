# benchmark for x86 instruction generator
from itertools import islice

import pytest
from more_itertools import consume

from xensifter.fuzzer.random import random_fuzzer_gen


@pytest.mark.parametrize("count", [10**3, 10**4, 10**5, 10**6])
def test_gen_insn(count: int):
    consume(islice(random_fuzzer_gen(), count))

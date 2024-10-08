# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: MIT

from itertools import count

import pytest

from vmsifter.disasm.adapter import DisasmAdapter
from vmsifter.disasm.capstone import CapstoneDisasmAdaptee
from vmsifter.fuzzer.tunnel import FuzzerExecResult, TunnelFuzzer


@pytest.mark.parametrize("max_count", [10**3, 10**4, 10**5, 10**6])
def test_capstone_tunnel(max_count: int):
    # arrange
    cap_adaptee = CapstoneDisasmAdaptee()
    adapter = DisasmAdapter(cap_adaptee)
    # act
    tun = TunnelFuzzer()
    gen = tun.gen()
    result = None
    for i in count():
        if i == max_count:
            break
        next_buff = gen.send(result)
        # disasm
        disas_res = adapter.disasm(next_buff)
        if disas_res is None:
            result = FuzzerExecResult(pagefault=True)
        else:
            result = FuzzerExecResult(length=disas_res.size)

# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: MIT

from pickle import dumps, loads

from capstone import CS_MODE_64

from xensifter.disasm.adapter import DisasmAdapter, DisasmResult
from xensifter.disasm.capstone import CapstoneDisasmAdaptee


def test_disasm_x86():
    # arrange
    cap_adaptee_32 = CapstoneDisasmAdaptee()
    adapter_32 = DisasmAdapter(cap_adaptee_32)
    buffer = b"\x55"  # push ebp
    expected_res_32 = DisasmResult(1, "push ebp")
    # act
    insn = adapter_32.disasm(buffer)
    # assert
    assert insn == expected_res_32

    cap_adaptee_64 = CapstoneDisasmAdaptee(mode=CS_MODE_64)
    adapter_64 = DisasmAdapter(cap_adaptee_64)
    expected_res_64 = DisasmResult(1, "push rbp")
    # act
    insn = adapter_64.disasm(buffer)
    # assert
    assert insn == expected_res_64


def test_pickle():
    cap_adaptee_32 = CapstoneDisasmAdaptee()
    adapter_32 = DisasmAdapter(cap_adaptee_32)
    adapter_32 = loads(dumps(adapter_32))
    buffer = b"\x55"  # push ebp
    expected_res_32 = DisasmResult(1, "push ebp")
    # act
    insn = adapter_32.disasm(buffer)
    # assert
    assert insn == expected_res_32

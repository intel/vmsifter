# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: MIT

from pickle import dump, dumps

from vmsifter.disasm.adapter import DisasmAdapter, DisasmResult
from vmsifter.disasm.yaxpeax import YaxpeaxDisasmAdaptee


def test_disasm_x64():
    yax_adaptee_64 = YaxpeaxDisasmAdaptee()
    adapter_64 = DisasmAdapter(yax_adaptee_64)
    buffer = b"\x55"
    expected_res_64 = DisasmResult(1, "push rbp")
    insn = adapter_64.disasm(buffer)
    assert insn == expected_res_64


def test_pickle_disasm():
    yax_adaptee_64 = YaxpeaxDisasmAdaptee()
    adapter_64 = DisasmAdapter(yax_adaptee_64)
    _ds = dumps(adapter_64)

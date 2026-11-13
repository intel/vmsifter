# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: MIT

from vmsifter.fuzzer import EPT, FuzzerExecResult, Other, TunnelFuzzer
from vmsifter.injector import EPTQual, EPTQualEnum, ExitReasonEnum, InjectorResultMessage, InjInterruptEnum


def exception_result(vector: InjInterruptEnum) -> FuzzerExecResult:
    msg = InjectorResultMessage()
    msg.reason = ExitReasonEnum.NMI.value
    # valid | hardware exception | vector
    msg.intr_info = 0x80000000 | (3 << 8) | vector.value
    return FuzzerExecResult.factory_from_injector_message(msg)


def test_different_exceptions_are_different_results():
    """The tunnel skips ahead on results that look the same: #UD and #GP must not look the same"""
    assert exception_result(InjInterruptEnum.INVALID_OPCODE) != exception_result(
        InjInterruptEnum.GENERAL_PROTECTION_FAULT
    )
    assert exception_result(InjInterruptEnum.INVALID_OPCODE) == exception_result(InjInterruptEnum.INVALID_OPCODE)


def test_skip_restarts_when_result_changes():
    """After skipping ahead, a new kind of result must again be seen 10 times before the next skip"""

    # fake CPU: 1 byte is incomplete, "0f xx" completes with one result below 0x40 and another from 0x40 on
    def execute(insn: bytes) -> FuzzerExecResult:
        if len(insn) < 2:
            res = EPT()
            res.exit_reason = ExitReasonEnum.EPT
            res.eptqual = EPTQual(EPTQualEnum.EXECUTE)
            return res
        res = Other()
        res.exit_reason = ExitReasonEnum.MTF
        res.reason = 37 if insn[1] < 0x40 else 12
        res.rep_length = 2
        return res

    gen = TunnelFuzzer(insn_buffer=bytearray(b"\x0f"), end_first_byte=b"\x10").gen()
    second_bytes = []
    insn = gen.send(None).tobytes()
    try:
        while True:
            if len(insn) == 2:
                second_bytes.append(insn[1])
            insn = gen.send(execute(insn)).tobytes()
    except StopIteration:
        pass

    # first region: 10 similar results, then one sample per nibble
    assert second_bytes[:14] == [*range(0x00, 0x0B), 0x10, 0x20, 0x30]
    # second region starts at 0x40: sampled like the first one, not skipped after 2 results
    assert second_bytes[14:28] == [*range(0x40, 0x4B), 0x50, 0x60, 0x70]

# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: MIT

from vmsifter.fuzzer import Interrupted, Other, RandomFuzzer
from vmsifter.injector import ExitReasonEnum


def test_result_is_marked_for_logging():
    gen = RandomFuzzer().gen()
    insn = gen.send(None).tobytes()
    result = Other()
    result.exit_reason = ExitReasonEnum.MTF
    result.final = None
    # act
    gen.send(result)
    # assert: the worker only logs results that have a final
    assert result.final is not None
    assert result.final.exec_res is result
    assert result.final.insn == insn.hex()
    assert result.final.len == len(insn)


def test_interrupted_insn_is_retried():
    fuzzer = RandomFuzzer(insn_buffer=bytearray(b"\x0f\x0b"))
    gen = fuzzer.gen()
    insn = gen.send(None).tobytes()
    result = Interrupted()
    result.exit_reason = ExitReasonEnum.EXTERNAL_INTERRUPT
    result.final = None
    # act
    retry = gen.send(result).tobytes()
    # assert
    assert retry == insn
    assert result.final is None

# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: MIT

import pytest

from vmsifter.fuzzer import Other, TunnelFuzzer
from vmsifter.injector import ExitReasonEnum


def first_bytes_sent(fuzzer: TunnelFuzzer) -> set:
    """Run the fuzzer against a fake CPU where every 1-byte instruction completes with a distinct result"""
    sent = set()
    gen = fuzzer.gen()
    insn = gen.send(None)
    try:
        while True:
            sent.add(insn[0])
            result = Other()
            result.exit_reason = ExitReasonEnum.MTF
            # a different reason per first byte: results never look alike, so nothing is skipped
            result.reason = insn[0]
            result.rep_length = len(insn)
            insn = gen.send(result)
    except StopIteration:
        pass
    return sent


@pytest.mark.parametrize("jobs", [1, 2, 8])
def test_partitions_cover_every_first_byte_once(jobs):
    parts = [first_bytes_sent(part) for part in TunnelFuzzer().partition(jobs)]
    # every first byte is fuzzed
    assert set().union(*parts) == set(range(256))
    # and by one worker only
    assert sum(len(part) for part in parts) == 256

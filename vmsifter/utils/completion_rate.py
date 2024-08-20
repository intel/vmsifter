# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: MIT

from attrs import define

from xensifter.config import settings
from xensifter.fuzzer.partition import X86Range

CACHE_DYNA_COMPLETION_RATE_PRECISION: int = settings.completion_rate_precision


@define(auto_attribs=True, repr=True)
class ByteRangeCompletion:
    """Utils to compute the completion rate of a given binary x86 range for the TunnelFuzzer"""

    range_start: int
    range_end: int

    @classmethod
    def from_x86_range(cls, range: X86Range):
        start = int.from_bytes(
            range.start[:CACHE_DYNA_COMPLETION_RATE_PRECISION]
            + b"\x00" * (CACHE_DYNA_COMPLETION_RATE_PRECISION - len(range.start)),
            byteorder="big",
        )
        end = int.from_bytes(
            range.end[:CACHE_DYNA_COMPLETION_RATE_PRECISION]
            + b"\x00" * (CACHE_DYNA_COMPLETION_RATE_PRECISION - len(range.end)),
            byteorder="big",
        )
        instance = cls(start, end)
        return instance

    def completion_rate(self, insn: memoryview) -> float:
        insn_bytes_part = bytearray(insn)[:CACHE_DYNA_COMPLETION_RATE_PRECISION]
        current = int.from_bytes(
            insn_bytes_part + b"\x00" * (CACHE_DYNA_COMPLETION_RATE_PRECISION - len(insn_bytes_part)), byteorder="big"
        )
        val = ((current - self.range_start) * 100) / (self.range_end - self.range_start)
        return val

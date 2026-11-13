# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: MIT

from typing import List

from attrs import define

from vmsifter.config import settings


@define(auto_attribs=True)
class X86Range:
    start: bytes
    end: bytes


DEFAULT_X86_RANGE = X86Range(settings.x86.min_buffer, settings.x86.max_end_first_byte)


def partition(nb_parts: int, x86_range: X86Range = DEFAULT_X86_RANGE) -> List[X86Range]:
    end = int.from_bytes(x86_range.end[0:1], byteorder="big")
    start = int.from_bytes(x86_range.start[0:1], byteorder="big")
    # number of first-byte values to share, both ends included
    span = end - start + 1
    if not 0 < nb_parts <= span:
        raise ValueError(f"Cannot split {span} first-byte values into {nb_parts} ranges")

    def int_to_bytes(value: int):
        return value.to_bytes(1, byteorder="big")

    # ex: nb_parts = 2 over [0x00-0xff]: bounds = [0, 128, 256] => [0x00-0x7f] [0x80-0xff]
    bounds = [start + i * span // nb_parts for i in range(nb_parts + 1)]
    ranges = [X86Range(start=int_to_bytes(lo), end=int_to_bytes(hi - 1)) for lo, hi in zip(bounds, bounds[1:])]
    # keep the full start / end buffers on the outer ranges
    ranges[0].start = x86_range.start
    ranges[-1].end = x86_range.end
    return ranges

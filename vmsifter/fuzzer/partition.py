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
    if nb_parts > end:
        raise ValueError(f"Partitioning over {max} ranges is unsupported")

    def int_to_bytes(value: int):
        return value.to_bytes(1, byteorder="big")

    step = (end - start) // nb_parts
    rem = (end - start) % nb_parts
    # ex: nb_parts = 2
    # start=0, end=0 + 127 - 1
    # start=127, end=255-1 (remainder) converted to 255 below since it's the last range
    ranges = [X86Range(start=int_to_bytes(v), end=int_to_bytes(v + step - 1)) for v in range(start, end - rem, step)]
    # set first range
    ranges[0].start = x86_range.start
    # set last range
    ranges[-1].end = x86_range.end
    return ranges

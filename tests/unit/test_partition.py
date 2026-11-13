# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: MIT

import pytest

from vmsifter.config import settings
from vmsifter.fuzzer.partition import X86Range, partition


@pytest.mark.parametrize(
    "nb_part, expected",
    [
        (1, [X86Range(start=settings.x86.min_buffer, end=settings.x86.max_end_first_byte)]),
        (
            2,
            [
                X86Range(start=settings.x86.min_buffer, end=b"\x7f"),
                X86Range(start=b"\x80", end=settings.x86.max_end_first_byte),
            ],
        ),
        (
            3,
            [
                X86Range(start=settings.x86.min_buffer, end=b"T"),
                X86Range(start=b"U", end=b"\xa9"),
                X86Range(start=b"\xaa", end=settings.x86.max_end_first_byte),
            ],
        ),
    ],
)
def test_partition_one_part(nb_part, expected):
    assert partition(nb_part) == expected


@pytest.mark.parametrize("nb_part", [7, 48, 96, 128, 255, 256])
def test_partition_is_balanced(nb_part):
    ranges = partition(nb_part)
    sizes = [r.end[0] - r.start[0] + 1 for r in ranges]
    assert len(ranges) == nb_part
    # the whole space is covered, without overlap
    assert sum(sizes) == 256
    assert all(prev.end[0] + 1 == nxt.start[0] for prev, nxt in zip(ranges, ranges[1:]))
    # no worker gets more than one extra first byte
    assert max(sizes) - min(sizes) <= 1


@pytest.mark.parametrize("nb_part", [0, 257])
def test_partition_rejects_impossible_split(nb_part):
    with pytest.raises(ValueError, match=str(nb_part)):
        partition(nb_part)

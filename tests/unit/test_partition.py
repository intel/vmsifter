# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: MIT

import pytest

from xensifter.config import settings
from xensifter.fuzzer.partition import X86Range, partition


@pytest.mark.parametrize(
    "nb_part, expected",
    [
        (1, [X86Range(start=settings.x86.min_buffer, end=settings.x86.max_end_first_byte)]),
        (
            2,
            [
                X86Range(start=settings.x86.min_buffer, end=b"\x7e"),
                X86Range(start=b"\x7f", end=settings.x86.max_end_first_byte),
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

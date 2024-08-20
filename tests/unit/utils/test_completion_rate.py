# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: MIT

import pytest

from xensifter.config import settings
from xensifter.fuzzer.partition import X86Range
from xensifter.utils.completion_rate import ByteRangeCompletion


def test_completion_rate():
    x86range = X86Range(start=b"\x00", end=b"\xff")
    completion = ByteRangeCompletion.from_x86_range(x86range)
    buffer = b"\x42"
    res = completion.completion_rate(buffer)
    assert round(res, 4) == 25.8824

    x86range = X86Range(start=b"\x10", end=b"\x30")
    completion = ByteRangeCompletion.from_x86_range(x86range)
    buffer = b"\x15"
    res = completion.completion_rate(buffer)
    assert round(res, 4) == 15.625

    x86range = X86Range(start=b"\x10", end=b"\x30")
    completion = ByteRangeCompletion.from_x86_range(x86range)
    buffer = b"\x15\x02\x04\xff"
    res = completion.completion_rate(buffer)
    assert round(res, 4) == 15.6497

    x86range = X86Range(start=b"\x7f", end=b"\xff")
    completion = ByteRangeCompletion.from_x86_range(x86range)
    buffer = b"\x80\x04\x05\x07"
    res = completion.completion_rate(buffer)
    assert round(res, 4) == 0.7935

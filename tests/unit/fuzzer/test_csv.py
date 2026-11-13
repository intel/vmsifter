# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: MIT

import pytest

from vmsifter.config import settings
from vmsifter.fuzzer import Other
from vmsifter.fuzzer.csv import CsvFuzzer
from vmsifter.injector import ExitReasonEnum

HEADER = "insn,length,exit-type,misc,pfct1,pfct2,pfct3,pfct4,pfct5,pfct6,pfct7,reg-delta\n"


@pytest.fixture
def csv_file(tmp_path):
    path = tmp_path / "input.csv"
    path.write_text(HEADER + "90,1,vmexit:37,,0,0,0,0,0,0,0,\n0f0b,2,vmexit:0,,0,0,0,0,0,0,0,\n")
    return str(path)


def replay(fuzzer: CsvFuzzer, limit: int = 1000) -> list:
    sent = []
    gen = fuzzer.gen()
    insn = gen.send(None).tobytes()
    try:
        while len(sent) < limit:
            sent.append(insn)
            result = Other()
            result.exit_reason = ExitReasonEnum.MTF
            insn = gen.send(result).tobytes()
    except StopIteration:
        pass
    return sent


def test_rows_are_replayed_as_is(csv_file):
    assert replay(CsvFuzzer(extra_params=[csv_file])) == [b"\x90", b"\x0f\x0b"]


def test_extra_byte(csv_file, monkeypatch):
    monkeypatch.setitem(settings, "extra_byte", 1)
    sent = replay(CsvFuzzer(extra_params=[csv_file]))
    # each row is followed by every value of the extra byte
    assert sent[:256] == [b"\x90" + bytes([i]) for i in range(256)]
    assert sent[256:] == [b"\x0f\x0b" + bytes([i]) for i in range(256)]


def test_prefix(csv_file, monkeypatch):
    monkeypatch.setitem(settings, "min_prefix_count", 1)
    monkeypatch.setitem(settings, "max_prefix_count", 1)
    sent = replay(CsvFuzzer(extra_params=[csv_file]))
    prefixes = list(settings.mode_prefix)
    # each row is replayed behind every prefix
    assert sent[: len(prefixes)] == [bytes([p, 0x90]) for p in prefixes]
    assert sent[len(prefixes) :] == [bytes([p, 0x0F, 0x0B]) for p in prefixes]

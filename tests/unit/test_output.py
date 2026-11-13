# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: MIT

from vmsifter.config import settings
from vmsifter.output import CSVOutput


def test_second_run_does_not_append_to_first(tmp_path, monkeypatch):
    monkeypatch.setitem(settings, "workdir", str(tmp_path))
    header = ",".join(CSVOutput.CSV_HEADER)
    # act: two runs in the same workdir
    for _ in range(2):
        with CSVOutput(0):
            pass
    # assert
    assert (tmp_path / "results_0.csv").read_text().splitlines() == [header]
    assert (tmp_path / "invalid_instructions_0.csv").read_text().splitlines() == [header]

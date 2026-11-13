# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: MIT

import subprocess
import time
from pathlib import Path

from vmsifter.injector import xenvm
from vmsifter.injector.xenvm import XenVMInjector


def start_fake_injector(tmp_path: Path, on_sigterm: str) -> XenVMInjector:
    """An injector whose process is a shell script, started and tracked like the real one"""
    ready = tmp_path / "ready"
    script = f'trap "{on_sigterm}" TERM; touch {ready}; while :; do sleep 0.05; done'
    injector = XenVMInjector(tmp_path / "sock", 0)
    injector._proc = injector._ex.enter_context(subprocess.Popen(["sh", "-c", script]))
    while not ready.exists():
        time.sleep(0.01)
    return injector


def test_injector_can_clean_up_on_exit(tmp_path):
    """The injector destroys its fork VM in its exit path: it must get the chance to run it"""
    cleaned = tmp_path / "cleaned"
    injector = start_fake_injector(tmp_path, on_sigterm=f"touch {cleaned}; exit 0")
    # act
    injector.__exit__(None, None, None)
    # assert
    assert cleaned.exists()
    assert injector._proc.returncode == 0


def test_stuck_injector_is_killed(tmp_path, monkeypatch):
    monkeypatch.setattr(xenvm, "INJECTOR_STOP_TIMEOUT", 0.3)
    injector = start_fake_injector(tmp_path, on_sigterm="")
    # act
    injector.__exit__(None, None, None)
    # assert
    assert injector._proc.returncode == -9

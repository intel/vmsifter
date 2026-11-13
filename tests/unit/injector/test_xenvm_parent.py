# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: MIT

from contextlib import contextmanager
from pathlib import Path

import pytest

from vmsifter.injector import xenvm
from vmsifter.injector.xenvm import XenVMInjector

PARENT_DOMID = 42


class FakePopen:
    """Stands for the C injector process"""

    def __init__(self, cmd, **kwargs):
        self.cmd = cmd

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return None

    def terminate(self):
        pass

    def wait(self, timeout=None):
        return 0


@pytest.fixture
def xen_events(monkeypatch):
    """Replace every Xen / injector command by a recorder"""
    events = []

    @contextmanager
    def fake_xtf_vm(cfg_file_path):
        events.append("parent created")
        try:
            yield PARENT_DOMID
        finally:
            events.append("parent destroyed")

    @contextmanager
    def fake_cfg_file():
        yield Path("parent.cfg")

    def fake_popen(cmd, **kwargs):
        events.append(f"fork of {cmd[cmd.index('--domid') + 1]}")
        return FakePopen(cmd)

    monkeypatch.setattr(xenvm, "xtf_vm", fake_xtf_vm)
    monkeypatch.setattr(xenvm, "gen_tmp_xenvm_configfile", fake_cfg_file)
    monkeypatch.setattr(xenvm.subprocess, "call", lambda cmd, **kwargs: 0)
    monkeypatch.setattr(xenvm.subprocess, "check_call", lambda cmd, **kwargs: 0)
    monkeypatch.setattr(xenvm.subprocess, "Popen", fake_popen)
    return events


def test_parent_vm_outlives_every_injector(xen_events, tmp_path):
    with XenVMInjector.shared_setup():
        first = XenVMInjector(tmp_path / "sock", 0).__enter__()
        second = XenVMInjector(tmp_path / "sock", 2).__enter__()
        # first worker is done, second one still fuzzes a fork of the parent
        first.__exit__(None, None, None)
        assert "parent destroyed" not in xen_events
        second.__exit__(None, None, None)
        assert "parent destroyed" not in xen_events
    assert xen_events == ["parent created", f"fork of {PARENT_DOMID}", f"fork of {PARENT_DOMID}", "parent destroyed"]


def test_injector_needs_the_parent_vm(xen_events, tmp_path):
    with pytest.raises(RuntimeError):
        XenVMInjector(tmp_path / "sock", 0).__enter__()
    assert xen_events == []

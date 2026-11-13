# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: MIT

import subprocess

import pytest

from vmsifter.utils import xen

VM_NAME = "test-hvm32-vmsifter-0b0e3b0c"


@pytest.fixture
def cfg_file(tmp_path):
    path = tmp_path / "vm.cfg"
    path.write_text(f'name="{VM_NAME}"\nvcpus=1\n')
    return path


@pytest.fixture
def xl_calls(monkeypatch):
    """Record xl commands instead of running them"""
    calls = []
    monkeypatch.setattr(xen.subprocess, "check_call", lambda cmd: calls.append(cmd))
    return calls


def test_domid_is_looked_up_by_exact_name(cfg_file, xl_calls, monkeypatch):
    def check_output(cmd):
        xl_calls.append(cmd)
        return b"7\n"

    monkeypatch.setattr(xen.subprocess, "check_output", check_output)
    # act
    with xen.xtf_vm(cfg_file) as domid:
        assert domid == 7
    # assert
    assert xl_calls == [
        ["sudo", "xl", "create", "-p", str(cfg_file)],
        ["sudo", "xl", "domid", VM_NAME],
        ["sudo", "xl", "destroy", VM_NAME],
    ]


def test_vm_is_destroyed_when_lookup_fails(cfg_file, xl_calls, monkeypatch):
    def check_output(cmd):
        raise subprocess.CalledProcessError(1, cmd)

    monkeypatch.setattr(xen.subprocess, "check_output", check_output)
    # act
    with pytest.raises(subprocess.CalledProcessError):
        with xen.xtf_vm(cfg_file):
            pass
    # assert: the VM we created does not stay behind
    assert xl_calls[-1] == ["sudo", "xl", "destroy", VM_NAME]

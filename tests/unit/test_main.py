# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: MIT

import sys

import pytest

import vmsifter.__main__ as cli
from vmsifter.config import FuzzerType, settings


class FakeExecutor:
    def __enter__(self):
        return self

    def __exit__(self, *args):
        return None

    def run(self, extra_params):
        pass


@pytest.fixture
def run_main(monkeypatch):
    """Run the CLI entrypoint without Xen: no executor, no logging setup"""
    monkeypatch.setattr(cli, "SifterExecutor", FakeExecutor)
    monkeypatch.setattr(cli, "setup_logging", lambda debug_enabled=False: None)
    # restore what main() changes
    for key in ("debug", "fuzzer_mode", "injector_mode"):
        monkeypatch.setitem(settings, key, settings[key])

    def run(*argv):
        monkeypatch.setattr(sys, "argv", ["vmsifter", *argv])
        return cli.main()

    return run


def test_fuzzer_mode_from_config_is_kept(run_main):
    # as set by VMSIFTER_FUZZER_MODE=CSV
    settings.fuzzer_mode = FuzzerType.CSV
    run_main()
    assert settings.fuzzer_mode == FuzzerType.CSV


def test_debug_from_config_is_kept(run_main):
    # as set by VMSIFTER_DEBUG=true
    settings.debug = True
    run_main()
    assert settings.debug is True


def test_cli_options_override_config(run_main):
    settings.fuzzer_mode = FuzzerType.CSV
    settings.debug = False
    run_main("--fuzzer-mode", "random", "--debug")
    assert settings.fuzzer_mode == FuzzerType.RANDOM
    assert settings.debug is True


def test_unknown_fuzzer_mode_is_refused(run_main):
    assert run_main("--fuzzer-mode", "nope") == 1

# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: MIT

from collections import Counter

import pytest

from vmsifter.config import settings
from vmsifter.fuzzer import Other
from vmsifter.fuzzer.drizzler import DrizzlerFuzzer
from vmsifter.injector import ExitReasonEnum


@pytest.fixture
def generated(monkeypatch):
    """Record which tests the fuzzer generates, without assembling them"""
    generated = []

    def record(self, test, chance, type):
        generated.append((self.generation, self.current_test_set, self.current_test, chance > 0, type))
        self.count = 1

    monkeypatch.setattr(DrizzlerFuzzer, "generate_test", record)
    monkeypatch.setitem(settings.fuzzer.drizzler, "seed", 1234)
    return generated


def run(fuzzer: DrizzlerFuzzer, limit: int = 100000) -> int:
    gen = fuzzer.gen()
    gen.send(None)
    for executed in range(1, limit):
        result = Other()
        result.exit_reason = ExitReasonEnum.MTF
        try:
            gen.send(result)
        except StopIteration:
            return executed
    pytest.fail(f"fuzzer still running after {limit} tests")


@pytest.mark.parametrize("num_seeds", [1, 3])
def test_every_test_of_every_seed_runs_once(generated, monkeypatch, num_seeds):
    monkeypatch.setitem(settings.fuzzer.drizzler, "num_seeds", num_seeds)
    fuzzer = DrizzlerFuzzer()
    # act
    executed = run(fuzzer)
    # assert: one execution per generated test
    assert executed == len(generated)
    # each test of each set: without and with injection, in the 3 injection types
    variants = [(injection, type) for injection in (False, True) for type in range(3)]
    for test_set, tests in enumerate(fuzzer.driver.tests):
        assert len(tests) > 2
        for test in range(len(tests)):
            for generation in range(1, num_seeds + 1):
                for injection, type in variants:
                    assert Counter(generated)[(generation, test_set, test, injection, type)] == 1
    assert {generation for generation, *_ in generated} == set(range(1, num_seeds + 1))


def test_can_be_partitioned(generated):
    """The executor always partitions the fuzzer, even for a single worker"""
    parts = list(DrizzlerFuzzer().partition(2))
    assert len(parts) == 2

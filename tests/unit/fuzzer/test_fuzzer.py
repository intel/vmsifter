# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: MIT

import pickle
from concurrent.futures import ProcessPoolExecutor

import pytest

from xensifter.fuzzer import RandomFuzzer, TunnelFuzzer


@pytest.mark.parametrize(
    "fuzzer_cls, fuzzer_args",
    [
        (TunnelFuzzer, {"insn_buffer": bytearray(b"\x04\x05"), "marker_idx": 1, "end_first_byte": b"\xab"}),
        (RandomFuzzer, {}),
    ],
)
def test_fuzzer_can_be_pickle(fuzzer_cls, fuzzer_args):
    """Test fuzzer instance can be sent to ProcessPool"""
    # this test was needed because sending the object instance worked
    # but the received instance had 0 attributes (?)
    instance = fuzzer_cls(**fuzzer_args)

    pickled = pickle.dumps(instance)
    unpickeled = pickle.loads(pickled)
    assert instance == unpickeled


def func_process_pool(fuzzer):
    return fuzzer


@pytest.mark.parametrize(
    "fuzzer_cls, fuzzer_args",
    [
        (TunnelFuzzer, {"insn_buffer": bytearray(b"\x04\x05"), "marker_idx": 1, "end_first_byte": b"\xab"}),
        (RandomFuzzer, {}),
    ],
)
def test_fuzzer_can_be_sent_to_process_pool(fuzzer_cls, fuzzer_args):
    instance = fuzzer_cls(**fuzzer_args)

    with ProcessPoolExecutor(max_workers=1) as pool:
        fut = pool.submit(func_process_pool, instance)
        result = fut.result()
        assert result == instance

# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: MIT

import socket

import pytest

from vmsifter.executor import SifterExecutor


class SilentInjector:
    """An injector that never connects back"""

    exited = False

    def __init__(self, socket_path, pinned_cpu):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *args):
        SilentInjector.exited = True


def test_injector_that_never_connects_is_reported(tmp_path):
    # executor without its Xen specific setup, only what _allocate_pcpu needs
    executor = SifterExecutor.__new__(SifterExecutor)
    executor._sock_path = tmp_path / "sock"
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.bind(str(executor._sock_path))
        sock.listen(1)
        sock.settimeout(0.2)
        executor._sock = sock
        # act
        with pytest.raises(RuntimeError, match="did not connect"):
            executor._allocate_pcpu(3, None, SilentInjector)
    # assert: the injector is not left running
    assert SilentInjector.exited

# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: MIT

import logging
import socket
import threading

import pytest

from vmsifter.config import settings
from vmsifter.fuzzer import TunnelFuzzer
from vmsifter.injector import InjectorResultMessage
from vmsifter.worker import Worker


@pytest.fixture
def workdir(tmp_path, monkeypatch):
    monkeypatch.setitem(settings, "workdir", str(tmp_path))
    # test_tunnel.py::test_min_prefix leaves prefixes enabled
    monkeypatch.setitem(settings, "min_prefix_count", 0)
    # the worker replaces the root logger handlers by its log file
    root = logging.getLogger()
    handlers = root.handlers[:]
    yield tmp_path
    for handler in root.handlers:
        handler.close()
    root.handlers[:] = handlers


def test_log_tells_where_the_worker_stopped(workdir):
    worker_sock, injector_sock = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)

    def injector():
        with injector_sock:
            # ready
            injector_sock.send(bytes(InjectorResultMessage()))
            # first instruction: fine
            injector_sock.recv(15)
            msg = InjectorResultMessage()
            msg.reason = 37
            msg.insn_length = 1
            injector_sock.send(bytes(msg))
            # second instruction: a message the worker cannot make sense of (unknown interruption type)
            injector_sock.recv(15)
            msg = InjectorResultMessage()
            msg.reason = 0
            msg.intr_info = 0x80000000 | (1 << 8)
            injector_sock.send(bytes(msg))

    thread = threading.Thread(target=injector)
    thread.start()
    worker = Worker(0, TunnelFuzzer(insn_buffer=bytearray(b"\x0e")))
    # act
    with worker_sock, pytest.raises(ValueError):
        worker.handle_client(worker_sock, None)
    thread.join()
    # assert: 0e was done, the worker died on 0f
    log = (workdir / "worker_0.log").read_text()
    assert "Worker stopped on instruction: [0f]" in log

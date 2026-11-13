# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: MIT

import logging
import socket

import pytest

from vmsifter.injector import InjectorResultMessage
from vmsifter.worker import Worker


@pytest.fixture
def worker():
    worker = Worker(0, None)
    worker._logger = logging.getLogger("test_worker")
    return worker


@pytest.fixture
def sockets():
    worker_sock, injector_sock = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    with worker_sock, injector_sock:
        yield worker_sock, injector_sock


def recv(worker: Worker, sock) -> InjectorResultMessage:
    view = memoryview(bytearray(InjectorResultMessage.size()))
    return worker._recv_injector_result(sock, 1, view)


def test_full_message_is_accepted(worker, sockets):
    worker_sock, injector_sock = sockets
    msg = InjectorResultMessage()
    msg.reason = 48
    injector_sock.send(bytes(msg))
    assert recv(worker, worker_sock).reason == 48


def test_message_of_wrong_size_is_refused(worker, sockets):
    """An injector built with another struct layout must not be silently misread"""
    worker_sock, injector_sock = sockets
    injector_sock.send(bytes(InjectorResultMessage())[:-8])
    with pytest.raises(ValueError, match="248 bytes"):
        recv(worker, worker_sock)


def test_closed_injector_is_eof(worker, sockets):
    worker_sock, injector_sock = sockets
    injector_sock.close()
    with pytest.raises(EOFError):
        recv(worker, worker_sock)

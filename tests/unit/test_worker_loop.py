# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: MIT

import csv
import logging
import socket
import threading

import pytest

from vmsifter.config import settings
from vmsifter.fuzzer import TunnelFuzzer
from vmsifter.injector import ExitReasonEnum, InjectorResultMessage, InjInterruptEnum
from vmsifter.worker import Worker

CANARY = 0x1100


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


class FakeInjector(threading.Thread):
    """Plays the C injector on the other end of the socket: 0xfd is an invalid opcode,
    0xfe is interrupted once then completes and changes rax, anything else completes"""

    def __init__(self, sock: socket.socket):
        super().__init__()
        self.sock = sock
        self.received: list = []

    def reply(self, insn: bytes) -> InjectorResultMessage:
        msg = InjectorResultMessage()
        for i in range(len(msg.regs)):
            msg.regs[i] = CANARY + i
        msg.insn_length = len(insn)
        if insn == b"\xfd":
            msg.reason = ExitReasonEnum.NMI.value
            msg.intr_info = 0x80000000 | (3 << 8) | InjInterruptEnum.INVALID_OPCODE.value
        elif insn == b"\xfe" and self.received.count(insn) == 1:
            msg.reason = ExitReasonEnum.EXTERNAL_INTERRUPT.value
        else:
            msg.reason = ExitReasonEnum.MTF.value
            msg.perfct[0] = 3
            if insn == b"\xfe":
                msg.regs[1] = 0xBEEF
        return msg

    def run(self):
        with self.sock:
            # ready
            self.sock.send(bytes(InjectorResultMessage()))
            while insn := self.sock.recv(15):
                self.received.append(insn)
                self.sock.send(bytes(self.reply(insn)))


def rows(path) -> dict:
    with open(path, newline="") as f:
        return {row["insn"]: row for row in csv.DictReader(f)}


def test_worker_logs_what_the_injector_reports(workdir):
    worker_sock, injector_sock = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    injector = FakeInjector(injector_sock)
    injector.start()
    worker = Worker(0, TunnelFuzzer(insn_buffer=bytearray(b"\xfd"), end_first_byte=b"\xff"))
    # act
    with worker_sock:
        stats = worker.handle_client(worker_sock, None)
    injector.join()
    # assert
    # the interrupted instruction was sent again
    assert injector.received[:3] == [b"\xfd", b"\xfe", b"\xfe"]
    # valid and invalid instructions go to their own file, the interrupted attempt to none
    valid = rows(workdir / "results_0.csv")
    invalid = rows(workdir / "invalid_instructions_0.csv")
    assert list(invalid) == ["fd"]
    assert "fd" not in valid
    assert valid["fe"]["length"] == "1"
    assert valid["fe"]["exit-type"] == "vmexit:37"
    assert valid["fe"]["pfct1"] == "3"
    # rip is always reported, then the registers that left their canary value
    assert set(valid["fe"]["reg-delta"].split()) == {f"rip:{hex(CANARY)}", "rax:0xbeef"}
    assert "invalid_opcode" in invalid["fd"]["exit-type"]
    assert invalid["fd"]["reg-delta"] == f"rip:{hex(CANARY)}"
    # stats
    assert stats.exitstats[ExitReasonEnum.EXTERNAL_INTERRUPT] == 1
    assert stats.exitstats[ExitReasonEnum.NMI] == 1

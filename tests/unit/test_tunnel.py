from itertools import chain

import pytest

from xensifter.config import settings
from xensifter.fuzzer import EPT, FuzzerExecResult, Interrupted, Other, TunnelFuzzer
from xensifter.fuzzer.partition import X86Range, partition
from xensifter.injector import EPTQual, EPTQualEnum, ExitReasonEnum, InjectorResultMessage, InjInterruptEnum


def test_tunnel_retry():
    """The tunnel should send the same insn if retry is requested"""
    # arrange
    tun = TunnelFuzzer()
    gen = tun.gen()
    # act
    failed_insn = gen.send(None).tobytes()
    exec_res = Interrupted()
    exec_res.exit_reason = ExitReasonEnum.EXTERNAL_INTERRUPT
    next_insn = gen.send(exec_res).tobytes()
    # assert
    assert failed_insn == next_insn


def test_default_tunnel_first_insn_is_one_byte_0x0():
    """The default tunnel should return a one byte 0x0 as its first insn"""
    # arrange
    tun = TunnelFuzzer()
    gen = tun.gen()
    # act
    insn = gen.send(None).tobytes()
    # assert
    assert insn == b"\x00"


def test_first_insn_is_same_as_init_value():
    # arrange
    init_fuzzer = [0x04, 0x05, 0xFF, 0xA, 0x22]
    tun = TunnelFuzzer(bytearray(init_fuzzer))
    gen = tun.gen()
    # act
    insn = gen.send(None).tobytes()
    # assert
    assert insn == bytes(init_fuzzer)


def test_pagefault_next_insn():
    """On a pagefault exec result, the next instruction should get one byte bigger"""
    # arrange
    tun = TunnelFuzzer()
    gen = tun.gen()
    prev_insn = gen.send(None).tobytes()
    exec_res = EPT()
    exec_res.eptqual = EPTQual(EPTQualEnum.EXECUTE)
    exec_res.exit_reason = ExitReasonEnum.EPT
    # act
    new_insn = gen.send(exec_res).tobytes()
    # assert
    assert len(new_insn) == len(prev_insn) + 1
    # last element should be set to 0
    assert new_insn[-1] == 0


def test_same_length_increment_last_byte():
    """on a valid exec result, if the length is the same, the last byte should be incremented"""
    # arrange
    tun = TunnelFuzzer()
    gen = tun.gen()
    prev_insn = gen.send(None).tobytes()
    exec_res = Other()
    exec_res.exit_reason = ExitReasonEnum.MTF
    # act
    new_insn = gen.send(exec_res).tobytes()
    # assert
    assert new_insn[-1] == prev_insn[-1] + 1


def test_rollover_previous_byte():
    """on a valid exec result, if the last byte was 0xFF, reset to 0 and move marker to previous byte"""
    # arrange
    tun = TunnelFuzzer(bytearray([0x04, 0xFF]), marker_idx=1)
    gen = tun.gen()
    prev_insn = gen.send(None).tobytes()
    exec_res = Other()
    exec_res.exit_reason = ExitReasonEnum.MTF
    # act
    new_insn = gen.send(exec_res).tobytes()
    # assert
    assert new_insn == bytes([0x05])
    # marker should be on 0x04 byte
    assert tun.marker_idx == 0


def test_rollover_multiple_bytes():
    # arrange
    init_content = [0x04, 0x05, 0xFF, 0xFF, 0xFF]
    tun = TunnelFuzzer(bytearray(init_content), marker_idx=4)
    gen = tun.gen()
    prev_insn = gen.send(None).tobytes()
    exec_res = Other()
    exec_res.exit_reason = ExitReasonEnum.MTF
    # act
    new_insn = gen.send(exec_res).tobytes()
    # assert
    assert new_insn == bytes([0x04, 0x06])
    assert tun.marker_idx == 1


@pytest.mark.skip(reason="double check backward search")
def test_marker_moved_new_instruction_length():
    """on a valid exec result, if the length has changed, the marker should have moved to the
    end of the new instruction"""
    # arrange
    init_content = [0xC7, 0x04, 0x06]
    tun = TunnelFuzzer(bytearray(init_content), marker_idx=2)
    gen = tun.gen()
    gen.send(None).tobytes()
    exec_res = Other()
    exec_res.exit_reason = ExitReasonEnum.MTF
    exec_res.rep_length = 7
    # act
    new_insn = gen.send(exec_res).tobytes()
    # assert
    # marker should have moved, and last byte incremented
    assert list(new_insn) == [0xC7, 0x04, 0x06, 0x00, 0x00, 0x00, 0x01]


def test_need_more_bytes_max_insn_size():
    """on a pagefault exec result, if the tunnel requests more bytes than an x86 insn can contain,
    the marker byte should be increased and the length reset to the marker index"""
    # arrange
    init_content = [0x6, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
    tun = TunnelFuzzer(bytearray(init_content), marker_idx=0)
    gen = tun.gen()
    gen.send(None).tobytes()
    exec_res = EPT()
    exec_res.exit_reason = ExitReasonEnum.EPT
    exec_res.eptqual = EPTQual(EPTQualEnum.EXECUTE)
    # act
    new_insn = gen.send(exec_res).tobytes()
    # assert
    assert list(new_insn) == [0x7]


@pytest.mark.parametrize("x86_range", list(chain(*[partition(i) for i in [1, 3, 8, 64]])))
def test_fuzzing_complete(x86_range: X86Range):
    """test that the tunnel generator stops"""
    # arrange
    init_content = [int.from_bytes(x86_range.end, byteorder="big")]
    tun = TunnelFuzzer(bytearray(init_content), marker_idx=0, end_first_byte=x86_range.end)
    gen = tun.gen()
    prev_insn = gen.send(None).tobytes()
    exec_res = Other()
    exec_res.exit_reason = ExitReasonEnum.APIC_ACCESS
    exec_res.rep_length = len(prev_insn)
    # act
    with pytest.raises(StopIteration):
        gen.send(exec_res)


@pytest.mark.parametrize("mode", ["32", "64"])
def test_min_prefix(mode):
    # arrange
    settings.x86.exec_mode = mode
    settings.min_prefix_count = 1
    settings.max_prefix_count = 5
    settings.validators.validate()
    settings.prefix_range = range(settings.min_prefix_count, settings.max_prefix_count + 1)
    tun = TunnelFuzzer(marker_idx=settings.min_prefix_count + 1)
    gen = tun.gen()
    # act
    prev_insn = gen.send(None).tobytes()
    exec_res = Other()
    exec_res.exit_reason = ExitReasonEnum.MTF
    exec_res.rep_length = len(prev_insn)
    new_insn = gen.send(exec_res)
    # assert
    assert len([b for b in prev_insn if b in settings.x86.prefix]) >= settings.min_prefix_count
    assert len([b for b in prev_insn if b in settings.x86.prefix]) < settings.max_prefix_count


def test_backward_search():
    # arrange
    init_content = bytearray([0x00, 0xC0, 0x00, 0x00, 0x00, 0x00])
    tun = TunnelFuzzer(insn_buffer=init_content, marker_idx=1)
    gen = tun.gen()
    # act
    gen.send(None)
    msg = InjectorResultMessage()
    msg.reason = 37
    msg.qualification = 0
    msg.insn_length = 2
    msg.rip = 0x1FFC
    exec_res = FuzzerExecResult.factory_from_injector_message(msg)
    insn_1 = gen.send(exec_res)
    msg.rip = 0x1FFD
    exec_res = FuzzerExecResult.factory_from_injector_message(msg)
    insn_2 = gen.send(exec_res)
    msg.rip = 0x1FFE
    exec_res = FuzzerExecResult.factory_from_injector_message(msg)
    insn_3 = gen.send(exec_res)
    msg.rip = 0x1FFF
    exec_res = FuzzerExecResult.factory_from_injector_message(msg)
    insn_4 = gen.send(exec_res)
    msg.rip = 0x2000
    exec_res = FuzzerExecResult.factory_from_injector_message(msg)
    # assert
    assert list(insn_1) == [0x00, 0xC0, 0x00, 0x00, 0x00]
    assert list(insn_2) == [0x00, 0xC0, 0x00, 0x00]
    assert list(insn_3) == [0x00, 0xC0, 0x00]
    assert list(insn_4) == [0x00, 0xC0]


@pytest.mark.skip(reason="infinite recursion since prefix added")
def test_bump_10_insn():
    # arrange
    init_content = bytearray([0x00, 0x04, 0x05, 0x00, 0x00, 0x00, 0x00])
    tun = TunnelFuzzer(content=init_content, marker_idx=2)
    gen = tun.gen()
    # act
    # init with 2 exec similar behavior
    gen.send(None)
    msg = InjectorResultMessage()
    msg.reason = 48
    msg.qualification = 0x7AB
    # msg.qualification = 0x783
    msg.insn_length = 7
    msg.rip = 0x1FF9
    exec_res = FuzzerExecResult.factory_from_injector_message(msg)
    insn = gen.send(exec_res)
    assert list(insn) == [0x00, 0x04, 0x05, 0x00, 0x00, 0x00, 0x01]
    msg.qualification = 0x783
    exec_res = FuzzerExecResult.factory_from_injector_message(msg)
    insn = gen.send(exec_res)
    # now counter has started for 10 insn
    assert tun.counter == 1
    assert list(insn) == [0x00, 0x04, 0x05, 0x00, 0x00, 0x00, 0x02]
    last_byte = 0x2
    for _ in range(8):
        insn = gen.send(exec_res)
        last_byte += 1
        assert list(insn) == [0x00, 0x04, 0x05, 0x00, 0x00, 0x00, last_byte]

    # check first insn with bump
    first_insn_bump = list(gen.send(exec_res))
    # continue for 9 insn
    last_byte = 0x10
    for _ in range(9):
        insn = gen.send(exec_res)
        last_byte += 0x10
        assert list(insn) == [0x00, 0x04, 0x05, 0x00, 0x00, 0x00, last_byte]
    # check last insn is final marker 0xFF
    final_insn_bump = list(gen.send(exec_res))
    # assert
    assert list(first_insn_bump) == [0x00, 0x04, 0x05, 0x00, 0x00, 0x00, 0x10]
    assert list(final_insn_bump) == [0x00, 0x04, 0x05, 0x00, 0x00, 0x01]

# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: MIT

import logging
from abc import ABC, abstractmethod
from functools import lru_cache
from typing import Any, Dict, Generator, List, Optional, Tuple, Type, Union

from attr import define, evolve, field

from vmsifter.config import settings
from vmsifter.injector import (
    NUMBER_OF_REGISTERS,
    EPTQual,
    ExitReasonEnum,
    InjInterruptEnum,
    InjInterruptTypeEnum,
    PageFaultEC,
    RegistersEnum,
)
from vmsifter.injector.types import InjectorResultMessage
from vmsifter.utils import fact_logging

REGISTER_CANARY = 0x1100
# build set(dict[RegisterEnum.RAX: 0x1101, ...])
SET_REG_DELTA_REF = set(
    {
        RegistersEnum(index): val
        for index, val in enumerate(range(REGISTER_CANARY, REGISTER_CANARY + NUMBER_OF_REGISTERS))
        if index not in [RegistersEnum.CR2.value, RegistersEnum.RIP.value]
    }.items()
)


@define(init=False)
class FuzzerExecResult:
    rep_length: Optional[int] = field(eq=False)
    """Length reported by the CPU on VMEXIT"""
    exit_reason: ExitReasonEnum
    perfct: List[int] = field(eq=False)
    regs: Dict[RegistersEnum, int] = field(eq=False)
    # can be a reference to self or the self.last_complete_type from the Tunnel
    final: Optional["FinalLogResult"] = field(eq=False)
    """Attribute set by the fuzzer when the current insn is a 'final' insn that can be logged into the CSV writer"""
    # extra info from VMExit
    insn_info: Optional[int] = field(eq=False)
    gla: Optional[int] = field(eq=False)
    intr_info: Optional[int] = field(eq=False)
    intr_error: Optional[int] = field(eq=False)
    vec_info: Optional[int] = field(eq=False)
    vec_error: Optional[int] = field(eq=False)

    @abstractmethod
    def type_str(self) -> str:
        """return a string representation of the FuzzerExecResult type for CSV logging"""
        pass

    def misc_str(self) -> str:
        """return a string representation of the misc field for CSV logging"""
        s = f"cpu_len:{self.rep_length}"
        if self.insn_info and self.insn_info != 0:
            s += " insn_info:" + str(self.insn_info)
        if self.vec_info and self.vec_info != 0:
            s += " vec_info:" + str(self.vec_info)
        if self.vec_error and self.vec_error != 0:
            s += " vec_error:" + str(self.vec_error)
        return s

    def reg_delta_str(self) -> str:
        """return a string representation of the register deltas for CSV logging"""
        diff = set(self.regs.items()) - SET_REG_DELTA_REF
        return " ".join([f"{reg.name.lower()}:{hex(value)}" for reg, value in dict(diff).items()])

    @classmethod
    def factory_from_injector_message(cls, msg: InjectorResultMessage):
        # exit_reason
        exit_reason = cls.exit_reason_enum(msg.reason)
        # define Map when all types are defined
        MAP_EXITREASON_TUNNELEXECRESULT: Dict[ExitReasonEnum, Type[FuzzerExecResult]] = {
            ExitReasonEnum.NMI: NMI,
            ExitReasonEnum.EXTERNAL_INTERRUPT: Interrupted,
            ExitReasonEnum.EPT: EPT,
        }

        try:
            subcls = MAP_EXITREASON_TUNNELEXECRESULT[exit_reason]
        except KeyError:
            subcls = Other

        return subcls.from_injector_message(msg)

    @classmethod
    def from_injector_message(cls, msg):
        instance = cls()
        instance.exit_reason = cls.exit_reason_enum(msg.reason)
        instance.rep_length = msg.insn_length
        instance.perfct = [x for x in msg.perfct]
        # skip cr2 at the end of the list, gets saved in misc column for pagefault
        instance.regs = {
            RegistersEnum(index): value for index, value in enumerate(msg.regs) if index != RegistersEnum.CR2.value
        }
        instance.final = None
        instance.insn_info = msg.insn_info
        instance.gla = msg.gla
        instance.intr_info = msg.intr_info
        instance.intr_error = msg.intr_error
        instance.vec_info = msg.vec_info
        instance.vec_error = msg.vec_error
        return instance

    @staticmethod
    @lru_cache(1)
    def exit_reason_enum(reason):
        try:
            return ExitReasonEnum(reason)
        except ValueError:
            return ExitReasonEnum.UNKNOWN


@define(init=False)
class Interrupted(FuzzerExecResult):

    def type_str(self) -> str:
        return "interrupted"


@define(init=False)
class NMI(FuzzerExecResult):  # type: ignore[override]
    reason: int
    interrupt_type: InjInterruptTypeEnum
    interrupt: Optional[InjInterruptEnum] = field(eq=False, default=None)
    cr2: Optional[int] = field(eq=False, default=None)
    stack_value: Optional[int] = field(eq=False, default=None)
    nmi_unblocking_due_to_iret: Optional[int] = field(eq=False, default=None)
    external_vector: Optional[int] = field(eq=False, default=None)
    pagefaultec: Optional[PageFaultEC] = field(eq=False, default=None)

    @classmethod
    def from_injector_message(cls, msg):
        instance = super().from_injector_message(msg)
        instance.reason = msg.reason
        instance.interrupt = None

        if msg.intr_info & 0x80000000 == 0:
            instance.interrupt_type = InjInterruptTypeEnum(-1)
            return instance

        instance.interrupt_type = InjInterruptTypeEnum((msg.intr_info >> 8) & 7)
        vector = msg.intr_info & 0xFF

        instance.interrupt = InjInterruptEnum(vector)

        instance.external_vector = None
        if instance.interrupt_type == InjInterruptTypeEnum.EXTERNAL:
            instance.external_vector = vector
            return instance

        instance.pagefaultec = None
        if msg.intr_info & 0x800:
            if instance.interrupt != InjInterruptEnum.PAGE_FAULT:
                instance.stack_value = msg.intr_error
            else:
                instance.cr2 = msg.qualification
                instance.pagefaultec = PageFaultEC(msg.intr_error)

        if not (
            instance.interrupt_type == InjInterruptTypeEnum.HW_EXC
            and instance.interrupt == InjInterruptEnum.DOUBLE_FAULT
        ):
            instance.nmi_unblocking_due_to_iret = msg.intr_info >> 12 & 1

        instance.cr2 = msg.regs[RegistersEnum.CR2.value]
        instance.stack_value = msg.stack_value

        return instance

    def type_str(self) -> str:
        s = f"vmexit:{self.reason}"
        if hasattr(self, "interrupt_type") and self.interrupt_type is not None:
            s += f" interrupt_type:{self.interrupt_type.name.lower()}"
            if self.interrupt_type == InjInterruptTypeEnum.EXTERNAL and self.external_vector is not None:
                s += f" external_vector:{hex(self.external_vector)}"
            elif self.interrupt is not None:
                s += f" interrupt_vector:{self.interrupt.name.lower()}"
                if self.interrupt == InjInterruptEnum.PAGE_FAULT and self.pagefaultec is not None:
                    s += f":{self.pagefaultec}"
        return s

    def misc_str(self) -> str:
        s = ""
        if (
            hasattr(self, "stack_value")
            and self.stack_value is not None
            and self.interrupt != InjInterruptEnum.PAGE_FAULT
        ):
            s += f" stack:{hex(self.stack_value)}"
        if hasattr(self, "cr2") and self.cr2 is not None:
            s += f" cr2:{hex(self.cr2)}"
        if hasattr(self, "nmi_unblocking_due_to_iret") and self.nmi_unblocking_due_to_iret == 1:
            s += " nmi_unblocking_due_to_iret"
        return super().misc_str() + s


@define(init=False)
class EPT(FuzzerExecResult):  # type: ignore[override]
    eptqual: EPTQual
    reason: int

    @classmethod
    def from_injector_message(cls, msg):
        instance = super().from_injector_message(msg)
        instance.eptqual = EPTQual(msg.qualification)
        instance.reason = msg.reason
        return instance

    def type_str(self) -> str:
        s = f"vmexit:{self.reason} ept:{self.eptqual}"
        return s

    def misc_str(self) -> str:
        s = ""
        if self.eptqual.gla_valid and self.gla:
            s += " gla:" + str(hex(self.gla))
        return super().misc_str() + s


@define(init=False)
class Other(FuzzerExecResult):  # type: ignore[override]
    reason: int

    @classmethod
    def from_injector_message(cls, msg):
        instance = super().from_injector_message(msg)
        instance.reason = msg.reason
        return instance

    def type_str(self) -> str:
        s = f"vmexit:{self.reason}"
        return s


@define(slots=True, auto_attribs=True, auto_detect=True)
class AbstractInsnGenerator(ABC):
    """Abstract class implemented by every fuzzer"""

    @staticmethod
    def _get_default_buffer():
        buffer = bytearray(settings.insn_buf_size)
        # pick first available prefix if required
        for i in range(settings.min_prefix_count):
            buffer[i] = settings.mode_prefix[0]
        return buffer

    logger: logging.Logger = field(init=False, default=fact_logging)
    insn_buffer: bytearray = None  # type: ignore[assignment]
    extra_params: Optional[List[str]] = None
    insn_length: int = field(init=False)
    view: memoryview = field(init=False)
    # workaround dynaconf perf bug
    # retrieve values here and keep them
    cache_dyna_mode_prefix: List[int] = field(init=False, default=settings.mode_prefix)
    cache_dyna_prefix_range: range = field(init=False, default=settings.prefix_range)
    cache_dyna_insn_buf_size: int = field(init=False, default=settings.insn_buf_size)

    def __attrs_post_init__(self):
        self.init_buffer(self.insn_buffer)

    # open this method since we might need to reinit the buffer in a child class
    # due to additional fuzzer params
    def init_buffer(self, buffer):
        min_len = settings.min_prefix_count + 1
        if buffer is None:
            self.insn_length = min_len
            self.insn_buffer = self.__class__._get_default_buffer()
        else:
            self.insn_length = len(self.insn_buffer)
            # fill if needed
            fill_size = settings.insn_buf_size - self.insn_length
            self.insn_buffer.extend(bytearray(fill_size))
        # validate length
        if self.insn_length < min_len:
            raise ValueError(f"insn_length < settings.min_prefix_count + 1 ({min_len})")
        # init view
        self.view = memoryview(self.insn_buffer)

    # required custom impl to be able to pickle this class and sent it to ProcessPool
    def __reduce__(self) -> Union[str, Tuple[Any, ...]]:
        # all attrs declared attributes for this class
        # who are init args
        # ['insn_buffer', 'extra_params', ...]
        init_args_name = [attribute.name for attribute in self.__attrs_attrs__ if attribute.init]
        # (class, [self.insn_buffer, self.extra_params, ... + child attributes])
        init_args = [getattr(self, attr_name) for attr_name in init_args_name]
        # special case for insn_buffer (first arg)
        init_args[0] = self.insn_buffer[: self.insn_length]
        return (self.__class__, tuple(init_args))

    def __str__(self):
        current_str = self.current_insn.hex(" ")
        # 15 * 2: one byte uses 2 chars to be displayed: 00
        # 15 - 1: the spaces between the bytes
        filler_size: int = (15 * 2 + (15 - 1)) - len(current_str)
        return f"{current_str}{' ' * filler_size}"

    @property
    def current_insn(self) -> memoryview:
        return self.view[: self.insn_length]

    @abstractmethod
    def gen(self) -> Generator[memoryview, FuzzerExecResult, None]:
        """Generate the next instruction for the injector and receives a FuzzerExecResult upon execution"""
        pass

    def partition(self, nb_parts: int) -> Generator["AbstractInsnGenerator", None, None]:
        """
        Partition the fuzzer's own search space into smaller chunks, if supported.
        Otherwise just return a copy of itself
        """
        # default implementation: assume cannot partition, return copy of itself
        for _ in range(nb_parts):
            # invoke classmethod and pass own self instance
            yield self.__class__.from_instance(self)

    @staticmethod
    def from_instance(other_instance: "AbstractInsnGenerator", **changes: Any) -> "AbstractInsnGenerator":
        """Copy constructor from another instance"""
        # dumb implementation based on attrs
        return evolve(other_instance, **changes)

    def str_fuzzing_range(self) -> str:
        """Display fuzzing range according to the current Fuzzer type"""
        return "Undefined"


@define(slots=True)
class FinalLogResult:
    exec_res: FuzzerExecResult
    insn: str
    len: int
    misc: str = ""

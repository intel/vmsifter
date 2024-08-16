import ctypes
import logging
from abc import abstractmethod
from enum import Enum, IntFlag, auto
from pathlib import Path
from typing import Dict, Optional, Type

from attr import define, field

from xensifter.config import InjectorType, settings
from xensifter.utils.protected_manager import ProtectedContextManager


class AbstractInjector(ProtectedContextManager):
    @abstractmethod
    def __init__(self, socket_path: Path, pinned_cpu: int):
        """Initialize abstract injector

        Args:
            socket_path: path to Unix domain socket where the Executor will communicate
            new instructions and receive InjectorResultMessage from the injector
        """
        super().__init__()
        self._logger: Optional[logging.Logger] = None
        self._socket_path: Path = socket_path
        self._pinned_cpu = pinned_cpu
        # return the injector dict nested under "injector.xxxx"
        self._inj_settings = settings.injector[self.get_type().name]

    @staticmethod
    @abstractmethod
    def get_type() -> InjectorType:
        pass

    @property
    def logger(self):
        """instantiate the logger on first use, which will be with the concrete class type"""
        if self._logger is None:
            self._logger = logging.getLogger(f"{self.__module__}.{self.__class__.__name__}[CPU: {self._pinned_cpu}]")
        return self._logger

    @property
    def pinned_cpu(self) -> int:
        return self._pinned_cpu


class ExitReasonEnum(Enum):
    NMI = 0
    EXTERNAL_INTERRUPT = 1
    TRIPLE_FAULT = 2
    INIT_SIGNAL = 3
    SIPI = 4
    IO_SMI = 5
    OTHER_SMI = 6
    INTERRUPT_WINDOW = 7
    NMI_WINDOW = 8
    TASK_SWITCH = 9
    CPUID = 10
    GETSEC = 11
    HLT = 12
    INVD = 13
    INVLPG = 14
    RDPMC = 15
    RDTSC = 16
    RSM = 17
    VMCALL = 18
    VMCLEAR = 19
    VMLAUNCH = 20
    VMPTRLD = 21
    VMPTRST = 22
    VMREAD = 23
    VMRESUME = 24
    VMWRITE = 25
    VMXOFF = 26
    VMXON = 27
    CR_ACCESS = 28
    MOV_DR = 29
    IO_INSTRUCTION = 30
    RDMSR = 31
    WRMSR = 32
    VM_ENTRY_FAIL_INVALID_GUEST_STATE = 33
    VM_ENTRY_FAIL_MSR_LOADING = 34
    UNDEFINED35 = 35
    MWAIT = 36
    MTF = 37
    MONITOR = 39
    PAUSE = 40
    VM_ENTRY_FAIL_MACHINE_CHECK = 41
    UNDEFINED42 = 42
    TPR_BELOW_THRESHOLD = 43
    APIC_ACCESS = 44
    VIRTUALIZED_EOI = 45
    GDTR_IDTR = 46
    LDTR_TR = 47
    EPT = 48
    EPT_MISCONFIG = 49
    INVEPT = 50
    RDTSCP = 51
    PREEMPTION_TIMER = 52
    INVVPID = 53
    WBINVD_OR_WBNOINVD = 54
    XSETBV = 55
    APIC_WRITE = 56
    RDRAND = 57
    INVPCID = 58
    VMFUNC = 59
    ENCLS = 60
    RDSEED = 61
    PML_FULL = 62
    XSAVES = 63
    XSRSTORS = 64
    UNDEFINED65 = 65
    UNDEFINED66 = 66
    UMWAIT = 67
    TPAUSE = 68
    UNDEFINED69 = 69
    UNDEFINED70 = 70
    UNDEFINED71 = 71
    UNDEFINED72 = 72
    UNDEFINED73 = 73
    BUS_LOCK = 74
    NOTIFY = 75
    UNKNOWN = 1000


class InjInterruptEnum(Enum):
    DIV_BY_ZERO = 0
    SINGLE_STEP_INTERRUPT = 1
    NMI = 2
    BREAKPOINT = 3
    OVERFLOW = 4
    BOUND_RANGE_EXCEEDED = 5
    INVALID_OPCODE = 6
    COPROCESSOR_UNAVAILABLE = 7
    DOUBLE_FAULT = 8
    COPROCESSOR_SEGMENT_OVERRUN = 9
    INVALID_TASK_SEGMENT = 0xA
    SEGMENT_NOT_PRESENT = 0xB
    STACK_SEGMENT_FAULT = 0xC
    GENERAL_PROTECTION_FAULT = 0xD
    PAGE_FAULT = 0xE
    RESERVED = 0xF
    FLOATING_POINT_EXCEPTION = 0x10
    ALIGNMENT_CHECK = 0x11
    MACHINE_CHECK = 0x12
    SIMD_FLOATING_POINT_EXCEPTION = 0x13
    VIRTUALIZATION_EXCEPTION = 0x14
    CONTROL_PROTECTION_EXCEPTION = 0x15
    UNDEFINED22 = 0x16
    UNDEFINED23 = 0x17
    UNDEFINED24 = 0x18
    UNDEFINED25 = 0x19


# SDM 28.2.2
class InjInterruptTypeEnum(Enum):
    INVALID = -1
    EXTERNAL = 0
    NMI = 2
    HW_EXC = 3
    PRIV_SW_EXC = 5
    SW_EXC = 6


class PageFaultECEnum(IntFlag):
    PRESENT = 1
    READ_WRITE = 1 << 1
    USER_SUPERVISOR = 1 << 2
    RESERVED = 1 << 3
    EXECUTE = 1 << 4
    PROTECTION_KEY = 1 << 5
    SHADOW_STACK = 1 << 6
    SGX = 1 << 15


class InjRIPLocationType(Enum):
    STACK = 0x1234
    ECX = 0xBEEF3
    EDX = 0xBEEF4
    SYSCALL = 0xBEEF11
    COMPAT_SYSCALL = 0xBEEF12
    LONG_SYSCALL = 0xBEEF13
    SYSENTER = 0xBEEF14


# SDM 28.2.1 Table 28-7
class EPTQualEnum(IntFlag):
    READ = 1
    WRITE = 1 << 1
    EXECUTE = 1 << 2
    READABLE = 1 << 3
    WRITABLE = 1 << 4
    EXECUTABLE = 1 << 5
    U_EXECUTABLE = 1 << 6
    GLA_VALID = 1 << 7
    GLA_TRANSLATE_ACCESS = 1 << 8  # translate if 0
    GLA_U = 1 << 9
    G_RW = 1 << 10  # r if 0
    G_X = 1 << 11
    NMI_UNBLOCKING = 1 << 12
    SHADOW_STACK = 1 << 13
    GP_VER = 1 << 15


class RegistersEnum(Enum):
    RIP = 0
    RAX = auto()
    RBX = auto()
    RCX = auto()
    RDX = auto()
    RSI = auto()
    RDI = auto()
    RSP = auto()
    RBP = auto()
    R8 = auto()
    R9 = auto()
    R10 = auto()
    R11 = auto()
    R12 = auto()
    R13 = auto()
    R14 = auto()
    R15 = auto()
    CR2 = auto()


NUMBER_OF_REGISTERS = len(RegistersEnum)


@define(slots=True)
class PageFaultEC:
    ec: int = field(converter=lambda value: value.value if isinstance(value, PageFaultECEnum) else value)

    @property
    def read_write(self):
        return self.ec & PageFaultECEnum.READ_WRITE.value

    @property
    def execute(self):
        return self.ec & PageFaultECEnum.EXECUTE.value

    @property
    def present(self):
        return self.ec & PageFaultECEnum.PRESENT.value

    @property
    def reserved(self):
        return self.ec & PageFaultECEnum.RESERVED.value

    @property
    def user_supervisor(self):
        return self.ec & PageFaultECEnum.USER_SUPERVISOR.value

    def __str__(self) -> str:
        s = f"{'w' if self.read_write else 'r'}"
        s += f"{'x' if self.execute else ''}"
        s += f"{'p' if self.present else ''}"
        s += f"{'RSVD' if self.reserved else ''}"
        return s

    def __repr__(self) -> str:
        return self.__str__()


@define(slots=True)
class EPTQual:
    qualification: int = field(converter=lambda value: value.value if isinstance(value, EPTQualEnum) else value)

    # don't compare the exact qualification flags, just the permission bits
    def __eq__(self, __value: object) -> bool:
        if not isinstance(__value, EPTQual):
            return NotImplemented
        return self.read == __value.read and self.write == __value.write and self.execute == __value.execute

    @property
    def read(self) -> bool:
        return bool(self.qualification & EPTQualEnum.READ.value)

    @property
    def write(self) -> bool:
        return bool(self.qualification & EPTQualEnum.WRITE.value)

    @property
    def execute(self) -> bool:
        return bool(self.qualification & EPTQualEnum.EXECUTE.value)

    @property
    def gla_valid(self) -> bool:
        return bool(self.qualification & EPTQualEnum.GLA_VALID.value)

    @property
    def gla_translate_access(self) -> bool:
        if self.gla_valid:
            return bool(self.qualification & EPTQualEnum.GLA_TRANSLATE_ACCESS.value)
        else:
            return False

    def __str__(self) -> str:
        s = f"{'r' if self.read else ''}"
        s += f"{'w' if self.write else ''}"
        s += f"{'x' if self.execute else ''}"
        s += f"{'PTW' if not self.gla_translate_access else ''}"
        return s

    def __repr__(self) -> str:
        return self.__str__()


class InjectorResultMessage(ctypes.Structure):
    """Represents a data packet received from the injector C helper."""

    @classmethod
    def size(cls: Type["InjectorResultMessage"]) -> int:
        return ctypes.sizeof(cls)

    _pack_ = 1
    _fields_ = [
        ("reason", ctypes.c_uint64),
        ("qualification", ctypes.c_uint64),
        ("stack_value", ctypes.c_uint64),
        ("perfct", ctypes.c_uint64 * 7),
        ("regs", ctypes.c_uint64 * NUMBER_OF_REGISTERS),
        ("gla", ctypes.c_uint64),
        ("intr_info", ctypes.c_uint32),
        ("intr_error", ctypes.c_uint32),
        ("vec_info", ctypes.c_uint32),
        ("vec_error", ctypes.c_uint32),
        ("insn_length", ctypes.c_uint32),
        ("insn_info", ctypes.c_uint32),
    ]

    def repr_recv(self) -> Dict:
        return {
            "reason": self.reason,
            "qualification": hex(self.qualification),
            "rip": hex(self.regs[RegistersEnum.RIP.value]),
            "gla": hex(self.gla),
            "cr2": hex(self.regs[RegistersEnum.CR2.value]),
            "stack": hex(self.stack_value),
            "perfct0": self.perfct[0],
            "perfct1": self.perfct[1],
            "perfct2": self.perfct[2],
            "perfct3": self.perfct[3],
            "perfct4": self.perfct[4],
            "perfct5": self.perfct[5],
            "perfct6": self.perfct[6],
            "intr_info": self.intr_info,
            "intr_error": self.intr_error,
            "vec_info": self.vec_info,
            "vec_error": self.vec_error,
            "insn_length": self.insn_length,
            "insn_info": self.insn_info,
        }

    def tobytes(self) -> bytes:
        return ctypes.string_at(ctypes.byref(self), ctypes.sizeof(self))

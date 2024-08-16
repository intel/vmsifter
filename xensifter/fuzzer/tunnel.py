from contextlib import suppress
from typing import Generator

from attrs import define, field

from xensifter.config import settings
from xensifter.fuzzer.partition import X86Range
from xensifter.fuzzer.partition import partition as utils_partition
from xensifter.fuzzer.types import EPT, NMI, AbstractInsnGenerator, FinalLogResult, FuzzerExecResult, Interrupted
from xensifter.injector.types import InjInterruptEnum
from xensifter.utils.completion_rate import ByteRangeCompletion


@define(slots=True, auto_attribs=True, auto_detect=True)
class TunnelFuzzer(AbstractInsnGenerator):
    """Implements the tunnel algorithm to search the x86 instruction space for potential instructions"""

    marker_idx: int = 0
    end_first_byte: bytes = field(default=settings.x86.max_end_first_byte)

    # Rest of attributes excluded from init
    # keep value converted as int when we compare current memoryview[0] (which is an int)
    end_first_byte_int: int = field(init=False)
    previous_length: int = field(init=False)
    # We split each byte where the marker is to 4-bit parts that
    # correspond to a column when printed as hex. These are the "tunnels".
    split_byte_left: int = field(init=False, default=0)
    split_byte_right: int = field(init=False, default=0)
    # When the marker is in the middle of an instruction we need to verify
    # that we have the shortest version of a valid instruction. If we have
    # reason to doubt we have the shortest version, we switch to backwards
    # search, shortening the instruction until we get an EPT-x fault.
    backwards_search: bool = field(init=False, default=False)
    type: FuzzerExecResult = field(init=False, default=None)
    last_complete_insn: memoryview = field(init=False, default=None)
    last_complete_type: FuzzerExecResult = field(init=False, default=None)
    # workaround dynaconf perf bug
    # retrieve values here and keep them
    cache_dyna_completion_rate_precision: int = field(init=False, default=settings.completion_rate_precision)
    byterange_completion: ByteRangeCompletion = field(init=False, default=None)
    # counters to skip ahead
    counter: int = field(init=False, default=0)
    counter2: int = field(init=False, default=0)

    def _check_end_first_byte(self, value):
        # make sure that the byte is >= than the content's first byte
        if not value >= self.insn_buffer[0].to_bytes(length=1, byteorder="big"):
            raise ValueError(f"Unexpected content[0] (f{self.insn_buffer[0]}) >= end_first_byte ({value})")

    def __attrs_post_init__(self):
        super().__attrs_post_init__()
        # validators
        self._check_end_first_byte(self.end_first_byte)
        # additional inits
        self.end_first_byte_int = int.from_bytes(self.end_first_byte, byteorder="big")
        self.previous_length = self.insn_length
        # completion
        x86range = X86Range(bytes(self.insn_buffer), self.end_first_byte)
        self.byterange_completion = ByteRangeCompletion.from_x86_range(x86range)

    def _need_more_bytes(self):
        # increase length
        self.insn_length += 1
        if self.insn_length > self.cache_dyna_insn_buf_size:
            self._increment_last_byte()
            # reset length to marker idx
            self.insn_length = self.marker_idx + 1
        else:
            # ensure new byte is zeroed
            self.insn_buffer[self.insn_length - 1] = 0

    def _update_marker(self, new_length: int, type: FuzzerExecResult):
        assert new_length <= self.cache_dyna_insn_buf_size and new_length > 0
        is_invalid: bool = isinstance(type, NMI) and type.interrupt == InjInterruptEnum.INVALID_OPCODE
        if (not is_invalid and new_length != self.previous_length) or type != self.type:
            # move marker to the end of the new instruction
            self.marker_idx = new_length - 1
            # update previous
            self.previous_length = self.insn_length
            # and current length
            self.insn_length = new_length
            # and current type
            self.type = type

            self.counter = 0
            self.counter2 = 0
        else:
            # We'll skip ahead 4-bits after 0xA instructions that look the same
            self.split_byte_right += 1
            if self.split_byte_right >= 0xA:
                if self.split_byte_left >= 0xA:
                    self.view[self.marker_idx] = 0xFF
                else:
                    self.split_byte_left += 1
                    leftbits = self.view[self.marker_idx] >> 4
                    self.view[self.marker_idx] = (leftbits << 4) + 0xF

    def _increment_last_byte(self):
        if self.view[0] >= self.end_first_byte_int:
            raise StopIteration
        if self.view[self.marker_idx] == 0xFF:
            # roll over
            self.view[self.marker_idx] = 0
            self.split_byte_left = 0
            self.split_byte_right = 0
            # and move to the previous byte
            self.marker_idx -= 1
            # reduce length to new byte position
            self.insn_length = self.marker_idx + 1
            # recursive call, need to increment this new marker byte
            return self._increment_last_byte()
        else:
            # increment marker byte
            # print("Tunnel: increment byte at marker", self.marker_idx)
            self.view[self.marker_idx] += 1

            # check prefix count
            prefix_count = 0
            for i in range(self.marker_idx):
                if self.view[i] in self.cache_dyna_mode_prefix:
                    prefix_count += 1
                else:
                    break

            if prefix_count not in self.cache_dyna_prefix_range:
                # print("Prefix count not in range: ", prefix_count)
                return self._increment_last_byte()

    def _check_if_need_shorter_retry(self, result: FuzzerExecResult) -> int:
        insn = self.current_insn
        # TODO double check: msg.insn_length == 0  -> result.rep_length is None
        if (
            len(insn) > 1
            and insn[len(insn) - 1] == 0x0
            and (result.rep_length is None or len(insn) != result.rep_length)
        ):
            self.logger.debug("Switching to backwards search")
            self.backwards_search = True
            # retry length
            length = len(insn) - 1
        else:
            self.logger.debug("No backwards search needed, log results for %s", insn.hex())
            self.backwards_search = False

            result.final = FinalLogResult(exec_res=result, insn=insn.hex(), len=len(insn))
            length = len(insn)

        self.last_complete_insn = insn
        self.last_complete_type = result
        return length

    def gen(self) -> Generator[memoryview, FuzzerExecResult, None]:
        # suppress: catch _increment_last_byte StopIteration
        # and just return
        with suppress(StopIteration):
            while True:
                result: FuzzerExecResult = yield self.current_insn
                if isinstance(result, Interrupted):
                    # external interrupt, retry
                    continue
                elif isinstance(result, EPT) and result.eptqual.execute:
                    # pagefault
                    if self.backwards_search:
                        # we were searching backwards until we have X fault
                        result.final = FinalLogResult(
                            exec_res=self.last_complete_type,
                            insn=self.last_complete_insn.hex(),
                            len=len(self.last_complete_insn),
                        )
                        self.logger.debug(
                            "verified length of complete instruction: %s %s %i",
                            self.last_complete_type,
                            self.last_complete_insn.hex(),
                            len(self.last_complete_insn),
                        )
                        # resume sifting from last complete insn
                        self.insn_buffer[: len(self.last_complete_insn)] = self.last_complete_insn
                        self.insn_length = len(self.last_complete_insn)
                        self.backwards_search = False

                        self._update_marker(self.insn_length, self.last_complete_type)
                        self._increment_last_byte()
                        continue
                    else:
                        # need more bytes
                        self._need_more_bytes()
                else:
                    # valid instruction, complete execution
                    length = self._check_if_need_shorter_retry(result)
                    if self.backwards_search:
                        # retry length, skip update marker and increment
                        self.insn_length = length
                        continue
                    self._update_marker(length, result)

                    self._increment_last_byte()
                # check here if the fuzzing is complete / out of range
                # note: no strict equality check because we skip ahead a few bytes sometimes (see _update_marker)
                if self.view[0] >= self.end_first_byte_int:
                    # complete !
                    return

    def __str__(self):
        # pretty display next buffer
        view_hex_str = self.current_insn.hex(" ")
        # highlight marker
        # [00 01 02 [04] 05]
        stop = self.marker_idx * 2 + self.marker_idx
        filler_size: int = (
            (self.cache_dyna_insn_buf_size * 2 + (self.cache_dyna_insn_buf_size - 1)) - len(view_hex_str) + 2
        )
        marker_str = (
            f"{view_hex_str[:stop]}[{view_hex_str[stop:stop+2]}]{view_hex_str[stop+2:]}{' ':{filler_size}}"
            f" | {self.byterange_completion.completion_rate(self.view):.{self.cache_dyna_completion_rate_precision}f}%"
        )
        return marker_str

    def partition(self, nb_parts: int) -> Generator[AbstractInsnGenerator, None, None]:
        # split own range into nb_parts
        x86_range = X86Range(start=bytes(self.insn_buffer), end=self.end_first_byte)
        for sub_x86_range in utils_partition(nb_parts, x86_range):
            yield TunnelFuzzer(insn_buffer=bytearray(sub_x86_range.start), end_first_byte=sub_x86_range.end)

    def str_fuzzing_range(self) -> str:
        return f"[0x{self.current_insn.hex()}-0x{self.end_first_byte.hex()}]"

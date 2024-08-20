sys# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: MIT

from __future__ import annotations

import logging
import random
import re
import sys
from collections.abc import Generator
from typing import List, Optional

from attrs import define
from keystone import KS_ARCH_X86, KS_MODE_64, Ks, KsError

from vmsifter.config import settings
from vmsifter.fuzzer.types import AbstractInsnGenerator, FinalLogResult, FuzzerExecResult, Interrupted


@define(slots=False, auto_attribs=True, auto_detect=True)
class DrizzlerFuzzer(AbstractInsnGenerator):
    def prepareMOVSB(self, random):
        idx1 = random.randint(0, 2047)
        idx2 = random.randint(0, 2047)
        idx3 = random.randint(0, 128)
        return f"mov rcx, {idx3};mov rdi, 0xb000 + {idx1};mov rsi, 0xb000 + {idx2}; "

    def __init__(self, content: Optional[bytearray] = None, extra_params: Optional[List[str]] = None) -> None:
        super().__init__(insn_buffer=content, extra_params=extra_params)

        self.logger.info(
            "Drizzler starting with initial seed %u, number of seeds: %u, injections: %u",
            settings.fuzzer.drizzler.seed,
            settings.fuzzer.drizzler.num_seeds,
            settings.fuzzer.drizzler.injections,
        )

        self.generation = 0
        self.setup()
        self.drizzle()

    def setup(self):
        spec = X86Spec()
        self.targets = []

        self.generation += 1
        self.current_test_set = 0
        self.current_test = 0
        self.base_test_done = 0
        self.injection_type = 0
        self.nInjected = 0

        op1 = Operand(spec)
        op2 = Operand(spec)
        op1.setRegs(0, 1, 1, 1)
        op2.setMem(0, 1, 1, 1)
        op2.setRm(0, 1, 1, 1)
        op2.setRegs(0, 1, 1, 1)

        test = Instruction("lzcnt", 0, op1, op2)
        test.setAllKnownPrefixes(spec)
        test.setChainPrefixes()
        self.targets.append(test)

        test = Instruction("movsb", 0, 0, 0)
        test.setAllKnownPrefixes(spec)
        test.setChainPrefixes()
        test.setPrepare(self.prepareMOVSB)
        self.targets.append(test)

        if settings.fuzzer.drizzler.num_seeds > 1:
            random.seed(settings.fuzzer.drizzler.seed)
            seeds = [random.randrange(sys.maxsize) for i in range(settings.fuzzer.drizzler.num_seeds)]
        else:
            seeds = [settings.fuzzer.drizzler.seed]

        for i, seed in enumerate(seeds, start=1):
            self.logger.debug("Generating tests with seed %u", seed)
            self.driver = Driver(seed, settings.fuzzer.drizzler.injections, spec)
            if settings.fuzzer.drizzler.aggressive:
                self.driver.setAggressiveTesting()
            self.driver.generateTests(self.targets)

    def fix_db_and_assemble(self, _generated_test):
        # We need to convert the "db xxx" string manually cause keystone doesn't get it
        # It's a hack anyway to manually define a byte with a particular value, we just use a different hack here
        keystone = Ks(KS_ARCH_X86, KS_MODE_64)
        encoding = []
        count = 0

        while True:
            split = _generated_test.split("db ", 1)
            try:
                _encoding, _count = keystone.asm(split[0].encode("utf-8"))
            except KsError as e:
                print("ERROR:", e)
                raise e

            encoding += _encoding
            count += _count

            if len(split) == 1:
                break

            split2 = split[1].split(";", 1)
            _generated_test = split2[1]

            encoding += [int(split2[0], 0)]

        # self.logger.debug("Test encoding: %s length: %u count: %u", encoding, len(encoding), count)
        self.logger.debug("Assembled length: %u, instruction count: %u", len(encoding), count)
        return encoding, count

    def generate_test(self, test, chance, type):
        _generated_test = ""
        for random_instr in self.driver.RndInstrs:
            if random.randint(1, 100) <= chance and self.nInjected < self.driver.maxInjectedInstrs:
                injected = self.driver.getRandomTest(random)
                if type == 0:
                    _generated_test += injected
                elif type == 1:
                    _generated_test += self.driver.serializeInstr(injected)
                else:
                    _generated_test += self.driver.flushInstr(injected)

                self.nInjected += 1

            if type == 0:
                _generated_test += random_instr
            elif type == 1:
                _generated_test += self.driver.serializeInstr(random_instr)
            else:
                _generated_test += self.driver.flushInstr(random_instr)

            if random.randint(1, 100) <= chance and self.nInjected < self.driver.maxInjectedInstrs:
                injected = self.driver.getRandomTest(random)
                if type == 0:
                    _generated_test += injected
                elif type == 1:
                    _generated_test += self.driver.serializeInstr(injected)
                else:
                    _generated_test += self.driver.flushInstr(injected)

                self.nInjected += 1

        if type == 0:
            _generated_test += test
        elif type == 1:
            _generated_test += self.driver.serializeInstr(test)
        else:
            _generated_test += self.driver.flushInstr(test)

        self.logger.debug("Test set %i test %i is: %s", self.current_test_set, self.current_test, _generated_test)
        encoding, count = self.fix_db_and_assemble(_generated_test)

        if len(encoding) > settings.insn_buf_size:
            self.logger.info(
                "Assembled buffer is larger then max allowed: %u > %u", len(encoding), settings.insn_buf_size
            )
            raise StopIteration

        # h = ""
        for i in range(len(encoding)):
            self.view[i] = int(encoding[i])
            # h += str(hex(encoding[i]))

        self.insn_length = len(encoding)
        self.count = count
        # self.logger.debug("Setting test length to %u", self.insn_length)
        # self.logger.debug("Hex: %s", h)

    def drizzle(self):
        if self.current_test_set >= len(self.driver.tests):
            self.setup()

        test_set = self.driver.tests[self.current_test_set]
        test = test_set[self.current_test]

        if self.base_test_done == 0:
            if self.injection_type < 3:
                self.generate_test(test, 0, self.injection_type)
                self.injection_type += 1
                return
            else:
                self.injection_type = 0
                self.base_test_done = 1

        if self.injection_type < 3:
            self.generate_test(test, self.driver.injectionChance, self.injection_type)
            self.injection_type += 1
            return
        else:
            self.injection_type = 0

        self.current_test += 1
        self.base_test_done = 0

        if self.current_test >= len(self.driver.tests):
            self.current_test_set += 1
            self.current_test = 0

    def gen(self) -> Generator[memoryview, FuzzerExecResult, None]:
        while True:
            result: FuzzerExecResult = yield self.current_insn
            if isinstance(result, Interrupted):
                continue

            # Log results of previous execution
            _misc = f" drizzler:{self.generation}"
            _misc += f".{self.current_test_set}"
            _misc += f".{self.current_test}"
            _misc += f".{self.base_test_done}"
            _misc += f".{self.injection_type}"
            _misc += f" assembler_count:{self.count}"

            result.final = FinalLogResult(
                exec_res=result, insn=self.current_insn.hex(), len=self.insn_length, misc=_misc
            )

            try:
                self.drizzle()
            except StopIteration:
                return

    def __str__(self):
        s = f"{self.generation}"
        s += f".{self.current_test_set}"
        s += f".{self.current_test}"
        s += f".{self.base_test_done}"
        s += f".{self.injection_type} "
        s += f"encoded length: {self.insn_length} "
        s += f"instructions assembled: {self.count}"
        return s


class X86Spec(object):
    # TODO: explicitly leaving RSP and RBP out of the list. Figure out what to do in the future.

    def __init__(self):
        self.regs8b = [
            "al",
            "ah",
            "bl",
            "bh",
            "cl",
            "ch",
            "dl",
            "dh",
            "sil",
            "dil",
            "r8b",
            "r9b",
            "r10b",
            "r11b",
            "r12b",
            "r13b",
            "r14b",
            "r15b",
        ]
        self.regs8bh = ["ah", "bh", "ch", "dh"]
        self.regsRex = [
            "r8b",
            "r9b",
            "r10b",
            "r11b",
            "r12b",
            "r13b",
            "r14b",
            "r15b",
            "dil",
            "sil",
            "r8w",
            "r9w",
            "r10w",
            "r11w",
            "r12w",
            "r13w",
            "r14w",
            "r15w",
            "r8d",
            "r9d",
            "r10d",
            "r11d",
            "r12d",
            "r13d",
            "r14d",
            "r15d",
            "r8",
            "r9",
            "r10",
            "r11",
            "r12",
            "r13",
            "r14",
            "r15",
        ]
        self.regs16b = [
            "ax",
            "bx",
            "cx",
            "dx",
            "si",
            "di",
            "r8w",
            "r9w",
            "r10w",
            "r11w",
            "r12w",
            "r13w",
            "r14w",
            "r15w",
        ]
        self.regs32b = [
            "eax",
            "ebx",
            "ecx",
            "edx",
            "esi",
            "edi",
            "r8d",
            "r9d",
            "r10d",
            "r11d",
            "r12d",
            "r13d",
            "r14d",
            "r15d",
        ]
        self.regs64b = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]
        self.wordsizes = ["BYTE", "WORD", "DWORD", "QWORD"]
        self.bitwidths = [8, 16, 32, 64]

        self.regsAll = []
        for r in self.regs8b:
            self.regsAll.append(r)
        for r in self.regs16b:
            self.regsAll.append(r)
        for r in self.regs32b:
            self.regsAll.append(r)
        for r in self.regs64b:
            self.regsAll.append(r)

        # TODO: finish the list of prefixes
        # self.prefixes = ["repz", "repnz", "lock", "rex", "evex", "vex"]
        self.prefixes = [
            "66",
            "f2",
            "f3",
            "40",
            "41",
            "42",
            "43",
            "44",
            "45",
            "46",
            "47",
            "48",
            "49",
            "4a",
            "4b",
            "4c",
            "4d",
            "4e",
            "4f",
        ]
        self.maxChainedPrefixes = 8

        # TODO: divlabel data shouldnt be here...
        self.divlabel = 0

        self.randomInstrs = []

        # Group 1 - 64/32/16/8 bits.
        # operand1: Registers, Memory.
        # operand2: Registers, Memory, Immediate.
        instrs = ["add", "sub"]
        oper1 = Operand(self)
        oper2 = Operand(self)
        oper1.setRegsAll()
        oper1.setRmAll()
        oper2.setRegsAll()
        oper2.setImm(1, 1, 1, 0)
        oper2.setRmAll()
        self.randomInstrs.append(InstrGrp(instrs, oper1, oper2))

        # Group 2 - 64/32/16/8 bits.
        # Operand1: Registers, Memory.
        # Operand2: Registers, Memory, Immediate (up to 64b).
        # mov takes 64bits immediates, thus needs its own class
        instrs = ["mov"]
        oper1 = Operand(self)
        oper2 = Operand(self)
        oper1.setRegsAll()
        oper1.setRmAll()
        oper2.setRegsAll()
        oper2.setImmAll()
        oper2.setRmAll()
        self.randomInstrs.append(InstrGrp(instrs, oper1, oper2))

        # Group 3 - 64/32/16/8 bits.
        # Operand1: Registers, Memory
        instrs = ["div", "mul"]
        oper1 = Operand(self)
        oper1.setRmAll()
        self.randomInstrs.append(InstrGrp(instrs, oper1, 0))

        # Group 4 - 64/32/16/8 bits.
        # Operand 1: Registers, Memory
        instrs = ["inc", "dec"]
        oper1 = Operand(self)
        oper1.setRmAll()
        oper1.setRegs(1, 1, 1, 1)
        self.randomInstrs.append(InstrGrp(instrs, oper1, 0))

        # Group 5 - nops.
        instrs = []
        instrs.append("nop")
        instrs.append("db 0x66; nop")
        instrs.append("nop DWORD PTR [eax]")
        instrs.append("nop DWORD PTR [eax + 0x0]")
        instrs.append("nop DWORD PTR [eax + eax + 0x0]")
        instrs.append("db 0x66; nop DWORD PTR [eax + eax + 0x0]")
        instrs.append("nop DWORD PTR [eax + 0x0]")
        instrs.append("nop DWORD PTR [eax + eax + 0x0]")
        instrs.append("db 0x66; nop DWORD PTR [eax + eax + 0x0]")
        self.randomInstrs.append(InstrGrp(instrs, 0, 0))

        # Group 6 - clflush.
        instrs = ["clflush"]
        oper1 = Operand(self)
        oper1.setMem(1, 0, 0, 0)
        self.randomInstrs.append(InstrGrp(instrs, oper1, 0))

    def getRandomInstr(self, random):
        pos = random.randint(0, len(self.randomInstrs) - 1)
        grp = self.randomInstrs[pos]
        pos = random.randint(0, len(grp.mnemonics) - 1)
        mnemonic = grp.mnemonics[pos]
        instr = Instruction(mnemonic, 0, grp.oper1, grp.oper2)
        instr = instr.getCanonical(random, 0)

        # prepare should be used to prevent things like div by zero.
        instr = self.prepare(instr)

        return instr

    def getDivLabel(self):
        return self.divlabel

    def prepare(self, instr):
        # prep is for what may need to be put before the instruction.
        # post is for what may need to be put after the instruction.

        # if "div" in instr:
        # if instr is a div, it needs a hack to recover from FPExceptions.
        # - When returning, the signal handler used to catch SIGFPE will
        # return to the same instruction, causing the fault again and then
        # being trapped in doom and dread forever.
        # - To prevent this, we save the address of the next instruction
        # in RBP (that is not currently used by the fuzzer) prior to
        # running the div.
        # - If there is an FPE, the handler gets the address of the next
        # instruction from RBP and returns to it.
        # - See templates/basic.f for handler implementation.
        # TODO: This is cute hack. Find a better way to deal with this.

        #    if "div" in instr:
        #        label = "divlabel_" + str(self.divlabel)
        # instr = "mov rbp, " + label + "; " + instr + label + ":; "
        #        instr = f"{instr}{label}:; "
        #        self.divlabel = self.divlabel + 1
        return instr


class Operand(object):
    # Reference: Vol.2A 3-5 (3.1.1.3): Intel Developer's Manual
    # TODO: implement all types of operands specified in the manual.
    def __init__(self, spec):
        self.regs8 = 0
        self.regs16 = 0
        self.regs32 = 0
        self.regs64 = 0

        self.imm8 = 0
        self.imm16 = 0
        self.imm32 = 0
        self.imm64 = 0

        self.rel8 = 0
        self.rel16 = 0
        self.rel32 = 0

        self.rm8 = 0
        self.rm16 = 0
        self.rm32 = 0
        self.rm64 = 0

        self.mem8 = 0
        self.mem16 = 0
        self.mem32 = 0
        self.mem64 = 0

        self.prep = ""
        self.value = ""
        self.kind = ""
        self.bitwidth = ""

        self.spec = spec
        return

    def setRegs(self, b8, b16, b32, b64):
        self.regs8 = b8
        self.regs16 = b16
        self.regs32 = b32
        self.regs64 = b64

    def setRegsAll(self):
        self.setRegs(1, 1, 1, 1)

    def setImm(self, i8, i16, i32, i64):
        self.imm8 = i8
        self.imm16 = i16
        self.imm32 = i32
        self.imm64 = i64

    def setImmAll(self):
        self.setImm(1, 1, 1, 1)

    # Contrary to Intel's documentation, Drizzle's RM/b only generates memory
    # address dereference through ptr registers, not through immediate memory
    # address, as a way to provide more control for when creating custom fuzzing
    # test-cases. For immediate memory address operand use setMem.
    def setRm(self, rm8, rm16, rm32, rm64):
        self.rm8 = rm8
        self.rm16 = rm16
        self.rm32 = rm32
        self.rm64 = rm64

    def setRmAll(self):
        self.setRm(1, 1, 1, 1)

    def setMem(self, m8, m16, m32, m64):
        self.mem8 = m8
        self.mem16 = m16
        self.mem32 = m32
        self.mem64 = m64

    def setMemAll(self):
        self.setMem(1, 1, 1, 1)

    def setRel(self, rel8, rel16, rel32):
        self.rel8 = rel8
        self.rel16 = rel16
        self.rel32 = rel32

    def setRelAll(self):
        self.setRelAll(1, 1, 1)

    def isRm(self):
        if self.value.endswith("]"):
            for r in self.spec.regsAll:
                if r in self.value:
                    return 1
        return 0

    def isImm(self):
        if self.value.startswith("0x"):
            return 1
        return 0

    def isReg(self):
        if self.value in self.spec.regs8b:
            return 1
        if self.value in self.spec.regs16b:
            return 1
        if self.value in self.spec.regs32b:
            return 1
        if self.value in self.spec.regs64b:
            return 1
        return 0

    def getRandomReg8(self, random):
        length = len(self.spec.regs8b)
        return self.spec.regs8b[random.randint(0, length - 1)]

    def getRandomReg16(self, random):
        length = len(self.spec.regs16b)
        return self.spec.regs16b[random.randint(0, length - 1)]

    def getRandomReg32(self, random):
        length = len(self.spec.regs32b)
        return self.spec.regs32b[random.randint(0, length - 1)]

    def getRandomReg64(self, random):
        length = len(self.spec.regs64b)
        return self.spec.regs64b[random.randint(0, length - 1)]

    def getRandomBitWidth(self, random):
        length = len(self.spec.bitwidths)
        return self.spec.bitwidths[random.randint(0, length - 1)]

    def getRandomImm8(self, random):
        return str(hex(random.randint(0, pow(2, 7) - 1)).rstrip("L"))

    def getRandomImm16(self, random):
        return str(hex(random.randint(0, pow(2, 15) - 1)).rstrip("L"))

    def getRandomImm32(self, random):
        return str(hex(random.randint(0, pow(2, 31) - 1)).rstrip("L"))

    def getRandomImm64(self, random):
        return str(hex(random.randint(0, pow(2, 63) - 1)).rstrip("L"))

    def getRandomMem8(self, random):
        return "[0xb000 + " + str(random.randint(0, 2047)) + "]"

    def getRandomMem16(self, random):
        return "[0xb000 + " + str(random.randint(0, 2046)) + "]"

    def getRandomMem32(self, random):
        return "[0xb000 + " + str(random.randint(0, 2044)) + "]"

    def getRandomMem64(self, random):
        return "[0xb000 + " + str(random.randint(0, 2040)) + "]"

    def getRandomRm8(self, random):
        offset = str(random.randint(0, 2047))
        return "BYTE PTR [" + str(self.getRandomReg64(random)) + " + " + offset + "]"

    def getRandomRm16(self, random):
        offset = str(random.randint(0, 2046))
        return "WORD PTR [" + str(self.getRandomReg64(random)) + " + " + offset + "]"

    def getRandomRm32(self, random):
        offset = str(random.randint(0, 2044))
        return "DWORD PTR [" + str(self.getRandomReg64(random)) + " + " + offset + "]"

    def getRandomRm64(self, random):
        offset = str(random.randint(0, 2040))
        return "QWORD PTR [" + str(self.getRandomReg64(random)) + " + " + offset + "]"

    def getRandomWordsize(self, random):
        while 1:
            word = self.spec.wordsizes[random.randint(0, 3)]
            if self.mem:
                return word
            if (
                (self.rm8 and word == "BYTE")
                or (self.rm16 and word == "WORD")
                or (self.rm32 and word == "DWORD")
                or (self.rm64 and word == "QWORD")
            ):
                return word

    def getRandomOperandKind(self, random):
        pool = []
        if self.regs64:
            pool.append("regs64")
        if self.regs32:
            pool.append("regs32")
        if self.regs16:
            pool.append("regs16")
        if self.regs8:
            pool.append("regs8")

        if self.imm64:
            pool.append("imm64")
        if self.imm32:
            pool.append("imm32")
        if self.imm16:
            pool.append("imm16")
        if self.imm8:
            pool.append("imm8")

        if self.mem64:
            pool.append("mem64")
        if self.mem32:
            pool.append("mem32")
        if self.mem16:
            pool.append("mem16")
        if self.mem8:
            pool.append("mem8")

        if self.rm64:
            pool.append("rm64")
        if self.rm32:
            pool.append("rm32")
        if self.rm16:
            pool.append("rm16")
        if self.rm8:
            pool.append("rm8")

        return pool[random.randint(0, len(pool) - 1)]

    def getRandomOperand(self, random):
        # self.kind = self.getRandomOperandKind(random)
        if self.kind == "regs8":
            self.bw = 8
            self.value = self.getRandomReg8(random)
            return
        if self.kind == "regs16":
            self.bw = 16
            self.value = self.getRandomReg16(random)
            return
        if self.kind == "regs32":
            self.bw = 32
            self.value = self.getRandomReg32(random)
            return
        if self.kind == "regs64":
            self.bw = 64
            self.value = self.getRandomReg64(random)
            return

        if self.kind == "imm8":
            self.bw = 8
            self.value = self.getRandomImm8(random)
            return
        if self.kind == "imm16":
            self.bw = 16
            self.value = self.getRandomImm16(random)
            return
        if self.kind == "imm32":
            self.bw = 32
            self.value = self.getRandomImm32(random)
            return
        if self.kind == "imm64":
            self.bw = 64
            self.value = self.getRandomImm64(random)
            return

        if self.kind == "mem8":
            self.bw = 8
            self.value = self.getRandomMem8(random)
            return
        if self.kind == "mem16":
            self.bw = 16
            self.value = self.getRandomMem16(random)
            return
        if self.kind == "mem32":
            self.bw = 32
            self.value = self.getRandomMem32(random)
            return
        if self.kind == "mem64":
            self.bw = 64
            self.value = self.getRandomMem64(random)
            return

        if self.kind == "rm8":
            self.bw = 8
            self.value = self.getRandomRm8(random)
            return
        if self.kind == "rm16":
            self.bw = 16
            self.value = self.getRandomRm16(random)
            return
        if self.kind == "rm32":
            self.bw = 32
            self.value = self.getRandomRm32(random)
            return
        if self.kind == "rm64":
            self.bw = 64
            self.value = self.getRandomRm64(random)
            return

        print("Error, invalid kind of operand: " + self.kind)
        return "error"

    def getRandomSecondOperand(self, random, oper1, combinations):
        while 1:
            self.kind = self.getRandomOperandKind(random)
            combination = oper1.kind + ":" + self.kind
            if combination in combinations:
                self.getRandomOperand(random)
                if not self.combinationCornerCases(oper1):
                    return

    def combinationCornerCases(self, oper1):
        if oper1.value in self.spec.regsRex and self.value in self.spec.regs8bh:
            return 1
        if self.value in self.spec.regsRex and oper1.value in self.spec.regs8bh:
            return 1
        if oper1.value in self.spec.regs8bh and self.isRm():
            return 1
        if self.value in self.spec.regs8bh and oper1.isRm():
            return 1
        return 0

    def prepareOper(self):
        if self.isRm():
            reg = self.value.split(" ")[2].strip("[")
            prep = "mov " + reg + ", 0xb000"
            return prep
        return ""


class InstrGrp(object):
    def __init__(self, mnemonics, oper1, oper2):
        self.mnemonics = mnemonics
        self.oper1 = oper1
        self.oper2 = oper2


class Instruction(object):
    # TODO: is Instruction.kind being used anywhere?
    def __init__(self, mnemonic, kind, oper1, oper2):
        self.mnemonic = mnemonic
        self.kind = kind
        self.oper1 = oper1
        self.oper2 = oper2
        self.prefixes = []
        self.numPrefixes = 0
        self.chainPrefixes = 0
        self.valid = []
        self.buildValidOperandCombinations()
        self.prepare = 0

    def setPrepare(self, func):
        self.prepare = func

    def getCanonical(self, random, pfx):
        instr = ""
        prep1 = ""
        prep2 = ""

        # prepare here is used to initialize memory ptr with valid address
        if self.oper1:
            self.oper1.kind = self.oper1.getRandomOperandKind(random)
            self.oper1.getRandomOperand(random)
            prep1 = self.oper1.prepareOper()

        if self.oper2:
            self.oper2.getRandomSecondOperand(random, self.oper1, self.valid)
            prep2 = self.oper2.prepareOper()

        if len(prep1) > 0:
            instr = prep1 + "; "
        if len(prep2) > 0:
            instr = instr + prep2 + "; "
        if pfx:
            instr = instr + pfx
        instr = instr + self.mnemonic
        if self.oper1:
            instr = instr + " " + self.oper1.value
        if self.oper2:
            instr = instr + ", " + self.oper2.value
        instr = instr + "; "

        return instr

    def getSinglePrefixTests(self, random):
        prefixed = []
        for pfx in self.prefixes:
            prefixed.append(self.getCanonical(random, "db 0x" + pfx + "; "))
        return prefixed

    def getChainedPrefixTest(self, random, spec):
        cpfx = ""
        c = 0
        while (random.randint(0, 1) == 1) and c < spec.maxChainedPrefixes:
            pfx = self.prefixes[random.randint(0, self.numPrefixes - 1)]
            cpfx = cpfx + "db 0x" + pfx + "; "
            c = c + 1
        return self.getCanonical(random, cpfx)

    def setAllKnownPrefixes(self, spec):
        for pfx in spec.prefixes:
            self.prefixes.append(pfx)
            self.numPrefixes = self.numPrefixes + 1

    def setChainPrefixes(self):
        self.chainPrefixes = 1

    def buildValidOperandCombinations(self):
        if not self.oper1 or not self.oper2:
            return
        aux8 = []
        aux16 = []
        aux32 = []
        aux64 = []
        if self.oper1.regs8:
            aux8.append("regs8:")
        if self.oper1.imm8:
            aux8.append("imm8:")
        if self.oper1.rm8:
            aux8.append("rm8:")
        if self.oper1.mem8:
            aux8.append("mem8:")

        if self.oper1.regs16:
            aux16.append("regs16:")
        if self.oper1.imm16:
            aux16.append("imm16:")
        if self.oper1.rm16:
            aux16.append("rm16:")
        if self.oper1.mem16:
            aux16.append("mem16")

        if self.oper1.regs32:
            aux32.append("regs32:")
        if self.oper1.imm32:
            aux32.append("imm32:")
        if self.oper1.rm32:
            aux32.append("rm32:")
        if self.oper1.mem32:
            aux32.append("mem32")

        if self.oper1.regs64:
            aux64.append("regs64:")
        if self.oper1.imm64:
            aux64.append("imm64:")
        if self.oper1.rm64:
            aux64.append("rm64:")
        if self.oper1.mem64:
            aux64.append("mem64")

        # here we assume there won't ever be an instruction that gets:
        # opcode imm, imm; opcode mem,mem; opcode mem, rm...
        # TODO: check if there are corner cases.
        for oper in aux8:
            if self.oper2.regs8:
                self.valid.append(oper + "regs8")
            if self.oper2.imm8 and not oper.startswith("imm"):
                self.valid.append(oper + "imm8")
            if self.oper2.rm8 and not oper.startswith("mem") and not oper.startswith("rm"):
                self.valid.append(oper + "rm8")
            if self.oper2.mem8 and not oper.startswith("mem") and not oper.startswith("rm"):
                self.valid.append(oper + "mem8")

        for oper in aux16:
            if self.oper2.regs16:
                self.valid.append(oper + "regs16")
            if self.oper2.imm16 and not oper.startswith("imm"):
                self.valid.append(oper + "imm16")
            if self.oper2.rm16 and not oper.startswith("mem") and not oper.startswith("rm"):
                self.valid.append(oper + "rm16")
            if self.oper2.mem16 and not oper.startswith("mem") and not oper.startswith("rm"):
                self.valid.append(oper + "mem16")

        for oper in aux32:
            if self.oper2.regs32:
                self.valid.append(oper + "regs32")
            if self.oper2.imm32 and not oper.startswith("imm"):
                self.valid.append(oper + "imm32")
            if self.oper2.rm32 and not oper.startswith("mem") and not oper.startswith("rm"):
                self.valid.append(oper + "rm32")
            if self.oper2.mem32 and not oper.startswith("mem") and not oper.startswith("rm"):
                self.valid.append(oper + "mem32")

        for oper in aux64:
            if self.oper2.regs64:
                self.valid.append(oper + "regs64")
            # only 64b immediate case is mov, and first oper must be register.
            if self.oper2.imm64 and oper.startswith("regs"):
                self.valid.append(oper + "imm64")
            if self.oper2.rm64 and not oper.startswith("mem") and not oper.startswith("rm"):
                self.valid.append(oper + "rm64")
            if self.oper2.mem64 and not oper.startswith("mem") and not oper.startswith("rm"):
                self.valid.append(oper + "mem64")

        def addValidCustomOperandCombination(self, combination):
            self.valid.append(combination)

        def __str__(self):
            return self.valid


class RandomBytes(object):
    def __init__(self, length):
        self.length = length
        self.bytes = []
        i = 0
        while i < length:
            self.bytes.append(random.randint(0, 255))
            i = i + 1

    def dump(self):
        i = 0
        while i < self.length:
            print("db 0x" + hex(self.bytes[i]))
            i = i + 1


class Driver(object):
    def __init__(self, seed, numInjections, spec):
        self.logger = logging.getLogger(f"{self.__module__}.{self.__class__.__name__}")
        self.spec = spec
        self.templateHeader = ""
        self.templateBottom = ""
        self.extraData = ""
        self.tests = []
        self.numTests = 0
        self.RndInstrs = []
        self.injectPool = []

        # default setup
        self.maxInjectedInstrs = 6
        self.injectionChance = 1  # 1% chance
        self.injectionsPerTest = numInjections
        self.serializerInstr = "lfence"
        self.flusherInstr = "clflush"
        self.maxInjectTests = 160
        self.maxTestsPerUnit = 12
        self.conservativeTesting = 1

        random.seed(seed)

    def setConservativeTesting(self):
        self.conservativeTesting = 1

    def setAggressiveTesting(self):
        self.conservativeTesting = 0

    def setChance(self, chance):
        self.injectionChance = chance

    def setMaxInjected(self, n):
        self.maxInjected = n

    def setInjectionsPerTest(self, injects):
        self.injectionsPerTest = injects

    def unsetInjections(self):
        self.injectionsPerTest = 0

    def header(self, text):
        self.templateHeader = self.templateHeader + text

    def bottom(self, text):
        self.templateBottom = self.templateBottom + text

    def extraData(self, text):
        self.extraData = self.extraData + text

    def emitFunctionStart(self):
        self.header("extern dumpRegs; ")
        self.header("extern buffer; ")
        self.header("section .note.GNU-stack noalloc noexec nowrite progbits; ")
        self.header("section .text;global foo;;foo:; ")
        # rbp is our scratch register within signal handlers. save it.
        self.header("push rbp; ")

    def emitInitializeRegs(self):
        if random.randint(0, 1000) % 10 == 0:
            for r in self.spec.regs64b:
                instr = "mov " + str(r) + ", 0x0;"
                self.header(instr)

        else:
            for r in self.spec.regs64b:
                # random value between 0 and max unsigned long int
                value = random.randint(0, 18446744073709551615)
                instr = "mov " + str(r) + ", " + str(value) + ";"
                self.header(instr)

    def emitBottom(self):
        self.bottom("mov rbp, rsp;")
        self.bottom("push rax;")
        self.bottom("push rbx;")
        self.bottom("push rcx;")
        self.bottom("push rdx;")
        self.bottom("push rsi;")
        self.bottom("push rdi;")
        self.bottom("push r8;")
        self.bottom("push r9;")
        self.bottom("push r10;")
        self.bottom("push r11;")
        self.bottom("push r12;")
        self.bottom("push r13;")
        self.bottom("push r14;")
        self.bottom("push r15;")
        self.bottom("call dumpRegs;")
        self.bottom("add rsp, 112;")
        # rbp is our scratch reg within signal handlers. recover it.
        self.bottom("pop rbp;")
        self.bottom("retq;")

    def emitExtraData(self):
        self.extraData = ";global divdata;divdata:; "

        nLabels = self.spec.getDivLabel()
        i = 0
        while i < nLabels:
            self.extraData = f"{self.extraData}db QWORD divlabel_{i}; "
            i = i + 1

    def generateTests(self, targets):
        self.initializeRandomInjection(targets)
        # self.emitFunctionStart()
        self.emitInitializeRegs()
        self.emitRandomInstructions()
        for t in targets:
            self.emitTests(t)
        # self.emitBottom()
        # self.emitExtraData()
        # self.writeTests(targets)

    def initializeRandomInjection(self, targets):
        for t in targets:
            test = t.getCanonical(random, 0)
            if t.prepare:
                test = t.prepare(random) + test
            self.injectPool.append(test)

        # injecting prefixed instructions in the middle of the tests will
        # cause a lot of crashes and is likely to obfuscate results. It is
        # also very hard to debug the tool in these circumstances. Because
        # of that, we use the following flag to enable/disable injection
        # of prefixed tested instruction in the middle of the tests.
        if self.conservativeTesting:
            return

        for t in targets:
            for n, pfx in enumerate(t.getSinglePrefixTests(random)):
                if t.prepare:
                    pfx = t.prepare(random) + pfx
                self.injectPool.append(pfx)

        # Generate randomly chained prefixes.
        i = len(self.injectPool)
        while i < self.maxInjectTests:
            tmp = targets[random.randint(0, len(targets) - 1)]
            if tmp.chainPrefixes:
                test = tmp.getChainedPrefixTest(random, self.spec)
                if tmp.prepare:
                    test = tmp.prepare(random) + test
                self.injectPool.append(test)
                i = i + 1

    def getRandomTest(self, random):
        return self.injectPool[random.randint(0, len(self.injectPool) - 1)]

    def emitRandomInstructions(self):
        numRndInstrs = random.randint(0, 512)
        i = 0
        while i < numRndInstrs:
            self.RndInstrs.append(self.spec.getRandomInstr(random))
            i = i + 1
        return 0

    def emitTests(self, tested):
        tests = []

        # test[0] holds the test without any prefix. We call it the base.
        test = tested.getCanonical(random, 0)
        if tested.prepare:
            test = tested.prepare(random) + test
        tests.append(test)

        # Generate tests for the given instruction with prefixes.
        i = 0
        for pfx in tested.getSinglePrefixTests(random):
            if tested.prepare:
                pfx = tested.prepare(random) + pfx
            tests.append(pfx)
            i = i + 1

        # Generate randomly chained prefixes.
        if tested.chainPrefixes:
            while i < self.maxTestsPerUnit:
                pfx = tested.getChainedPrefixTest(random, self.spec)
                if tested.prepare:
                    pfx = tested.prepare(random) + pfx

                tests.append(pfx)
                i = i + 1

        self.tests.append(tests)

    def writeTests(self, targets):
        for i, testVariants in enumerate(self.tests):
            tgt = targets[i]
            for j, test in enumerate(testVariants):
                # TODO: separate testVariants in subdirectories.
                name = f"{self.output}/t_{tgt.mnemonic}"
                lfs = "oracle.lfence.s"
                cfs = "oracle.clflush.s"
                if j == 0:
                    tname = f"{name}.base.s"
                    fname = f"{name}.base.{cfs}"
                    oname = f"{name}.base.{lfs}"
                else:
                    tname = f"{name}.{i:02x}.{j:04x}.s"
                    fname = f"{name}.{i:02x}.{j:04x}.{cfs}"
                    oname = f"{name}.{i:02x}.{j:04x}.{lfs}"

                # write test without any injection.
                self.writeTest(random, tname, oname, fname, test, 0)

                if self.injectionChance > 0:
                    k = 0
                    while k < self.injectionsPerTest:
                        if j == 0:
                            tname = f"{name}.inject.base.s"
                            fname = f"{name}.inject.base.{cfs}"
                            oname = f"{name}.inject.base.{lfs}"
                        else:
                            tname = f"{name}.inject.{i:02x}.{j:04x}.{k:04x}.s"
                            fname = f"{name}.inject.{i:02x}.{j:04x}.{k:04x}.{cfs}"
                            oname = f"{name}.inject.{i:02x}.{j:04x}.{k:04x}.{lfs}"

                        self.writeTest(random, tname, oname, fname, test, self.injectionChance)
                        k = k + 1

    def serializeInstr(self, instr):
        serialized = ""
        for line in instr.split("; "):
            if len(line) > 0:
                # we don't want to separate instruction from prefixes, thus
                # skip adding the serialized if this is a raw byte (prefix).
                if line.startswith("db 0x"):
                    serialized = f"{serialized}{line}; "
                else:
                    serialized = f"{serialized}{line};{self.serializerInstr}; "

        return serialized

    def flushInstr(self, instr):
        flush = ""

        # first grab all the memory operands that need to be flushed
        for line in instr.split("; "):
            if "clflush" in line:
                continue
            if "nop" in line:
                continue

            memOper = re.search("\\[[a-zA-Z0-9 +]+\\]", line)
            if memOper:
                pattern = memOper.group()
                if not pattern.startswith("["):
                    pattern = "[" + pattern + "]"
                flush = flush + self.flusherInstr + " " + pattern + "; "

        # now we count prefix lines and labels
        idx = 0
        for line in instr.split("; "):
            if line.startswith("db 0x"):
                idx = idx + 1
            if line.endswith(":"):
                idx = idx + 1

        # now order the properly for emission (accounting for prefixes)
        final = ""
        lines = instr.split("; ")
        for n, line in enumerate(lines):
            if len(line) == 0:
                continue
            if n == len(lines) - 2 - idx and len(flush) > 0:
                final = final + "; " + flush
            final = final + line + "; "

        return final

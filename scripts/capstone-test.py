#!/usr/bin/env python3
"""
Instruction Disassembler using Capstone.

Usage:
  capstone-test.py <instruction>
  capstone-test.py (-h | --help)
  capstone-test.py --version

Options:
  -h --help     Show this screen.
  --version     Show version.

"""

from capstone import *
from docopt import docopt


def disassemble_instruction(instruction):
    # Initialize Capstone disassembler (x86 in this case, change if necessary)
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    code = bytes.fromhex(instruction)

    for i in md.disasm(code, 0x1000):
        print("0x{:x}:\t{}\t{}".format(i.address, i.mnemonic, i.op_str))


if __name__ == "__main__":
    arguments = docopt(__doc__, version="Instruction Disassembler 1.0")

    instruction_hex = arguments["<instruction>"]
    disassemble_instruction(instruction_hex)

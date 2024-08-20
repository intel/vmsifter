# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: MIT

from typing import Dict, Type

from xensifter.config import FuzzerType, settings

from .csv import CsvFuzzer
from .drizzler import DrizzlerFuzzer
from .random import RandomFuzzer
from .tunnel import TunnelFuzzer
from .types import EPT, NMI, AbstractInsnGenerator, FinalLogResult, FuzzerExecResult, Interrupted, Other

MAP_CONFIG_FUZZER: Dict[FuzzerType, Type[AbstractInsnGenerator]] = {
    FuzzerType.RANDOM: RandomFuzzer,
    FuzzerType.TUNNEL: TunnelFuzzer,
    FuzzerType.CSV: CsvFuzzer,
    FuzzerType.DRIZZLER: DrizzlerFuzzer,
}

MAP_INJECTOR_SETTINGS: Dict[FuzzerType, str] = {
    FuzzerType.RANDOM: "--mtf",
    FuzzerType.TUNNEL: "--mtf",
    FuzzerType.CSV: "--mtf",
    FuzzerType.DRIZZLER: "--drizzler",
}


def get_selected_gen() -> Type[AbstractInsnGenerator]:
    """Returns the generator for the configured fuzzer mode"""
    return MAP_CONFIG_FUZZER[settings.fuzzer_mode]


def get_injector_settings() -> str:
    """Returns the default injector setting for the configured fuzzer mode"""
    return MAP_INJECTOR_SETTINGS[settings.fuzzer_mode]


__all__ = ["AbstractInsnGenerator", "FuzzerExecResult", "FinalLogResult", "Interrupted", "EPT", "NMI", "Other"]

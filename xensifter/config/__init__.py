# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: MIT

"""Xensifter configuration

This module handles most of Xensifter's configuration through Dynaconf, and
exports the settings object

The default configuration is both defined in xensifter/config/settings.toml for simple values
and inside this module as well for complex values depending on each other, or computed at runtime,
with Dynaconf Validators.
"""

import logging
import random
import shutil
import sys
from enum import Enum, auto
from pathlib import Path
from typing import Dict, List

from dynaconf import Dynaconf, Validator, loaders
from dynaconf.utils.boxing import DynaBox
from dynaconf.utils.functional import empty
from dynaconf.utils.parse_conf import Lazy

CUR_DIR = Path(__file__).parent


# define some types here to avoid circular dependency
class FuzzerType(Enum):
    RANDOM = auto()
    TUNNEL = auto()
    CSV = auto()
    DRIZZLER = auto()


class InjectorType(Enum):
    XENVM = auto()


MAP_INJECTOR_SETTINGS: Dict[FuzzerType, str] = {
    FuzzerType.RANDOM: "--mtf",
    FuzzerType.TUNNEL: "--mtf",
    FuzzerType.CSV: "--mtf",
    FuzzerType.DRIZZLER: "--drizzler",
}


def get_injector_settings() -> str:
    """Returns the default injector setting for the configured fuzzer mode"""
    return MAP_INJECTOR_SETTINGS[settings.fuzzer_mode]


EXEC_MODE_TO_FILE = {"32": "hvm32", "32pae": "hvm32pae", "64": "hvm64"}


def lazy_prefix_eval(value, **context) -> range:
    return range(context["this"].min_prefix_count, context["this"].max_prefix_count + 1)


def assign_prefix(settings, validator) -> List[int]:
    mode_prefix = settings.x86.prefix
    if settings.x86.exec_mode in ["64"]:
        mode_prefix.extend(settings.x86.prefix_64)
    mode_prefix.sort()
    return mode_prefix


settings = Dynaconf(
    envvar_prefix="XENSIFTER",
    settings_files=[str(CUR_DIR / "settings.toml"), str(CUR_DIR / ".secrets.toml")],
    validators=[
        Validator("logging.format", must_exist=True, default=logging.Formatter(logging.BASIC_FORMAT)),
        Validator("jobs", cast=int, must_exist=True, condition=lambda v: v > 0),
        Validator("fuzzer_mode", default=FuzzerType.TUNNEL.name, must_exist=True),
        Validator("injector_mode", default=InjectorType.XENVM.name, must_exist=True),
        Validator("workdir", default=str(Path.cwd() / "workdir"), must_exist=True),
        Validator("max_prefix_count", cast=int, must_exist=True),
        Validator("min_prefix_count", cast=int, must_exist=True),
        Validator("prefix_range", default=Lazy(empty, formatter=lazy_prefix_eval)),
        Validator("x86.prefix_64", default=lambda _settings, _value: [i for i in range(0x40, 0x50)]),  # rex
        Validator("x86.exec_mode", cast=str),
        Validator("x86.min_buffer", cast=bytes, default=b"\x00"),
        Validator("x86.max_end_first_byte", cast=bytes, default=b"\xFF"),
        # TODO: validation 32/32pae/64
        Validator("mode_prefix", default=assign_prefix),
        Validator("fuzzer.drizzler.seed", default=random.randrange(sys.maxsize), cast=int),
        Validator("fuzzer.drizzler.num_seeds", cast=int),
        Validator("fuzzer.drizzler.injections", cast=int),
        Validator("fuzzer.drizzler.aggressive", cast=bool),
        Validator("injector.xenvm.injector_path", default=shutil.which("injector"), must_exist=True),
        # TODO: why we need str(  ) ? settings.x86.exec_mode already has a cast
        Validator(
            "injector.xenvm.xl.config",
            default=lambda _settings, _value: EXEC_MODE_TO_FILE[str(_settings.x86.exec_mode)],
        ),
    ],
)
# enum "validator"


# force to validate and raise errors early
settings.validators.validate()
settings.fuzzer_mode = FuzzerType[settings.fuzzer_mode]
settings.injector_mode = InjectorType[settings.injector_mode]


def dump_config(directory: Path):
    """Dump current configuration in workdir config file"""
    global settings
    # generate a dict with all the keys for the current environment
    config = settings.to_dict()
    # dump to a file, format is infered by file extension
    config_path = directory / "config.yaml"
    loaders.write(str(config_path), DynaBox(config).to_dict())

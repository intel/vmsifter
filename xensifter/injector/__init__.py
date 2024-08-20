# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: MIT

from typing import Dict, Type

from xensifter.config import InjectorType, settings

from .types import (
    NUMBER_OF_REGISTERS,
    AbstractInjector,
    EPTQual,
    EPTQualEnum,
    ExitReasonEnum,
    InjectorResultMessage,
    InjInterruptEnum,
    InjInterruptTypeEnum,
    PageFaultEC,
    RegistersEnum,
)
from .xenvm import XenVMInjector

MAP_CONFIG_INJECTOR: Dict[InjectorType, Type[AbstractInjector]] = {InjectorType.XENVM: XenVMInjector}


def get_selected_injector() -> Type[AbstractInjector]:
    """Returns the selected injector class"""
    # hardcoded to XENVM for now
    return MAP_CONFIG_INJECTOR[settings.injector_mode]


__all__ = [
    "EPTQual",
    "EPTQualEnum",
    "ExitReasonEnum",
    "InjInterruptEnum",
    "InjInterruptTypeEnum",
    "InjectorResultMessage",
    "PageFaultEC",
    "RegistersEnum",
    "get_selected_injector",
    "NUMBER_OF_REGISTERS",
]

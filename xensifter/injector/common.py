# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: MIT

from abc import abstractmethod

from attrs import define

from xensifter.utils.protected_manager import ProtectedContextManager


@define(slots=True)
class InjectorResult:
    valid: bool
    length: int


class InjectorInterface(ProtectedContextManager):
    """Defines the interface to communicate with the injector"""

    @abstractmethod
    def feed(self, insn):
        """Feed a new instruction"""
        pass

    @abstractmethod
    def get_result(self) -> InjectorResult:
        """Get the next injector result"""
        pass

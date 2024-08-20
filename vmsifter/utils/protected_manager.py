# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: MIT

from contextlib import AbstractAsyncContextManager, AbstractContextManager, AsyncExitStack, ExitStack, contextmanager
from types import TracebackType
from typing import Any, Coroutine, Optional, Type


class ProtectedContextManager(AbstractContextManager, AbstractAsyncContextManager):
    """
    This class implements a protected __enter__ and __exit__ by an ExitStack
    Ensuring that:
    - if an exception is raised in __enter__, __exit__ will be called
    - __exit__ will cleanup any context manager used in __enter__, if pushed onto the ExitStack
    """

    def __init__(self):
        self._ex = ExitStack()
        self._aex = AsyncExitStack()

    @contextmanager
    def _cleanup_on_error(self):
        with ExitStack() as stack:
            # push self.__exit__ on stack
            # in case __enter__ implementation raises an exception
            stack.push(self)
            yield
            # nothing happened, pop everything and continue
            stack.pop_all()

    def _safe_enter(self):
        """safe __enter__ with cleanup on error"""
        return self

    def __enter__(self):
        """if an Exception occurs, the cleanup can happen anyway"""
        super().__enter__()
        with self._cleanup_on_error():
            return self._safe_enter()

    def __exit__(
        self, __exc_type: Optional[Type[BaseException]], __exc_value: Optional[BaseException], __traceback
    ) -> Optional[bool]:
        super().__exit__(__exc_type, __exc_value, __traceback)
        # cleanup
        self._ex.__exit__(__exc_type, __exc_value, __traceback)
        return None

    async def _asafe_enter(self):
        return self

    async def __aenter__(self) -> Coroutine[Any, Any, Any]:
        await super().__aenter__()
        with self._cleanup_on_error():
            return await self._asafe_enter()

    async def __aexit__(
        self,
        __exc_type: Optional[Type[BaseException]],
        __exc_value: Optional[BaseException],
        __traceback: Optional[TracebackType],
    ):
        await super().__aexit__(__exc_type, __exc_value, __traceback)
        await self._aex.__aexit__(__exc_type, __exc_value, __traceback)
        return None

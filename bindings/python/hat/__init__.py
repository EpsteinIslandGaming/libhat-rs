from __future__ import annotations

import ctypes
import weakref
from typing import Optional

from hat._native import (
    _Signature,
    _check_status,
    parse_signature as _parse_signature,
    create_signature as _create_signature,
    free_signature as _free_signature,
    find_pattern as _find_pattern,
    find_pattern_mod as _find_pattern_mod,
    module_at as _module_at,
    get_module as _get_module,
)

__all__ = [
    "ScanAlignment",
    "Signature",
    "parse_signature",
    "create_signature",
    "find_pattern",
    "find_pattern_mod",
    "get_process_module",
    "get_module",
    "module_at",
]

X1 = 0
X4 = 1
X16 = 2


class ScanAlignment:
    X1 = 0
    X4 = 1
    X16 = 2


class Signature:
    def __init__(self, handle: ctypes.pointer) -> None:
        self._handle = handle
        self._closed = False
        self._finalizer = weakref.finalize(self, _free_signature, handle)

    @classmethod
    def parse(cls, sig_str: str) -> Signature:
        return cls(_parse_signature(sig_str))

    @classmethod
    def create(cls, bytes_: bytes, mask: Optional[bytes] = None) -> Signature:
        return cls(_create_signature(bytes_, mask))

    def close(self) -> None:
        if getattr(self, "_closed", False):
            return
        self._closed = True
        self._finalizer.detach()
        handle = self._handle
        self._handle = None
        if handle is not None:
            _free_signature(handle)

    def __enter__(self) -> Signature:
        return self

    def __exit__(self, *args) -> None:
        self.close()


def parse_signature(sig_str: str) -> Signature:
    return Signature.parse(sig_str)


def create_signature(bytes_: bytes, mask: Optional[bytes] = None) -> Signature:
    return Signature.create(bytes_, mask)


def find_pattern(
    signature: Signature,
    buffer: bytes,
    alignment: int = X1,
) -> Optional[int]:
    if signature._closed:
        raise ValueError("signature has been closed")
    return _find_pattern(signature._handle, buffer, alignment)


def find_pattern_mod(
    signature: Signature,
    module: int,
    section: str,
    alignment: int = X1,
) -> Optional[int]:
    if signature._closed:
        raise ValueError("signature has been closed")
    return _find_pattern_mod(signature._handle, module, section, alignment)


def get_process_module() -> Optional[int]:
    return _get_module(None)


def get_module(name: str) -> Optional[int]:
    return _get_module(name)


def module_at(address: int) -> Optional[int]:
    return _module_at(address)

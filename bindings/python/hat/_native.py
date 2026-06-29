import ctypes
import ctypes.util
import os
import platform
from typing import Optional


def _find_library() -> str:
    path = os.environ.get("LIBHAT_PATH")
    if path:
        return path
    name = {"Windows": "hat.dll", "Linux": "libhat.so", "Darwin": "libhat.dylib"}.get(
        platform.system()
    )
    if not name:
        raise OSError(f"unsupported platform: {platform.system()}")
    found = ctypes.util.find_library(name)
    if found:
        return found
    candidates = []
    if build_dir := os.environ.get("CARGO_TARGET_DIR"):
        candidates.append(os.path.join(build_dir, "release", name))
    candidates.append(os.path.join("target", "release", name))
    for c in candidates:
        if os.path.isfile(c):
            return os.path.abspath(c)
    raise OSError(
        f"libhat shared library not found. Set LIBHAT_PATH or build with `cargo build --release`"
    )


_lib = ctypes.cdll.LoadLibrary(_find_library())


class _Signature(ctypes.Structure):
    _fields_ = [("data", ctypes.c_void_p), ("count", ctypes.c_size_t)]


class LibhatStatus:
    Success = 0
    ErrUnknown = 1
    SigInvalid = 2
    SigEmpty = 3
    SigNoByte = 4


_lib.libhat_parse_signature.argtypes = [
    ctypes.c_char_p,
    ctypes.POINTER(ctypes.POINTER(_Signature)),
]
_lib.libhat_parse_signature.restype = ctypes.c_int

_lib.libhat_create_signature.argtypes = [
    ctypes.POINTER(ctypes.c_ubyte),
    ctypes.POINTER(ctypes.c_ubyte),
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.POINTER(_Signature)),
]
_lib.libhat_create_signature.restype = ctypes.c_int

_lib.libhat_find_pattern.argtypes = [
    ctypes.POINTER(_Signature),
    ctypes.c_void_p,
    ctypes.c_size_t,
    ctypes.c_int,
]
_lib.libhat_find_pattern.restype = ctypes.c_void_p

_lib.libhat_find_pattern_mod.argtypes = [
    ctypes.POINTER(_Signature),
    ctypes.c_void_p,
    ctypes.c_char_p,
    ctypes.c_int,
]
_lib.libhat_find_pattern_mod.restype = ctypes.c_void_p

_lib.libhat_module_at.argtypes = [ctypes.c_void_p]
_lib.libhat_module_at.restype = ctypes.c_void_p

_lib.libhat_get_module.argtypes = [ctypes.c_char_p]
_lib.libhat_get_module.restype = ctypes.c_void_p

_lib.libhat_free.argtypes = [ctypes.c_void_p]
_lib.libhat_free.restype = None


def _check_status(status: int) -> None:
    if status == LibhatStatus.Success:
        return
    msg = {
        LibhatStatus.SigEmpty: "signature is empty",
        LibhatStatus.SigInvalid: "signature is invalid",
        LibhatStatus.SigNoByte: "signature has no fixed bytes",
        LibhatStatus.ErrUnknown: "unknown error",
    }.get(status, f"unknown status {status}")
    raise RuntimeError(msg)


def parse_signature(sig_str: str) -> ctypes.pointer:
    sig_out = ctypes.POINTER(_Signature)()
    status = _lib.libhat_parse_signature(sig_str.encode("utf-8"), ctypes.byref(sig_out))
    _check_status(status)
    return sig_out


def create_signature(
    bytes_: bytes, mask: Optional[bytes] = None
) -> ctypes.pointer:
    n = len(bytes_)
    if mask is None:
        mask = b"\xff" * n
    elif len(mask) != n:
        raise ValueError("bytes and mask must have the same length")
    bytes_arr = (ctypes.c_ubyte * n).from_buffer_copy(bytes_)
    mask_arr = (ctypes.c_ubyte * n).from_buffer_copy(mask)
    sig_out = ctypes.POINTER(_Signature)()
    status = _lib.libhat_create_signature(
        bytes_arr, mask_arr, n, ctypes.byref(sig_out)
    )
    _check_status(status)
    return sig_out


def free_signature(sig: ctypes.pointer) -> None:
    _lib.libhat_free(ctypes.cast(sig, ctypes.c_void_p))


def find_pattern(
    sig: ctypes.pointer, buffer: bytes, align: int = 0
) -> Optional[int]:
    buf = (ctypes.c_ubyte * len(buffer)).from_buffer_copy(buffer)
    ptr = _lib.libhat_find_pattern(sig, buf, len(buffer), align)
    if not ptr:
        return None
    base = ctypes.addressof(buf)
    return ptr - base


def find_pattern_mod(
    sig: ctypes.pointer,
    module: int,
    section: str,
    align: int = 0,
) -> Optional[int]:
    ptr = _lib.libhat_find_pattern_mod(
        sig, ctypes.c_void_p(module), section.encode("utf-8"), align
    )
    if not ptr:
        return None
    return ptr


def module_at(address: int) -> Optional[int]:
    ptr = _lib.libhat_module_at(ctypes.c_void_p(address))
    if not ptr:
        return None
    return ptr


def get_module(name: Optional[str] = None) -> Optional[int]:
    c_name = name.encode("utf-8") if name is not None else None
    ptr = _lib.libhat_get_module(c_name)
    if not ptr:
        return None
    return ptr

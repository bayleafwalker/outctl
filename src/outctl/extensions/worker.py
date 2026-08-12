"""Isolated child process for exactly one extension JSON invocation."""

from __future__ import annotations

import argparse
import ctypes
import errno
import os
import platform
import resource
import sys
from typing import Final, cast

from outctl.extensions.contracts import (
    MAX_REQUEST_BYTES,
    ExtensionProtocol,
    ExtensionResult,
    ExtensionStatus,
)
from outctl.extensions.discovery import discover_extensions, select_extension
from outctl.extensions.protocol import ExtensionInvocation, ExtensionProtocolError, result_document

MAX_ADDRESS_SPACE: Final = 256 * 1024 * 1024
MAX_FILE_BYTES: Final = 64 * 1024
MAX_OPEN_FILES: Final = 32
MAX_CPU_SECONDS: Final = 2

_PR_SET_NO_NEW_PRIVS: Final = 38
_PR_SET_SECCOMP: Final = 22
_SECCOMP_MODE_FILTER: Final = 2
_SECCOMP_RET_KILL_PROCESS: Final = 0x80000000
_SECCOMP_RET_ERRNO: Final = 0x00050000
_SECCOMP_RET_ALLOW: Final = 0x7FFF0000
_BPF_LD_W_ABS: Final = 0x20
_BPF_JMP_JEQ_K: Final = 0x15
_BPF_JMP_JGE_K: Final = 0x35
_BPF_RET_K: Final = 0x06


class _SockFilter(ctypes.Structure):
    _fields_ = [
        ("code", ctypes.c_ushort),
        ("jt", ctypes.c_ubyte),
        ("jf", ctypes.c_ubyte),
        ("k", ctypes.c_uint32),
    ]


class _SockFprog(ctypes.Structure):
    _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.POINTER(_SockFilter))]


def _syscall_policy() -> tuple[int, tuple[int, ...], bool]:
    machine = platform.machine().lower()
    if machine in {"x86_64", "amd64"}:
        # clone, fork, vfork, execve, socket, connect, accept, sendto,
        # bind, listen, socketpair, accept4, execveat, clone3
        return (
            0xC000003E,
            (56, 57, 58, 59, 41, 42, 43, 44, 49, 50, 53, 288, 322, 435),
            True,
        )
    if machine in {"aarch64", "arm64"}:
        # AArch64 has no separate fork/vfork syscall numbers.
        return (
            0xC00000B7,
            (220, 221, 198, 199, 200, 201, 202, 203, 206, 242, 281, 435),
            False,
        )
    raise RuntimeError("extension seccomp architecture is unsupported")


def _install_seccomp() -> None:
    audit_arch, denied, reject_x32 = _syscall_policy()
    instructions: list[_SockFilter] = [
        _SockFilter(_BPF_LD_W_ABS, 0, 0, 4),
        _SockFilter(_BPF_JMP_JEQ_K, 1, 0, audit_arch),
        _SockFilter(_BPF_RET_K, 0, 0, _SECCOMP_RET_KILL_PROCESS),
        _SockFilter(_BPF_LD_W_ABS, 0, 0, 0),
    ]
    if reject_x32:
        instructions.extend(
            [
                _SockFilter(_BPF_JMP_JGE_K, 0, 1, 0x40000000),
                _SockFilter(_BPF_RET_K, 0, 0, _SECCOMP_RET_ERRNO | errno.EPERM),
            ]
        )
    for syscall_number in sorted(set(denied)):
        instructions.extend(
            [
                _SockFilter(_BPF_JMP_JEQ_K, 0, 1, syscall_number),
                _SockFilter(_BPF_RET_K, 0, 0, _SECCOMP_RET_ERRNO | errno.EPERM),
            ]
        )
    instructions.append(_SockFilter(_BPF_RET_K, 0, 0, _SECCOMP_RET_ALLOW))
    filters = (_SockFilter * len(instructions))(*instructions)
    program = _SockFprog(len(instructions), filters)
    libc = ctypes.CDLL(None, use_errno=True)
    libc.prctl.argtypes = [
        ctypes.c_int,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_ulong,
    ]
    libc.prctl.restype = ctypes.c_int
    if libc.prctl(_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "PR_SET_NO_NEW_PRIVS failed")
    if libc.prctl(_PR_SET_SECCOMP, _SECCOMP_MODE_FILTER, ctypes.addressof(program), 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "PR_SET_SECCOMP failed")


def _install_resource_limits() -> None:
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_CPU, (MAX_CPU_SECONDS, MAX_CPU_SECONDS))
    resource.setrlimit(resource.RLIMIT_AS, (MAX_ADDRESS_SPACE, MAX_ADDRESS_SPACE))
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_FILE_BYTES, MAX_FILE_BYTES))
    resource.setrlimit(resource.RLIMIT_NOFILE, (MAX_OPEN_FILES, MAX_OPEN_FILES))
    resource.setrlimit(resource.RLIMIT_NPROC, (0, 0))


def _evaluate(loaded: object, invocation: ExtensionInvocation) -> ExtensionResult:
    if hasattr(loaded, "evaluate"):
        result = cast(ExtensionProtocol, loaded).evaluate(invocation.request)
    elif callable(loaded):
        result = loaded(invocation.request)
    else:
        raise TypeError("extension entry point is not callable")
    if not isinstance(result, ExtensionResult):
        raise TypeError("extension returned an invalid result type")
    return result


def _write_all(descriptor: int, body: bytes) -> None:
    offset = 0
    while offset < len(body):
        offset += os.write(descriptor, body[offset:])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--plugin-root", action="append", required=True)
    args = parser.parse_args(argv)
    try:
        # These are read-only distribution roots mounted explicitly by the
        # parent. Isolated mode ignores PYTHONPATH, so add only these pins.
        sys.path[:0] = args.plugin_root
        body = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
        invocation = ExtensionInvocation.from_bytes(body)
        discovered = discover_extensions(args.plugin_root)
        selected = select_extension(discovered, invocation.pin)
        _install_resource_limits()
        _install_seccomp()
        try:
            result = _evaluate(selected._entry_point.load(), invocation)
        except BaseException:
            result = ExtensionResult.failed(
                invocation.request,
                ExtensionStatus.FAILED,
                diagnostics=("extension-failed",),
            )
        try:
            encoded = result_document(invocation, result)
        except ExtensionProtocolError:
            encoded = result_document(
                invocation,
                ExtensionResult.failed(
                    invocation.request,
                    ExtensionStatus.MALFORMED,
                    diagnostics=("invalid-extension-result",),
                ),
            )
        _write_all(1, encoded)
        return 0
    except BaseException:
        # The parent maps empty output/exit failure to a bounded generic error.
        # Never serialize exception text: it may contain plugin-controlled data.
        return 70


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "MAX_ADDRESS_SPACE",
    "MAX_CPU_SECONDS",
    "MAX_FILE_BYTES",
    "MAX_OPEN_FILES",
    "main",
]

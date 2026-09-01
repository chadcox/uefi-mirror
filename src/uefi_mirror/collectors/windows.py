"""Read-only Windows UEFI variable collector."""

import ctypes
import hashlib
import struct
import uuid

from ..safety import MAX_VARIABLE_BYTES
from .efivarfs import Variable, decode_attributes

TOKEN_ADJUST_PRIVILEGES = 0x20
TOKEN_QUERY = 0x08
SE_PRIVILEGE_ENABLED = 0x02
ERROR_INSUFFICIENT_BUFFER = 122
ERROR_NOT_ALL_ASSIGNED = 1300
STATUS_BUFFER_TOO_SMALL = 0xC0000023
SYSTEM_ENVIRONMENT_VALUE_INFORMATION = 2
MAX_ENUMERATION_BYTES = 16 << 20
ENTRY_HEADER_SIZE = 32


class _LUID(ctypes.Structure):
    _fields_ = [("LowPart", ctypes.c_uint32), ("HighPart", ctypes.c_int32)]


class _LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Luid", _LUID), ("Attributes", ctypes.c_uint32)]


class _TOKEN_PRIVILEGES(ctypes.Structure):
    _fields_ = [("PrivilegeCount", ctypes.c_uint32),
                ("Privileges", _LUID_AND_ATTRIBUTES * 1)]


def _dll(name: str):
    return getattr(ctypes, "WinDLL")(name, use_last_error=True)


def _check_adjustment(adjusted: bool, error: int) -> None:
    if not adjusted:
        raise OSError(error, "AdjustTokenPrivileges failed")
    if error == ERROR_NOT_ALL_ASSIGNED:
        raise PermissionError("needs elevation: SeSystemEnvironmentPrivilege is not available")


def enable_privilege() -> None:
    """Enable SeSystemEnvironmentPrivilege in the current process token."""
    kernel32, advapi32 = _dll("kernel32"), _dll("advapi32")
    get_process = kernel32.GetCurrentProcess
    get_process.argtypes, get_process.restype = [], ctypes.c_void_p
    close = kernel32.CloseHandle
    close.argtypes, close.restype = [ctypes.c_void_p], ctypes.c_int32

    open_token = advapi32.OpenProcessToken
    open_token.argtypes = [ctypes.c_void_p, ctypes.c_uint32,
                           ctypes.POINTER(ctypes.c_void_p)]
    open_token.restype = ctypes.c_int32
    lookup = advapi32.LookupPrivilegeValueW
    lookup.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.POINTER(_LUID)]
    lookup.restype = ctypes.c_int32
    adjust = advapi32.AdjustTokenPrivileges
    adjust.argtypes = [ctypes.c_void_p, ctypes.c_int32,
                       ctypes.POINTER(_TOKEN_PRIVILEGES), ctypes.c_uint32,
                       ctypes.c_void_p, ctypes.c_void_p]
    adjust.restype = ctypes.c_int32

    token = ctypes.c_void_p()
    if not open_token(get_process(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                      ctypes.byref(token)):
        raise OSError(ctypes.get_last_error(), "OpenProcessToken failed; needs elevation")
    try:
        privileges = _TOKEN_PRIVILEGES()
        privileges.PrivilegeCount = 1
        if not lookup(None, "SeSystemEnvironmentPrivilege",
                      ctypes.byref(privileges.Privileges[0].Luid)):
            raise OSError(ctypes.get_last_error(), "LookupPrivilegeValueW failed")
        privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
        ctypes.set_last_error(0)
        adjusted = bool(adjust(token, False, ctypes.byref(privileges), 0, None, None))
        _check_adjustment(adjusted, ctypes.get_last_error())
    finally:
        close(token)


def _errored(name: str, guid: str, message: str) -> Variable:
    guid = guid.lower()
    var = Variable(name=name, guid=guid, filename=f"{name}-{guid}")
    var.error = message
    return var


def _variable(name: str, guid: str, attributes: int, payload: bytes) -> Variable:
    source = attributes.to_bytes(4, "little") + payload
    return Variable(
        name=name,
        guid=guid,
        filename=f"{name}-{guid}",
        attributes=attributes,
        payload=payload,
        size=len(payload),
        payload_sha256=hashlib.sha256(payload).hexdigest(),
        source_sha256=hashlib.sha256(source).hexdigest(),
        attribute_names=decode_attributes(attributes),
    )


def read_variable(name: str, guid: str) -> Variable:
    """Read one named variable through GetFirmwareEnvironmentVariableExW."""
    enable_privilege()
    get_variable = _dll("kernel32").GetFirmwareEnvironmentVariableExW
    get_variable.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_void_p,
                             ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32)]
    get_variable.restype = ctypes.c_uint32
    size = 4096
    while size <= MAX_VARIABLE_BYTES:
        buffer, attributes = ctypes.create_string_buffer(size), ctypes.c_uint32()
        ctypes.set_last_error(0)
        length = get_variable(name, f"{{{guid}}}", buffer, size, ctypes.byref(attributes))
        error = ctypes.get_last_error()
        if length or not error:
            return _variable(name, guid.lower(), attributes.value, buffer.raw[:length])
        if error != ERROR_INSUFFICIENT_BUFFER:
            return _errored(name, guid,
                            f"OSError {error}: GetFirmwareEnvironmentVariableExW failed")
        size *= 2
    return _errored(name, guid, f"variable exceeds {MAX_VARIABLE_BYTES} byte limit")


def _enumerate_raw() -> bytes:
    enumerate_values = _dll("ntdll").NtEnumerateSystemEnvironmentValuesEx
    enumerate_values.argtypes = [ctypes.c_uint32, ctypes.c_void_p,
                                 ctypes.POINTER(ctypes.c_uint32)]
    enumerate_values.restype = ctypes.c_int32
    size = ctypes.c_uint32()
    status = enumerate_values(SYSTEM_ENVIRONMENT_VALUE_INFORMATION, None,
                              ctypes.byref(size)) & 0xFFFFFFFF
    if status == 0 and size.value == 0:
        return b""
    if status != STATUS_BUFFER_TOO_SMALL:
        raise OSError(f"NtEnumerateSystemEnvironmentValuesEx failed: NTSTATUS 0x{status:08x}")
    if not size.value:
        raise OSError("NtEnumerateSystemEnvironmentValuesEx returned no buffer size")
    while size.value <= MAX_ENUMERATION_BYTES:
        buffer = ctypes.create_string_buffer(size.value)
        status = enumerate_values(SYSTEM_ENVIRONMENT_VALUE_INFORMATION, buffer,
                                  ctypes.byref(size)) & 0xFFFFFFFF
        if status == 0:
            return buffer.raw[:size.value]
        if status != STATUS_BUFFER_TOO_SMALL:
            raise OSError(
                f"NtEnumerateSystemEnvironmentValuesEx failed: NTSTATUS 0x{status:08x}")
    raise OSError(f"firmware-variable enumeration exceeds {MAX_ENUMERATION_BYTES} byte limit")


def _parse_enumeration(raw: bytes) -> list[Variable]:
    variables = []
    offset = 0
    while offset < len(raw):
        if len(raw) - offset < ENTRY_HEADER_SIZE:
            raise ValueError("truncated VARIABLE_NAME_AND_VALUE header")
        next_offset, value_offset, value_length, attributes = struct.unpack_from(
            "<IIII", raw, offset)
        entry_size = next_offset or len(raw) - offset
        if entry_size < ENTRY_HEADER_SIZE or entry_size > len(raw) - offset:
            raise ValueError("invalid NextEntryOffset in firmware enumeration")
        if value_offset < ENTRY_HEADER_SIZE or value_offset + value_length > entry_size:
            raise ValueError("invalid value bounds in firmware enumeration")
        name_bytes = raw[offset + ENTRY_HEADER_SIZE:offset + value_offset]
        terminator = next((i for i in range(0, len(name_bytes) - 1, 2)
                           if name_bytes[i:i + 2] == b"\0\0"), None)
        if terminator is None:
            raise ValueError("unterminated variable name in firmware enumeration")
        name = name_bytes[:terminator].decode("utf-16-le", errors="replace")
        guid = str(uuid.UUID(bytes_le=raw[offset + 16:offset + 32]))
        start = offset + value_offset
        if value_length > MAX_VARIABLE_BYTES:
            # Match named reads and snapshot reload: a payload over the limit is
            # recorded as an error, never written, so a live snapshot cannot
            # exceed what the same release will agree to reload.
            variables.append(_errored(name, guid,
                                      f"variable exceeds {MAX_VARIABLE_BYTES} byte limit"))
        else:
            variables.append(_variable(name, guid, attributes, raw[start:start + value_length]))
        if not next_offset:
            break
        offset += next_offset
    variables.sort(key=lambda variable: (variable.name, variable.guid))
    return variables


def collect() -> list[Variable]:
    """Enable read privilege and enumerate every Windows UEFI variable."""
    enable_privilege()
    try:
        return _parse_enumeration(_enumerate_raw())
    except (OSError, ValueError) as exc:
        raise RuntimeError(f"firmware-variable enumeration unavailable: {exc}") from exc

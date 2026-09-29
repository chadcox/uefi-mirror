import ctypes
import hashlib
import struct
import uuid

import pytest

from uefi_mirror.collectors import windows


def _entry(name, guid, attributes, payload, next_offset=0):
    name_bytes = name.encode("utf-16-le") + b"\0\0"
    value_offset = windows.ENTRY_HEADER_SIZE + len(name_bytes)
    return (struct.pack("<IIII", next_offset, value_offset, len(payload), attributes)
            + uuid.UUID(guid).bytes_le + name_bytes + payload)


def test_parse_windows_variable_enumeration():
    first_guid = "8be4df61-93ca-11d2-aa0d-00e098032b8c"
    first = _entry("BootOrder", first_guid, 7, b"\x00\x01")
    first = _entry("BootOrder", first_guid, 7, b"\x00\x01", len(first))
    raw = first + _entry("SecureBoot", first_guid, 6, b"\x01")

    variables = windows._parse_enumeration(raw)

    assert [(var.name, var.guid, var.attributes, var.payload) for var in variables] == [
        ("BootOrder", first_guid, 7, b"\x00\x01"),
        ("SecureBoot", first_guid, 6, b"\x01"),
    ]
    assert variables[0].attribute_names == [
        "NON_VOLATILE", "BOOTSERVICE_ACCESS", "RUNTIME_ACCESS"]
    assert variables[0].payload_sha256 == hashlib.sha256(b"\x00\x01").hexdigest()


@pytest.mark.parametrize(("field_offset", "bad_value", "message"), [
    (0, 31, "NextEntryOffset"),
    (4, 1 << 20, "value bounds"),
])
def test_parse_windows_variable_enumeration_rejects_bad_offsets(
        field_offset, bad_value, message):
    raw = bytearray(_entry("BootOrder", "8be4df61-93ca-11d2-aa0d-00e098032b8c", 7, b"x"))
    struct.pack_into("<I", raw, field_offset, bad_value)
    with pytest.raises(ValueError, match=message):
        windows._parse_enumeration(raw)


def test_parse_windows_variable_enumeration_requires_terminated_name():
    raw = bytearray(_entry("BootOrder", "8be4df61-93ca-11d2-aa0d-00e098032b8c", 7, b"x"))
    value_offset = struct.unpack_from("<I", raw, 4)[0]
    raw[value_offset - 2:value_offset] = b"xx"
    with pytest.raises(ValueError, match="unterminated"):
        windows._parse_enumeration(raw)


def test_adjust_token_privileges_checks_not_all_assigned():
    with pytest.raises(PermissionError, match="needs elevation"):
        windows._check_adjustment(True, windows.ERROR_NOT_ALL_ASSIGNED)


TOO_SMALL = windows.STATUS_BUFFER_TOO_SMALL - (1 << 32)
ACCESS_DENIED = 0xC0000022 - (1 << 32)
GUID = "ec87d643-eba4-4bb5-a1e5-3f3e36b20da9"


class _Fn:
    """One native export: records calls and accepts argtypes/restype like a ctypes function."""

    def __init__(self, impl):
        self.impl, self.calls = impl, []

    def __call__(self, *args):
        self.calls.append(args)
        return self.impl(*args)


class _Dll:
    """Only the named exports exist, so a renamed binding raises AttributeError."""

    def __init__(self, **exports):
        self.__dict__.update(exports)


@pytest.fixture
def native(monkeypatch):
    state = {"error": 0, "dlls": {}}
    monkeypatch.setattr(windows.ctypes, "set_last_error",
                        lambda value: state.update(error=value), raising=False)
    monkeypatch.setattr(windows.ctypes, "get_last_error", lambda: state["error"], raising=False)
    monkeypatch.setattr(windows, "_dll", lambda name: state["dlls"][name])
    return state


def _privilege_dlls(native, *, lookup_ok=True, adjust_error=0):
    closed, adjusted = [], []

    def open_token(process, access, token):
        assert (process, access) == (-1, windows.TOKEN_ADJUST_PRIVILEGES | windows.TOKEN_QUERY)
        token._obj.value = 0x1234
        return 1

    def adjust(_token, _disable_all, privileges, *_rest):
        adjusted.append(privileges._obj.Privileges[0].Attributes)
        native["error"] = adjust_error
        return 1

    native["dlls"]["kernel32"] = _Dll(
        GetCurrentProcess=_Fn(lambda: -1),
        CloseHandle=_Fn(lambda handle: closed.append(handle.value) or 1))
    native["dlls"]["advapi32"] = _Dll(
        OpenProcessToken=_Fn(open_token),
        LookupPrivilegeValueW=_Fn(
            lambda _system, name, _luid: lookup_ok and name == "SeSystemEnvironmentPrivilege"),
        AdjustTokenPrivileges=_Fn(adjust))
    return closed, adjusted


def test_enable_privilege_enables_the_privilege_and_closes_the_token(native):
    closed, adjusted = _privilege_dlls(native)

    windows.enable_privilege()

    assert (closed, adjusted) == ([0x1234], [windows.SE_PRIVILEGE_ENABLED])


@pytest.mark.parametrize(("options", "error", "match"), [
    ({"lookup_ok": False}, OSError, "LookupPrivilegeValueW failed"),
    ({"adjust_error": windows.ERROR_NOT_ALL_ASSIGNED}, PermissionError, "needs elevation"),
])
def test_enable_privilege_closes_the_token_on_every_failure(native, options, error, match):
    closed, _adjusted = _privilege_dlls(native, **options)

    with pytest.raises(error, match=match):
        windows.enable_privilege()

    assert closed == [0x1234]


def test_read_variable_doubles_the_buffer_until_the_payload_fits(native, monkeypatch):
    monkeypatch.setattr(windows, "enable_privilege", lambda: None)
    payload = bytes(range(256)) * 20  # 5120 bytes: the first 4096-byte attempt is too small

    def get_variable(_name, _guid, buffer, size, attributes):
        if size < len(payload):
            native["error"] = windows.ERROR_INSUFFICIENT_BUFFER
            return 0
        ctypes.memmove(buffer, payload, len(payload))
        attributes._obj.value = 7
        return len(payload)

    get = _Fn(get_variable)
    native["dlls"]["kernel32"] = _Dll(GetFirmwareEnvironmentVariableExW=get)

    var = windows.read_variable("Setup", GUID)

    assert [(call[0], call[1], call[3]) for call in get.calls] == [
        ("Setup", "{" + GUID + "}", 4096), ("Setup", "{" + GUID + "}", 8192)]
    assert (var.error, var.attributes, var.payload) == (None, 7, payload)
    assert get.argtypes == [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_void_p,
                            ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32)]
    assert get.restype is ctypes.c_uint32


@pytest.mark.parametrize(("error", "payload", "message"), [
    (0, b"", None),
    (5, None, "OSError 5: GetFirmwareEnvironmentVariableExW failed"),
])
def test_read_variable_zero_length_is_empty_only_without_an_error(
        native, monkeypatch, error, payload, message):
    monkeypatch.setattr(windows, "enable_privilege", lambda: None)

    def get_variable(*_args):
        native["error"] = error
        return 0

    native["dlls"]["kernel32"] = _Dll(GetFirmwareEnvironmentVariableExW=_Fn(get_variable))

    var = windows.read_variable("Setup", GUID)

    assert (var.payload, var.error) == (payload, message)


def test_read_variable_stops_at_the_variable_size_cap(native, monkeypatch):
    monkeypatch.setattr(windows, "enable_privilege", lambda: None)

    def get_variable(*_args):
        native["error"] = windows.ERROR_INSUFFICIENT_BUFFER
        return 0

    get = _Fn(get_variable)
    native["dlls"]["kernel32"] = _Dll(GetFirmwareEnvironmentVariableExW=get)

    var = windows.read_variable("Setup", GUID)

    sizes = [call[3] for call in get.calls]
    assert sizes[0] == 4096 and sizes[-1] == windows.MAX_VARIABLE_BYTES
    assert all(after == before * 2 for before, after in zip(sizes, sizes[1:]))
    assert var.error == f"variable exceeds {windows.MAX_VARIABLE_BYTES} byte limit"


def test_enumeration_renegotiates_when_the_store_grows_between_calls(native):
    raw = _entry("BootOrder", GUID, 7, b"\x00\x01")
    sizes = iter([len(raw) - 8, len(raw)])  # a variable grew after the size query

    def enumerate_values(klass, buffer, size):
        assert klass == windows.SYSTEM_ENVIRONMENT_VALUE_INFORMATION
        if buffer is None or len(buffer) < len(raw):
            size._obj.value = next(sizes)
            return TOO_SMALL
        ctypes.memmove(buffer, raw, len(raw))
        size._obj.value = len(raw)
        return 0

    fn = _Fn(enumerate_values)
    native["dlls"]["ntdll"] = _Dll(NtEnumerateSystemEnvironmentValuesEx=fn)

    assert windows._enumerate_raw() == raw
    assert [None if call[1] is None else len(call[1]) for call in fn.calls] == [
        None, len(raw) - 8, len(raw)]
    assert fn.argtypes == [ctypes.c_uint32, ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)]
    assert fn.restype is ctypes.c_int32


@pytest.mark.parametrize(("status", "size", "outcome"), [
    (0, 0, b""),
    (ACCESS_DENIED, 0, "NTSTATUS 0xc0000022"),
    (TOO_SMALL, 0, "returned no buffer size"),
])
def test_enumeration_size_query_outcomes(native, status, size, outcome):
    def enumerate_values(_klass, _buffer, size_ref):
        size_ref._obj.value = size
        return status

    native["dlls"]["ntdll"] = _Dll(NtEnumerateSystemEnvironmentValuesEx=_Fn(enumerate_values))

    if isinstance(outcome, bytes):
        assert windows._enumerate_raw() == outcome
    else:
        with pytest.raises(OSError, match=outcome):
            windows._enumerate_raw()


def test_collect_reports_a_native_failure_as_unavailable(native, monkeypatch):
    monkeypatch.setattr(windows, "enable_privilege", lambda: None)
    native["dlls"]["ntdll"] = _Dll(
        NtEnumerateSystemEnvironmentValuesEx=_Fn(lambda *_args: ACCESS_DENIED))

    with pytest.raises(RuntimeError, match="enumeration unavailable: .*0xc0000022"):
        windows.collect()

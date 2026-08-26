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

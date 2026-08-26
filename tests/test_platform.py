from uefi_mirror import platform


def _structure(kind, formatted, strings):
    return bytes([kind, len(formatted) + 4, 0, 0]) + formatted + b"\0".join(strings) + b"\0\0"


def test_parse_windows_smbios_dmi():
    table = b"".join((
        _structure(0, bytes([1, 2, 0, 0, 3]) + bytes(11) + bytes([1, 9]),
                   [b"AMI", b"1.2.3", b"08/25/2026"]),
        _structure(1, bytes([1, 2]), [b"Acme", b"Roadrunner"]),
        _structure(2, bytes([1, 2, 3]), [b"Acme", b"X1", b"Rev A"]),
        _structure(127, b"", []),
    ))
    raw = bytes([0, 3, 7, 0]) + len(table).to_bytes(4, "little") + table

    assert platform._parse_smbios(raw) == {
        "bios_vendor": "AMI", "bios_version": "1.2.3", "bios_date": "08/25/2026",
        "bios_release": "1.9", "sys_vendor": "Acme", "product_name": "Roadrunner",
        "board_vendor": "Acme", "board_name": "X1", "board_version": "Rev A",
    }


def test_parse_windows_smbios_rejects_truncated_table():
    assert platform._parse_smbios(b"\0\x03\x07\0\x20\0\0\0short") == {}


def test_windows_capability_states():
    assert platform._capability(1, 0)["status"] == "not_uefi"
    assert platform._capability(0, 0)["status"] == "unavailable"
    assert platform._capability(2, platform.ERROR_PRIVILEGE_NOT_HELD)["status"] == "needs_elevation"
    assert platform._capability(2, 998)["status"] == "ready"

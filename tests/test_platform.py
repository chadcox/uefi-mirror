import json
import pathlib

import pytest

from uefi_mirror import platform, safety

DATA = pathlib.Path(__file__).resolve().parent / "data"
SECURITY = (DATA / "fwupd_security.json").read_bytes()
DEVICES = (DATA / "fwupd_devices.json").read_bytes()
VERSION = b"compile   org.freedesktop.fwupd  2.1.7\nruntime   org.freedesktop.fwupd  2.1.7\n"


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


@pytest.mark.parametrize(("output", "expected"), [
    ("compile   info.libusb                   1.0.30\n"
     "compile   org.freedesktop.fwupd         2.1.7\n"
     "runtime   org.freedesktop.fwupd         2.1.8\n", "2.1.8"),
    ("compile   info.libusb                   1.0.30\n"
     "compile   org.freedesktop.fwupd         2.1.7\n", "2.1.7"),
    ("client version:\t1.9.5\n", "1.9.5"),
    ("client version:\t1.9.5\ndaemon version:\t1.9.6\n", "1.9.6"),
])
def test_fwupdmgr_reports_the_running_fwupd_version(monkeypatch, output, expected):
    """fwupd 2.x lists dependencies first; probe once showed libusb's, then the whole record."""
    monkeypatch.setattr(platform, "OPTIONAL_TOOLS", ("fwupdmgr",))
    monkeypatch.setattr(platform.safety, "run_readonly_tool", lambda argv, **_:
                        safety.ToolResult("/usr/bin/fwupdmgr", 0, output.encode(), b""))

    assert platform.optional_tools() == {"fwupdmgr": expected}


def test_optional_tools_other_than_fwupd_are_located_but_never_run(monkeypatch):
    monkeypatch.setattr(platform.shutil, "which", lambda tool: f"/opt/{tool}")
    ran = []

    def run(argv, **_):
        ran.append(tuple(argv))
        return safety.ToolResult("/opt/fwupdmgr", 0, VERSION, b"")

    monkeypatch.setattr(platform.safety, "run_readonly_tool", run)
    assert platform.optional_tools() == {
        "UEFIExtract": "/opt/UEFIExtract", "uefiextract": "/opt/uefiextract",
        "ifrextractor": "/opt/ifrextractor", "chipsec_util": "/opt/chipsec_util",
        "fwupdmgr": "2.1.7",
    }
    assert ran == [("fwupdmgr", "--version")]


def _fwupd_with(monkeypatch, overrides):
    """Answer each fwupdmgr command from fixtures unless `overrides` replaces it
    with an exception to raise or a (returncode, stdout, stderr) triple."""
    answers = {("fwupdmgr", "--version"): (0, VERSION, b""),
               ("fwupdmgr", "security", "--json"): (0, SECURITY, b""),
               ("fwupdmgr", "get-devices", "--json"): (0, DEVICES, b"")}
    answers.update(overrides)

    def run(argv, **_):
        answer = answers[tuple(argv)]
        if isinstance(answer, BaseException):
            raise answer
        return safety.ToolResult("/usr/bin/fwupdmgr", *answer)

    monkeypatch.setattr(platform, "WINDOWS", False)
    monkeypatch.setattr(platform.safety, "run_readonly_tool", run)
    return platform.fwupd()


def test_fwupd_report_keeps_fwupd_json_verbatim_with_its_source(monkeypatch):
    report = _fwupd_with(monkeypatch, {})
    assert report["reported_by"] == "fwupd" and report["available"] is True
    assert report["version"] == {"command": ["fwupdmgr", "--version"],
                                 "program": "/usr/bin/fwupdmgr", "available": True,
                                 "output": "2.1.7"}
    assert report["security"]["command"] == ["fwupdmgr", "security", "--json"]
    assert report["security"]["output"] == json.loads(SECURITY)
    assert report["devices"]["command"] == ["fwupdmgr", "get-devices", "--json"]
    assert report["devices"]["output"] == json.loads(DEVICES)
    spi = next(a for a in report["security"]["output"]["SecurityAttributes"]
               if a["AppstreamId"] == "org.fwupd.hsi.Amd.SpiWriteProtection")
    assert spi["HsiResult"] == "enabled"


@pytest.mark.parametrize(("answer", "error"), [
    (TimeoutError("/usr/bin/fwupdmgr did not finish within 30 seconds"), "did not finish"),
    (ValueError("/usr/bin/fwupdmgr: output exceeds 1048576 byte limit"), "byte limit"),
    ((1, b"", b"Failed to connect to daemon\n"), "exit status 1: Failed to connect to daemon"),
    ((0, b"{not json", b""), "invalid JSON"),
    ((0, b"[1, 2]", b""), "expected an object"),
    ((0, b"[" * 100_000 + b"]" * 100_000, b""), "invalid JSON"),
])
def test_one_failed_fwupd_query_is_recorded_and_the_rest_still_run(monkeypatch, answer, error):
    report = _fwupd_with(monkeypatch, {("fwupdmgr", "security", "--json"): answer})
    security = report["security"]
    assert security["available"] is False and error in security["error"]
    assert "output" not in security
    assert report["devices"]["output"] == json.loads(DEVICES)
    assert report["version"]["output"] == "2.1.7"


def test_fwupd_1x_version_is_recorded(monkeypatch):
    output = b"client version:\t1.9.5\ncompile-time dependency versions\n\tgusb:\t0.4.8\n" \
             b"daemon version:\t1.9.6\n"
    report = _fwupd_with(monkeypatch, {("fwupdmgr", "--version"): (0, output, b"")})
    assert report["version"]["output"] == "1.9.6"


def test_unrecognised_fwupd_version_is_not_guessed(monkeypatch):
    output = b"gusb:\t0.4.8\nfwupd version unknown\n"
    report = _fwupd_with(monkeypatch, {("fwupdmgr", "--version"): (0, output, b"")})
    assert report["version"]["available"] is False
    assert "unrecognised version output: gusb:" in report["version"]["error"]


def test_missing_fwupd_or_windows_is_reported_unavailable(monkeypatch):
    missing = FileNotFoundError("fwupdmgr not found on PATH")
    report = _fwupd_with(monkeypatch, {("fwupdmgr", "--version"): missing})
    assert report == {"reported_by": "fwupd", "available": False,
                      "error": "fwupdmgr not found on PATH"}

    monkeypatch.setattr(platform, "WINDOWS", True)
    assert platform.fwupd() == {"reported_by": "fwupd", "available": False,
                                "error": "fwupd is not available on Windows"}

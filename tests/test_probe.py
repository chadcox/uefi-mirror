import json
import pathlib

from typer.testing import CliRunner

from uefi_mirror import cli, platform
from uefi_mirror.collectors.efivarfs import Variable

DATA = pathlib.Path(__file__).resolve().parent / "data"


def _summary(status):
    return {
        "uefi_boot": True, "efivarfs_mounted": False, "euid": None,
        "dmi": {}, "firmware_attributes": {}, "optional_tools": {},
        "firmware_variables": {"status": status, "message": status},
    }


def test_probe_checks_windows_enumeration_before_saying_live_collection_ready(monkeypatch):
    monkeypatch.setattr(platform, "summary", lambda: _summary("ready"))
    monkeypatch.setattr(cli.windows, "collect", lambda: [Variable("Setup", "guid", "Setup-guid",
                                                                  payload=b"x")])
    result = CliRunner().invoke(cli.app, ["probe"])
    assert result.exit_code == 0
    assert "Live collection ready" in result.stdout

    monkeypatch.setattr(cli.windows, "collect", lambda: [])
    result = CliRunner().invoke(cli.app, ["probe"])
    assert result.exit_code == 0
    assert "no readable variables" in result.stdout

    def unavailable():
        raise RuntimeError("enumeration unavailable")

    monkeypatch.setattr(cli.windows, "collect", unavailable)
    result = CliRunner().invoke(cli.app, ["probe"])
    assert result.exit_code == 0
    assert "Live collection unavailable" in result.stdout


def test_probe_explains_windows_elevation(monkeypatch):
    monkeypatch.setattr(platform, "summary", lambda: _summary("needs_elevation"))
    result = CliRunner().invoke(cli.app, ["probe"])
    assert result.exit_code == 0
    assert "elevated Administrator terminal" in result.stdout


def _record(command, output):
    return {"command": command, "program": "/usr/bin/fwupdmgr", "available": True,
            "output": output}


def _fwupd_report():
    return {
        "reported_by": "fwupd", "available": True,
        "version": _record(["fwupdmgr", "--version"], "2.1.7"),
        "security": _record(["fwupdmgr", "security", "--json"],
                            json.loads((DATA / "fwupd_security.json").read_text())),
        "devices": _record(["fwupdmgr", "get-devices", "--json"],
                           json.loads((DATA / "fwupd_devices.json").read_text())),
    }


def _probe(monkeypatch, report, *args):
    monkeypatch.setattr(platform, "summary", lambda: _summary("needs_elevation"))
    monkeypatch.setattr(platform, "fwupd", lambda: report)
    return CliRunner().invoke(cli.app, ["probe", *args], env={"COLUMNS": "200"})


def test_probe_fwupd_attributes_security_and_devices_to_fwupd(monkeypatch):
    result = _probe(monkeypatch, _fwupd_report(), "--fwupd")
    assert result.exit_code == 0, result.output
    out = result.stdout
    assert "Reported by fwupd 2.1.7" in out and "did not read these values itself" in out
    spi = next(line for line in out.splitlines() if "Amd.SpiWriteProtection" in line)
    assert "enabled" in spi and "yes" in spi and "2" in spi
    lockdown = next(line for line in out.splitlines() if "Kernel.Lockdown" in line)
    assert "runtime" in lockdown and "not-enabled" in lockdown and "no" in lockdown
    psp = next(line for line in out.splitlines() if "Secure Processor" in line)
    assert "00.42.00.26" in psp
    assert "devices report a version" in out


def test_probe_fwupd_reports_gaps_without_failing(monkeypatch):
    report = _fwupd_report()
    report["security"] = {"command": ["fwupdmgr", "security", "--json"], "available": False,
                          "error": "[Errno 110] did not finish"}
    result = _probe(monkeypatch, report, "--fwupd")
    assert result.exit_code == 0, result.output
    assert "fwupdmgr security --json: [Errno 110] did not finish" in result.stdout
    assert "Host security" not in result.stdout and "Device firmware" in result.stdout

    missing = {"reported_by": "fwupd", "available": False, "error": "fwupdmgr not found on PATH"}
    result = _probe(monkeypatch, missing, "--fwupd")
    assert result.exit_code == 0, result.output
    assert "fwupd not available: fwupdmgr not found on PATH" in result.stdout


def test_probe_runs_fwupd_only_when_asked(monkeypatch):
    def boom():
        raise AssertionError("fwupd queried without --fwupd")

    monkeypatch.setattr(platform, "summary", lambda: _summary("needs_elevation"))
    monkeypatch.setattr(platform, "fwupd", boom)
    result = CliRunner().invoke(cli.app, ["probe"])
    assert result.exit_code == 0, result.output
    assert "Reported by fwupd" not in result.stdout

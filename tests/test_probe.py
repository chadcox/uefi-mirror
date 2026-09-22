from typer.testing import CliRunner

from uefi_mirror import cli, platform
from uefi_mirror.collectors.efivarfs import Variable


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

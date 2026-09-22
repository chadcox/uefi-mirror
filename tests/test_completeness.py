from typer.testing import CliRunner

from uefi_mirror import cli
from uefi_mirror.schema.model import Schema


def test_export_require_complete_refuses_warnings_before_collecting(tmp_path, monkeypatch):
    schema = Schema(image={}, formsets=[], settings=[], warnings=["section dropped"])
    monkeypatch.setattr(cli, "_load_schema", lambda *_: (schema, None, "firmware.cap"))

    def collect(_):
        raise AssertionError("collected variables before checking parser warnings")

    monkeypatch.setattr(cli, "_live_store", collect)
    output = tmp_path / "export.json"
    result = CliRunner().invoke(cli.app, ["export", "firmware.cap", "--require-complete",
                                          "--output", str(output)])
    assert result.exit_code != 0
    assert "refusing partial export" in result.output
    assert not output.exists()

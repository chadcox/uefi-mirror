"""The --schema flag exists so a machine that never sees the firmware image can
still decode its own variables. These tests pin the two halves of that promise:
the schema file must decode identically, and it must not buy back the safety
evidence that only the raw image can provide."""

import hashlib
import json

import pytest
from typer.testing import CliRunner

from tests import fixtures
from uefi_mirror import __version__, decode
from uefi_mirror.cli import app

runner = CliRunner()
GUID = str(fixtures.VARSTORE_GUID)


def test_version_option():
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert result.stdout.strip() == f"uefi-mirror {__version__}"


@pytest.fixture
def image(tmp_path):
    path = tmp_path / "BIOS.CAP"
    path.write_bytes(fixtures.build_capsule(
        fixtures.build_image(fixtures.build_conditional_ifr())))
    return path


def _snapshot(tmp_path, payload=bytes(0x100)):
    root = tmp_path / f"snap-{len(payload)}"
    (root / "raw-variables").mkdir(parents=True, exist_ok=True)
    filename = f"Setup-{GUID}"
    (root / "raw-variables" / filename).write_bytes(payload)
    (root / "manifest.json").write_text(json.dumps({
        "format_version": decode.SNAPSHOT_FORMAT_VERSION,
        "variables": [{"name": "Setup", "guid": GUID.upper(), "filename": filename,
                       "attributes": 7, "payload_size": len(payload),
                       "payload_sha256": hashlib.sha256(payload).hexdigest(),
                       "error": None}],
    }))
    return root


def _schema_file(tmp_path, image):
    path = tmp_path / "schema.json"
    result = runner.invoke(app, ["schema", str(image), "--output", str(path)])
    assert result.exit_code == 0, result.output
    return path


def _export(tmp_path, name, *args):
    out = tmp_path / name
    result = runner.invoke(app, ["export", "--snapshot", str(_snapshot(tmp_path)),
                                 "--output", str(out), *args])
    assert result.exit_code == 0, result.output
    return json.loads(out.read_text()), result.output


def test_exporting_from_a_schema_file_decodes_exactly_like_the_image(tmp_path, image):
    from_image, _ = _export(tmp_path, "image.json", str(image))
    from_schema, _ = _export(tmp_path, "schema-export.json",
                             "--schema", str(_schema_file(tmp_path, image)))
    assert from_schema["settings"] == from_image["settings"]
    assert from_schema["counts"] == from_image["counts"]


def test_exporting_from_a_schema_file_reports_reduced_evidence(tmp_path, image):
    _, output = _export(tmp_path, "schema-export.json",
                        "--schema", str(_schema_file(tmp_path, image)))
    assert "matched" not in output
    assert "no firmware image" in output


def test_a_schema_file_that_does_not_fit_the_machine_is_refused(tmp_path, image):
    result = runner.invoke(app, ["export", "--schema", str(_schema_file(tmp_path, image)),
                                 "--snapshot", str(_snapshot(tmp_path, b"\x01"))])
    assert result.exit_code != 0
    assert "does not match" in result.output


def test_a_refused_schema_can_still_be_forced_open(tmp_path, image):
    result = runner.invoke(app, ["export", "--schema", str(_schema_file(tmp_path, image)),
                                 "--snapshot", str(_snapshot(tmp_path, b"\x01")),
                                 "--allow-mismatch"])
    assert result.exit_code == 0, result.output


@pytest.mark.parametrize("args,match", [
    ([], "pass a firmware image"),
    (["IMAGE", "--schema", "SCHEMA"], "not both"),
])
def test_export_needs_exactly_one_schema_source(tmp_path, args, match):
    args = [str(image) if a == "IMAGE" else a for a in args]
    result = runner.invoke(app, ["export", *args])
    assert result.exit_code != 0
    assert match in result.output


def test_a_corrupt_schema_file_is_named_in_the_error(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{oops")
    result = runner.invoke(app, ["export", "--schema", str(bad)])
    assert result.exit_code != 0
    assert "bad.json" in result.output and "JSON" in result.output


def test_diff_can_name_settings_from_a_schema_file(tmp_path, image):
    old = _snapshot(tmp_path / "a")
    new = _snapshot(tmp_path / "b", bytes([1]) + bytes(0xFF))
    result = runner.invoke(app, ["diff", str(old), str(new),
                                 "--schema", str(_schema_file(tmp_path, image))])
    assert result.exit_code == 0, result.output
    assert "named settings changed" in result.output


def test_diff_marks_a_change_the_setup_menu_would_not_show(tmp_path, image):
    """A value that moved while the firmware suppresses its question is the
    interesting case -- nobody could have made that change from the menu -- so
    the table has to say so rather than look like an ordinary edit."""
    master_on = bytes([1, 0]) + bytes(0xFE)
    old = _snapshot(tmp_path / "a", master_on)
    new = _snapshot(tmp_path / "b", bytes([1, 1]) + bytes(0xFE))
    result = runner.invoke(app, ["diff", str(old), str(new),
                                 "--schema", str(_schema_file(tmp_path, image))])
    assert result.exit_code == 0, result.output
    assert "Vis" in result.output and decode.HIDDEN in result.output

    # The master switch alone changes in plain sight: no column, no noise.
    plain = runner.invoke(app, ["diff", str(_snapshot(tmp_path / "c", bytes(0x100))),
                                str(_snapshot(tmp_path / "d", master_on)),
                                "--schema", str(_schema_file(tmp_path, image))])
    assert plain.exit_code == 0, plain.output
    assert "Vis" not in plain.output


def test_renaming_a_schema_file_cannot_invent_bios_version_evidence(tmp_path, image):
    """Version evidence is read out of the firmware filename. If it were read
    out of the schema file's name, renaming the download would forge it."""
    schema = _schema_file(tmp_path, image)
    forged = tmp_path / "BIOS-9999.json"
    forged.write_bytes(schema.read_bytes())

    document, output = _export(tmp_path, "forged.json", "--schema", str(forged))
    assert "9999" not in output
    assert document["image"]["filename"] == "BIOS.CAP"
    assert document["image"]["schema_file"] == "BIOS-9999.json"

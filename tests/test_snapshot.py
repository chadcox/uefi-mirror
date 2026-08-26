import hashlib
import json
import os
import subprocess

import pytest

from tests import fixtures
from uefi_mirror import cli, decode, platform
from uefi_mirror.collectors.efivarfs import Variable

GUID = str(fixtures.VARSTORE_GUID)
FILENAME = f"Setup-{GUID}"


def _snapshot(tmp_path, payload=b"payload", **changes):
    raw = tmp_path / "raw-variables"
    raw.mkdir()
    (raw / FILENAME).write_bytes(payload)
    entry = {"name": "Setup", "guid": GUID.upper(), "filename": FILENAME,
             "attributes": 7, "payload_size": len(payload),
             "payload_sha256": hashlib.sha256(payload).hexdigest(), "error": None}
    entry.update(changes)
    manifest = {"format_version": decode.SNAPSHOT_FORMAT_VERSION, "variables": [entry]}
    (tmp_path / "manifest.json").write_text(json.dumps(manifest))
    return manifest


def test_valid_snapshot_round_trip(tmp_path):
    _snapshot(tmp_path)
    assert decode.from_snapshot(str(tmp_path)).get("Setup", GUID) == b"payload"


@pytest.mark.parametrize("changes,match", [
    ({"filename": "/tmp/" + FILENAME}, "filename"),
    ({"filename": "../" + FILENAME}, "filename"),
    ({"filename": f"Other-{GUID}"}, "filename"),
    ({"payload_size": 999}, "size mismatch"),
    ({"payload_sha256": "0" * 64}, "SHA-256 mismatch"),
])
def test_snapshot_rejects_invalid_payload_metadata(tmp_path, changes, match):
    _snapshot(tmp_path, **changes)
    with pytest.raises(ValueError, match=match):
        decode.from_snapshot(str(tmp_path))


def test_snapshot_rejects_symlink_payload(tmp_path):
    _snapshot(tmp_path)
    target = tmp_path / "target"
    os.unlink(tmp_path / "raw-variables" / FILENAME)
    link = tmp_path / "raw-variables" / FILENAME
    if os.name == "nt":
        target.mkdir()
        subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(target)],
                       check=True, capture_output=True)
    else:
        target.write_bytes(b"payload")
        os.symlink(target, link)
    with pytest.raises(ValueError, match="unreadable payload"):
        decode.from_snapshot(str(tmp_path))


def test_snapshot_rejects_duplicate_keys_and_filenames(tmp_path):
    manifest = _snapshot(tmp_path)
    manifest["variables"].append(dict(manifest["variables"][0]))
    (tmp_path / "manifest.json").write_text(json.dumps(manifest))
    with pytest.raises(ValueError, match="duplicate"):
        decode.from_snapshot(str(tmp_path))


def test_snapshot_rejects_unsupported_version(tmp_path):
    manifest = _snapshot(tmp_path)
    manifest["format_version"] += 1
    (tmp_path / "manifest.json").write_text(json.dumps(manifest))
    with pytest.raises(ValueError, match="unsupported"):
        decode.from_snapshot(str(tmp_path))


def test_missing_payload_is_allowed_only_for_collection_error(tmp_path):
    manifest = _snapshot(tmp_path)
    os.unlink(tmp_path / "raw-variables" / FILENAME)
    manifest["variables"][0]["error"] = "permission denied"
    (tmp_path / "manifest.json").write_text(json.dumps(manifest))
    store = decode.from_snapshot(str(tmp_path))
    assert store.payloads == {}
    assert store.errors


def _boom(*_args, **_kwargs):
    raise AssertionError("read the local machine's DMI while inspecting a snapshot")


def test_snapshot_without_dmi_does_not_borrow_local_dmi(tmp_path, monkeypatch):
    """A snapshot missing DMI yields no evidence, not this machine's evidence."""
    _snapshot(tmp_path)
    monkeypatch.setattr(platform, "dmi", _boom)
    store = decode.from_snapshot(str(tmp_path))
    assert cli._dmi_for(store) == {}


def test_snapshot_dmi_is_preferred_over_local(tmp_path, monkeypatch):
    manifest = _snapshot(tmp_path)
    manifest["platform"] = {"dmi": {"board_name": "RECORDED-B550"}}
    (tmp_path / "manifest.json").write_text(json.dumps(manifest))
    monkeypatch.setattr(platform, "dmi", _boom)
    store = decode.from_snapshot(str(tmp_path))
    assert cli._dmi_for(store) == {"board_name": "RECORDED-B550"}


def test_live_store_still_reads_local_dmi(monkeypatch):
    monkeypatch.setattr(platform, "dmi", lambda: {"board_name": "LOCAL-X570"})
    store = decode.VariableStore(source="/sys/firmware/efi/efivars", kind="efivarfs")
    assert cli._dmi_for(store) == {"board_name": "LOCAL-X570"}


def test_windows_live_store_dispatches_to_windows_collector(monkeypatch):
    variable = Variable("SecureBoot", GUID, FILENAME, attributes=7, payload=b"\x01")
    monkeypatch.setattr(platform, "WINDOWS", True)
    monkeypatch.setattr(cli.windows, "collect", lambda: [variable])
    monkeypatch.setattr(cli.efivarfs, "collect", _boom)

    store = cli._live_store(None)

    assert store.source == store.kind == cli.WINDOWS_FIRMWARE
    assert store.get("SecureBoot", GUID) == b"\x01"
    assert store.kind in decode.LIVE_KINDS

    monkeypatch.setattr(cli.windows, "collect", _boom)
    monkeypatch.setattr(
        cli.efivarfs, "collect", lambda directory, require_mount: [variable])
    fixture_store = cli._live_store("fixture-efivars")
    assert fixture_store.source == "fixture-efivars"
    assert fixture_store.kind == "efivarfs"

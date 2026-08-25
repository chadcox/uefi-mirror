import hashlib
import json
import os

import pytest

from tests import fixtures
from uefi_mirror import decode

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
    target.write_bytes(b"payload")
    os.unlink(tmp_path / "raw-variables" / FILENAME)
    os.symlink(target, tmp_path / "raw-variables" / FILENAME)
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

import hashlib
import io
import json
import os
import stat
import struct
import subprocess
import warnings
import zipfile
from dataclasses import replace
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest
from typer.testing import CliRunner

from tests import fixtures
from uefi_mirror import cli, decode, fetch

FIXTURE = Path(__file__).parent / "data" / "asus_x870e_e_bios.json"
RUNNER = CliRunner()
FETCH_DMI = {
    "sys_vendor": "ASUSTeK COMPUTER INC.",
    "product_name": "System Product Name",
    "board_vendor": "ASUSTeK COMPUTER INC.",
    "board_name": "ROG STRIX X870E-E GAMING WIFI",
    "board_version": "Rev 1.xx",
    "bios_version": "2402",
}


def _metadata() -> bytes:
    return FIXTURE.read_bytes()


def _records() -> tuple[fetch.Product, list[fetch.Release]]:
    product = fetch.supported_model("ASUSTeK COMPUTER INC.", "rog strix x870e-e gaming wifi")
    return product, fetch.parse_asus_metadata(_metadata(), product)


def _zip(*members, compression=zipfile.ZIP_DEFLATED) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=compression) as archive:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            for name, data in members:
                archive.writestr(name, data)
    return output.getvalue()


def _artifact(data: bytes, name: str) -> fetch.safety.HttpResult:
    return fetch.safety.HttpResult(data, f"https://dlcdnets.asus.com/files/{name}")


def _release(data: bytes, *, checksum=True, target="artifact") -> fetch.Release:
    release = _records()[1][0]
    digest = hashlib.sha256(data).hexdigest() if checksum else None
    return replace(release, publisher_sha256=digest, publisher_checksum_target=target)


def _patch_zip_field(data: bytes, signature: bytes, offset: int, value: int) -> bytes:
    changed = bytearray(data)
    position = changed.find(signature)
    assert position >= 0
    struct.pack_into("<I" if value > 0xffff else "<H", changed, position + offset, value)
    return bytes(changed)


def _fetch_inputs():
    image = fixtures.build_capsule()
    artifact = _zip(("BIOS.CAP", image), ("BIOSRenamer.exe", b"not executed"))
    metadata = json.loads(_metadata())
    records = metadata["Result"]["Obj"][0]["Files"]
    next(record for record in records if record["Version"] == "2402")["sha256"] = (
        hashlib.sha256(artifact).hexdigest())
    return image, artifact, json.dumps(metadata).encode()


def _fake_fetch_network(monkeypatch, artifact, metadata):
    calls = []

    def read_https(url, limit, hosts, *, stage, budget):
        calls.append((url, limit, hosts, stage, budget))
        data = metadata if stage == "ASUS metadata" else artifact
        return fetch.safety.HttpResult(data, url)

    monkeypatch.setattr(fetch.safety, "read_https", read_https)
    return calls


def _identity_snapshot(root: Path, dmi: dict, payload: bytes | None = None) -> Path:
    raw = root / "raw-variables"
    raw.mkdir(parents=True)
    variables = []
    if payload is not None:
        guid = str(fixtures.VARSTORE_GUID)
        filename = f"Setup-{guid}"
        (raw / filename).write_bytes(payload)
        variables.append({
            "name": "Setup", "guid": guid, "filename": filename,
            "attributes": 7, "payload_size": len(payload),
            "payload_sha256": hashlib.sha256(payload).hexdigest(), "error": None,
        })
    (root / "manifest.json").write_text(json.dumps({
        "format_version": decode.SNAPSHOT_FORMAT_VERSION,
        "platform": {"dmi": dmi},
        "variables": variables,
    }))
    return root


def test_supported_model_uses_the_reviewed_asus_endpoint():
    product = fetch.supported_model("ASUSTeK COMPUTER INC.", " ROG  STRIX X870E-E GAMING WIFI ")
    url = urlsplit(product.metadata_url)

    assert product is fetch.SUPPORTED_MODELS[("asus", product.model.casefold())]
    assert (url.scheme, url.netloc, url.path) == (
        "https", "www.asus.com", "/support/webapi/ProductV2/GetPDBIOS")
    assert parse_qs(url.query)["model"] == ["rog strix x870e-e gaming wifi"]


def test_exact_older_and_beta_releases_are_selected_from_offline_metadata():
    product, releases = _records()

    older = fetch.select_release(releases, "1701")
    beta = fetch.select_release(releases, " 2401 ")

    assert len(releases) == 4  # The unrelated Firmware category is ignored.
    assert older.product_id == product.product_id
    assert older.download_url == (
        "https://dlcdnets.asus.com/pub/ASUS/mb/BIOS/"
        "ROG-STRIX-X870E-E-GAMING-WIFI-ASUS-1701.zip"
    )
    assert beta.beta is True
    assert beta.publisher_checksum_target == "artifact"
    assert beta.publisher_sha256 == (
        "d26c830a48def3bbb741aba75e1563b76b712f92b609f13f2bdb1079159d17d5"
    )


def test_leading_zeroes_are_part_of_the_exact_version():
    _, releases = _records()
    assert fetch.select_release(releases, "0706").publisher_sha256 is None
    with pytest.raises(ValueError, match="no BIOS release exactly matching"):
        fetch.select_release(releases, "706")


def test_dmi_identity_resolves_the_installed_release_without_rewriting_facts():
    product, releases = _records()
    selection = fetch.resolve_identity({
        "sys_vendor": " ASUSTeK  COMPUTER INC. ",
        "product_name": "System Product Name",
        "board_vendor": "ASUSTeK COMPUTER INC.",
        "board_name": " ROG  STRIX X870E-E GAMING WIFI ",
        "board_version": " Rev 1.xx ",
        "bios_version": " 2402 ",
    })

    assert selection.detected_identity == {
        "sys_vendor": "ASUSTeK COMPUTER INC.",
        "board_vendor": "ASUSTeK COMPUTER INC.",
        "board_name": product.model,
        "board_version": "Rev 1.xx",
        "bios_version": "2402",
    }
    assert selection.overrides == {}
    assert selection.selected_identity == fetch.Identity(
        "ASUS", product.model, "2402", "Rev 1.xx")
    assert fetch.resolve_release(selection, releases).version == "2402"


def test_explicit_identity_works_when_dmi_is_missing_or_placeholder():
    selection = fetch.resolve_identity(
        {"sys_vendor": "System manufacturer", "board_name": "Default string"},
        manufacturer="asus", model="rog strix x870e-e gaming wifi",
        bios_version="0706", revision=" 1.0 ",
    )

    assert selection.detected_identity == {}
    assert selection.overrides == {
        "manufacturer": "ASUS",
        "model": "rog strix x870e-e gaming wifi",
        "revision": "1.0",
        "bios_version": "0706",
    }
    assert selection.selected_identity.bios_version == "0706"


def test_oem_board_identity_requires_complete_explicit_selection():
    dmi = {
        "sys_vendor": "Dell Inc.", "product_name": "Alienware",
        "board_vendor": "ASUSTeK COMPUTER INC.",
        "board_name": "ROG STRIX X870E-E GAMING WIFI", "bios_version": "2402",
    }
    with pytest.raises(ValueError, match="system vendor.*differs from board vendor"):
        fetch.resolve_identity(dmi)

    selection = fetch.resolve_identity(
        dmi, manufacturer="ASUS", model="ROG STRIX X870E-E GAMING WIFI",
        bios_version="2402")
    assert selection.selected_identity.manufacturer == "ASUS"


def test_different_model_override_requires_its_own_version():
    dmi = {
        "board_vendor": "ASUS", "board_name": "ANOTHER BOARD",
        "bios_version": "9999",
    }
    with pytest.raises(ValueError, match="--bios-version is required"):
        fetch.resolve_identity(
            dmi, manufacturer="ASUS", model="ROG STRIX X870E-E GAMING WIFI")


@pytest.mark.parametrize("dmi,match", [
    ({}, "--manufacturer, --model, --bios-version"),
    ({"board_vendor": "ASUS", "board_name": "ROG STRIX X870E-E GAMING WIFI"},
     "--bios-version"),
    ({"board_vendor": "ASUS", "bios_version": "2402"}, "--model"),
])
def test_incomplete_identity_reports_the_required_overrides(dmi, match):
    with pytest.raises(ValueError, match=match):
        fetch.resolve_identity(dmi)


def test_cross_product_release_list_is_rejected():
    selection = fetch.resolve_identity(
        {}, manufacturer="ASUS", model="ROG STRIX X870E-E GAMING WIFI",
        bios_version="2402")
    other = replace(_records()[1][0], product_id="another product")

    with pytest.raises(ValueError, match="different product"):
        fetch.resolve_release(selection, [other])


def test_vendor_reads_use_reviewed_hosts_limits_and_one_shared_budget(monkeypatch):
    product = fetch.supported_model("ASUS", "ROG STRIX X870E-E GAMING WIFI")
    budget = fetch.safety.HttpBudget()
    calls = []

    def read_https(url, limit, hosts, *, stage, budget):
        calls.append((url, limit, hosts, stage, budget))
        data = _metadata() if stage == "ASUS metadata" else b"artifact"
        return fetch.safety.HttpResult(data, url)

    monkeypatch.setattr(fetch.safety, "read_https", read_https)
    releases = fetch.fetch_releases(product, budget)
    artifact = fetch.download_artifact(releases[0], budget)

    assert len(releases) == 4 and artifact.data == b"artifact"
    assert calls[0][1:4] == (
        fetch.safety.MAX_METADATA_BYTES, fetch.ASUS_METADATA_HOSTS, "ASUS metadata")
    assert calls[1][1:4] == (
        fetch.safety.MAX_ARTIFACT_BYTES, fetch.ASUS_ARTIFACT_HOSTS, "ASUS BIOS artifact")
    assert calls[0][4] is calls[1][4] is budget


def test_direct_image_is_checksum_verified_and_parser_validated():
    image = fixtures.build_capsule()
    result = fetch.validate_artifact(_release(image), _artifact(image, "BIOS.CAP"))

    assert result.image_name == "BIOS.CAP"
    assert result.image_data == image
    assert result.artifact_size == len(image)
    assert result.artifact_sha256 == hashlib.sha256(image).hexdigest()
    assert result.publisher_checksum_status == "verified"
    assert result.capsule.data == fixtures.build_image()
    assert result.settings_count == 1


def test_zip_selects_one_safe_nested_image_and_ignores_tools():
    image = fixtures.build_capsule()
    artifact = _zip(
        ("nested/BIOS.CAP", image),
        ("BIOSRenamer.exe", b"MZ-not-executed"),
        ("notes/config.cfg", b"configuration"),
    )
    result = fetch.validate_artifact(
        _release(artifact), _artifact(artifact, "update.zip"))

    assert result.image_name == "BIOS.CAP"
    assert result.image_data == image
    assert result.publisher_checksum_status == "verified"
    assert result.settings_count == 1


def test_image_scoped_and_missing_publisher_checksums_are_distinct():
    image = fixtures.build_capsule()
    artifact = _zip(("BIOS.CAP", image))
    image_scoped = replace(
        _release(artifact), publisher_sha256=hashlib.sha256(image).hexdigest(),
        publisher_checksum_target="image")

    verified = fetch.validate_artifact(image_scoped, _artifact(artifact, "update.zip"))
    unavailable = fetch.validate_artifact(
        _release(image, checksum=False), _artifact(image, "BIOS.CAP"))

    assert verified.publisher_checksum_status == "verified"
    assert unavailable.publisher_checksum_status == "unavailable"


@pytest.mark.parametrize("checksum,target,match", [
    ("0" * 64, "artifact", "mismatch"),
    ("bad", "artifact", "malformed"),
    ("0" * 64, "unknown", "unsupported target"),
])
def test_bad_publisher_checksum_fails_before_image_parsing(checksum, target, match):
    release = replace(
        _records()[1][0], publisher_sha256=checksum,
        publisher_checksum_target=target)
    with pytest.raises(ValueError, match=match):
        fetch.validate_artifact(release, _artifact(b"not firmware", "BIOS.CAP"))


@pytest.mark.parametrize("name", [
    "../BIOS.CAP",
    "/absolute/BIOS.CAP",
    "C:\\BIOS.CAP",
    "\\\\server\\share\\BIOS.CAP",
    "safe/../../BIOS.CAP",
    "safe\\..\\BIOS.CAP",
    "CON.CAP",
    "BIOS.CAP:stream",
    "BIOS\x7f.CAP",
])
def test_zip_rejects_unsafe_image_paths(name):
    artifact = _zip((name, fixtures.build_capsule()))
    with pytest.raises(ValueError, match="unsafe"):
        fetch.validate_artifact(
            _release(artifact), _artifact(artifact, "update.zip"))


def test_zip_rejects_unsafe_unrelated_paths_and_duplicate_names():
    image = fixtures.build_capsule()
    unsafe = _zip(("../notes.txt", b"x"), ("BIOS.CAP", image))
    duplicate = _zip(("BIOS.CAP", image), ("bios.cap", image))

    with pytest.raises(ValueError, match="unsafe"):
        fetch.validate_artifact(_release(unsafe), _artifact(unsafe, "update.zip"))
    with pytest.raises(ValueError, match="duplicate"):
        fetch.validate_artifact(
            _release(duplicate), _artifact(duplicate, "update.zip"))


def test_zip_rejects_multiple_missing_and_nested_images():
    image = fixtures.build_capsule()
    cases = (
        (_zip(("one.CAP", image), ("two.ROM", image)), "multiple firmware images"),
        (_zip(("readme.txt", b"none")), "no supported firmware image"),
        (_zip(("nested.zip", b"not opened"), ("BIOS.CAP", image)),
         "nested ZIP archives"),
    )
    for artifact, match in cases:
        with pytest.raises(ValueError, match=match):
            fetch.validate_artifact(
                _release(artifact), _artifact(artifact, "update.zip"))


def test_zip_rejects_symlink_and_encrypted_image_members():
    link = zipfile.ZipInfo("BIOS.CAP")
    link.create_system = 3
    link.external_attr = (stat.S_IFLNK | 0o777) << 16
    symlink = _zip((link, b"target"))
    with pytest.raises(ValueError, match="not a regular file"):
        fetch.validate_artifact(_release(symlink), _artifact(symlink, "update.zip"))

    encrypted = _zip(("BIOS.CAP", fixtures.build_capsule()))
    encrypted = _patch_zip_field(encrypted, b"PK\x03\x04", 6, 1)
    encrypted = _patch_zip_field(encrypted, b"PK\x01\x02", 8, 1)
    with pytest.raises(ValueError, match="encrypted"):
        fetch.validate_artifact(
            _release(encrypted), _artifact(encrypted, "update.zip"))


def test_zip_enforces_entry_and_advertised_size_limits():
    too_many = _zip(*((f"notes/{index}.txt", b"")
                      for index in range(fetch.MAX_ZIP_ENTRIES + 1)))
    with pytest.raises(ValueError, match="entry limit"):
        fetch.validate_artifact(
            _release(too_many), _artifact(too_many, "update.zip"))

    oversized = _zip(("BIOS.CAP", b"x"))
    oversized = _patch_zip_field(
        oversized, b"PK\x01\x02", 24, fetch.cap.MAX_IMAGE_BYTES + 1)
    with pytest.raises(ValueError, match="firmware image exceeds"):
        fetch.validate_artifact(
            _release(oversized), _artifact(oversized, "update.zip"))

    huge = _zip(("BIOS.CAP", b"x"))
    huge = _patch_zip_field(
        huge, b"PK\x01\x02", 24, fetch.MAX_ZIP_UNCOMPRESSED + 1)
    with pytest.raises(ValueError, match="uncompressed limit"):
        fetch.validate_artifact(_release(huge), _artifact(huge, "update.zip"))


def test_zip_rejects_unsupported_compression_and_crc_corruption():
    unsupported = _zip(("BIOS.CAP", b"firmware"), compression=zipfile.ZIP_STORED)
    unsupported = _patch_zip_field(unsupported, b"PK\x03\x04", 8, 99)
    unsupported = _patch_zip_field(unsupported, b"PK\x01\x02", 10, 99)
    with pytest.raises(ValueError, match="unsupported compression"):
        fetch.validate_artifact(
            _release(unsupported), _artifact(unsupported, "update.zip"))

    corrupt = bytearray(_zip(("BIOS.CAP", fixtures.build_capsule()),
                             compression=zipfile.ZIP_STORED))
    local = corrupt.find(b"PK\x03\x04")
    name_length = struct.unpack_from("<H", corrupt, local + 26)[0]
    extra_length = struct.unpack_from("<H", corrupt, local + 28)[0]
    corrupt[local + 30 + name_length + extra_length] ^= 0xff
    corrupt = bytes(corrupt)
    with pytest.raises(ValueError, match="invalid or unsupported ZIP"):
        fetch.validate_artifact(_release(corrupt), _artifact(corrupt, "update.zip"))


@pytest.mark.parametrize("name,data,match", [
    ("update.exe", b"MZ", "unsupported BIOS artifact container"),
    ("update.zip", b"not a ZIP", "invalid or unsupported ZIP"),
    ("BIOS.CAP", b"<!doctype html><html>error</html>", "HTML"),
    ("BIOS.CAP", b"not firmware", "no parseable settings"),
    ("CON.CAP", b"not firmware", "unsafe firmware image filename"),
    ("fetch.json", b"not firmware", "unsafe firmware image filename"),
])
def test_artifact_rejects_unsupported_or_unusable_content(name, data, match):
    with pytest.raises(ValueError, match=match):
        fetch.validate_artifact(
            _release(data, checksum=False), _artifact(data, name))


def test_fetch_cli_downloads_private_files_and_emits_clean_json(tmp_path, monkeypatch):
    image, artifact, metadata = _fetch_inputs()
    calls = _fake_fetch_network(monkeypatch, artifact, metadata)
    monkeypatch.setattr(cli.platform, "dmi", lambda: FETCH_DMI)
    monkeypatch.setattr(cli, "_live_variables", lambda *_args: pytest.fail(
        "fetch collected firmware variables"))
    output = tmp_path / "firmware"

    result = RUNNER.invoke(cli.app, ["fetch", "--output", str(output), "--json"])

    assert result.exit_code == 0, result.output
    wrapper = json.loads(result.stdout)
    saved = json.loads((output / "fetch.json").read_text())
    assert sorted(path.name for path in output.iterdir()) == ["BIOS.CAP", "fetch.json"]
    assert (output / "BIOS.CAP").read_bytes() == image
    assert wrapper == {
        "format_version": 1,
        "operation": "fetch",
        "image_path": str(output / "BIOS.CAP"),
        "manifest_path": str(output / "fetch.json"),
        "provenance": saved,
    }
    assert saved["identity_source"] == "local"
    assert set(saved) == {
        "format_version", "tool_version", "fetched_at", "identity_source",
        "detected_identity", "overrides", "selected_identity", "release",
        "support_url", "download_url", "final_download_url", "artifact",
        "publisher_checksum", "image", "validation", "warnings",
    }
    assert saved["detected_identity"]["board_name"] == FETCH_DMI["board_name"]
    assert saved["publisher_checksum"]["status"] == "verified"
    assert saved["artifact"] == {
        "size": len(artifact), "sha256": hashlib.sha256(artifact).hexdigest()}
    assert saved["image"]["file_sha256"] == hashlib.sha256(image).hexdigest()
    assert saved["validation"] == {
        "settings_count": 1, "installed_firmware_identity": "unverified"}
    assert len(calls) == 2 and calls[0][4] is calls[1][4]
    if os.name != "nt":
        assert output.stat().st_mode & 0o777 == 0o700
        assert (output / "BIOS.CAP").stat().st_mode & 0o777 == 0o600
        assert (output / "fetch.json").stat().st_mode & 0o777 == 0o600


def test_fetched_image_flows_through_existing_schema_and_export(tmp_path, monkeypatch):
    _image, artifact, metadata = _fetch_inputs()
    calls = _fake_fetch_network(monkeypatch, artifact, metadata)
    monkeypatch.setattr(cli.platform, "dmi", lambda: FETCH_DMI)
    output = tmp_path / "firmware"
    fetched = RUNNER.invoke(cli.app, ["fetch", "-o", str(output)])
    assert fetched.exit_code == 0, fetched.output

    schema_path = tmp_path / "schema.json"
    schema_result = RUNNER.invoke(
        cli.app, ["schema", str(output / "BIOS.CAP"), "-o", str(schema_path)])
    assert schema_result.exit_code == 0, schema_result.output

    snapshot = _identity_snapshot(
        tmp_path / "snapshot", FETCH_DMI, bytes(0x100))
    export_path = tmp_path / "export.json"
    export_result = RUNNER.invoke(cli.app, [
        "export", str(output / "BIOS.CAP"), "--snapshot", str(snapshot),
        "-o", str(export_path),
    ])
    assert export_result.exit_code == 0, export_result.output
    assert json.loads(export_path.read_text())["image"]["compatibility"]["status"] == (
        "unverified")
    assert len(calls) == 2  # Existing schema/export commands remain offline.


def test_resolve_only_json_does_not_download_or_write(tmp_path, monkeypatch):
    _image, artifact, metadata = _fetch_inputs()
    calls = _fake_fetch_network(monkeypatch, artifact, metadata)
    monkeypatch.setattr(cli.platform, "dmi", lambda: FETCH_DMI)

    result = RUNNER.invoke(cli.app, ["fetch", "--resolve-only", "--json"])

    assert result.exit_code == 0, result.output
    document = json.loads(result.stdout)
    assert document["operation"] == "resolve"
    assert document["release"]["version"] == "2402"
    assert document["publisher_checksum"]["status"] == "advertised"
    assert not {"artifact", "image", "image_path", "manifest_path", "validation"} & document.keys()
    assert [call[3] for call in calls] == ["ASUS metadata"]
    assert list(tmp_path.iterdir()) == []


def test_fetch_uses_validated_snapshot_identity_without_reading_local_dmi(
        tmp_path, monkeypatch):
    _image, artifact, metadata = _fetch_inputs()
    calls = _fake_fetch_network(monkeypatch, artifact, metadata)
    snapshot = _identity_snapshot(tmp_path / "snapshot", FETCH_DMI)
    monkeypatch.setattr(cli.platform, "dmi", lambda: pytest.fail("local DMI was read"))

    result = RUNNER.invoke(cli.app, [
        "fetch", "--snapshot", str(snapshot), "--resolve-only", "--json"])

    assert result.exit_code == 0, result.output
    document = json.loads(result.stdout)
    assert document["identity_source"] == "snapshot"
    assert document["detected_identity"]["bios_version"] == "2402"
    assert len(calls) == 1


def test_snapshot_without_dmi_never_borrows_local_identity(tmp_path, monkeypatch):
    snapshot = _identity_snapshot(tmp_path / "snapshot", {})
    monkeypatch.setattr(cli.platform, "dmi", lambda: pytest.fail("local DMI was read"))
    monkeypatch.setattr(fetch, "fetch_releases", lambda *_args: pytest.fail(
        "network was used without an identity"))

    result = RUNNER.invoke(cli.app, [
        "fetch", "--snapshot", str(snapshot), "--resolve-only"])

    assert result.exit_code == 1
    assert "--manufacturer, --model, --bios-version" in result.output


@pytest.mark.parametrize("args,match", [
    ([], "--output is required"),
    (["--resolve-only", "--output", "unused"], "cannot be used"),
])
def test_fetch_rejects_conflicting_output_options_before_network(monkeypatch, args, match):
    monkeypatch.setattr(fetch, "fetch_releases", lambda *_args: pytest.fail("network used"))
    result = RUNNER.invoke(cli.app, ["fetch", *args])
    assert result.exit_code == 2
    assert match in result.output


def test_fetch_help_exposes_the_public_contract():
    result = RUNNER.invoke(cli.app, ["fetch", "--help"])
    assert result.exit_code == 0, result.output
    for option in ("--output", "--snapshot", "--manufacturer", "--model", "--revision",
                   "--bios-version", "--resolve-only", "--json"):
        assert option in result.stdout


def test_fetch_accepts_complete_explicit_identity_without_dmi(monkeypatch):
    _image, artifact, metadata = _fetch_inputs()
    calls = _fake_fetch_network(monkeypatch, artifact, metadata)
    monkeypatch.setattr(cli.platform, "dmi", lambda: {})
    result = RUNNER.invoke(cli.app, [
        "fetch", "--resolve-only", "--json", "--manufacturer", "ASUS",
        "--model", FETCH_DMI["board_name"], "--bios-version", "2402",
    ])

    assert result.exit_code == 0, result.output
    document = json.loads(result.stdout)
    assert document["detected_identity"] == {}
    assert document["overrides"]["bios_version"] == "2402"
    assert len(calls) == 1


def test_fetch_refuses_nonempty_output_before_network(tmp_path, monkeypatch):
    output = tmp_path / "firmware"
    output.mkdir()
    sentinel = output / "keep"
    sentinel.write_text("unchanged")
    monkeypatch.setattr(fetch, "fetch_releases", lambda *_args: pytest.fail("network used"))

    result = RUNNER.invoke(cli.app, ["fetch", "--output", str(output)])

    assert result.exit_code == 1
    assert "not empty" in result.output
    assert sentinel.read_text() == "unchanged"


def test_fetch_refuses_symlinked_or_reparse_output_before_network(tmp_path, monkeypatch):
    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "firmware"
    if os.name == "nt":
        subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(target)],
                       check=True, capture_output=True)
    else:
        os.symlink(target, link)
    monkeypatch.setattr(fetch, "fetch_releases", lambda *_args: pytest.fail("network used"))

    result = RUNNER.invoke(cli.app, ["fetch", "--output", str(link)])

    assert result.exit_code == 1
    assert "output" in result.output
    assert list(target.iterdir()) == []


def test_fetch_reports_partial_output_when_manifest_write_fails(tmp_path, monkeypatch):
    image, artifact, metadata = _fetch_inputs()
    _fake_fetch_network(monkeypatch, artifact, metadata)
    monkeypatch.setattr(cli.platform, "dmi", lambda: FETCH_DMI)
    real_write = cli.write_private

    def fail_manifest(path, data):
        if path.endswith("fetch.json"):
            raise OSError("disk full")
        real_write(path, data)

    monkeypatch.setattr(cli, "write_private", fail_manifest)
    output = tmp_path / "firmware"
    result = RUNNER.invoke(
        cli.app, ["fetch", "--output", str(output), "--json"])

    assert result.exit_code == 1
    assert "may be partial" in result.output
    assert (output / "BIOS.CAP").read_bytes() == image
    assert not (output / "fetch.json").exists()
    assert result.stdout == ""


def test_provenance_warns_when_override_differs_from_detected_version():
    image = fixtures.build_capsule()
    artifact = _artifact(image, "BIOS.CAP")
    selection = fetch.resolve_identity(
        FETCH_DMI, bios_version="2401")
    release = replace(_release(image), version="2401")
    validated = fetch.validate_artifact(release, artifact)

    document = fetch.provenance_document(
        selection, release, artifact, validated, "local", "1.0.0",
        "2026-09-10T00:00:00Z")

    assert any("differs from detected version" in warning
               for warning in document["warnings"])

    missing_release = replace(release, publisher_sha256=None)
    missing_image = fetch.validate_artifact(missing_release, artifact)
    missing = fetch.provenance_document(
        selection, missing_release, artifact, missing_image, "local", "1.0.0",
        "2026-09-10T00:00:00Z")
    assert missing["publisher_checksum"] == {"status": "unavailable"}
    assert "Publisher SHA-256 was unavailable." in missing["warnings"]


def test_missing_and_ambiguous_releases_fail_instead_of_selecting_latest():
    _, releases = _records()
    with pytest.raises(ValueError, match="no BIOS release exactly matching"):
        fetch.select_release(releases, "9999")

    conflict = replace(releases[0], download_url=releases[0].download_url + ".other")
    with pytest.raises(ValueError, match="multiple BIOS releases"):
        fetch.select_release([*releases, conflict], "2402")


def test_identical_records_are_deduplicated():
    product, _ = _records()
    document = json.loads(_metadata())
    files = document["Result"]["Obj"][0]["Files"]
    files.append(dict(files[0]))

    releases = fetch.parse_asus_metadata(json.dumps(document).encode(), product)

    assert len([release for release in releases if release.version == "2402"]) == 1


@pytest.mark.parametrize("mutation, match", [
    (lambda doc: doc.update(Status="ERROR"), "did not report success"),
    (lambda doc: doc["Result"].update(Model="ROG STRIX X870E-F GAMING WIFI"),
     "returned product"),
    (lambda doc: doc["Result"].update(Obj={}), "Result.Obj must be an array"),
    (lambda doc: doc["Result"]["Obj"][0]["Files"][0].update(sha256="bad"),
     "invalid SHA-256"),
    (lambda doc: doc["Result"]["Obj"][0]["Files"][0]["DownloadUrl"].update(
        Global="https://example.invalid/bios.zip"), "unexpected download path"),
    (lambda doc: doc["Result"]["Obj"][0]["Files"][0].update(sha256=7),
     "invalid SHA-256"),
    (lambda doc: doc["Result"]["Obj"].append(1), "Result.Obj entry must be an object"),
])
def test_changed_or_unsafe_metadata_shape_fails_closed(mutation, match):
    product, _ = _records()
    document = json.loads(_metadata())
    mutation(document)

    with pytest.raises(ValueError, match=match):
        fetch.parse_asus_metadata(json.dumps(document).encode(), product)

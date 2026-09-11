import hashlib
import io
import json
import stat
import struct
import warnings
import zipfile
from dataclasses import replace
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

from tests import fixtures
from uefi_mirror import fetch

FIXTURE = Path(__file__).parent / "data" / "asus_x870e_e_bios.json"


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

import datetime
import hashlib
import io
import json
import os
import re
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

DATA = Path(__file__).parent / "data"


def _fixture_path(model: str) -> Path:
    slug = re.sub(r"[^a-z0-9]+", "_", model.casefold()).strip("_")
    return DATA / f"asus_{slug}_bios.json"


FIXTURE = _fixture_path("ROG STRIX X870E-E GAMING WIFI")
REPRESENTATIVE_FIXTURES = (
    ("ROG STRIX X870E-E GAMING WIFI", "2402", "1701", "2401", "0706", None),
    ("ROG STRIX B650E-F GAMING WIFI", "3881", "3854", "3886", None, "3854"),
    ("TUF GAMING X870-PLUS WIFI", "1681", "1654", "1686", "0237", None),
    ("TUF GAMING Z790-PLUS WIFI", "1836", "1825", None, None, "1645"),
    ("ROG STRIX Z790-E GAMING WIFI", "3202", "2102", None, None, "2102"),
)
RUNNER = CliRunner()
ANSI = re.compile(r"\x1b\[[0-9;]*m")
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


def _product() -> fetch.Product:
    return fetch.Product(
        manufacturer="ASUS",
        model="ROG STRIX X870E-E GAMING WIFI",
        product_id="rog strix x870e-e gaming wifi",
        support_url="https://www.asus.com/support/download-center/",
    )


def _records() -> tuple[fetch.Product, list[fetch.Release]]:
    return fetch.parse_asus_metadata(
        _metadata(),
        "ROG STRIX X870E-E GAMING WIFI",
        "rog strix x870e-e gaming wifi",
    )


@pytest.mark.parametrize(("value", "expected"), [
    ("/pub/ASUS/mb/BIOS/file.ZIP", "/pub/ASUS/mb/BIOS/file.ZIP"),
    ("/pub/ASUS/MB/BIOS/file.zip", "/pub/ASUS/MB/BIOS/file.zip"),
    ("/PuB/aSuS/mB/bIoS/file.zip", "/PuB/aSuS/mB/bIoS/file.zip"),
    (
        "/pub/ASUS/mb/BIOS/firmware%20file.zip",
        "/pub/ASUS/mb/BIOS/firmware%20file.zip",
    ),
])
def test_asus_download_path_accepts_exact_case_insensitive_prefix(
        value, expected):
    assert fetch._asus_download_path(value, "2402") == expected


@pytest.mark.parametrize("value", [
    "/pub/ASUS/mb/UEFI/file.zip",
    "/pub/ASUS/MB/BIOSX/file.zip",
    "//dlcdnets.asus.com/pub/ASUS/mb/BIOS/file.zip",
    "https://dlcdnets.asus.com/pub/ASUS/mb/BIOS/file.zip",
    "/pub/ASUS/mb/BIOS/./file.zip",
    "/pub/ASUS/mb/BIOS/../file.zip",
    "/pub/ASUS/mb/BIOS/%2e/file.zip",
    "/pub/ASUS/mb/BIOS/%2E%2e/file.zip",
    "/pub/ASUS/mb/BIOS/%252e%252e/file.zip",
    "/pub/ASUS/mb/BIOS/file%ZZ.zip",
    "/pub/ASUS/mb/BIOS/file%.zip",
    "/pub/ASUS/mb/BIOS/file%2.zip",
    "/pub/ASUS/mb/BIOS\\file.zip",
    "/pub/ASUS/mb/BIOS/%5cfile.zip",
    "/pub/ASUS/mb/BIOS//file.zip",
    "/pub/ASUS/mb/BIOS/file.zip?download=1",
    "/pub/ASUS/mb/BIOS/file.zip#fragment",
    "/pub/ASUS/mb/BIOS/file\x1f.zip",
    "/pub/ASUS/mb/BIOS/file%1f.zip",
    "/pub/ASUS/mb/BIOS/file\x7f.zip",
    "/pub/ASUS/mb/BIOS/file%7f.zip",
    "/pub/ASUS/mb/BIOS/",
])
def test_asus_download_path_rejects_unsafe_or_ambiguous_paths(value):
    with pytest.raises(ValueError) as exc:
        fetch._asus_download_path(value, "2402")

    assert exc.value.args == (
        "ASUS BIOS 2402 has an unexpected download path",
    )


def test_asus_path_prefix_parser_routes_global_through_download_path_policy():
    document = json.loads(_metadata())
    document["Result"]["Obj"][0]["Files"][0]["DownloadUrl"]["Global"] = (
        "/pub/ASUS/mb/BIOS/%252e%252e/file.zip"
    )

    with pytest.raises(ValueError) as exc:
        fetch.parse_asus_metadata(
            json.dumps(document).encode(),
            "ROG STRIX X870E-E GAMING WIFI",
            "rog strix x870e-e gaming wifi",
        )

    assert exc.value.args == (
        "ASUS BIOS 2402 has an unexpected download path",
    )


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


def _release(data: bytes, *, checksum=True) -> fetch.Release:
    release = _records()[1][0]
    digest = hashlib.sha256(data).hexdigest() if checksum else None
    return replace(release, publisher_sha256=digest)


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


def _fetch_inputs_for_model(model: str):
    image, artifact, metadata = _fetch_inputs()
    document = json.loads(metadata)
    document["Result"]["Model"] = model
    return image, artifact, json.dumps(document).encode()


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


@pytest.mark.parametrize(
    "model,stable,older,beta,leading_zero,uppercase_mb",
    REPRESENTATIVE_FIXTURES,
)
def test_representative_metadata_fixtures_resolve_dynamically(
        model, stable, older, beta, leading_zero, uppercase_mb):
    path = _fixture_path(model)
    document = json.loads(path.read_bytes())
    requested_model = f"  {model.swapcase()}  "
    product_id, metadata_url = fetch.asus_metadata_url(requested_model)
    product, releases = fetch.parse_asus_metadata(
        path.read_bytes(), requested_model, product_id)
    query = parse_qs(urlsplit(metadata_url).query)

    assert query["model"] == [model.casefold()]
    assert product == fetch.Product(
        "ASUS",
        model,
        model.casefold(),
        "https://www.asus.com/support/download-center/",
    )
    assert fetch.select_release(releases, stable).beta is False
    assert fetch.select_release(releases, older).beta is False
    if beta is not None:
        assert fetch.select_release(releases, beta).beta is True
    if leading_zero is not None:
        assert fetch.select_release(releases, leading_zero).version == leading_zero
        with pytest.raises(ValueError, match="no BIOS release exactly matching"):
            fetch.select_release(releases, leading_zero.lstrip("0"))
    if uppercase_mb is not None:
        assert "/ASUS/MB/BIOS/" in fetch.select_release(
            releases, uppercase_mb).download_url
    assert not hasattr(fetch, "SUPPORTED_MODELS")
    assert document["Result"]["Model"] == product.model


@pytest.mark.parametrize(
    "model,_stable,_older,_beta,_leading_zero,_uppercase_mb",
    REPRESENTATIVE_FIXTURES,
)
def test_representative_fixture_provenance_is_valid(
        model, _stable, _older, _beta, _leading_zero, _uppercase_mb):
    document = json.loads(_fixture_path(model).read_bytes())
    provenance = document["_fixture"]
    source = urlsplit(provenance["source"])
    retrieved = datetime.date.fromisoformat(provenance["retrieved"])

    assert (source.scheme, source.netloc, source.path) == (
        "https", "www.asus.com", "/support/webapi/ProductV2/GetPDBIOS")
    assert parse_qs(source.query)["model"] == [model.casefold()]
    assert retrieved <= datetime.date.today()
    assert "Sanitized to parser-consumed fields" in provenance["note"]


def test_readme_automatic_retrieval_examples_match_tracked_evidence():
    root = Path(__file__).parents[1]
    readme_columns = (
        "Model",
        "Endpoint verification date",
        "Smoke version",
        "Checksum target",
        "DMI status",
    )
    evidence_columns = (
        "Model",
        "Endpoint verification date",
        "Smoke version",
        "Release date",
        "Final host",
        "Artifact bytes",
        "Artifact SHA-256",
        "Image bytes",
        "Image file SHA-256",
        "Image payload SHA-256",
        "Settings",
        "Checksum target",
        "DMI status",
    )

    def table_after(path, marker, columns):
        lines = path.read_text(encoding="utf-8").splitlines()
        marker_index = next(
            index for index, line in enumerate(lines) if line.strip() == marker
        )
        marker_level = len(marker) - len(marker.lstrip("#"))
        section_end = next(
            (
                index
                for index in range(marker_index + 1, len(lines))
                if re.fullmatch(r"#{1,%d} .+" % marker_level, lines[index].strip())
            ),
            len(lines),
        )
        table_index = next(
            index
            for index in range(marker_index + 1, section_end)
            if lines[index].strip().startswith("|")
        )

        def cells(line):
            values = [value.strip() for value in line.strip().strip("|").split("|")]
            return [
                value[1:-1] if value.startswith("`") and value.endswith("`") else value
                for value in values
            ]

        assert tuple(cells(lines[table_index])) == columns
        separators = cells(lines[table_index + 1])
        assert len(separators) == len(columns)
        assert all(re.fullmatch(r":?-{3,}:?", value) for value in separators)

        rows = []
        for line in lines[table_index + 2:]:
            if not line.strip().startswith("|"):
                break
            values = cells(line)
            assert len(values) == len(columns)
            rows.append(dict(zip(columns, values, strict=True)))
        return rows

    readme_rows = table_after(
        root / "README.md",
        "### Automatic retrieval examples",
        readme_columns,
    )
    evidence_rows = table_after(
        root / "docs" / "release-checklist.md",
        "## Post-1.0 coverage",
        evidence_columns,
    )
    fixture_models = [values[0] for values in REPRESENTATIVE_FIXTURES]
    readme_models = [row["Model"] for row in readme_rows]
    evidence_models = [row["Model"] for row in evidence_rows]
    evidence_by_model = {row["Model"]: row for row in evidence_rows}

    assert len(readme_models) == len(set(readme_models))
    assert len(evidence_models) == len(set(evidence_models))
    assert readme_models == fixture_models
    assert evidence_models == fixture_models
    assert readme_rows == [
        {column: evidence_by_model[model][column] for column in readme_columns}
        for model in fixture_models
    ]
    assert {row["Checksum target"] for row in readme_rows} <= {"artifact", "image"}
    assert {row["DMI status"] for row in readme_rows} <= {
        "verified",
        "override-only",
    }


@pytest.mark.parametrize(
    "model,_stable,_older,_beta,_leading_zero,_uppercase_mb",
    REPRESENTATIVE_FIXTURES,
)
def test_materially_different_metadata_echo_fails(
        model, _stable, _older, _beta, _leading_zero, _uppercase_mb):
    document = json.loads(_fixture_path(model).read_bytes())
    document["Result"]["Model"] = f"{model} II"
    product_id, _url = fetch.asus_metadata_url(model)

    with pytest.raises(ValueError, match="returned product"):
        fetch.parse_asus_metadata(
            json.dumps(document).encode(), model, product_id)


def test_exact_older_and_beta_releases_are_selected_from_offline_metadata():
    product, releases = _records()

    older = fetch.select_release(releases, "1701")
    beta = fetch.select_release(releases, " 2401 ")

    assert len(releases) == 4
    assert older.product_id == product.product_id
    assert older.download_url == (
        "https://dlcdnets.asus.com/pub/ASUS/mb/BIOS/"
        "ROG-STRIX-X870E-E-GAMING-WIFI-ASUS-1701.zip"
    )
    assert beta.beta is True
    assert beta.publisher_sha256 == (
        "d26c830a48def3bbb741aba75e1563b76b712f92b609f13f2bdb1079159d17d5"
    )


def test_arbitrary_exact_asus_retail_model_produces_identity_request():
    request = fetch.resolve_identity(
        {},
        manufacturer="ASUS",
        model="ProArt X870E-CREATOR WIFI",
        bios_version="1001",
    )

    assert isinstance(request, fetch.IdentityRequest)
    assert request.requested_identity == fetch.Identity(
        "ASUS", "ProArt X870E-CREATOR WIFI", "1001")


@pytest.mark.parametrize(
    "alias", ["ASUS", "asus", "ASUSTeK COMPUTER INC.", "asustek computer inc"]
)
def test_asus_manufacturer_aliases_normalize(alias):
    request = fetch.resolve_identity(
        {}, manufacturer=alias, model="PRIME X870-P WIFI", bios_version="0812")

    assert request.requested_identity.manufacturer == "ASUS"


def test_non_asus_manufacturer_fails_before_network_access():
    with pytest.raises(ValueError, match="only ASUS"):
        fetch.resolve_identity(
            {}, manufacturer="Gigabyte", model="X870 AORUS ELITE", bios_version="F3")


def test_dmi_identity_resolves_the_installed_release_without_rewriting_facts():
    product, releases = _records()
    request = fetch.resolve_identity({
        "sys_vendor": " ASUSTeK  COMPUTER INC. ",
        "product_name": "System Product Name",
        "board_vendor": "ASUSTeK COMPUTER INC.",
        "board_name": " ROG  STRIX X870E-E GAMING WIFI ",
        "board_version": " Rev 1.xx ",
        "bios_version": " 2402 ",
    })
    selection = fetch.confirm_identity(request, product)

    assert request.detected_identity == {
        "sys_vendor": "ASUSTeK COMPUTER INC.",
        "board_vendor": "ASUSTeK COMPUTER INC.",
        "board_name": product.model,
        "board_version": "Rev 1.xx",
        "bios_version": "2402",
    }
    assert request.overrides == {}
    assert request.requested_identity == fetch.Identity(
        "ASUS", product.model, "2402", "Rev 1.xx")
    assert selection.selected_identity == request.requested_identity
    assert fetch.resolve_release(selection, releases).version == "2402"


def test_explicit_identity_works_when_dmi_is_missing_or_placeholder():
    request = fetch.resolve_identity(
        {"sys_vendor": "System manufacturer", "board_name": "Default string"},
        manufacturer="asus", model="rog strix x870e-e gaming wifi",
        bios_version="0706", revision=" 1.0 ",
    )

    assert request.detected_identity == {}
    assert request.overrides == {
        "manufacturer": "ASUS",
        "model": "rog strix x870e-e gaming wifi",
        "revision": "1.0",
        "bios_version": "0706",
    }
    assert request.requested_identity.bios_version == "0706"


def test_confirm_identity_uses_canonical_model_without_rewriting_request():
    request = fetch.resolve_identity(
        FETCH_DMI, manufacturer="asustek computer inc.",
        model="rog strix x870e-e gaming wifi")
    detected = request.detected_identity
    overrides = request.overrides

    selection = fetch.confirm_identity(request, _product())

    assert selection.detected_identity is detected
    assert selection.overrides is overrides
    assert selection.selected_identity == fetch.Identity(
        "ASUS", "ROG STRIX X870E-E GAMING WIFI", "2402", "Rev 1.xx")


def test_oem_board_identity_requires_complete_explicit_selection():
    dmi = {
        "sys_vendor": "Dell Inc.", "product_name": "Alienware",
        "board_vendor": "ASUSTeK COMPUTER INC.",
        "board_name": "ROG STRIX X870E-E GAMING WIFI", "bios_version": "2402",
    }
    with pytest.raises(ValueError, match="system vendor.*differs from board vendor"):
        fetch.resolve_identity(dmi)

    request = fetch.resolve_identity(
        dmi, manufacturer="ASUS", model="ROG STRIX X870E-E GAMING WIFI",
        bios_version="2402")
    assert request.requested_identity.manufacturer == "ASUS"


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
    request = fetch.resolve_identity(
        {}, manufacturer="ASUS", model="ROG STRIX X870E-E GAMING WIFI",
        bios_version="2402")
    selection = fetch.confirm_identity(request, _product())
    other = replace(_records()[1][0], product_id="another product")

    with pytest.raises(ValueError, match="different product"):
        fetch.resolve_release(selection, [other])


def test_vendor_reads_use_reviewed_hosts_limits_and_one_shared_budget(monkeypatch):
    request = fetch.resolve_identity(
        {}, manufacturer="ASUS", model="ROG STRIX X870E-E GAMING WIFI",
        bios_version="2402")
    budget = fetch.safety.HttpBudget()
    calls = []

    def read_https(url, limit, hosts, *, stage, budget):
        calls.append((url, limit, hosts, stage, budget))
        data = _metadata() if stage == "ASUS metadata" else b"artifact"
        return fetch.safety.HttpResult(data, url)

    monkeypatch.setattr(fetch.safety, "read_https", read_https)
    product, releases = fetch.fetch_releases(request, budget)
    artifact = fetch.download_artifact(releases[0], budget)

    assert product.model == "ROG STRIX X870E-E GAMING WIFI"
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
    assert result.publisher_checksum_target == "artifact"
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
    assert result.publisher_checksum_target == "artifact"
    assert result.settings_count == 1


def test_image_scoped_and_missing_publisher_checksums_are_distinct():
    image = fixtures.build_capsule()
    artifact = _zip(("BIOS.CAP", image))
    image_scoped = replace(
        _release(artifact), publisher_sha256=hashlib.sha256(image).hexdigest())

    verified = fetch.validate_artifact(image_scoped, _artifact(artifact, "update.zip"))
    unavailable = fetch.validate_artifact(
        _release(image, checksum=False), _artifact(image, "BIOS.CAP"))

    assert verified.publisher_checksum_status == "verified"
    assert verified.publisher_checksum_target == "image"
    assert unavailable.publisher_checksum_status == "unavailable"
    assert unavailable.publisher_checksum_target is None


def test_publisher_checksum_matching_neither_scope_fails_before_image_parsing(
        monkeypatch):
    image = fixtures.build_capsule()
    artifact = _zip(("BIOS.CAP", image))
    release = replace(_release(artifact), publisher_sha256="0" * 64)
    monkeypatch.setattr(
        fetch.cap, "parse",
        lambda *_args: pytest.fail("firmware parser called before checksum rejection"))

    with pytest.raises(ValueError) as exc:
        fetch.validate_artifact(release, _artifact(artifact, "update.zip"))

    assert str(exc.value) == "publisher SHA-256 mismatch for artifact and image"


def test_malformed_publisher_checksum_fails_before_image_parsing(monkeypatch):
    release = replace(_records()[1][0], publisher_sha256="bad")
    monkeypatch.setattr(
        fetch.cap, "parse",
        lambda *_args: pytest.fail("firmware parser called before checksum rejection"))

    with pytest.raises(ValueError, match="publisher SHA-256 is malformed"):
        fetch.validate_artifact(release, _artifact(b"not firmware", "BIOS.CAP"))


@pytest.mark.parametrize(("name", "data", "match"), [
    ("BIOS.CAP", b"<!doctype html><html>error</html>", "HTML"),
    ("update.exe", b"MZ", "unsupported BIOS artifact container"),
])
def test_outer_container_validation_precedes_checksum_resolution(
        name, data, match):
    release = replace(_release(data, checksum=False), publisher_sha256="bad")

    with pytest.raises(ValueError, match=match):
        fetch.validate_artifact(release, _artifact(data, name))


@pytest.mark.parametrize(("case", "match"), [
    ("unsafe", "unsafe"),
    ("oversized", "firmware image exceeds"),
])
def test_bounded_zip_validation_precedes_checksum_resolution(case, match):
    image = fixtures.build_capsule()
    if case == "unsafe":
        artifact = _zip(("../BIOS.CAP", image))
    else:
        artifact = _zip(("BIOS.CAP", image))
        artifact = _patch_zip_field(
            artifact, b"PK\x01\x02", 24, fetch.cap.MAX_IMAGE_BYTES + 1)
    release = replace(_release(image, checksum=False), publisher_sha256="bad")

    with pytest.raises(ValueError, match=match):
        fetch.validate_artifact(release, _artifact(artifact, "update.zip"))


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
def test_image_scoped_checksum_does_not_bypass_unsafe_zip_paths(name):
    image = fixtures.build_capsule()
    artifact = _zip((name, image))
    with pytest.raises(ValueError, match="unsafe"):
        fetch.validate_artifact(
            _release(image), _artifact(artifact, "update.zip"))


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

    oversized_image = b"x"
    oversized = _zip(("BIOS.CAP", oversized_image))
    oversized = _patch_zip_field(
        oversized, b"PK\x01\x02", 24, fetch.cap.MAX_IMAGE_BYTES + 1)
    with pytest.raises(ValueError, match="firmware image exceeds"):
        fetch.validate_artifact(
            _release(oversized_image), _artifact(oversized, "update.zip"))

    huge_image = b"x"
    huge = _zip(("BIOS.CAP", huge_image))
    huge = _patch_zip_field(
        huge, b"PK\x01\x02", 24, fetch.MAX_ZIP_UNCOMPRESSED + 1)
    with pytest.raises(ValueError, match="uncompressed limit"):
        fetch.validate_artifact(
            _release(huge_image), _artifact(huge, "update.zip"))


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
        "format_version": 2,
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


def test_fetch_cli_supports_arbitrary_exact_asus_model_with_canonical_provenance(
        tmp_path, monkeypatch):
    canonical_model = "PRO WS X999-SYNTHETIC"
    requested_model = canonical_model.casefold()
    image, artifact, metadata = _fetch_inputs_for_model(canonical_model)
    calls = _fake_fetch_network(monkeypatch, artifact, metadata)
    monkeypatch.setattr(cli.platform, "dmi", lambda: {
        **FETCH_DMI,
        "board_name": requested_model,
    })
    output = tmp_path / "firmware"

    result = RUNNER.invoke(cli.app, ["fetch", "--output", str(output), "--json"])

    assert result.exit_code == 0, result.output
    provenance = json.loads((output / "fetch.json").read_text())
    assert provenance["selected_identity"]["model"] == canonical_model
    assert (output / "BIOS.CAP").read_bytes() == image
    assert [call[3] for call in calls] == ["ASUS metadata", "ASUS BIOS artifact"]
    assert parse_qs(urlsplit(calls[0][0]).query)["model"] == [requested_model]


def test_fetch_cli_rejects_metadata_echo_mismatch_before_artifact(
        tmp_path, monkeypatch):
    requested_model = "PRO WS X999-SYNTHETIC"
    _image, artifact, metadata = _fetch_inputs_for_model("DIFFERENT MODEL")
    calls = _fake_fetch_network(monkeypatch, artifact, metadata)
    monkeypatch.setattr(cli.platform, "dmi", lambda: {
        **FETCH_DMI,
        "board_name": requested_model,
    })
    output = tmp_path / "firmware"

    result = RUNNER.invoke(cli.app, ["fetch", "--output", str(output)])

    assert result.exit_code == 1
    assert "returned product 'DIFFERENT MODEL'" in result.output
    assert [call[3] for call in calls] == ["ASUS metadata"]
    assert not output.exists()


def test_fetch_cli_rejects_non_asus_identity_before_network(monkeypatch):
    monkeypatch.setattr(cli.platform, "dmi", lambda: {
        **FETCH_DMI,
        "sys_vendor": "Micro-Star International Co., Ltd.",
        "board_vendor": "Micro-Star International Co., Ltd.",
    })
    monkeypatch.setattr(fetch.safety, "read_https", lambda *_args, **_kwargs: pytest.fail(
        "network used for a non-ASUS identity"))

    result = RUNNER.invoke(cli.app, ["fetch", "--resolve-only"])

    assert result.exit_code == 1
    assert "supports only ASUS" in result.output


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
    monkeypatch.setattr(cli, "_output_dir", lambda *_args: pytest.fail(
        "resolve-only created an output directory"))
    monkeypatch.setattr(cli, "_write_output", lambda *_args: pytest.fail(
        "resolve-only wrote output"))

    result = RUNNER.invoke(cli.app, ["fetch", "--resolve-only", "--json"])

    assert result.exit_code == 0, result.output
    document = json.loads(result.stdout)
    assert document["operation"] == "resolve"
    assert document["release"]["version"] == "2402"
    assert document["publisher_checksum"]["status"] == "advertised"
    assert not {"artifact", "image", "image_path", "manifest_path", "validation"} & document.keys()
    assert [call[3] for call in calls] == ["ASUS metadata"]
    assert list(tmp_path.iterdir()) == []


def test_fetch_uses_validated_snapshot_without_reading_local_dmi(
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
    assert match in ANSI.sub("", result.output)


def test_fetch_help_exposes_the_public_contract():
    result = RUNNER.invoke(cli.app, ["fetch", "--help"])
    assert result.exit_code == 0, result.output
    output = ANSI.sub("", result.stdout)
    for option in ("--output", "--snapshot", "--manufacturer", "--model", "--revision",
                   "--bios-version", "--resolve-only", "--json"):
        assert option in output


def test_fetch_accepts_complete_explicit_target_without_dmi(monkeypatch):
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


def test_fetch_cli_refuses_nonempty_output_before_network(tmp_path, monkeypatch):
    output = tmp_path / "firmware"
    output.mkdir()
    sentinel = output / "keep"
    sentinel.write_text("unchanged")
    monkeypatch.setattr(fetch, "fetch_releases", lambda *_args: pytest.fail("network used"))

    result = RUNNER.invoke(cli.app, ["fetch", "--output", str(output)])

    assert result.exit_code == 1
    assert "not empty" in result.output
    assert sentinel.read_text() == "unchanged"


def test_fetch_cli_refuses_symlinked_or_reparse_output_before_network(
        tmp_path, monkeypatch):
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


def test_fetch_cli_reports_partial_output_when_manifest_write_fails(
        tmp_path, monkeypatch):
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
    request = fetch.resolve_identity(FETCH_DMI, bios_version="2401")
    selection = fetch.confirm_identity(request, _product())
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


def test_format_two_resolution_document_checksum_contract():
    image = fixtures.build_capsule()
    request = fetch.resolve_identity(FETCH_DMI, bios_version="2401")
    selection = fetch.confirm_identity(request, _product())
    release = replace(_release(image), version="2401")

    advertised = fetch.resolution_document(
        selection, release, "local", "1.0.0")
    unavailable = fetch.resolution_document(
        selection, replace(release, publisher_sha256=None), "local", "1.0.0")

    assert advertised["publisher_checksum"] == {
        "status": "advertised",
        "algorithm": "sha256",
        "expected": release.publisher_sha256,
        "target": "undetermined",
    }
    assert advertised["format_version"] == 2
    assert unavailable["publisher_checksum"] == {"status": "unavailable"}


@pytest.mark.parametrize("target", ["artifact", "image"])
def test_format_two_provenance_checksum_contract_uses_validated_target(target):
    image = fixtures.build_capsule()
    artifact_data = image if target == "artifact" else _zip(("BIOS.CAP", image))
    artifact_name = "BIOS.CAP" if target == "artifact" else "update.zip"
    artifact = _artifact(artifact_data, artifact_name)
    request = fetch.resolve_identity(FETCH_DMI, bios_version="2401")
    selection = fetch.confirm_identity(request, _product())
    release = replace(
        _release(artifact_data),
        version="2401",
        publisher_sha256=hashlib.sha256(
            artifact_data if target == "artifact" else image).hexdigest(),
    )
    validated = fetch.validate_artifact(release, artifact)

    provenance = fetch.provenance_document(
        selection, release, artifact, validated, "local", "1.0.0",
        "2026-09-10T00:00:00Z")
    checksum = provenance["publisher_checksum"]

    assert validated.publisher_checksum_target == target
    assert checksum == {
        "status": "verified",
        "algorithm": "sha256",
        "expected": release.publisher_sha256,
        "target": target,
    }
    assert provenance["format_version"] == 2
    assert checksum["target"] != "undetermined"


def test_format_two_provenance_unavailable_checksum_contract():
    image = fixtures.build_capsule()
    artifact = _artifact(image, "BIOS.CAP")
    request = fetch.resolve_identity(FETCH_DMI, bios_version="2401")
    selection = fetch.confirm_identity(request, _product())
    release = replace(_release(image, checksum=False), version="2401")
    validated = fetch.validate_artifact(release, artifact)

    provenance = fetch.provenance_document(
        selection, release, artifact, validated, "local", "1.0.0",
        "2026-09-10T00:00:00Z")

    assert provenance["format_version"] == 2
    assert provenance["publisher_checksum"] == {"status": "unavailable"}


@pytest.mark.parametrize(("checksum_present", "status", "target"), [
    (False, "unavailable", None),
    (True, "advertised", "undetermined"),
    (True, "verified", "artifact"),
    (True, "verified", "image"),
])
def test_format_two_publisher_checksum_accepts_every_valid_state_tuple(
        checksum_present, status, target):
    release = _release(fixtures.build_capsule(), checksum=checksum_present)

    checksum = fetch._publisher_checksum(release, status, target)

    if not checksum_present:
        assert checksum == {"status": "unavailable"}
    else:
        assert checksum == {
            "status": status,
            "algorithm": "sha256",
            "expected": release.publisher_sha256,
            "target": target,
        }


@pytest.mark.parametrize(("checksum_present", "status", "target"), [
    (False, "advertised", "undetermined"),
    (False, "verified", "artifact"),
    (True, "unavailable", None),
    (True, "advertised", "artifact"),
    (True, "verified", "undetermined"),
    (True, "verified", None),
])
def test_format_two_publisher_checksum_rejects_impossible_state_tuples(
        checksum_present, status, target):
    release = _release(fixtures.build_capsule(), checksum=checksum_present)

    with pytest.raises(ValueError, match="invalid publisher checksum state"):
        fetch._publisher_checksum(release, status, target)


def test_missing_and_ambiguous_releases_fail_instead_of_selecting_latest():
    _, releases = _records()
    with pytest.raises(ValueError, match="no BIOS release exactly matching"):
        fetch.select_release(releases, "9999")

    conflict = replace(releases[0], download_url=releases[0].download_url + ".other")
    with pytest.raises(ValueError, match="multiple BIOS releases"):
        fetch.select_release([*releases, conflict], "2402")


def test_identical_records_are_deduplicated():
    document = json.loads(_metadata())
    files = document["Result"]["Obj"][0]["Files"]
    files.append(dict(files[0]))

    _product, releases = fetch.parse_asus_metadata(
        json.dumps(document).encode(),
        "ROG STRIX X870E-E GAMING WIFI",
        "rog strix x870e-e gaming wifi",
    )

    assert len([release for release in releases if release.version == "2402"]) == 1


def test_non_success_metadata_names_clean_model_and_explains_recovery():
    document = json.loads(_metadata())
    document["Status"] = "ERROR"

    with pytest.raises(ValueError) as exc:
        fetch.parse_asus_metadata(
            json.dumps(document).encode(),
            "  ROG   STRIX X870E-E UNKNOWN  ",
            "rog strix x870e-e unknown",
        )

    assert exc.value.args == (
        "ASUS metadata did not recognize exact model "
        "'ROG STRIX X870E-E UNKNOWN'; check ASUS spelling or pass the exact "
        "retail model with --model",
    )


@pytest.mark.parametrize("mutation, match", [
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
    document = json.loads(_metadata())
    mutation(document)

    with pytest.raises(ValueError, match=match):
        fetch.parse_asus_metadata(
            json.dumps(document).encode(),
            "ROG STRIX X870E-E GAMING WIFI",
            "rog strix x870e-e gaming wifi",
        )

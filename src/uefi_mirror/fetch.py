"""Pure vendor metadata and release selection for BIOS image retrieval."""

import datetime
import hashlib
import hmac
import io
import json
import ntpath
import stat
import zipfile
import zlib
from collections.abc import Mapping
from dataclasses import dataclass
from urllib.parse import unquote, urlencode, urlsplit

from . import safety
from .firmware import cap, firmware_volume
from .schema import builder

ASUS_METADATA_ENDPOINT = "https://www.asus.com/support/webapi/ProductV2/GetPDBIOS"
ASUS_ARTIFACT_ORIGIN = "https://dlcdnets.asus.com"
ASUS_SUPPORT_URL = "https://www.asus.com/support/download-center/"
ASUS_METADATA_HOSTS = frozenset({"www.asus.com"})
ASUS_ARTIFACT_HOSTS = frozenset({"dlcdnets.asus.com"})
MAX_ZIP_ENTRIES = 128
MAX_ZIP_UNCOMPRESSED = 256 << 20
FETCH_FORMAT_VERSION = 1
_IMAGE_SUFFIXES = frozenset({".cap", ".rom", ".bin", ".fd"})
_ZIP_COMPRESSION = frozenset({zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED})

_VENDOR_ALIASES = {
    "asus": "ASUS",
    "asustek computer inc": "ASUS",
    "asustek computer inc.": "ASUS",
}

_DMI_FIELDS = (
    "sys_vendor", "product_name", "board_vendor", "board_name",
    "board_version", "bios_vendor", "bios_version", "bios_date", "bios_release",
)
_DMI_PLACEHOLDERS = frozenset({
    "base board product name",
    "default string",
    "n/a",
    "none",
    "not applicable",
    "not specified",
    "oem",
    "system manufacturer",
    "system product name",
    "to be filled by o.e.m.",
    "to be filled by oem",
    "unknown",
})


@dataclass(frozen=True)
class Product:
    manufacturer: str
    model: str
    product_id: str
    support_url: str


@dataclass(frozen=True)
class Release:
    product_id: str
    version: str
    date: str
    beta: bool
    download_url: str
    publisher_sha256: str | None
    publisher_checksum_target: str = "artifact"


@dataclass(frozen=True)
class Identity:
    manufacturer: str
    model: str
    bios_version: str
    revision: str | None = None


@dataclass(frozen=True)
class IdentityRequest:
    detected_identity: dict[str, str]
    overrides: dict[str, str]
    requested_identity: Identity


@dataclass(frozen=True)
class IdentitySelection:
    detected_identity: dict[str, str]
    overrides: dict[str, str]
    selected_identity: Identity
    product: Product


@dataclass(frozen=True)
class ValidatedImage:
    image_name: str
    image_data: bytes
    artifact_size: int
    artifact_sha256: str
    publisher_checksum_status: str
    capsule: cap.Capsule
    settings_count: int
    parser_warnings: tuple[str, ...]


def _text(value: object) -> str:
    if not isinstance(value, str):
        return ""
    return " ".join(value.split())


def asus_metadata_url(model: str) -> tuple[str, str]:
    """Return the normalized product ID and reviewed ASUS metadata URL."""
    cleaned = _text(model)
    if not cleaned:
        raise ValueError("ASUS model must not be blank")
    product_id = cleaned.casefold()
    query = urlencode({
        "website": "global",
        "model": product_id,
        "pdhashedid": "",
        "pdid": "99999",
        "cpu": "",
        "siteID": "www",
        "sitelang": "",
    })
    return product_id, f"{ASUS_METADATA_ENDPOINT}?{query}"


def _vendor(value: object) -> str:
    cleaned = _text(value)
    return _VENDOR_ALIASES.get(cleaned.casefold(), cleaned)


def _dmi_text(value: object) -> str:
    cleaned = _text(value)
    return "" if cleaned.casefold() in _DMI_PLACEHOLDERS else cleaned


def _override(name: str, value: str | None) -> str | None:
    if value is None:
        return None
    cleaned = _text(value)
    if not cleaned:
        raise ValueError(f"--{name} cannot be blank")
    return _vendor(cleaned) if name == "manufacturer" else cleaned


def resolve_identity(
    dmi: Mapping[str, object], *, manufacturer: str | None = None,
    model: str | None = None, revision: str | None = None,
    bios_version: str | None = None,
) -> IdentityRequest:
    """Resolve the requested ASUS identity without changing detected DMI facts."""
    detected = {key: value for key in _DMI_FIELDS
                if (value := _dmi_text(dmi.get(key)))}
    supplied = {
        "manufacturer": _override("manufacturer", manufacturer),
        "model": _override("model", model),
        "revision": _override("revision", revision),
        "bios_version": _override("bios-version", bios_version),
    }
    overrides = {key: value for key, value in supplied.items() if value is not None}

    system_vendor = _vendor(detected.get("sys_vendor", ""))
    board_vendor = _vendor(detected.get("board_vendor", ""))
    if (system_vendor and board_vendor and system_vendor.casefold() != board_vendor.casefold()
            and not all(supplied[key] is not None
                        for key in ("manufacturer", "model", "bios_version"))):
        raise ValueError(
            "automatic motherboard identity is ambiguous because system vendor "
            f"{system_vendor!r} differs from board vendor {board_vendor!r}; pass "
            "--manufacturer, --model, and --bios-version"
        )

    detected_model = detected.get("board_name") or detected.get("product_name", "")
    if (supplied["model"] is not None and detected_model
            and supplied["model"].casefold() != detected_model.casefold()
            and supplied["bios_version"] is None):
        raise ValueError(
            "--bios-version is required when --model selects a different product"
        )

    selected_manufacturer = supplied["manufacturer"] or board_vendor or system_vendor
    selected_model = supplied["model"] or detected_model
    selected_version = supplied["bios_version"] or detected.get("bios_version", "")
    missing = [flag for flag, value in (
        ("--manufacturer", selected_manufacturer),
        ("--model", selected_model),
        ("--bios-version", selected_version),
    ) if not value]
    if missing:
        raise ValueError(f"missing BIOS identity; pass {', '.join(missing)}")
    if selected_manufacturer != "ASUS":
        raise ValueError(
            f"BIOS fetch supports only ASUS, not {selected_manufacturer!r}")

    identity = Identity(
        manufacturer=selected_manufacturer,
        model=selected_model,
        bios_version=selected_version,
        revision=supplied["revision"] or detected.get("board_version") or None,
    )
    return IdentityRequest(detected, overrides, identity)


def confirm_identity(request: IdentityRequest, product: Product) -> IdentitySelection:
    """Confirm a request with the canonical product returned by ASUS."""
    identity = Identity(
        manufacturer=product.manufacturer,
        model=product.model,
        bios_version=request.requested_identity.bios_version,
        revision=request.requested_identity.revision,
    )
    return IdentitySelection(
        request.detected_identity, request.overrides, identity, product)


def _mapping(value: object, where: str) -> Mapping[str, object]:
    if not isinstance(value, dict):
        raise ValueError(f"ASUS metadata {where} must be an object")
    return value


def _required_text(record: Mapping[str, object], field: str) -> str:
    value = _text(record.get(field))
    if not value:
        raise ValueError(f"ASUS BIOS record has invalid {field}")
    return value


def _asus_download_path(value: object, version: str) -> str:
    message = f"ASUS BIOS {version} has an unexpected download path"
    if not isinstance(value, str) or not value:
        raise ValueError(message)
    try:
        parsed = urlsplit(value)
        decoded = unquote(parsed.path, errors="strict")
    except (UnicodeDecodeError, ValueError) as exc:
        raise ValueError(message) from exc
    components = decoded.split("/")
    if (
        parsed.scheme
        or parsed.netloc
        or parsed.query
        or parsed.fragment
        or parsed.path != value
        or len(components) < 6
        or tuple(part.casefold() for part in components[:5])
        != ("", "pub", "asus", "mb", "bios")
        or "\\" in decoded
        or any(ord(char) < 32 or 0x7f <= ord(char) <= 0x9f
               for char in decoded)
        or any(part in ("", ".", "..") for part in components[5:])
    ):
        raise ValueError(message)
    return value


def parse_asus_metadata(
        data: bytes, requested_model: str,
        product_id: str) -> tuple[Product, list[Release]]:
    """Parse ASUS GetPDBIOS metadata and confirm the exact requested model."""
    try:
        root = _mapping(json.loads(data), "root")
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValueError(f"invalid ASUS metadata JSON: {exc}") from exc
    if root.get("Status") != "SUCCESS":
        raise ValueError("ASUS metadata request did not report success")
    result = _mapping(root.get("Result"), "Result")
    returned_model = _required_text(result, "Model")
    expected_model = _text(requested_model)
    if returned_model.casefold() != expected_model.casefold():
        raise ValueError(
            f"ASUS metadata returned product {returned_model!r}, "
            f"expected {expected_model!r}"
        )
    product = Product("ASUS", returned_model, product_id, ASUS_SUPPORT_URL)
    categories = result.get("Obj")
    if not isinstance(categories, list):
        raise ValueError("ASUS metadata Result.Obj must be an array")
    bios_categories = []
    for item in categories:
        category = _mapping(item, "Result.Obj entry")
        if _required_text(category, "Name").casefold() == "bios":
            bios_categories.append(category)
    if len(bios_categories) != 1:
        raise ValueError(f"ASUS metadata contains {len(bios_categories)} BIOS categories")
    files = bios_categories[0].get("Files")
    if not isinstance(files, list):
        raise ValueError("ASUS metadata BIOS.Files must be an array")

    releases: list[Release] = []
    for item in files:
        record = _mapping(item, "BIOS record")
        version = _required_text(record, "Version")
        date = _required_text(record, "ReleaseDate")
        try:
            datetime.datetime.strptime(date, "%Y/%m/%d")
        except ValueError as exc:
            raise ValueError(f"ASUS BIOS record has invalid ReleaseDate: {date!r}") from exc
        stable = record.get("IsRelease")
        if stable not in ("0", "1"):
            raise ValueError(f"ASUS BIOS {version} has invalid IsRelease")
        urls = _mapping(record.get("DownloadUrl"), f"BIOS {version} DownloadUrl")
        path = _asus_download_path(urls.get("Global"), version)
        raw_checksum = record.get("sha256", "")
        if not isinstance(raw_checksum, str):
            raise ValueError(f"ASUS BIOS {version} has an invalid SHA-256")
        checksum = _text(raw_checksum) or None
        if checksum is not None:
            try:
                valid_checksum = len(checksum) == 64 and len(bytes.fromhex(checksum)) == 32
            except ValueError:
                valid_checksum = False
            if not valid_checksum:
                raise ValueError(f"ASUS BIOS {version} has an invalid SHA-256")
            checksum = checksum.lower()
        release = Release(
            product_id=product.product_id,
            version=version,
            date=date,
            beta=stable == "0",
            download_url=ASUS_ARTIFACT_ORIGIN + path,
            publisher_sha256=checksum,
        )
        if release not in releases:
            releases.append(release)
    return product, releases


def fetch_releases(
        request: IdentityRequest,
        budget: safety.HttpBudget) -> tuple[Product, list[Release]]:
    model = request.requested_identity.model
    product_id, metadata_url = asus_metadata_url(model)
    response = safety.read_https(
        metadata_url, safety.MAX_METADATA_BYTES, ASUS_METADATA_HOSTS,
        stage="ASUS metadata", budget=budget)
    return parse_asus_metadata(response.data, model, product_id)


def download_artifact(release: Release, budget: safety.HttpBudget) -> safety.HttpResult:
    return safety.read_https(
        release.download_url, safety.MAX_ARTIFACT_BYTES, ASUS_ARTIFACT_HOSTS,
        stage="ASUS BIOS artifact", budget=budget)


def _image_suffix(name: str) -> str:
    return "." + name.rsplit(".", 1)[-1].casefold() if "." in name else ""


def _safe_image_name(name: str) -> str:
    if (not safety.safe_component(name) or not name.isprintable()
            or name.casefold() == "fetch.json"):
        raise ValueError(f"unsafe firmware image filename: {name!r}")
    return name


def _url_filename(url: str) -> str:
    try:
        name = unquote(urlsplit(url).path.rsplit("/", 1)[-1], errors="strict")
    except (UnicodeDecodeError, ValueError) as exc:
        raise ValueError("artifact URL has an invalid filename") from exc
    return _safe_image_name(name)


def _zip_path(info: zipfile.ZipInfo) -> tuple[str, bool]:
    original = info.orig_filename
    if not isinstance(original, str) or "\x00" in original:
        raise ValueError("ZIP contains an invalid member name")
    normalized = "/".join(original.split("\\"))
    is_dir = normalized.endswith("/")
    path = normalized.rstrip("/") if is_dir else normalized
    drive, _tail = ntpath.splitdrive(original)
    parts = path.split("/")
    if (drive or normalized.startswith("/") or not path
            or any(not safety.safe_component(part) for part in parts)):
        raise ValueError(f"ZIP contains unsafe member path: {original!r}")
    return "/".join(parts), is_dir


def _zip_image(data: bytes) -> tuple[str, bytes]:
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            infos = archive.infolist()
            if len(infos) > MAX_ZIP_ENTRIES:
                raise ValueError(f"ZIP exceeds the {MAX_ZIP_ENTRIES} entry limit")
            total = sum(info.file_size for info in infos)
            if total > MAX_ZIP_UNCOMPRESSED:
                raise ValueError(
                    f"ZIP exceeds the {MAX_ZIP_UNCOMPRESSED} byte uncompressed limit")

            seen: set[str] = set()
            candidates: list[tuple[zipfile.ZipInfo, str]] = []
            for info in infos:
                path, is_dir = _zip_path(info)
                key = path.casefold()
                if key in seen:
                    raise ValueError(f"ZIP contains duplicate member name: {path!r}")
                seen.add(key)
                if info.flag_bits & 1:
                    raise ValueError(f"ZIP contains encrypted member: {path!r}")
                if info.compress_type not in _ZIP_COMPRESSION:
                    raise ValueError(f"ZIP member uses unsupported compression: {path!r}")
                if is_dir:
                    continue
                suffix = _image_suffix(path)
                if suffix == ".zip":
                    raise ValueError(f"nested ZIP archives are unsupported: {path!r}")
                if suffix not in _IMAGE_SUFFIXES:
                    continue
                mode = info.external_attr >> 16
                if stat.S_IFMT(mode) not in (0, stat.S_IFREG):
                    raise ValueError(f"firmware image member is not a regular file: {path!r}")
                name = _safe_image_name(path.rsplit("/", 1)[-1])
                candidates.append((info, name))

            if not candidates:
                raise ValueError("ZIP contains no supported firmware image")
            if len(candidates) != 1:
                names = ", ".join(repr(name) for _info, name in candidates)
                raise ValueError(f"ZIP contains multiple firmware images: {names}")
            info, name = candidates[0]
            if info.file_size > cap.MAX_IMAGE_BYTES:
                raise ValueError(
                    f"firmware image exceeds the {cap.MAX_IMAGE_BYTES} byte limit")
            image = bytearray()
            with archive.open(info) as member:
                while len(image) <= cap.MAX_IMAGE_BYTES:
                    chunk = member.read(min(
                        64 << 10, cap.MAX_IMAGE_BYTES + 1 - len(image)))
                    if not chunk:
                        break
                    image.extend(chunk)
            if len(image) > cap.MAX_IMAGE_BYTES:
                raise ValueError(
                    f"firmware image exceeds the {cap.MAX_IMAGE_BYTES} byte limit")
            return name, bytes(image)
    except (zipfile.BadZipFile, zlib.error, OSError, EOFError,
            NotImplementedError, RuntimeError) as exc:
        raise ValueError(f"invalid or unsupported ZIP artifact: {exc}") from exc


def _check_publisher_checksum(release: Release, data: bytes, target: str) -> str:
    expected = release.publisher_sha256
    if expected is None:
        return "unavailable"
    if (not isinstance(expected, str) or len(expected) != 64
            or any(char not in "0123456789abcdefABCDEF" for char in expected)):
        raise ValueError("publisher SHA-256 is malformed")
    if release.publisher_checksum_target not in ("artifact", "image"):
        raise ValueError("publisher SHA-256 has an unsupported target")
    if release.publisher_checksum_target == target:
        actual = hashlib.sha256(data).hexdigest()
        if not hmac.compare_digest(actual, expected.casefold()):
            raise ValueError(f"publisher SHA-256 mismatch for {target}")
        return "verified"
    return "pending"


def validate_artifact(release: Release, artifact: safety.HttpResult) -> ValidatedImage:
    """Verify and parse a downloaded direct image or ZIP entirely in memory."""
    artifact_sha256 = hashlib.sha256(artifact.data).hexdigest()
    checksum_status = _check_publisher_checksum(release, artifact.data, "artifact")
    artifact_name = _url_filename(artifact.final_url)
    suffix = _image_suffix(artifact_name)
    if artifact.data.lstrip()[:32].lower().startswith((b"<!doctype html", b"<html")):
        raise ValueError("artifact is HTML, not firmware")
    if suffix == ".zip":
        image_name, image_data = _zip_image(artifact.data)
    elif suffix in _IMAGE_SUFFIXES:
        image_name, image_data = artifact_name, artifact.data
    else:
        raise ValueError(f"unsupported BIOS artifact container: {artifact_name!r}")

    image_status = _check_publisher_checksum(release, image_data, "image")
    if image_status == "verified":
        checksum_status = image_status
    try:
        capsule = cap.parse(image_data, image_name)
        schema = builder.build(
            {**capsule.info(), "filename": image_name},
            firmware_volume.walk(capsule.data),
        )
    except (ValueError, RuntimeError) as exc:
        raise ValueError(f"firmware image validation failed: {exc}") from exc
    if not schema.settings:
        raise ValueError("firmware image contains no parseable settings")
    return ValidatedImage(
        image_name=image_name,
        image_data=image_data,
        artifact_size=len(artifact.data),
        artifact_sha256=artifact_sha256,
        publisher_checksum_status=checksum_status,
        capsule=capsule,
        settings_count=len(schema.settings),
        parser_warnings=tuple(schema.warnings),
    )


def _selected_dict(identity: Identity) -> dict[str, object]:
    result: dict[str, object] = {
        "manufacturer": identity.manufacturer,
        "model": identity.model,
        "bios_version": identity.bios_version,
    }
    if identity.revision is not None:
        result["revision"] = identity.revision
    return result


def _release_dict(release: Release) -> dict[str, object]:
    return {
        "product_id": release.product_id,
        "version": release.version,
        "date": release.date,
        "beta": release.beta,
    }


def _publisher_checksum(release: Release, status: str) -> dict[str, str]:
    if release.publisher_sha256 is None:
        return {"status": "unavailable"}
    return {
        "status": status,
        "algorithm": "sha256",
        "expected": release.publisher_sha256,
        "target": release.publisher_checksum_target,
    }


def resolution_document(
    selection: IdentitySelection, release: Release, identity_source: str,
    tool_version: str,
) -> dict[str, object]:
    return {
        "format_version": FETCH_FORMAT_VERSION,
        "operation": "resolve",
        "tool_version": tool_version,
        "identity_source": identity_source,
        "detected_identity": selection.detected_identity,
        "overrides": selection.overrides,
        "selected_identity": _selected_dict(selection.selected_identity),
        "release": _release_dict(release),
        "support_url": selection.product.support_url,
        "download_url": release.download_url,
        "publisher_checksum": _publisher_checksum(release, "advertised"),
    }


def provenance_document(
    selection: IdentitySelection, release: Release, artifact: safety.HttpResult,
    image: ValidatedImage, identity_source: str, tool_version: str, fetched_at: str,
) -> dict[str, object]:
    warnings = list(image.parser_warnings)
    if image.publisher_checksum_status == "unavailable":
        warnings.append("Publisher SHA-256 was unavailable.")
    detected_version = selection.detected_identity.get("bios_version")
    if ("bios_version" in selection.overrides and detected_version
            and detected_version.casefold() != selection.selected_identity.bios_version.casefold()):
        warnings.append(
            f"Selected BIOS version {selection.selected_identity.bios_version!r} differs "
            f"from detected version {detected_version!r}.")
    return {
        "format_version": FETCH_FORMAT_VERSION,
        "tool_version": tool_version,
        "fetched_at": fetched_at,
        "identity_source": identity_source,
        "detected_identity": selection.detected_identity,
        "overrides": selection.overrides,
        "selected_identity": _selected_dict(selection.selected_identity),
        "release": _release_dict(release),
        "support_url": selection.product.support_url,
        "download_url": release.download_url,
        "final_download_url": artifact.final_url,
        "artifact": {
            "size": image.artifact_size,
            "sha256": image.artifact_sha256,
        },
        "publisher_checksum": _publisher_checksum(
            release, image.publisher_checksum_status),
        "image": {
            "filename": image.image_name,
            "size": len(image.image_data),
            "file_sha256": image.capsule.file_sha256,
            "payload_sha256": image.capsule.payload_sha256,
        },
        "validation": {
            "settings_count": image.settings_count,
            "installed_firmware_identity": "unverified",
        },
        "warnings": warnings,
    }


def select_release(releases: list[Release], requested_version: str) -> Release:
    version = _text(requested_version)
    if not version:
        raise ValueError("missing BIOS version")
    matches = [release for release in releases if release.version.casefold() == version.casefold()]
    if not matches:
        raise ValueError(f"ASUS has no BIOS release exactly matching {version!r}")
    if len(matches) != 1:
        raise ValueError(f"ASUS returned multiple BIOS releases exactly matching {version!r}")
    return matches[0]


def resolve_release(selection: IdentitySelection, releases: list[Release]) -> Release:
    if any(release.product_id != selection.product.product_id for release in releases):
        raise ValueError("BIOS metadata contains a release for a different product")
    return select_release(releases, selection.selected_identity.bios_version)

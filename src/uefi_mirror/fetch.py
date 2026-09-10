"""Pure vendor metadata and release selection for BIOS image retrieval."""

import datetime
import json
from collections.abc import Mapping
from dataclasses import dataclass
from urllib.parse import urlencode

ASUS_METADATA_ENDPOINT = "https://www.asus.com/support/webapi/ProductV2/GetPDBIOS"
ASUS_ARTIFACT_ORIGIN = "https://dlcdnets.asus.com"

_VENDOR_ALIASES = {
    "asus": "ASUS",
    "asustek computer inc": "ASUS",
    "asustek computer inc.": "ASUS",
}


@dataclass(frozen=True)
class Product:
    manufacturer: str
    model: str
    product_id: str
    support_url: str

    @property
    def metadata_url(self) -> str:
        query = urlencode({
            "website": "global",
            "model": self.product_id,
            "pdhashedid": "",
            "pdid": "99999",
            "cpu": "",
            "siteID": "www",
            "sitelang": "",
        })
        return f"{ASUS_METADATA_ENDPOINT}?{query}"


@dataclass(frozen=True)
class Release:
    product_id: str
    version: str
    date: str
    beta: bool
    download_url: str
    publisher_sha256: str | None
    publisher_checksum_target: str = "artifact"


_X870E_E = Product(
    manufacturer="ASUS",
    model="ROG STRIX X870E-E GAMING WIFI",
    product_id="rog strix x870e-e gaming wifi",
    support_url=(
        "https://www.asus.com/supportonly/"
        "rog%20strix%20x870e-e%20gaming%20wifi/helpdesk_bios/"
    ),
)
SUPPORTED_MODELS = {("asus", _X870E_E.model.casefold()): _X870E_E}


def _text(value: object) -> str:
    if not isinstance(value, str):
        return ""
    return " ".join(value.split())


def _vendor(value: object) -> str:
    cleaned = _text(value)
    return _VENDOR_ALIASES.get(cleaned.casefold(), cleaned)


def supported_model(manufacturer: str, model: str) -> Product:
    key = (_vendor(manufacturer).casefold(), _text(model).casefold())
    try:
        return SUPPORTED_MODELS[key]
    except KeyError as exc:
        raise ValueError(f"unsupported BIOS fetch target: {manufacturer} {model}".strip()) from exc


def _mapping(value: object, where: str) -> Mapping[str, object]:
    if not isinstance(value, dict):
        raise ValueError(f"ASUS metadata {where} must be an object")
    return value


def _required_text(record: Mapping[str, object], field: str) -> str:
    value = _text(record.get(field))
    if not value:
        raise ValueError(f"ASUS BIOS record has invalid {field}")
    return value


def parse_asus_metadata(data: bytes, product: Product) -> list[Release]:
    """Parse the reviewed ASUS GetPDBIOS response without performing I/O."""
    try:
        root = _mapping(json.loads(data), "root")
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValueError(f"invalid ASUS metadata JSON: {exc}") from exc
    if root.get("Status") != "SUCCESS":
        raise ValueError("ASUS metadata request did not report success")
    result = _mapping(root.get("Result"), "Result")
    returned_model = _required_text(result, "Model")
    if returned_model.casefold() != product.model.casefold():
        raise ValueError(
            f"ASUS metadata returned product {returned_model!r}, expected {product.model!r}"
        )
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
        path = _required_text(urls, "Global")
        if not path.startswith("/pub/ASUS/mb/BIOS/") or path.startswith("//"):
            raise ValueError(f"ASUS BIOS {version} has an unexpected download path")
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
    return releases


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

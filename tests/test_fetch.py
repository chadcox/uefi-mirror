import json
from dataclasses import replace
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

from uefi_mirror import fetch

FIXTURE = Path(__file__).parent / "data" / "asus_x870e_e_bios.json"


def _metadata() -> bytes:
    return FIXTURE.read_bytes()


def _records() -> tuple[fetch.Product, list[fetch.Release]]:
    product = fetch.supported_model("ASUSTeK COMPUTER INC.", "rog strix x870e-e gaming wifi")
    return product, fetch.parse_asus_metadata(_metadata(), product)


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
])
def test_changed_or_unsafe_metadata_shape_fails_closed(mutation, match):
    product, _ = _records()
    document = json.loads(_metadata())
    mutation(document)

    with pytest.raises(ValueError, match=match):
        fetch.parse_asus_metadata(json.dumps(document).encode(), product)

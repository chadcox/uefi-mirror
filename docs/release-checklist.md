# Release checklist

This checklist records the evidence used to declare 1.0. Items marked complete
are covered by the repository or the recorded reference-system validation.

## Completed locally

- [x] Full automated suite passes on Windows.
- [x] Standalone read-only safety suite passes.
- [x] Ruff lint passes.
- [x] Physical Windows UEFI enumeration succeeds with Administrator elevation.
- [x] ASUS ROG Strix X870E-E Gaming WiFi firmware 2402 produces a schema with
  no layout conflicts (the compatibility check reports `unverified`;
  `matched` is reserved for a future identity check).
- [x] All 1552 statically decodable live enum values are declared by the image.
- [x] Dynamic `BootOrder` and `PlatformLang` questions are not treated as scalar
  enum mismatches.
- [x] Schema serialize/reload preserves decoding, visibility, and schema hash.
- [x] Unsupported format versions fail closed; additive unknown fields are
  tolerated.
- [x] Firmware, snapshots, and conventional private export paths are ignored by
  Git.
- [x] The CLI exposes stable `--help` and `--version` discovery interfaces.
- [x] The compatibility policy identifies the intended 1.0 contract.
- [x] The 1.0 hardware scope is explicitly limited to the ASUS ROG Strix
  X870E-E Gaming WiFi with firmware 2402.

## Remaining 1.0 validation

- [x] A real Windows before/after test changed Bluetooth Controller from
  Disabled to Enabled. Raw diff reported reboot-related variable churn; named
  diff isolated that one setting among 2720 compared, with both snapshots
  matching the firmware 2402 schema.
- [x] CI run
  [33925522676](https://github.com/chadcox/uefi-mirror/actions/runs/33925522676)
  passed on Linux and Windows with Python 3.12 and 3.13; both hosted Windows
  firmware smoke steps also completed successfully.
- [x] Version 1.0.0 is set consistently and release notes are written.
- [x] The 1.0.0 wheel and source distribution pass Twine validation; the wheel
  installs into a clean environment and its `--version`, `--help`, and `probe`
  smoke tests pass.

## Post-1.0 coverage

- [x] The opt-in ASUS fetch path was live-smoked on 2026-09-10 against the
  [official support page](https://www.asus.com/supportonly/rog%20strix%20x870e-e%20gaming%20wifi/helpdesk_bios/)
  and its public metadata endpoint for the exact ROG Strix X870E-E Gaming WiFi
  2402 release. The official 19,203,110-byte ZIP
  matched published SHA-256
  `ae633a16f92774ab130203417b770f12fab48f0ea4a9be357f0137ff9205a825`;
  its 33,558,528-byte CAP produced 5,376 settings. Installed-firmware identity
  remained `unverified`, and neither artifact nor host data was committed.

- [x] On 2026-09-19, `pytest -q tests/test_fetch.py` passed all 127 tests, and
  live format-2 resolve/download verification against official ASUS endpoints
  completed for five representative exact releases. Each resolve returned
  operation `resolve`, the canonical requested model/version, an advertised
  SHA-256 with target `undetermined`, and official download host
  `dlcdnets.asus.com`. Each download saved a `0600` CAP and `fetch.json`,
  verified the publisher checksum against the artifact, found settings, and
  left installed-firmware identity `unverified`.

  | Model | Endpoint verification date | Smoke version | Release date | Final host | Artifact bytes | Artifact SHA-256 | Image bytes | Image file SHA-256 | Image payload SHA-256 | Settings | Checksum target | DMI status |
  | --- | --- | ---: | --- | --- | ---: | --- | ---: | --- | --- | ---: | --- | --- |
  | ROG STRIX X870E-E GAMING WIFI | 2026-09-19 | 2402 | 2026/07/15 | `dlcdnets.asus.com` | 19,203,110 | `ae633a16f92774ab130203417b770f12fab48f0ea4a9be357f0137ff9205a825` | 33,558,528 | `73fc809520172630bc2132a7f4e8e4242f25e6c3095fff6641e8688d041d4204` | `4140e3d5c644dafc5c08fe5cb91067f45f18fcb5237575b298723a3d7c9bca1e` | 5,376 | `artifact` | `override-only` |
  | ROG STRIX B650E-F GAMING WIFI | 2026-09-19 | 3881 | 2026/06/29 | `dlcdnets.asus.com` | 18,069,780 | `a207d283c9be39e3d2341023b580dada9da97dd94958fe77d0d2e5da70eb1129` | 33,558,528 | `309294a1b204a1e3717e768d2debddbd72c03d0ca6254ab41049d0b884a6bd4f` | `bae3945f94ca047475c3597f31f0358a9eb5e0bddd45fbded1648a62c0f3df88` | 5,023 | `artifact` | `override-only` |
  | TUF GAMING X870-PLUS WIFI | 2026-09-19 | 1681 | 2026/06/22 | `dlcdnets.asus.com` | 19,044,618 | `296192d08798f4f206dea137c02dc5d56047319e3ddd1ddb818d6d0c1770ba18` | 33,558,528 | `86bb62765e8441f40c274449189e24ffbaf30d0c518af50cb4bbd64f5f54e291` | `1d6d8d0b5c75cbe5b954e99f8eef219cd7f53133ea32d47f87afbcf9d8636dae` | 5,335 | `artifact` | `override-only` |
  | TUF GAMING Z790-PLUS WIFI | 2026-09-19 | 1836 | 2026/05/14 | `dlcdnets.asus.com` | 11,922,046 | `395ee06891e297bab93cc8daa7d7f132846859c43eb997364ef6728aaec49ed5` | 25,169,920 | `86be886f8d6008d8ea0b744578616f50b221160da12e5658988706e0d67f8703` | `7add48a64db12b04b832ee99ccc8559a069c453d2d0483ed9ada40c1f96a70a4` | 5,716 | `artifact` | `override-only` |
  | ROG STRIX Z790-E GAMING WIFI | 2026-09-19 | 3202 | 2026/08/17 | `dlcdnets.asus.com` | 13,632,016 | `e4b9c52218cdaddd8d6a571a4ad59ac85f999869574960ca496d99e073972f0a` | 33,558,528 | `3ddfeb13592e9d7ea291eb004d5c370a86f86f5ae654ad81af5f457685215c7e` | `04184885fcebf15436b238766b5876ad2ced5d0b40730416ca1fb702243efb90` | 5,806 | `artifact` | `override-only` |

  The physical X870E-E/2402 host did not upgrade that row to `verified`:
  no-override resolution was refused because system vendor `CyberPowerPC`
  differs from board vendor `ASUS`.

  Capability boundary: PRIME X570-P 5044 was removed from the representative
  matrix and replaced by TUF GAMING Z790-PLUS WIFI 1836 after the current PRIME
  endpoint response included an older release outside the reviewed artifact
  path. Both exact PRIME commands stopped with `ASUS BIOS 3603 has an unexpected
  download path` before selecting 5044. Validation was not broadened; the
  official 5044 record itself remained unchanged.
- [x] Fetch tests are offline and included in the existing Linux/Windows,
  Python 3.12/3.13 CI matrix.

- [x] Validate live decoding on physical Gigabyte hardware with the matching
  firmware image (`ffd821d`: X870 AORUS ELITE WIFI7 ICE, F12; values
  sanity-checked, not menu-compared).
- [ ] Validate live decoding on physical MSI hardware with the matching
  firmware image before claiming support for that platform.
- [ ] Validate physical Windows collection on at least one additional board.

### Next Windows support release gate

Do not claim broader physical Windows support in a release until the preceding
item is checked with evidence from a second UEFI board. The hosted Windows CI
smoke remains diagnostic because runner firmware access is not guaranteed.

On that board, record the model, firmware version, Windows build, `probe`
capability, variable count, and any per-variable errors. From an elevated
terminal, run `probe`, capture `snapshot --output before/`, decode it with the
matching image using `export IMAGE --snapshot before/ --output before.json`,
change one known non-sensitive setup setting in firmware, then capture
`snapshot --output after/` and run `diff before/ after/ --image IMAGE`. Confirm
that enumeration succeeds, the export has no definite compatibility mismatch,
and the named diff identifies the changed setting. Record counts and conclusions
here; do not commit the raw snapshots or machine-specific export.

Cross-vendor items are follow-up coverage rather than 1.0 blockers. The
before/after diff and clean-build checks remain release gates.

## Publishing

- [x] Configure the PyPI trusted publisher (owner `chadcox`, repo
  `uefi-mirror`, workflow `release.yml`, environment `pypi`) and a protected
  `pypi` environment before the first tag push. Done 2026-09-29: pending
  publisher registered; `pypi` requires reviewer `chadcox`.
- [ ] Push a `vX.Y.Z` tag matching `pyproject.toml`, `__version__`, and the
  `CHANGELOG.md` heading. The `release` workflow re-runs the safety suite,
  tests, and lint, builds the sdist and wheel, smoke-installs the wheel, and
  publishes to PyPI through trusted publishing.
  1.2.0 was published this way on 2026-09-29 (release run 36644311803, approved
  by `chadcox`); `pip install uefi-mirror==1.2.0` was checked in a fresh venv.

# Changelog

All notable changes to `uefi-mirror` are documented here.

## Unreleased

Behavior changes since 1.0.0, pending the next release.

### Changed

- **Output writes are refused in more cases on Linux.** Output files and
  directories that are (or pass through) symlinks, existing hard-linked files,
  files or directories owned by another user, or destinations resolving under
  `/sys/firmware` (including symlink aliases and `..` traversal) are refused
  before any mutation. Existing output files are tightened to `0600` (output
  directories to `0700`) through their own open descriptor before truncation,
  so a pre-existing world-readable file is never briefly writable by others.
  New files and directories start with those private permissions on both
  platforms.
- **Compatibility status vocabulary.** The compatibility check no longer
  emits `matched`; a clean check now reports `unverified` with an evidence
  line explaining what was and was not verified. Exit codes are unchanged and
  `--allow-mismatch` behaves as before. Scripts that scraped the terminal
  string `matched` must now read `unverified`; the stable interface remains
  the JSON `compatibility` field and the nonzero exit on definite mismatch.
- **Saved schemas are validated strictly on load.** `export --schema` and
  `diff --schema` refuse schema JSON containing JSON booleans where integers
  are required, negative offsets, field widths outside the 1/2/4/8-byte set,
  negative varstore sizes, or negative string/ordered-list lengths, with a
  `ValueError` naming the malformed field, before any report is written.
  Previously accepted malformed schemas (for example a hand-edited
  `offset: -2`) now fail to load. No schema format-version bump: the
  serialized shape is unchanged; only invalid data is now rejected.

## 1.0.0 - 2026-09-04

First stable release.

### Highlights

- Read-only live UEFI-variable collection on Linux and Windows.
- Firmware-schema extraction from AMI Aptio capsule and raw SPI images.
- Named terminal, JSON, text, and offline HTML configuration exports.
- Raw and schema-aware before/after snapshot comparison.
- Tri-state firmware-menu visibility evaluation and CPU-family variant
  resolution.
- Self-contained, reusable schema JSON with deterministic hashes.
- Compatibility checks for board identity, firmware filename, variable layout,
  sizes, and statically declared enum values.
- Owner-only snapshot and report permissions, bounded reads, traversal defenses,
  and a standalone static safety contract.

### Validated 1.0 hardware scope

- ASUS ROG Strix X870E-E Gaming WiFi with firmware 2402.
- Live collection and decoding validated on physical Linux and Windows hosts.
- Physical Windows validation collected 137 variables and decoded 5376 settings
  with 1552/1552 statically decodable enum values accepted by the image.
- A physical Windows before/after test isolated Bluetooth Controller changing
  from Disabled to Enabled among 2720 named settings compared.

Gigabyte X570 AORUS ELITE F40 and MSI MS-7E54 firmware images parse successfully,
but physical validation and support claims for those platforms are deferred until
after 1.0.

### Compatibility

- Snapshot format: 1.
- Schema format: 3.
- Export format: 3.
- Python: 3.12 or newer.

See [`docs/compatibility.md`](docs/compatibility.md) for the stable interface and
machine-readable format policy.

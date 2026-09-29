# Changelog

All notable changes to `uefi-mirror` are documented here.

## Unreleased

No changes yet.

## 1.2.0 - 2026-09-29

### Added

- **Release workflow and pipx install route.** A tag-triggered GitHub Actions
  workflow runs the safety contract, tests and lint, builds and smoke-installs
  the wheel, then publishes to PyPI through trusted publishing. README documents
  installing a tagged release with pipx from GitHub.

### Changed

- **fetch reports integrity on the terminal.** Human output now states the
  publisher checksum status and prints every provenance warning (for example a
  missing publisher SHA-256 or a BIOS version that differs from the detected
  one); previously these reached only fetch.json.

### Fixed

- `probe` reports the fwupd version number (preferring the running version)
  instead of a whole `fwupdmgr --version` record.

## 1.1.0 - 2026-09-22

### Added

- **Cross-version named diff.** `diff` accepts paired `--old-image`/`--new-image`
  or `--old-schema`/`--new-schema` sources, compares stable setting IDs, and
  reports settings whose definitions changed instead of comparing unlike bytes.
- **Snapshot scope and stability options.** `snapshot --schema` captures only
  declared variables. `--verify-stable` compares two reads before writing and
  refuses observed drift; it cannot make firmware reads atomic.
- **Parser completeness control.** `schema`, `export`, and `diff` accept
  `--require-complete` to refuse schemas with parser warnings.
- **EFI standard compression decoding.** Type `0x01` sections now use a bounded
  decoder. Synthetic and malformed-stream tests pass; vendor-image validation
  of this path is pending. Unknown GUID compression still produces warnings.
- **Visibility diagnostics.** Unknown visibility results include per-setting
  causes and an export summary. Safe `THIS` and additional IFR operations are
  evaluated when their inputs are available.
- **Windows physical release gate.** The tracked release checklist now states
  how to validate another physical board before claiming broader Windows
  support; that result is still pending.
- **Capability-based official ASUS retail-motherboard retrieval.** The opt-in
  `fetch` command now has capability-based support for exact ASUS
  retail-motherboard models exposed by the reviewed endpoint, rather than a
  fixed model registry. It fails closed unless ASUS identity is unambiguous,
  the endpoint normalized-exactly echoes the requested model, the exact
  requested release exists, the returned path and host are approved, and a
  direct image or bounded ZIP contains exactly one safe firmware image. When
  ASUS advertises a SHA-256, it must match its discovered `artifact` or `image`
  target; a missing publisher checksum is allowed and reported `unavailable`.
  Parser validation must still find at least one setting in either case. The
  command never falls back to latest, flashes firmware, executes vendor tools,
  or expands the existing network and output-write boundaries.
- **Fetch provenance format 2.** Resolve-only output records an advertised
  checksum target as `undetermined`; a successful verified download records the
  target discovered from the bytes as `artifact` or `image`. Snapshot remains
  format 1 and schema/export remain format 3.
  `--snapshot`, explicit identity/version overrides, `--resolve-only`, and
  clean JSON output remain supported.
- **Fetch provenance check in `export`.** Compares a download `fetch.json`
  with the image and the machine being decoded — automatically when
  `fetch.json` sits beside the image, or from `--provenance PATH`. A matching image SHA-256, model and BIOS
  version add compatibility evidence but never raise the status above
  `unverified`; a disagreement is a `mismatch` that stops the export unless
  `--allow-mismatch` is given. Resolve documents and other fetch format
  versions are rejected.
- **Representative live retrieval evidence.** Exact releases X870E-E/2402,
  B650E-F/3881, TUF X870-PLUS/1681, TUF Z790-PLUS/1836, and Z790-E/3202 passed
  format-2 resolve/download smokes against official ASUS endpoints. These are
  evidence examples, not a whitelist or physical hardware-validation claims.
- **Firmware volume walker warnings.** The firmware volume walker now
  records every place it had to give up: malformed section or file headers,
  sections whose decompressor this parser does not implement, and
  decompression, file, or nesting budget exhaustion. The notes join the
  schema's `warnings` channel and appear in `schema`, `export`, and `diff`
  output on every surface (terminal, text, JSON, and HTML), so a partially
  readable image says so instead of silently under-reporting. The diff JSON
  document gains the same notes as an additive `warnings` array, present
  only when non-empty. A fully readable image produces no walk warnings.
  The walker skips volumes that are not FFS file systems (such as NVRAM
  variable stores) and does not parse RAW files as section lists, so neither
  raises a false "malformed" warning.

### Changed

- **Private output replacement is atomic per file.** A failed payload write
  leaves an existing report intact. Windows output paths now check ancestor
  reparse points as well as the final component.
- **`probe` checks live enumeration.** It reports a next step and calls a
  collection ready only when at least one variable is readable.
- **Firmware image size limit raised from 64 MiB to 128 MiB.** Some vendor
  images exceed 64 MiB (Lenovo ThinkPad BIOS N3VET59W ships a 68 MiB image)
  and were refused before parsing. The limit applies to `schema`, `export`,
  and `diff` image inputs and to the image `fetch` extracts, and still sits
  within the existing 128 MiB download and 256 MiB ZIP-contents limits.
- **Output writes are refused in more cases on Linux.** Output files and
  directories that are (or pass through) symlinks, existing hard-linked files,
  files or directories owned by another user, or destinations resolving under
  `/sys/firmware` (including symlink aliases and `..` traversal) are refused
  before any mutation. Existing output files are tightened to `0600` (output
  directories to `0700`) through their own open descriptor before replacement,
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

### Fixed

- **Unreadable variables in diffs.** A failed read is reported as `unreadable`,
  never as an added or removed variable. Named diffs report material settings
  they could not compare.
- **`probe` reports the fwupd version.** fwupd 2.x prints its dependencies
  first, so the optional-tools row showed libusb's version
  (`info.libusb 1.0.30`) as fwupd's. It now shows the `org.freedesktop.fwupd`
  line.

### Hardware validation

- **Gigabyte X870 AORUS ELITE WIFI7 ICE, firmware F12.** Live collection and
  decoding validated on physical Linux (Fedora 44, non-root): 92/92 variables
  read, 4392 settings in 21 form sets, 3637 decoded `ok`, compatibility
  `unverified` with no problems. Decoded values were checked for validity
  (1040/1040 live enum values), not against the setup menu. One compressed section with an unknown
  decompressor GUID is dropped and reported as a warning. Windows collection on
  this board is not yet validated.

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

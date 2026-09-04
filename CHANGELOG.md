# Changelog

All notable changes to `uefi-mirror` are documented here.

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

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
- [x] Fetch tests are offline and included in the existing Linux/Windows,
  Python 3.12/3.13 CI matrix.

- [ ] Validate live decoding on physical Gigabyte or MSI hardware with the
  matching firmware image before claiming support for either platform.
- [ ] Validate physical Windows collection on at least one additional board.

Cross-vendor items are follow-up coverage rather than 1.0 blockers. The
before/after diff and clean-build checks remain release gates.

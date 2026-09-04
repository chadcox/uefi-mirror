# Release checklist

Use this list before declaring 1.0. Items marked complete are covered by the
repository or the recorded reference-system validation.

## Completed locally

- [x] Full automated suite passes on Windows.
- [x] Standalone read-only safety suite passes.
- [x] Ruff lint passes.
- [x] Physical Windows UEFI enumeration succeeds with Administrator elevation.
- [x] ASUS ROG Strix X870E-E Gaming WiFi firmware 2402 produces a matched schema.
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
- [ ] Run CI on the release commit and review the non-gating hosted Windows smoke
  result.
- [ ] Choose the release version, update package metadata consistently, write
  release notes, build artifacts, and verify them in a clean environment.

## Post-1.0 coverage

- [ ] Validate live decoding on physical Gigabyte or MSI hardware with the
  matching firmware image before claiming support for either platform.
- [ ] Validate physical Windows collection on at least one additional board.

Cross-vendor items are follow-up coverage rather than 1.0 blockers. The
before/after diff and clean-build checks remain release gates.

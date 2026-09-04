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

## Remaining 1.0 decisions and external validation

- [ ] Decide whether 1.0 supports only the ASUS reference platform or claims a
  broader AMI Aptio hardware scope.
- [ ] If claiming broader hardware support, validate live decoding on physical
  Gigabyte or MSI hardware with the matching firmware image.
- [ ] Validate physical Windows collection on at least one additional board.
- [ ] Capture a real before/after BIOS change on Windows and verify both raw and
  named `diff` output.
- [ ] Run CI on the release commit and review the non-gating hosted Windows smoke
  result.
- [ ] Choose the release version, update package metadata consistently, write
  release notes, build artifacts, and verify them in a clean environment.

If 1.0 is explicitly scoped to the ASUS reference platform, the cross-vendor
items are follow-up coverage rather than blockers. The before/after diff and
clean-build checks should remain release gates for either scope.

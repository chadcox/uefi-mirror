# uefi-mirror

Read the current BIOS/UEFI configuration of a running Linux or Windows system
and export it to the terminal, JSON, text, or HTML — without rebooting into
firmware setup.

The operating system exposes UEFI variables as opaque blobs: `AmdSetupRPL` is
2016 bytes of undocumented struct. The names, menu paths, options and defaults
that make those bytes meaningful live only inside the BIOS image. `uefi-mirror`
extracts that schema from a vendor BIOS update file, joins it to your machine's
live variables, and tells you what your firmware is actually set to.

That schema can be saved once and reused: extract it to a JSON file on one
machine, and every later `export` or `diff` — here or on another machine — can
decode from that file alone, without the original firmware image or another
vendor download.

Host support and firmware-image support are separate. Live collection runs on
Linux and Windows. Decoding and physical Windows collection have been
hardware-verified on the ASUS reference board listed in
[Firmware-image support](#firmware-image-support). Windows collection has also
passed on a hosted Hyper-V UEFI machine.

On the reference board it recovers **5376 settings across 15 firmware menu
groups**, and narrows the 34 that differ from firmware-declared defaults down to
the **4** that are currently visible in setup.

**Strictly read-only.** No code path creates, modifies, deletes, unlocks or
writes a UEFI variable or SPI flash region. The claim is backed by a test
suite of static scans and behavioral checks rather than convention; it is a
regression guard, not a formal proof. The only filesystem writes the tool
ever performs are the output files and snapshot directories you name on the
command line, and those go through the two guarded helpers described in
[`docs/safety.md`](docs/safety.md).

## What's new in 1.1.0

- `fetch` retrieves a reviewed, exact ASUS release and records provenance;
  `export` checks that record against the image and machine when present.
- Named `diff` can use a different image or schema for each side of a firmware
  update. Failed variable reads are reported as unreadable, not as changes.
- Snapshots can be limited to a saved schema and checked for changes between
  two reads. Output files are replaced atomically after a successful write.
- The parser handles EFI standard compression and reports why a visibility
  condition is undecidable. `--require-complete` refuses parser warnings.

The compression path has synthetic tests but no vendor-image validation yet.
Physical Windows validation beyond the ASUS reference board remains a release
gate for any broader support claim. See [1.1.0 changes](CHANGELOG.md) for detail.

## Who this is for

- **Headless or remote machines.** Read the configuration over ssh. No reboot, no
  KVM, no trip to the rack.
- **After a firmware update.** Compare snapshots before and after. Raw comparison
  does not need a schema; named comparison requires one schema compatible with
  both versions.
- **Fleets and homelabs.** Export every machine, diff against a reference; find
  the one box someone tweaked two years ago.
- **Passthrough and virtualization debugging.** IOMMU, SR-IOV, Above 4G decoding,
  Resizable BAR, CSM — all in one output instead of five menu pages.
- **Audit and compliance.** Secure Boot, TPM, boot order and wake sources as JSON,
  produced by a tool that has no code path that can write.
- **Machines whose setup menu you cannot open.** A setup password blocks entry to
  the menu; it does not stop the operating system from reading the variables the
  firmware exposes at runtime. If the machine boots, `export` still shows what it
  is set to. This reads only: it changes nothing, and settings the firmware
  declares to be passwords are redacted, never decoded.
- **Bug reports and support threads.** Attach an export instead of a photograph of
  the setup screen.

## Install from source

Python 3.12+. Two dependencies (`typer`, `rich`); the firmware parsers are pure
standard library.

```console
$ git clone https://github.com/chadcox/uefi-mirror.git
$ cd uefi-mirror
$ python -m pip install -e .
$ uefi-mirror probe
```

Or run directly from the clone without installing.

Linux/macOS:

```console
$ PYTHONPATH=src python3 -m uefi_mirror.cli probe
```

PowerShell:

```powershell
$env:PYTHONPATH = "src"
python -m uefi_mirror.cli probe
```

### Host operating-system support

| Host | Live-variable support |
|---|---|
| Linux, booted with UEFI | Reads `efivarfs`; root is normally unnecessary, though firmware permissions can hide individual variables. |
| Windows, booted with UEFI | `probe` and offline work run normally. Live `snapshot`, `export`, and `diff` require an elevated Administrator terminal to enable `SeSystemEnvironmentPrivilege`. Collection is validated on hosted Hyper-V UEFI and physical ASUS hardware. |
| Legacy BIOS / CSM boot | Live UEFI-variable collection is unavailable. Image parsing and work with existing schemas or snapshots still work. |

Windows full enumeration uses the undocumented
`NtEnumerateSystemEnvironmentValuesEx` syscall because the documented firmware
API can read only variables whose names are already known. If Windows or the
host blocks that syscall, live collection stops with `enumeration unavailable`
instead of returning a guessed or partial snapshot.

## Quick start

### 1. Identify the machine and installed firmware

```console
$ uefi-mirror probe
```

Confirm that the machine booted in UEFI mode and note the exact board model,
board revision, and firmware version. Linux also reports whether `efivarfs` is
mounted. On Windows, `probe` explains whether the process needs elevation;
rerun live commands from an elevated Administrator terminal when it does.

### 2. Obtain the matching firmware image

`fetch` provides capability-based support for exact ASUS retail-motherboard
models exposed by the reviewed endpoint. It can resolve an exact installed
release and save a validated image plus `fetch.json`:

```console
$ uefi-mirror fetch --manufacturer ASUS \
    --model "ROG STRIX X870E-E GAMING WIFI" --bios-version 2402 \
    --output firmware/
Fetched 2402 to firmware/ROG-STRIX-X870E-E-GAMING-WIFI-ASUS-2402.CAP
Provenance written to firmware/fetch.json
```

This is an explicit network operation. With unambiguous ASUS retail-board DMI,
the three identity options may be omitted. If local DMI differs from ASUS's
exact marketing name or is ambiguous, pass `--manufacturer`, `--model`, and
`--bios-version` only after independently confirming the retail model and exact
installed release. To inspect the selection without downloading or writing
files, use `uefi-mirror fetch --resolve-only --json` (this still contacts ASUS).

When automatic retrieval fails, and for other vendors, download the BIOS update
for the exact motherboard model, revision, and installed firmware version from
the motherboard or system vendor.
Extract the archive and pass its `.CAP`, `.ROM`, `.BIN`, or vendor-named raw
image to `uefi-mirror`. The extension does not matter; capsule-wrapped updates
and raw SPI images are detected from their contents.

Do not substitute an image merely because it comes from the same manufacturer
or chipset. Setup variable layouts can change between motherboard models and
BIOS releases. The image is only read—`uefi-mirror` never flashes it.

### 3. Export the current configuration

Start with the settings that differ from firmware-declared defaults and would
currently be visible in the setup menu:

```console
$ uefi-mirror export BIOS.CAP --changed-only --visible-only
```

For a complete archival record or an offline viewer:

```console
$ uefi-mirror export BIOS.CAP --output bios.json
$ uefi-mirror export BIOS.CAP --format html --output bios.html
```

The compatibility line reports how safely the selected schema describes the
collected variables:

- `unverified` — no definite layout conflict was found, but nothing
  independently verifies that the image is the installed firmware release.
  A board model embedded in the image and a BIOS version in the filename
  are reported as weak evidence; neither upgrades the status. Treat decoded
  values cautiously.
- `mismatch` — the image cannot safely describe these variables. The command
  stops before writing a report.

`matched` is reserved for a future check that can verify image identity
independently; no command emits it today.

When a `fetch.json` saved by `uefi-mirror fetch` sits beside the image,
`export` compares it with the image and the machine automatically; use
`--provenance PATH` for a manifest stored elsewhere. Matching image SHA-256,
model and BIOS version are added as evidence only; a local manifest cannot
prove identity, so the status stays `unverified`. Any disagreement is a
`mismatch`, which catches exporting against a stale download or another
board's image:

```console
$ uefi-mirror export firmware/BIOS.CAP -o bios.json   # checks firmware/fetch.json
```

`--allow-mismatch` exists for parser research and forensic inspection, not
normal exports. It can produce believable but incorrect setting names and
values.

When decoding from a saved schema JSON, variable identities, sizes and enum
values are still checked against the live machine. A real layout conflict still
stops the run, and a clean check reads `unverified` whether the schema came
from an image or from JSON, because neither can prove which board its source
image belonged to. A filename can suggest a BIOS version and is reported as
weak evidence; it is never proof.

In this README and the CLI, “changed” means “different from the
firmware-declared default.” It does not prove that a person changed the value.

### 4. Capture and compare a change

Take one snapshot, reboot into firmware setup and make the desired change, then
take another snapshot:

```console
$ uefi-mirror snapshot --output before/
$ uefi-mirror snapshot --output after/
$ uefi-mirror diff before/ after/ --image BIOS.CAP
```

The tool never makes the firmware change itself. For a firmware update that
changed the layout, give named `diff` each side's matching image or schema:

```console
$ uefi-mirror diff before/ after/ --old-image OLD.CAP --new-image NEW.CAP
```

Settings whose definitions changed are reported as not comparable; the tool
does not present their differing bytes as the same setting value.

### 5. Keep the schema, drop the image

Parsing a 32 MB firmware image on every run is unnecessary. Extract the schema
once:

```console
$ uefi-mirror schema BIOS.CAP --output x870e-2402.json
5376 settings in 15 form sets from ROG-STRIX-X870E-E-GAMING-WIFI-ASUS-2402.CAP
  schema 9d9a61217ea60dc4
...
Schema written to x870e-2402.json
```

Then decode against the JSON instead of the image, anywhere:

```console
$ uefi-mirror export --schema x870e-2402.json --changed-only
$ uefi-mirror diff before/ after/ --schema x870e-2402.json
```

The JSON is self-contained — names, menu paths, options, defaults, varstore
offsets and the raw IFR condition bytes — so visibility is evaluated exactly as
it would have been from the image. It describes firmware, not your machine: it
contains no live values and is safe to share, unlike a snapshot.

One caveat: a schema JSON cannot prove which board it came from, so
compatibility is `unverified` at best (step 3). Where certainty matters, decode
from the image itself.

### Work with another machine offline

Run `probe` and `snapshot` on the target machine, then privately copy both its
snapshot and matching firmware image (or schema JSON) to the analysis machine:

```console
$ uefi-mirror export TARGET.CAP --snapshot target-snapshot/ --output target.json
$ uefi-mirror export --schema target-schema.json --snapshot target-snapshot/
```

The snapshot records the target's DMI identity for compatibility checking.
Snapshots contain boot paths, machine identifiers, and other sensitive values;
do not publish or commit them.

`probe` and `snapshot` need no firmware image. `schema` reads an image without
live variables and therefore cannot verify that the image matches a machine.
`export` and named `diff` perform compatibility checks, against the image when
given one and against the schema's own declarations when given `--schema`.

## Command reference

### `fetch` — retrieve an exact official image

```console
$ uefi-mirror fetch --manufacturer ASUS \
    --model "ROG STRIX X870E-E GAMING WIFI" --bios-version 2402 \
    --output firmware/
```

`fetch` is the only networked command. It has capability-based support for
exact ASUS retail-motherboard models exposed by the reviewed endpoint. It fails
closed unless the request identifies ASUS without OEM/prebuilt ambiguity, the
endpoint normalized-exactly echoes the requested model, and the exact requested
version exists (there is no fallback to latest). The returned release must also
use the reviewed download path and host and have a supported direct-image or
bounded-ZIP container with exactly one safe firmware image. When ASUS
advertises a publisher SHA-256, it must match the discovered `artifact` or
`image` target; a missing publisher checksum is allowed and reported as
`unavailable`. In either case, the parser must find at least one setting.
Firmware parsing occurs only after any advertised checksum is verified.

It never flashes firmware, executes vendor tools, or collects UEFI variables.
Use `--snapshot` to resolve from a validated snapshot's DMI identity; local DMI
is never substituted when that snapshot lacks identity.

The output directory must be missing or empty and safe. A successful download
contains only the original firmware-image basename and `fetch.json`, both
private. The manifest records URLs, selected and detected identity, artifact
and image hashes, checksum scope, and parsing results. Successful parsing and a
verified download checksum do **not** prove that the image is the firmware
installed on the machine; that status remains `unverified`.

Network limits are 4 MiB metadata, 128 MiB artifact, 128 MiB extracted image,
128 ZIP entries, 256 MiB total advertised ZIP contents, 5 redirects per
request, 20 resolution requests, a 15-second socket timeout, and a 180-second
whole-fetch deadline. Only HTTPS on port 443 to the reviewed ASUS metadata and
artifact hosts is allowed. Ambient proxy discovery is disabled in this first
release. See [`docs/safety.md`](docs/safety.md) for the exact boundary.

Machine-readable modes emit one JSON object. `fetch --resolve-only --json`
reports the selected release without downloading. Its advertised checksum
target is `undetermined` because no bytes were retrieved. A successful
`fetch -o firmware/ --json` includes saved paths and the same format-2
provenance written to `fetch.json`, with a verified checksum target of
`artifact` or `image` when ASUS advertised a checksum.

### `probe` — what is this machine?

```console
$ uefi-mirror probe
 Boot mode            UEFI
 Board                ASUSTeK COMPUTER INC. ROG STRIX X870E-E GAMING WIFI
 Firmware             American Megatrends Inc. 2402 (07/13/2026)
 efivarfs             mounted
 Variables            134 readable of 134, 127889 payload bytes
 firmware-attributes  none
 Optional tools       fwupdmgr: compile   info.libusb   1.0.30
 Privileges           uid 1000 (some variables may be unreadable)
```

### `snapshot` — capture the current state

```console
$ uefi-mirror snapshot --output before/
Snapshot: 134 variables -> before/
```

Writes every readable variable plus a manifest with sizes, attributes and
SHA-256. On Linux a destination that is (or passes through) a symlink, is a
hard-linked file, is owned by another user, or resolves under `/sys/firmware`
is refused before any write; new files start `0600` and directories `0700`,
and an existing file is tightened to `0600` before a private temporary file
atomically replaces it. On Windows the tree is created with a protected,
non-inheriting owner-only DACL that is read back and verified before payload
bytes are written; junctions and reparse points are refused.
`docs/safety.md` states the exact guarantees and their limits. Feed it to
`export --snapshot` or `diff` later. **Do not commit it** — raw variables
contain boot paths and machine identifiers.

Use `--schema schema.json` to capture only variables referenced by that schema.
Use `--verify-stable` to read the selected variables twice and refuse a capture
if their bytes, attributes, or read errors change between sweeps. This detects
observed drift; it does not make UEFI reads atomic.

### `schema` — what does each setting *mean*?

Reads the BIOS image alone. No live machine involved.

```console
$ uefi-mirror schema BIOS.CAP --grep "above 4g"
5376 settings in 15 form sets from BIOS.CAP
3 match 'above 4g'

Setting               Menu path                                  Type  Default      Variable
Above 4G Decoding     Setup / Advanced / PCI Subsystem Settings  enum  Enabled      Setup+0x90
Above 4GB MMIO Limit  Setup / Advanced / PCI Subsystem Settings  enum  40bit (1TB)  Setup+0x88
Above 4GB MMIO Limit  Setup / Advanced / System Agent (SA)       enum  40bit (1TB)  Setup+0x88
                      Configuration
```

`--output schema.json` writes the full schema: help text, value ranges, option
lists, backing variable offsets, and the conditions gating each setting. The
short hash printed beside the header (`schema 9d9a61217ea60dc4`) is the SHA-256
prefix of that document's canonical form; the same image always yields the same
hash, so two people can confirm they are reading the same firmware definition.

Feed the result back to `export --schema` or `diff --schema` to work without the
BIOS image.
`--require-complete` refuses an image or saved schema when the parser reported
warnings about content it could not read.

### `export` — the live configuration, with names

```console
$ uefi-mirror export BIOS.CAP --changed-only
schema compatibility: unverified (...)
5376 settings, 34 differ from firmware default  (134 variables from /sys/firmware/efi/efivars)
  no_variable 693
  redacted 6
  unsupported 6
```

`no_variable` means the schema declares a varstore this machine does not expose;
`redacted` is a password field, never read out.

Pass either a BIOS image or `--schema schema.json`; with neither, the command
refuses to guess:

```console
$ uefi-mirror export --schema x870e-2402.json --changed-only
schema compatibility: unverified (schema carries no firmware image, so the board
id behind it cannot be confirmed; filename contains installed BIOS version
'2402'; 26/36 declared varstores are readable; 1552/1552 live enum values are
valid; board text and filename hints cannot prove the image is the installed
firmware release)
5376 settings, 34 differ from firmware default
```

Values come from the live machine, or from a capture with `--snapshot before/`.
Write with `--output bios.json`, `--output bios.txt --format text`, or create an
offline interactive viewer with:

```console
uefi-mirror export BIOS.CAP --format html --output bios.html
```

When given a firmware image, `export` checks for an embedded board-model and
BIOS-version match. Both image and saved-schema workflows validate declared
variable GUIDs, minimum sizes, and enum values against the collected variables.
On Linux, an `--output` destination that is (or passes through) a symlink, a
hard-linked file, owned by another user, or resolving under `/sys/firmware` is
refused before any write; new files start `0600` and an existing one is
tightened to `0600` before an atomic private-file replacement. On
Windows the file is created with a protected, non-inheriting owner-only DACL
that is read back and verified before payload bytes are written, and reparse
points are refused.
`--grep`, `--changed-only`, `--visible-only`, and `--include-inactive` filter
terminal and text rows; archival JSON remains complete. HTML embeds every
setting and uses those flags only as initial UI filters.
Use `--require-complete` to refuse exports from schemas with parser warnings.

### `diff` — what changed?

```console
$ uefi-mirror diff before/ after/ --image BIOS.CAP
1 variables changed, 0 added, 0 removed
2 named settings changed of 2720 compared

Setting                 Was   Now       Menu path
Core Performance Boost  Auto  Disabled  AMD CBS
ECC                     Auto  Disabled  AMD CBS
```

If any changed setting is one the firmware would not show in setup, a `Vis`
column appears marking it `hidden` / `grayed` / `disabled` — a value that moved
while its question was suppressed is not a change anyone made from the menu:

```console
Setting                Was   Now  Vis     Menu path
FAR enforcement state  0     1    grayed  AMD CBS / SOC Miscellaneous Control
  1 of these the firmware's own conditions keep off the setup menu (Vis column)
```

Snapshot against snapshot, or against `live`. `--schema schema.json` names the
settings without the image, on the same terms as `export --schema`:

```console
$ uefi-mirror diff before/ after/ --schema x870e-2402.json
```

For a firmware update, use `--old-image` and `--new-image`, or the paired
`--old-schema` and `--new-schema` options. A failed variable read is reported
as `unreadable` rather than as an added or removed variable. `--require-complete`
refuses schemas with parser warnings.

Without either, it compares raw variable bytes and says only which variables
moved:

```console
$ uefi-mirror diff before/ after/
1 variables changed, 0 added, 0 removed
  pass --image BIOS.CAP or --schema schema.json to name the settings behind these bytes
  changed  AmdSetupRPL
```

## Which changes can you actually see?

Most settings that differ from firmware-declared defaults are ones the menu
would never show you. The firmware decides that with `suppress_if` / `gray_out_if` /
`disable_if` expressions — postfix bytecode stored alongside each question.
`uefi-mirror` evaluates them against your live values.

```console
$ uefi-mirror export BIOS.CAP --changed-only --visible-only
5376 settings, 34 differ from firmware default  (134 variables from /sys/firmware/efi/efivars)
  ... status tallies as above ...
3073 settings apply to this machine (5 disabled, 7 grayed, 1416 hidden, 645 unknown, 1000 visible)
4 of the changed settings are ones the setup menu would actually show you
  variant: AMD Overclocking: only AodSetupRpl exists at runtime
  variant: AMD CBS: AmdSetupRPL matches platform family 'rpl'

*   SVM Enable          Enabled         AMD CBS / CPU Common Options
*   Ai Overclock Tuner  EXPO I          Setup / Ai Tweaker
*   PMIC Voltages       Sync All PMICs  Setup / Ai Tweaker / Advanced Memory Voltages
*   DIMM Slot Number    DIMM_A2         Setup / Tool / ASUS SPD Information
```

Those four are visible settings whose stored values differ from their declared
defaults. The other thirty are real stored bytes the menu hides — memory timings
left behind by an EXPO profile, for example. Under *Ai Tweaker / DRAM Timing
Control*, `Tcl` holds `0x1c`, but its
`suppress_if` evaluates true because the `Manual` toggles that would reveal it
sit at `Auto`. The value is genuinely stored; the menu just will not show it to
you. The JSON records the governing expression for every such setting, so you
can see why a value was classified the way it was.

Evaluation is **tri-state**: a condition that reads a question we could not
decode, or uses an opcode with no static meaning, reports `unknown` rather than
guessing. The export records causes such as a missing question value or an
unsupported opcode for each unknown result and summarizes their frequency.
The reference result recorded 645 unknown settings before these additional
expression evaluations; the current count may be lower.

The image also ships one `AMD CBS` form set per CPU family. `uefi-mirror` works
out which applies to the installed processor, marks the other 2303 settings
`active: false`, and prints the evidence for its choice instead of asserting it.

## Output formats

JSON (`format_version: 3`) is the complete archival record: every setting's
schema, live value, visibility, and provenance.

Setting ids are `formset-guid:question-id`, stable across BIOS versions as long
as the vendor keeps the question id.

Enum entries are listed as **firmware-declared options**. Each exported option
has a `visible`, `hidden`, or `unknown` state. A live label is used only when
exactly one visible option matches; otherwise the numeric value and all still-
possible candidate labels are retained. Numeric exports also retain the raw
unsigned value used by IFR expressions, separate from signed display values.

Text output is plain, grouped by menu section, safe to redirect or diff, with
`*` marking changes and `[hidden]` / `[grayed]` / `[other CPU family]` marking
what the menu would not offer.

A schema JSON document — what `schema --output` writes and what `export
--schema` / `diff --schema` read — is self-contained: each condition carries the IFR
expression bytes (`code`, base64) alongside its human-readable form, so a
schema parsed on one machine and reloaded on another evaluates visibility
identically. `Schema.from_json()` refuses a document whose `format_version`
is not the one this parser writes, and refuses malformed fields rather than
loading a partial schema. Storage coordinates are validated strictly: a
negative or boolean offset, a field width outside the 1/2/4/8-byte IFR set, a
negative varstore size, or a negative string/ordered-list length is refused
on load, where a hand-edited file once decoded from the wrong end of the
variable. `schema_hash()` names a schema by the SHA-256 of its
canonical JSON, which the same parser reproduces byte for byte from the same
image.

The stability rules for CLI behavior and machine-readable formats are documented
in [`docs/compatibility.md`](docs/compatibility.md). Format versions are independent
of the package version so incompatible document changes can be rejected clearly.
The remaining 1.0 gates are tracked in
[`docs/release-checklist.md`](docs/release-checklist.md).

## How it works

```
BIOS.CAP ──▶ capsule ──▶ firmware volumes ──▶ HII packages ──▶ IFR + strings
                                                                    │
                                        schema (names, paths, options, defaults)
                                                       ▲            │
                              schema.json ─────────────┘            │
                                                                    │
/sys/firmware/efi/efivars ──▶ variables ──────▶ join by varstore + offset
                                                                    │
                                        expression evaluation ──▶ export / diff
```

On Windows, the native firmware APIs replace the `efivarfs` input shown above;
the schema, decode, export, and diff pipeline is shared.

| Stage | Module | Job |
|---|---|---|
| Capsule | `firmware/cap.py` | Strip the update header, find the payload |
| Volumes | `firmware/firmware_volume.py` | Walk FVs, FFS files and sections; LZMA and uncompressed encapsulation |
| HII | `firmware/hii.py` | Pair form packages with string packages from the same file |
| Strings | `firmware/strings.py` | UCS-2 string blocks, per language |
| Forms | `firmware/ifr.py` | Parse the IFR opcode tree into questions, varstores, scopes |
| Conditions | `firmware/expr.py` | Extract and evaluate postfix expressions, tri-state |
| Schema | `schema/` | Menu paths, options, defaults, stable setting ids |
| Values | `decode.py` | Read variables, decode by offset, resolve CPU-family variants |
| Diff | `diff.py` | Compare variables and named settings |
| Fetch | `fetch.py` + `safety.py` | Resolve an exact official release through capability gates; retrieve and validate it within fixed network/archive limits |

## Firmware-image support

Physical decoding support and automatic retrieval evidence are separate. The
1.0 hardware support scope is the ASUS ROG Strix X870E-E Gaming WiFi with
firmware 2402. The other physical-support entries below are parser coverage for
post-1.0 hardware validation, not 1.0 support claims.

| Image family | Support |
|---|---|
| ASUS ROG Strix X870E-E Gaming WiFi, firmware 2402 | Decoding hardware-verified; live collection validated on Linux and physical Windows |
| Gigabyte X870 AORUS ELITE WIFI7 ICE, firmware F12 | Decoding validated, values not checked against the setup menu; live collection validated on Linux (post-1.0); 4392 settings/21 form sets |
| Gigabyte X570 AORUS ELITE F40 | Parsed: 2342 settings/20 form sets; hardware unverified |
| MSI MS-7E54, firmware 2.A90 | Parsed: 9511 settings/10 form sets; hardware unverified |
| Other AMI Aptio images | Expected, not verified |
| Insyde/Phoenix images | Unverified |
| EFI standard compression sections (type `0x01`) | Decoder implemented with bounded synthetic tests; vendor-image validation pending |
| Unknown GUID compression | Reported as a parser warning; content is skipped |

### Automatic retrieval examples

These five exact releases are representative live-smoke evidence for the
capability gates, not a whitelist and not physical hardware validation.
Retrieval succeeds or fails on the current endpoint response and the identity,
exact-version, path, checksum, container, and parser gates described above.

| Model | Endpoint verification date | Smoke version | Checksum target | DMI status |
|---|---|---:|---|---|
| ROG STRIX X870E-E GAMING WIFI | 2026-09-19 | 2402 | `artifact` | `override-only` |
| ROG STRIX B650E-F GAMING WIFI | 2026-09-19 | 3881 | `artifact` | `override-only` |
| TUF GAMING X870-PLUS WIFI | 2026-09-19 | 1681 | `artifact` | `override-only` |
| TUF GAMING Z790-PLUS WIFI | 2026-09-19 | 1836 | `artifact` | `override-only` |
| ROG STRIX Z790-E GAMING WIFI | 2026-09-19 | 3202 | `artifact` | `override-only` |

## Known limitations

- **Use the matching firmware image.** Setting layouts can change between BIOS
  versions, even on the same motherboard. Use the image matching the installed
  version; `uefi-mirror` refuses definite mismatches unless `--allow-mismatch`
  is explicitly passed.

- **Automatic identity must match ASUS's exact retail marketing name.** Generic
  or differing DMI names and OEM/prebuilt ambiguity fail before artifact
  retrieval. Use exact `--manufacturer`, `--model`, and `--bios-version`
  overrides only after independently confirming the retail-board identity and
  installed release; there is no fuzzy product discovery.

- **Automatic retrieval accepts only reviewed containers.** Safe direct
  firmware images and bounded ZIPs containing exactly one image are accepted.
  Unsupported containers such as updater executables fail; vendor executables
  and renamers are never run.

- **Some settings are unavailable to the operating system.** Firmware can hide
  variables after boot. Those settings appear as `no_variable`; no userspace
  tool can recover their current values.

- **“Changed” does not necessarily mean user-modified.** It means the stored
  value differs from the firmware-declared default. Hardware initialization,
  firmware updates, and vendor logic can also produce such differences.

- **Visibility cannot always be determined.** Some firmware conditions depend
  on values or operations that cannot be evaluated safely. These settings are
  reported as `unknown`, never guessed. The 1.0 reference export recorded
  645 of 3073 applicable settings as unknown; newer expression evaluation may
  reduce that count.

- **Some menu paths may be incomplete.** Firmware sometimes links menu pages in
  ways the parser does not yet follow. On the reference firmware, 29 of 5376
  settings have only a top-level menu location.

- **Firmware may contain settings for several CPU families.** The tool selects
  the applicable group when the available variables identify it. Otherwise,
  multiple possible groups remain in the export rather than choosing one
  without evidence.

- **Windows live collection depends on an undocumented Windows interface.** It
  works on tested hosted Hyper-V and physical ASUS hardware, but Microsoft may
  change or restrict it. If enumeration is unavailable, the command stops with
  a clear error instead of returning a partial snapshot.

## Tests

```console
$ pytest
$ python tests/test_safety.py  # safety suite, no pytest needed
$ ruff check .
```

### Manual fetch smoke test

Fetching is read-only with respect to firmware, but it uses the network and
writes the output directory you name. The X870E-E command below is one
representative, live-verified example of the capability-based retrieval flow;
it is not the only accepted model and does not define a whitelist. First resolve
the exact release without downloading or writing files:

```console
$ uefi-mirror fetch --manufacturer ASUS \
    --model "ROG STRIX X870E-E GAMING WIFI" --bios-version 2402 \
    --resolve-only --json | python -m json.tool
```

The format-2 result should have `operation: "resolve"`, release `2402`, and
publisher checksum status `advertised` with target `undetermined`. Then use a
missing or empty directory to exercise download, checksum, archive, parser, and
private-output validation:

```console
$ uefi-mirror fetch --manufacturer ASUS \
    --model "ROG STRIX X870E-E GAMING WIFI" --bios-version 2402 \
    --output firmware-test-2402
$ python -m json.tool firmware-test-2402/fetch.json
$ uefi-mirror schema \
    firmware-test-2402/ROG-STRIX-X870E-E-GAMING-WIFI-ASUS-2402.CAP
```

For this representative artifact, `fetch.json` reports format 2, publisher
checksum `verified` against the downloaded ZIP with target `artifact`, a
33,558,528-byte image, 5,376 settings, the explicit identity overrides, and
installed-firmware identity `unverified`. The smoke/evidence row is
`override-only` because the command supplies those overrides. The schema
command reports 5,376 settings in 15 form sets. The artifact checksum and
successful parse do not prove that release 2402 is installed; confirm the
machine's exact model,
revision, and BIOS version independently before using the image for export.

Automatic detection may deliberately refuse an OEM/prebuilt system even when
its board name resembles an ASUS retail model. Use exact identity overrides
only after confirming that retail-board identity; refusal is safer than
silently selecting incompatible firmware.

CI runs this offline suite on Python 3.12 and 3.13 on both `ubuntu-latest` and
`windows-latest`, including fetch transport/archive tests and native Windows
DACL and junction checks. A non-gating Windows smoke step also probes the
hosted runner and attempts a live snapshot; the
[2026-09-01 validation run](https://github.com/chadcox/uefi-mirror/actions/runs/33569671960)
detected Hyper-V UEFI and collected 31 variables. Synthetic buffers still provide
the deterministic enumeration coverage. Physical Windows validation on an ASUS
ROG Strix X870E-E Gaming WiFi running firmware 2402 collected 137 variables and
successfully decoded 5376 settings with a clean compatibility check
(`unverified`, no layout conflicts). A physical Windows
before/after test changed Bluetooth Controller from Disabled to Enabled: raw
comparison observed the expected reboot-related variable churn, while named
comparison isolated that single setting among 2720 compared. Once dependencies
are installed, test execution needs no root or Administrator access and no network.

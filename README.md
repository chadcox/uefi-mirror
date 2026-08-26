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
decode from that file alone, with no capsule and no second vendor download.

On the reference board it recovers **5376 settings across 15 form sets**, and
narrows the 34 that differ from firmware default down to the **4** the setup
menu would actually show you.

**Strictly read-only.** No code path creates, modifies, deletes, unlocks or
writes a UEFI variable or SPI flash region. Enforced by static scans of the
shipped source, not by convention — see [`docs/safety.md`](docs/safety.md).

## Who this is for

- **Headless or remote machines.** Read the configuration over ssh. No reboot, no
  KVM, no trip to the rack.
- **After a firmware update.** Snapshot before and after; see which settings the
  vendor moved while you weren't looking.
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

## Install

Python 3.12+. Two dependencies (`typer`, `rich`); the firmware parsers are pure
standard library.

```console
$ pip install -e .
$ uefi-mirror probe
```

Or run without installing:

```console
$ PYTHONPATH=src python3 -m uefi_mirror.cli probe
```

### Platform support

| Host | Live-variable support |
|---|---|
| Linux, booted with UEFI | Reads `efivarfs`; root is normally unnecessary, though firmware permissions can hide individual variables. |
| Windows, booted with UEFI | `probe` and offline work run normally. Live `snapshot`, `export`, and `diff` require an elevated Administrator terminal to enable `SeSystemEnvironmentPrivilege`. |
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

Download the BIOS update for that exact motherboard model, revision, and
installed firmware version from the motherboard or system vendor. Extract the
downloaded archive and pass its `.CAP`, `.ROM`, `.BIN`, or vendor-named raw image
to `uefi-mirror`. The extension does not matter; both capsule-wrapped updates
and raw SPI images are detected from their contents.

Do not substitute an image merely because it comes from the same manufacturer
or chipset. Setup variable layouts can change between motherboard models and
BIOS releases. The image is only read—`uefi-mirror` never flashes it.

### 3. Export the current configuration

Start with the settings that differ from firmware defaults and would currently
be visible in the setup menu:

```console
$ uefi-mirror export BIOS.CAP --changed-only --visible-only
```

For a complete archival record or an offline viewer:

```console
$ uefi-mirror export BIOS.CAP --output bios.json
$ uefi-mirror export BIOS.CAP --format html --output bios.html
```

The first output line reports image compatibility:

- `matched` — the embedded board model, installed BIOS version, variable
  identities and sizes, and decoded enum values agree.
- `unverified` — no portable board identity was available, but no definite
  layout conflict was found. Treat decoded values cautiously.
- `mismatch` — the image cannot safely describe these variables. The command
  stops before writing a report.

`--allow-mismatch` exists for parser research and forensic inspection, not
normal exports. It can produce believable but incorrect setting names and
values.

Decoding from a schema JSON reports `schema compatibility` instead. Variable
identities, sizes and enum values are still checked against the live machine, so
a real layout conflict still stops the run — but the board identity behind a
schema cannot be confirmed without the image, so a clean check reads
`unverified` rather than `matched`. A filename can suggest a BIOS version and is
reported as weak evidence; it is never accepted as proof.

### 4. Capture and compare a change

Take one snapshot, reboot into firmware setup and make the desired change, then
take another snapshot:

```console
$ uefi-mirror snapshot --output before/
$ uefi-mirror snapshot --output after/
$ uefi-mirror diff before/ after/ --image BIOS.CAP
```

The tool never makes the firmware change itself. Without `--image`, `diff`
still reports which raw variables changed, but cannot name the settings.

### 5. Keep the schema, drop the image

Parsing a 32 MB capsule on every run is unnecessary. Extract the schema once:

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
SHA-256. Linux uses directory mode `0700` and file mode `0600`; Windows uses a
verified, protected owner-only DACL. Feed it to `export --snapshot` or `diff`
later. **Do not commit it** — raw variables contain boot paths and machine
identifiers.

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

### `export` — the live configuration, with names

```console
$ uefi-mirror export BIOS.CAP --changed-only
image compatibility: matched (...)
5376 settings, 34 differ from firmware default  (134 variables from /sys/firmware/efi/efivars)
  no_variable 693
  redacted 6
  unknown_value 2
  unsupported 4
```

`no_variable` means the schema declares a varstore this machine does not expose;
`redacted` is a password field, never read out.

Pass either a BIOS image or `--schema schema.json`; with neither, the command
refuses to guess:

```console
$ uefi-mirror export --schema x870e-2402.json --changed-only
schema compatibility: unverified (schema carries no firmware image, so the board
id behind it cannot be confirmed; filename contains installed BIOS version
'2402'; 26/36 declared varstores are readable; 1552/1554 live enum values are
valid)
5376 settings, 34 differ from firmware default
```

Values come from the live machine, or from a capture with `--snapshot before/`.
Write with `--output bios.json`, `--output bios.txt --format text`, or create an
offline interactive viewer with:

```console
uefi-mirror export BIOS.CAP --format html --output bios.html
```

Before decoding, `export` checks for an embedded board-model and BIOS-version
match and validates the image's declared variable GUIDs, minimum sizes, and enum
values against the live machine.

All outputs use `0600` on Linux or a verified owner-only DACL on Windows.
`--grep`, `--changed-only`, `--visible-only`, and `--include-inactive` filter
terminal and text rows; archival JSON remains complete. HTML embeds every
setting and uses those flags only as initial UI filters.

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

Without either, it compares raw variable bytes and says only which variables
moved:

```console
$ uefi-mirror diff before/ after/
1 variables changed, 0 added, 0 removed
  pass --image BIOS.CAP to name the settings behind these bytes
  changed  AmdSetupRPL
```

## Which changes can you actually see?

Most settings that differ from firmware default are ones the menu would never
show you. The firmware decides that with `suppress_if` / `gray_out_if` /
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

Those four are exactly what this machine has changed. The other thirty are real
stored bytes the menu hides — memory timings left behind by an EXPO profile, for
example. `Tcl` holds `0x1c` under *Ai Tweaker / DRAM Timing Control*, but its
`suppress_if` evaluates true because the `Manual` toggles that would reveal it
sit at `Auto`. The value is genuinely stored; the menu just will not show it to
you. The JSON records the governing expression for every such setting, so you
can see why a value was classified the way it was.

Evaluation is **tri-state**: a condition that reads a question we could not
decode, or uses an opcode with no static meaning, reports `unknown` rather than
guessing. 645 settings land there and say so.

The image also ships one `AMD CBS` form set per CPU family. `uefi-mirror` works
out which applies to the installed processor, marks the other 2303 settings
`active: false`, and prints the evidence for its choice instead of asserting it.

## Output

JSON (`format_version: 3`) is the complete archival record — every setting with schema,
live value, visibility and provenance:

```json
{
  "id": "7b59104a-c00d-4158-87ff-f04d6396a915:0x01c8",
  "name": "Tcl",
  "path": ["Setup", "Ai Tweaker", "DRAM Timing Control"],
  "type": "integer",
  "help": "DRAM CAS# Latency, the value stepping is 2.",
  "question_id": 456,
  "read_only": false,
  "display": "hex",
  "varstore": {
    "guid": "a3a3b874-7636-4182-ba1e-f52c584494e3",
    "name": "VARSTORE_OCMR_SETTINGS_NAME",
    "offset": 2154, "size": 2, "kind": "buffer", "varstore_id": 38
  },
  "default": 0, "minimum": 0, "maximum": 64, "step": 1,
  "conditions": [{"kind": "suppress_if", "expression": "true",
                  "code": "RgI=", "question_refs": []}],
  "live": {
    "status": "ok", "value": 28, "raw_value": 28,
    "label": "0x1c", "candidate_labels": [], "display": "0x1c",
    "is_default": false, "visibility": "hidden", "active": true
  }
}
```

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
loading a partial schema. `schema_hash()` names a schema by the SHA-256 of its
canonical JSON, which the same parser reproduces byte for byte from the same
image.

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

## Support matrix

| Image family | Support |
|---|---|
| ASUS ROG Strix X870E-E Gaming WiFi, firmware 2402 | Hardware verified |
| Gigabyte X570 AORUS ELITE F40 | Parsed: 2342 settings/20 form sets; hardware unverified |
| MSI MS-7E54, firmware 2.A90 | Parsed: 9511 settings/10 form sets; hardware unverified |
| Other AMI Aptio images | Expected, not verified |
| Insyde/Phoenix images | Unverified |
| Tiano/EFI-1.1 compressed sections | Unsupported |

## Known limitations

- 645 of 3073 applicable settings have conditions that cannot be decided
  statically; reported as `unknown`, never guessed.
- 29 of 5376 settings (24 in AMD CBS) resolve to a depth-1 menu path, their
  parent form reachable only through a ref this walker does not follow.
- CPU-family inference needs at least one variant group where the members are
  distinguishable. Where none is, every variant is kept.
- Vendors ship settings that differ between BIOS versions. Use the image
  matching your installed firmware version.
- Only variables the firmware marks runtime-accessible reach the OS at all. A
  vendor that marks its setup store boot-services-only leaves nothing for any
  userspace tool to read: those settings decode as `no variable`, and the
  compatibility line reports how many declared varstores were readable. On the
  reference board every setup store carries `NV+BS+RT` and is readable
  unprivileged.
- Windows enumeration relies on an undocumented syscall and may be unavailable
  on future Windows releases or restricted hosts. The documented named-read API
  remains usable only when the caller already knows a variable's name and GUID.

## Tests

```console
$ pytest
$ python tests/test_safety.py  # safety suite, no pytest needed
$ ruff check .
```

CI runs this suite on `ubuntu-latest` and `windows-latest`, including native
Windows DACL and junction checks. It does not read the runner's real firmware
variables: hosted runners can restrict that access, so enumeration parsing uses
synthetic buffers. Tests need no root or Administrator access and no network,
and never touch the host's real firmware-variable store.

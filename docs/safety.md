# Safety model

`uefi-mirror` reads firmware configuration. It never writes it. This document
states what that means precisely and how the guarantee is enforced.

A tool that can brick a motherboard deserves more than a promise in a README,
so the claim is enforced by tests that fail the build, not by convention.

## The guarantee

No code path creates, modifies, deletes, unlocks or writes:

- a UEFI variable (`SetVariable`, efivarfs writes, `chattr -i`)
- an SPI flash region
- boot order or boot entries (`efibootmgr` is never invoked)
- anything at all under `/sys/firmware`

The tool needs no root. It runs as an ordinary user, reads fewer variables that
way, and says so in `probe` output rather than escalating.

## How reads are performed

Every firmware read goes through `safety.read_bounded`:

```python
RO_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
```

- `O_RDONLY` — the file descriptor is incapable of writing.
- `O_NOFOLLOW` — a symlink planted in the variable directory raises `ELOOP`
  instead of redirecting the read elsewhere.
- `O_CLOEXEC` — no descriptor leaks into a subprocess.
- **Bounded** — at most `MAX_VARIABLE_BYTES` (1 MiB) per file. efivarfs reports
  `st_size` as 0 for some entries, so the limit is enforced against bytes
  actually read rather than a stat that can lie. A buggy or hostile filesystem
  cannot hand back an endless stream.

Live collection records a truncated or unreadable variable and continues.
Snapshots are trusted inputs only after their whole manifest is validated:
version and types, safe matching filenames, duplicate rejection, payload size,
and SHA-256. Structural or integrity errors abort the snapshot load.

## Writes that do happen

Exactly one function writes anything, `safety.write_private`, and only to a
path the user named on the command line:

- output files are created `0600` (`snapshot` manifests, `--output` exports)
- output directories are created `0700`, and tightened if they already existed
  looser

## Enforcement

`tests/test_safety.py` runs under pytest or standalone with no dependencies:

```console
$ python3 tests/test_safety.py
```

The suite includes static scans of the shipped source and behavioral checks:

| Test | What it prevents |
|---|---|
| `production_mutation_is_confined_to_safety_helpers` | An AST visitor rejects writing open modes, `Path.write_*`, filesystem mutation/copy APIs, and firmware-writing subprocesses. `safety.write_private` is the sole allowlisted exception. |
| `no_sys_firmware_path_is_ever_written` | A `/sys/firmware` path ever being paired with an opening-for-write. |
| `read_flags_are_hardened` | `RO_FLAGS` losing `O_NOFOLLOW`/`O_CLOEXEC`, or gaining a write bit. |
| `cli_exposes_no_mutating_command` | A subcommand named `set`, `write`, `restore`, `flash`, `unlock`, `erase` or `modify` reaching the CLI. |
| `symlink_is_refused` | Following a symlink out of the variable directory. |
| `oversize_read_is_refused` | Unbounded reads. |
| `output_permissions_are_private` | World-readable exports or snapshots. |
| `truncated_variable_is_recorded_not_raised` | A malformed variable aborting the run. |

This is a regression guard, not a formal proof. New host-I/O code still needs
manual review.

Tests never touch the host's real efivarfs. `end_to_end_on_a_fake_efivarfs`
builds a temporary directory shaped like one.

## What is *not* protected

- **Snapshot contents are sensitive.** Raw variables include boot paths,
  machine identifiers, Secure Boot keys and other hardware detail. Files are
  `0600`, but do not commit a `snapshot/` directory or paste one publicly.
- **Password fields are never read out.** Questions the firmware flags as
  passwords decode to status `redacted` with no value, in JSON and text alike.
  On the reference board this covers 6 settings.
- **Reading is safe; acting on the output is your business.** Nothing here
  stops you taking an exported value and typing it into your BIOS.

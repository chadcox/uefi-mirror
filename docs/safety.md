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

Linux needs no root; an ordinary user may simply see fewer readable variables.
Windows live collection requires an elevated Administrator token solely to
enable `SeSystemEnvironmentPrivilege`. `probe` reports the requirement and the
tool never elevates itself.

## How reads are performed

Linux firmware and snapshot-file reads go through `safety.read_bounded`:

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

On Windows, named file reads use `CreateFileW` with
`FILE_FLAG_OPEN_REPARSE_POINT`; a reparse point is rejected before its handle is
adapted to a Python file descriptor. Firmware variables themselves are read
through the bounded Windows firmware APIs, not through the filesystem.

Live collection records a truncated or unreadable variable and continues.
Snapshots are trusted inputs only after their whole manifest is validated:
version and types, safe matching filenames, duplicate rejection, payload size,
and SHA-256. Structural or integrity errors abort the snapshot load.

## Writes that do happen

Exactly one function writes file contents, `safety.write_private`, and only to
a path the user named on the command line:

- on Linux, output files are `0600` and directories are `0700`
- on Windows, files and directories receive a protected DACL with exactly one
  full-access ACE for their owner; the ACL is read back and verified before any
  payload bytes are written
- Windows junctions and other reparse points are refused rather than followed

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
| `read_flags_are_hardened` | Linux `RO_FLAGS` losing `O_NOFOLLOW`/`O_CLOEXEC`, or gaining a write bit. |
| `cli_exposes_no_mutating_command` | A subcommand named `set`, `write`, `restore`, `flash`, `unlock`, `erase` or `modify` reaching the CLI. |
| `symlink_is_refused` | Following a Linux symlink or Windows directory junction. |
| `oversize_read_is_refused` | Unbounded reads. |
| `output_permissions_are_private` | World-readable exports or snapshots, checked as POSIX modes on Linux and the actual DACL on Windows. |
| `windows_acl_failure_refuses_before_writing` | Writing sensitive bytes after Windows ACL setup fails. |
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

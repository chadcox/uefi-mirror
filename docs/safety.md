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

Exactly two functions mutate the filesystem, `safety.write_private` (file
contents) and `safety.private_dir` (the output directory tree), and only to
paths the user named on the command line. On Linux both refuse, before any
`mkdir`, `chmod`, truncate or payload write:

- a destination that resolves under the kernel firmware tree `/sys/firmware`
  (symlink aliases and `..` traversal included, via the resolved real path);
- a final-component symlink, a hard-linked existing file (link count > 1), or
  an existing file owned by another user;
- an output directory that is a symlink or owned by another user.

Once the checks pass, an existing file is tightened with `fchmod(fd, 0o600)`
through its own descriptor before it is truncated, so a pre-existing `0644`
file is never writable by others even momentarily; a new file is created
`0600` from the start. Output directories are tightened with
`fchmod(fd, 0o700)` the same way. Permissions are applied by descriptor, so
they cannot race a swapped path and cannot follow a symlink.

On Windows, files and directories are created with a protected DACL already in
place — exactly one full-access ACE for their owner, no inheritance — so there
is no window in which an inherited DACL applies; the ACL is then read back and
verified before any payload bytes are written. Windows junctions and other
reparse points are refused rather than followed.

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
| `output_file_symlink_is_refused` | Writing through a symlinked output file (its target and mode stay untouched). |
| `output_dir_symlink_is_refused` | Using a symlinked output directory (target not re-tightened or written into). |
| `symlinked_parent_dir_cannot_redirect_output` | A snapshot `raw-variables` directory swapped for a symlink redirecting writes elsewhere. |
| `hardlinked_output_is_refused` | Overwriting a hard-linked file and corrupting its other link. |
| `existing_file_is_tightened_before_payload_write` | A `0644` file being writable by others between open and truncate. |
| `protected_firmware_root_is_refused` | Any write destination resolving under `/sys/firmware`, by alias or `..` traversal. |
| `cli_refuses_symlinked_output_dir` | A CLI command silently writing through a symlinked output destination. |

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

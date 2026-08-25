"""Read-only primitives. Nothing here may ever open a file for writing
inside /sys/firmware. Enforced by tests/test_safety.py."""

import os

# efivarfs vars are kernel-capped well under this; the limit is belt-and-braces
# against a hostile/buggy filesystem handing us an endless read.
MAX_VARIABLE_BYTES = 1 << 20

RO_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC


def read_bounded(path: str, limit: int = MAX_VARIABLE_BYTES) -> bytes:
    """Open O_RDONLY|O_NOFOLLOW|O_CLOEXEC and read at most `limit` bytes.

    Raises OSError(ELOOP) on a symlink, ValueError if the file exceeds `limit`.
    """
    fd = os.open(path, RO_FLAGS)
    try:
        data = os.read(fd, limit + 1)
        # efivarfs reports st_size 0 for some entries, so trust the read length.
        while len(data) <= limit:
            chunk = os.read(fd, limit + 1 - len(data))
            if not chunk:
                return data
            data += chunk
        raise ValueError(f"{path}: exceeds {limit} byte limit")
    finally:
        os.close(fd)


def private_dir(path: str) -> str:
    """mkdir -p with 0700, and tighten it if it already existed looser."""
    os.makedirs(path, mode=0o700, exist_ok=True)
    os.chmod(path, 0o700)
    return path


def write_private(path: str, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_CLOEXEC, 0o600)
    try:
        remaining = memoryview(data)
        while remaining:
            written = os.write(fd, remaining)
            if written == 0:
                raise OSError("zero-byte write")
            remaining = remaining[written:]
    finally:
        os.close(fd)
    os.chmod(path, 0o600)

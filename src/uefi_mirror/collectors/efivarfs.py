"""Read-only efivarfs collector.

Layout: /sys/firmware/efi/efivars/<Name>-<GUID>, first 4 bytes of each file are
the little-endian UEFI attribute mask, the rest is the variable payload.
"""

import hashlib
import os
import re
from dataclasses import dataclass, field

from ..platform import EFIVARS_DIR, efivarfs_mounted
from ..safety import MAX_VARIABLE_BYTES, read_bounded

GUID_RE = re.compile(
    r"^(?P<name>.+)-(?P<guid>[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12})$"
)

ATTRIBUTE_BITS = {
    0x01: "NON_VOLATILE",
    0x02: "BOOTSERVICE_ACCESS",
    0x04: "RUNTIME_ACCESS",
    0x08: "HARDWARE_ERROR_RECORD",
    0x10: "AUTHENTICATED_WRITE_ACCESS",
    0x20: "TIME_BASED_AUTHENTICATED_WRITE_ACCESS",
    0x40: "APPEND_WRITE",
    0x80: "ENHANCED_AUTHENTICATED_ACCESS",
}


def decode_attributes(mask: int) -> list[str]:
    return [n for bit, n in ATTRIBUTE_BITS.items() if mask & bit]


@dataclass
class Variable:
    name: str
    guid: str
    filename: str
    attributes: int | None = None
    payload: bytes | None = None
    error: str | None = None

    size: int = 0
    payload_sha256: str = ""
    source_sha256: str = ""
    attribute_names: list[str] = field(default_factory=list)

    def manifest(self) -> dict:
        return {
            "name": self.name,
            "guid": self.guid,
            "filename": self.filename,
            "attributes": self.attributes,
            "attribute_names": self.attribute_names,
            "payload_size": self.size,
            "payload_sha256": self.payload_sha256,
            "source_sha256": self.source_sha256,
            "error": self.error,
        }


def parse_filename(filename: str) -> tuple[str, str] | None:
    m = GUID_RE.match(filename)
    if not m:
        return None
    return m.group("name"), m.group("guid").lower()


def read_variable(directory: str, filename: str) -> Variable | None:
    parsed = parse_filename(filename)
    if parsed is None:
        return None
    name, guid = parsed
    var = Variable(name=name, guid=guid, filename=filename)
    try:
        raw = read_bounded(os.path.join(directory, filename), MAX_VARIABLE_BYTES)
    except (OSError, ValueError) as exc:
        var.error = f"{type(exc).__name__}: {exc}"
        return var
    if len(raw) < 4:
        var.error = f"short read: {len(raw)} bytes, need >= 4 for the attribute prefix"
        return var
    var.attributes = int.from_bytes(raw[:4], "little")
    var.attribute_names = decode_attributes(var.attributes)
    var.payload = raw[4:]
    var.size = len(var.payload)
    var.payload_sha256 = hashlib.sha256(var.payload).hexdigest()
    var.source_sha256 = hashlib.sha256(raw).hexdigest()
    return var


def collect(directory: str | None = EFIVARS_DIR, require_mount: bool = True) -> list[Variable]:
    """Read every variable. One unreadable entry never aborts the sweep."""
    if directory is None:
        raise RuntimeError("efivarfs is not available on this platform")
    if require_mount and not efivarfs_mounted():
        raise RuntimeError(f"{directory} is not an efivarfs mount")
    variables = []
    with os.scandir(directory) as entries:
        for entry in entries:
            # follow_symlinks=False: refuse to be redirected out of efivarfs.
            if not entry.is_file(follow_symlinks=False):
                continue
            var = read_variable(directory, entry.name)
            if var is not None:
                variables.append(var)
    variables.sort(key=lambda v: (v.name, v.guid))
    return variables

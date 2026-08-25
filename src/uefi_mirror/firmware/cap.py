"""ASUS/UEFI capsule wrapper handling.

EFI_CAPSULE_HEADER:
    EFI_GUID CapsuleGuid;      // 0
    UINT32   HeaderSize;       // 16
    UINT32   Flags;            // 20
    UINT32   CapsuleImageSize; // 24
"""

import hashlib
import struct
import uuid
from dataclasses import dataclass

MAX_IMAGE_BYTES = 64 << 20
CAPSULE_HEADER_MIN = 28
FV_SIGNATURE = b"_FVH"
FV_SIGNATURE_OFFSET = 40


@dataclass
class Capsule:
    data: bytes
    file_sha256: str
    payload_sha256: str
    capsule_guid: str | None = None
    header_size: int | None = None
    flags: int | None = None
    image_size: int | None = None

    def info(self) -> dict:
        return {
            "file_sha256": self.file_sha256,
            "payload_sha256": self.payload_sha256,
            "payload_size": len(self.data),
            "capsule_guid": self.capsule_guid,
            "capsule_header_size": self.header_size,
            "capsule_flags": self.flags,
            "capsule_image_size": self.image_size,
        }


def _looks_like_capsule(data: bytes) -> tuple[int, int, int] | None:
    if len(data) < CAPSULE_HEADER_MIN:
        return None
    header_size, flags, image_size = struct.unpack_from("<III", data, 16)
    if not (CAPSULE_HEADER_MIN <= header_size <= len(data)):
        return None
    # CapsuleImageSize covers the header plus payload, and must fit the file.
    if not (header_size < image_size <= len(data)):
        return None
    return header_size, flags, image_size


def load(path: str) -> Capsule:
    """Read a .CAP/.ROM, strip the capsule wrapper if one is really there."""
    with open(path, "rb") as fh:
        data = fh.read(MAX_IMAGE_BYTES + 1)
    if len(data) > MAX_IMAGE_BYTES:
        raise ValueError(f"{path}: larger than the {MAX_IMAGE_BYTES} byte limit")
    if not data:
        raise ValueError(f"{path}: empty")

    file_sha = hashlib.sha256(data).hexdigest()
    header = _looks_like_capsule(data)
    if header is None:
        # Already a bare SPI image.
        return Capsule(data=data, file_sha256=file_sha, payload_sha256=file_sha)

    header_size, flags, image_size = header
    payload = data[header_size:image_size]
    if FV_SIGNATURE not in payload[:MAX_IMAGE_BYTES]:
        raise ValueError(f"{path}: no firmware volume found after the capsule header")
    return Capsule(
        data=payload,
        file_sha256=file_sha,
        payload_sha256=hashlib.sha256(payload).hexdigest(),
        capsule_guid=str(uuid.UUID(bytes_le=data[:16])),
        header_size=header_size,
        flags=flags,
        image_size=image_size,
    )

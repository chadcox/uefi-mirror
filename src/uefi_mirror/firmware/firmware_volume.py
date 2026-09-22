"""Firmware volume / FFS file / section walking (PI 1.8 vol. 3).

HII form packages and the string packages they depend on are separate package
lists that can sit tens of kilobytes apart, so proximity is not enough to pair
them. What does hold is that both belong to the same FFS file -- one driver --
so this walks the real container hierarchy and reports leaf section data
grouped by file.
"""

import lzma
import struct
import uuid
from dataclasses import dataclass, field

from uefi_mirror.firmware import efi_compression

LZMA_CUSTOM_DECOMPRESS_GUID = uuid.UUID("EE4E5898-3914-4259-9D6E-DC7BD79403CF")
_LZMA_GUID_LE = LZMA_CUSTOM_DECOMPRESS_GUID.bytes_le

FV_SIGNATURE = b"_FVH"
FV_SIGNATURE_OFFSET = 40
FV_HEADER_MIN = 56
FV_ATTR_ERASE_POLARITY = 0x00000800
# Volumes whose files use the FFS layout. Anything else (e.g. an NVRAM
# variable-store volume) shares the _FVH header but not the file format.
FFS_FILESYSTEM_GUIDS = frozenset(uuid.UUID(g).bytes_le for g in (
    "7a9354d9-0468-444a-81ce-0bf617d890df",  # FFS1 (Framework)
    "8c8ce578-8a3d-4f1c-9935-896185c32dd3",  # FFS2
    "5473c07a-3dcb-4dca-bd6f-1e9689e7349a",  # FFS3
))

FFS_HEADER_SIZE = 24
FFS_ATTRIB_LARGE_FILE = 0x01
FFS_FILE_TYPE_RAW = 0x01  # opaque body, no section list
FFS_FILE_TYPE_PAD = 0xF0
FFS_FILE_TYPE_FREE = 0xFF

SECTION_COMPRESSION = 0x01
SECTION_GUID_DEFINED = 0x02
SECTION_USER_INTERFACE = 0x15
SECTION_FIRMWARE_VOLUME_IMAGE = 0x17
ENCAPSULATION_SECTIONS = {SECTION_COMPRESSION, SECTION_GUID_DEFINED,
                          SECTION_FIRMWARE_VOLUME_IMAGE}

COMPRESSION_NONE = 0x00
COMPRESSION_STANDARD = 0x01
GUID_ATTR_PROCESSING_REQUIRED = 0x0001

MAX_TOTAL_DECOMPRESSED = 512 << 20
MAX_SECTION_OUTPUT = 128 << 20
MAX_DEPTH = 16
MAX_FILES = 20000


@dataclass
class Section:
    type: int
    data: bytes
    path: str


@dataclass
class FfsFile:
    guid: str
    type: int
    path: str
    sections: list[Section] = field(default_factory=list)
    ui_name: str | None = None

    def describe(self) -> str:
        return self.ui_name or self.guid


@dataclass
class WalkResult:
    """Everything the walk found, and every place it had to give up.

    A drop is recorded, never hidden: each warning says what was lost, where,
    and why, so a schema built from a partially readable image can say so
    instead of quietly under-reporting."""

    files: list[FfsFile]
    warnings: list[str] = field(default_factory=list)


class _Walk:
    """Shared state: the decompression budget, every file discovered so far
    (including files inside nested volumes), and every place content was
    dropped."""

    def __init__(self, total: int) -> None:
        self.remaining = total
        self.files: list[FfsFile] = []
        self.warnings: list[str] = []


def decompress_lzma(blob: bytes, limit: int) -> bytes | None:
    """EFI LZMA payloads are LZMA1 'alone' streams: 5 property bytes then an
    8-byte size. Some builders write a bogus size, so retry as unknown-size."""
    if len(blob) < 14:
        return None
    for candidate in (blob, blob[:5] + b"\xff" * 8 + blob[13:]):
        try:
            out = lzma.LZMADecompressor(format=lzma.FORMAT_ALONE).decompress(
                candidate, max_length=limit + 1)
        except lzma.LZMAError:
            continue
        if out and len(out) <= limit:
            return out
    return None


def _warn_dropped(walk_state: "_Walk", where: str, what: str) -> None:
    walk_state.warnings.append(f"{where}; {what}")


def _is_uniform_fill(data: bytes, start: int, end: int,
                     allowed: tuple[int, ...]) -> bool:
    if start >= end:
        return True
    fill = data[start]
    return fill in allowed and all(data[pos] == fill for pos in range(start + 1, end))


def _fv_header(buf: bytes, start: int) -> tuple[int, int] | None:
    """Return (header_length, fv_length) for a plausible volume at `start`."""
    if start < 0 or start + FV_HEADER_MIN > len(buf):
        return None
    fv_length = struct.unpack_from("<Q", buf, start + 32)[0]
    header_length = struct.unpack_from("<H", buf, start + 48)[0]
    revision = buf[start + 55]
    if revision not in (1, 2):
        return None
    if not (FV_HEADER_MIN <= header_length <= fv_length):
        return None
    if not (header_length <= fv_length <= len(buf) - start):
        return None
    header = buf[start:start + header_length]
    if len(header) % 2 or sum(struct.unpack(f"<{len(header) // 2}H", header)) & 0xFFFF:
        return None
    return header_length, fv_length


def find_volumes(buf: bytes) -> list[tuple[int, int, int]]:
    volumes = []
    pos = 0
    while True:
        pos = buf.find(FV_SIGNATURE, pos + 1)
        if pos < 0:
            break
        start = pos - FV_SIGNATURE_OFFSET
        header = _fv_header(buf, start)
        if header is None:
            continue
        volumes.append((start, header[0], header[1]))
    return volumes


def _iter_sections(data: bytes, path: str, walk_state: "_Walk", depth: int):
    """Yield leaf sections, transparently unwrapping encapsulation sections."""
    pos = 0
    while pos + 4 <= len(data):
        size = int.from_bytes(data[pos:pos + 3], "little")
        stype = data[pos + 3]
        body_offset = 4
        if size == 0xFFFFFF:
            if pos + 8 > len(data):
                _warn_dropped(
                    walk_state, f"malformed section at {path}/sec@0x{pos:x}",
                    "rest of section list dropped")
                return
            size = struct.unpack_from("<I", data, pos + 4)[0]
            body_offset = 8
        if size < body_offset or pos + size > len(data):
            _warn_dropped(
                walk_state, f"malformed section at {path}/sec@0x{pos:x}",
                "rest of section list dropped")
            return
        body = data[pos + body_offset:pos + size]
        here = f"{path}/sec@0x{pos:x}"

        if stype in ENCAPSULATION_SECTIONS and depth < MAX_DEPTH:
            yield from _unwrap(stype, body, here, walk_state, depth)
        elif stype in ENCAPSULATION_SECTIONS:
            _warn_dropped(
                walk_state, f"nesting budget of {MAX_DEPTH} exceeded at {here}",
                "encapsulation section left unwrapped")
            yield Section(stype, body, here)
        else:
            yield Section(stype, body, here)
        pos += (size + 3) & ~3  # sections are 4-byte aligned
    if pos < len(data) and not _is_uniform_fill(data, pos, len(data), (0x00, 0xFF)):
        _warn_dropped(
            walk_state, f"malformed section at {path}/sec@0x{pos:x}",
            "rest of section list dropped")


def _unwrap(stype: int, body: bytes, path: str, walk_state: "_Walk", depth: int):
    """Encapsulation sections yield the leaf sections inside them. A nested
    volume instead contributes whole files, which are recorded separately so
    each driver keeps its own identity."""
    if stype == SECTION_FIRMWARE_VOLUME_IMAGE:
        _walk_volumes(body, path, walk_state, depth + 1)
        return
        yield  # pragma: no cover - keeps this a generator
    if stype == SECTION_GUID_DEFINED:
        if len(body) < 20:
            _warn_dropped(walk_state, f"malformed GUID-defined section at {path}",
                          "content dropped")
            return
        section_guid = body[:16]
        data_offset = struct.unpack_from("<H", body, 16)[0]
        if not (20 <= data_offset - 4 <= len(body)):
            _warn_dropped(walk_state, f"malformed GUID-defined section at {path}",
                          "content dropped")
            return
        payload = body[data_offset - 4:]
        if section_guid == _LZMA_GUID_LE:
            if walk_state.remaining <= 0:
                _warn_dropped(
                    walk_state, f"decompression budget exhausted at {path}",
                    "content dropped")
                return
            out = decompress_lzma(
                payload, min(MAX_SECTION_OUTPUT, walk_state.remaining))
            if out is None:
                _warn_dropped(walk_state,
                              f"LZMA section did not decompress at {path}",
                              "content dropped")
                return
            walk_state.remaining -= len(out)
        else:
            # GUID-defined section: attributes bit 0 (PROCESSING_REQUIRED) set
            # means the payload needs a decompressor this code does not know.
            attributes = struct.unpack_from("<H", body, 18)[0]
            if attributes & GUID_ATTR_PROCESSING_REQUIRED:
                _warn_dropped(
                    walk_state,
                    "compressed section with unknown decompressor GUID "
                    f"{uuid.UUID(bytes_le=section_guid)} at {path}",
                    "content dropped")
                return
            out = payload
        yield from _iter_sections(out, path, walk_state, depth + 1)
        return
    if stype == SECTION_COMPRESSION:
        if len(body) < 5:
            _warn_dropped(walk_state, f"malformed compression section at {path}",
                          "content dropped")
            return
        compression_type = body[4]
        if compression_type == COMPRESSION_STANDARD:
            declared_size = struct.unpack_from("<I", body)[0]
            limit = min(MAX_SECTION_OUTPUT, walk_state.remaining)
            if declared_size > limit or not limit:
                _warn_dropped(walk_state, f"decompression budget exceeded at {path}",
                              "content dropped")
                return
            out = efi_compression.decompress(body[5:], limit)
            if out is None or len(out) != declared_size:
                _warn_dropped(walk_state, f"EFI standard section did not decompress at {path}",
                              "content dropped")
                return
            walk_state.remaining -= len(out)
        elif compression_type == COMPRESSION_NONE:
            out = body[5:]
        else:
            _warn_dropped(
                walk_state,
                f"unsupported compression type {compression_type:#04x} at {path}",
                "content dropped")
            return
        yield from _iter_sections(out, path, walk_state, depth + 1)


def _iter_files(buf: bytes, fv_start: int, header_length: int, fv_length: int,
                path: str, walk_state: "_Walk", depth: int):
    pos = fv_start + header_length
    end = fv_start + fv_length
    count = 0
    fv_attributes = struct.unpack_from("<I", buf, fv_start + 44)[0]
    erase_fill = (0xFF if fv_attributes & FV_ATTR_ERASE_POLARITY else 0x00,)
    while pos + FFS_HEADER_SIZE <= end and count < MAX_FILES:
        if _is_uniform_fill(buf, pos, end, erase_fill):
            return
        header = buf[pos:pos + FFS_HEADER_SIZE]
        size = int.from_bytes(header[20:23], "little")
        file_type = header[18]
        attributes = header[19]
        body_offset = FFS_HEADER_SIZE
        if attributes & FFS_ATTRIB_LARGE_FILE:
            if pos + 32 > end:
                _warn_dropped(
                    walk_state, f"malformed file header at {path}/file@0x{pos - fv_start:x}",
                    "rest of volume dropped")
                return
            size = struct.unpack_from("<Q", buf, pos + 24)[0]
            body_offset = 32
        if size == 0xFFFFFF or size < body_offset or pos + size > end:
            _warn_dropped(
                walk_state, f"malformed file header at {path}/file@0x{pos - fv_start:x}",
                "rest of volume dropped")
            return
        count += 1
        if file_type not in (FFS_FILE_TYPE_PAD, FFS_FILE_TYPE_FREE):
            file_path = f"{path}/file@0x{pos - fv_start:x}"
            file = FfsFile(guid=str(uuid.UUID(bytes_le=header[:16])),
                           type=file_type, path=file_path)
            if file_type != FFS_FILE_TYPE_RAW:
                file.sections = list(_iter_sections(
                    buf[pos + body_offset:pos + size], file_path, walk_state, depth))
            for section in file.sections:
                if section.type == SECTION_USER_INTERFACE and file.ui_name is None:
                    file.ui_name = section.data.decode(
                        "utf-16-le", errors="replace").rstrip("\x00")
            walk_state.files.append(file)
        pos += (size + 7) & ~7  # files are 8-byte aligned
    if pos >= end or _is_uniform_fill(buf, pos, end, erase_fill):
        return
    if count >= MAX_FILES:
        _warn_dropped(
            walk_state, f"file budget of {MAX_FILES} reached at {path}",
            "remaining files dropped")
    else:
        _warn_dropped(
            walk_state, f"malformed file header at {path}/file@0x{pos - fv_start:x}",
            "rest of volume dropped")


def _walk_volumes(buf: bytes, path: str, walk_state: "_Walk", depth: int) -> None:
    if depth > MAX_DEPTH:
        _warn_dropped(
            walk_state, f"nesting budget of {MAX_DEPTH} exceeded at {path}",
            "volume dropped")
        return
    for fv_start, header_length, fv_length in find_volumes(buf):
        if buf[fv_start + 16:fv_start + 32] not in FFS_FILESYSTEM_GUIDS:
            continue
        _iter_files(buf, fv_start, header_length, fv_length,
                    f"{path}/fv@0x{fv_start:x}", walk_state, depth)


def walk(image: bytes) -> WalkResult:
    """Every FFS file in the image, including files inside nested volumes,
    plus a warning for every place the walk had to give up."""
    walk_state = _Walk(MAX_TOTAL_DECOMPRESSED)
    _walk_volumes(image, "image", walk_state, 0)
    return WalkResult(files=walk_state.files, warnings=walk_state.warnings)

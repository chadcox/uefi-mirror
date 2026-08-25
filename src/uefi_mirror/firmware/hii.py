"""Locate HII package lists inside firmware buffers.

Firmware stores HII data in several different section shapes depending on the
builder, so rather than trusting any one container this scans for form packages
and proves each candidate by walking its IFR opcode stream: a real form package
consumes exactly its declared length and closes every scope it opens. False
positives essentially cannot survive that (971 raw signature hits on the ASUS
2402 image collapse to 25 real packages).
"""

import hashlib
import re
import struct
import uuid
from dataclasses import dataclass, field

from .ifr import validate_ifr
from .strings import LANGUAGE_OFFSET, parse_string_package

PACKAGE_FORMS = 0x02
PACKAGE_STRINGS = 0x04
PACKAGE_END = 0xDF
VALID_PACKAGE_TYPES = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0xDF}

OP_FORM_SET = 0x0E
FORM_SET_MIN_HEADER = 0x17  # opcode, length, GUID, title, help, flags

MAX_PACKAGE_BYTES = 16 << 20
MIN_FORM_PACKAGE_BYTES = 0x20

LANGUAGE_PREFERENCE = ("en-US", "en-us", "en")
_LANGUAGE_CANDIDATE = re.compile(rb"[A-Za-z][A-Za-z0-9-]{1,31}\x00")


@dataclass
class PackageList:
    source: str
    offset: int
    formset_guid: str
    form_package: bytes
    strings: dict[str, dict[int, str]] = field(default_factory=dict)

    @property
    def ifr(self) -> bytes:
        return self.form_package[4:]

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.form_package).hexdigest()

    def language(self) -> str | None:
        for pref in LANGUAGE_PREFERENCE:
            if pref in self.strings:
                return pref
        for lang in self.strings:
            if lang.lower().startswith("en"):
                return lang
        return next(iter(self.strings), None)

    def text(self, string_id: int) -> str:
        lang = self.language()
        if lang is None or not string_id:
            return ""
        return self.strings[lang].get(string_id, "")


def _package_header(buf: bytes, pos: int) -> tuple[int, int] | None:
    if pos + 4 > len(buf):
        return None
    value = struct.unpack_from("<I", buf, pos)[0]
    length, ptype = value & 0xFFFFFF, value >> 24
    if ptype not in VALID_PACKAGE_TYPES or length < 4 or pos + length > len(buf):
        return None
    return length, ptype


def _trailing_strings(buf: bytes, pos: int) -> dict[str, dict[int, str]]:
    """Packages in a list are contiguous, so read forward from the form package
    until the list's END package or the first thing that is not a package."""
    out: dict[str, dict[int, str]] = {}
    while True:
        header = _package_header(buf, pos)
        if header is None:
            return out
        length, ptype = header
        if ptype == PACKAGE_END:
            return out
        if ptype == PACKAGE_STRINGS and length <= MAX_PACKAGE_BYTES:
            lang, strings = parse_string_package(buf[pos:pos + length])
            if lang and strings:
                out.setdefault(lang, strings)
        pos += length


def find_string_packages(buf: bytes) -> list[tuple[int, str, dict[int, str]]]:
    """String packages that are not part of a form package's own list.

    A string package declares HdrSize, which must land exactly past its
    NUL-terminated language code -- a tight enough constraint to scan on.
    """
    out = []
    for match in _LANGUAGE_CANDIDATE.finditer(buf):
        start = match.start() - LANGUAGE_OFFSET
        if start < 0 or buf[start + 3] != PACKAGE_STRINGS:
            continue
        header = _package_header(buf, start)
        if header is None or header[1] != PACKAGE_STRINGS:
            continue
        length = header[0]
        if length > MAX_PACKAGE_BYTES:
            continue
        header_size, string_info_offset = struct.unpack_from("<II", buf, start + 4)
        if header_size != match.end() - start or not (
                header_size <= string_info_offset < length):
            continue
        lang, strings = parse_string_package(buf[start:start + length])
        if lang and strings:
            out.append((start, lang, strings))
    return out


def find_package_lists(source: str, buf: bytes) -> list[PackageList]:
    found = []
    pos = 0
    while True:
        pos = buf.find(bytes([OP_FORM_SET]), pos + 1)
        if pos < 4:
            if pos < 0:
                break
            continue
        if buf[pos - 1] != PACKAGE_FORMS or pos + 2 > len(buf):
            continue
        start = pos - 4
        header = _package_header(buf, start)
        if header is None:
            continue
        length, _ = header
        if not (MIN_FORM_PACKAGE_BYTES <= length <= MAX_PACKAGE_BYTES):
            continue
        flags = buf[pos + 1]
        if not (flags & 0x80) or (flags & 0x7F) < FORM_SET_MIN_HEADER:
            continue
        if validate_ifr(buf[start + 4:start + length]) is None:
            continue
        found.append(PackageList(
            source=source,
            offset=start,
            formset_guid=str(uuid.UUID(bytes_le=buf[pos + 2:pos + 18])),
            form_package=buf[start:start + length],
            strings=_trailing_strings(buf, start + length),
        ))
        pos = start + length
    return found


def collect(files) -> list[PackageList]:
    """Find every form package, pairing it with the strings from its own FFS
    file, and drop the duplicates that recovery/backup volumes carry."""
    by_hash: dict[str, PackageList] = {}
    for file in files:
        found: list[PackageList] = []
        pool: dict[str, dict[int, str]] = {}
        for section in file.sections:
            found.extend(find_package_lists(file.describe(), section.data))
            for _, lang, strings in find_string_packages(section.data):
                # Earlier packages win; a driver lists its own strings first.
                pool.setdefault(lang, {}).update(
                    {k: v for k, v in strings.items() if k not in pool[lang]})
        for pkg in found:
            for lang, strings in pool.items():
                pkg.strings.setdefault(lang, strings)
            existing = by_hash.get(pkg.sha256)
            if existing is None or (not existing.strings and pkg.strings):
                by_hash[pkg.sha256] = pkg
    return sorted(by_hash.values(), key=lambda p: (p.formset_guid, p.sha256))

"""HII string package parsing (UEFI 2.10 sec. 33.3.6).

EFI_HII_STRING_PACKAGE_HDR:
    EFI_HII_PACKAGE_HEADER Header;      //  0  Length:24 | Type:8
    UINT32 HdrSize;                     //  4
    UINT32 StringInfoOffset;            //  8
    CHAR16 LanguageWindow[16];          // 12
    EFI_STRING_ID LanguageName;         // 44
    CHAR8 Language[];                   // 46, NUL-terminated
"""

import struct

LANGUAGE_OFFSET = 46
MAX_STRINGS_PER_PACKAGE = 1 << 17
MAX_STRING_CHARS = 4096

SIBT_END = 0x00
SIBT_STRING_UCS2 = 0x14
SIBT_STRING_UCS2_FONT = 0x15
SIBT_STRINGS_UCS2 = 0x16
SIBT_STRINGS_UCS2_FONT = 0x17
SIBT_DUPLICATE = 0x20
SIBT_SKIP2 = 0x21
SIBT_SKIP1 = 0x22
SIBT_EXT1 = 0x30
SIBT_EXT2 = 0x31
SIBT_EXT4 = 0x32
SIBT_FONT = 0x40


def _ucs2(buf: bytes, pos: int) -> tuple[str, int]:
    """Read one NUL-terminated UCS-2 string, return it and the position after."""
    end = pos
    limit = min(len(buf) - 1, pos + MAX_STRING_CHARS * 2)
    while end < limit and buf[end:end + 2] != b"\x00\x00":
        end += 2
    text = buf[pos:end].decode("utf-16-le", errors="replace")
    return text, end + 2


def parse_language(package: bytes) -> str:
    end = package.find(b"\x00", LANGUAGE_OFFSET)
    if end < 0:
        return ""
    return package[LANGUAGE_OFFSET:end].decode("ascii", errors="replace")


def parse_string_package(package: bytes) -> tuple[str, dict[int, str]]:
    """Return (language, {string_id: text}). String IDs start at 1; ID 0 is
    reserved and never emitted by a string block."""
    if len(package) < LANGUAGE_OFFSET + 1:
        return "", {}
    string_info_offset = struct.unpack_from("<I", package, 8)[0]
    if not (LANGUAGE_OFFSET <= string_info_offset < len(package)):
        return parse_language(package), {}

    strings: dict[int, str] = {}
    pos = string_info_offset
    sid = 1
    while pos < len(package) and len(strings) < MAX_STRINGS_PER_PACKAGE:
        block = package[pos]
        pos += 1
        if block == SIBT_END:
            break
        if block in (SIBT_STRING_UCS2, SIBT_STRING_UCS2_FONT):
            if block == SIBT_STRING_UCS2_FONT:
                pos += 1  # FontIdentifier
            strings[sid], pos = _ucs2(package, pos)
            sid += 1
        elif block in (SIBT_STRINGS_UCS2, SIBT_STRINGS_UCS2_FONT):
            if block == SIBT_STRINGS_UCS2_FONT:
                pos += 1
            if pos + 2 > len(package):
                break
            count = struct.unpack_from("<H", package, pos)[0]
            pos += 2
            for _ in range(min(count, MAX_STRINGS_PER_PACKAGE)):
                strings[sid], pos = _ucs2(package, pos)
                sid += 1
        elif block == SIBT_DUPLICATE:
            if pos + 2 > len(package):
                break
            source = struct.unpack_from("<H", package, pos)[0]
            pos += 2
            strings[sid] = strings.get(source, "")
            sid += 1
        elif block == SIBT_SKIP1:
            if pos >= len(package):
                break
            sid += package[pos]
            pos += 1
        elif block == SIBT_SKIP2:
            if pos + 2 > len(package):
                break
            sid += struct.unpack_from("<H", package, pos)[0]
            pos += 2
        elif block in (SIBT_EXT1, SIBT_EXT2, SIBT_EXT4, SIBT_FONT):
            # BlockType, ExtType(1), Length(1|2|4) -- Length covers the whole block.
            width = {SIBT_EXT1: 1, SIBT_EXT2: 2, SIBT_EXT4: 4, SIBT_FONT: 4}[block]
            if pos + 1 + width > len(package):
                break
            length = int.from_bytes(package[pos + 1:pos + 1 + width], "little")
            if length < 2 + width:
                break
            pos += length - 1
        else:
            # Unknown block: the ID numbering is now unrecoverable, so stop
            # rather than emit strings under wrong IDs.
            break
    return parse_language(package), strings

"""Build a miniature UEFI image in memory so the parsers can be tested without
shipping a multi-megabyte vendor BIOS."""

import struct
import uuid

FORMSET_GUID = uuid.UUID("11111111-2222-3333-4444-555555555555")
VARSTORE_GUID = uuid.UUID("ec87d643-eba4-4bb5-a1e5-3f3e36b20da9")
FFS_GUID = uuid.UUID("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
FV_FILESYSTEM_GUID = uuid.UUID("8c8ce578-8a3d-4f1c-9935-896185c32dd3")
CAPSULE_GUID = uuid.UUID("4a3ca68b-7723-48fb-803d-578cc1fec44d")

STRINGS = [
    "",                       # id 0 is reserved
    "Example Setup",          # 1 form set title
    "Advanced",               # 2 form title
    "PCI Subsystem Settings",  # 3 subtitle
    "Above 4G Decoding",      # 4 prompt
    "Enable or disable 64bit capable devices.",  # 5 help
    "Disabled",               # 6
    "Enabled",                # 7
    "Master Switch",          # 8 prompt of the question others depend on
    "Dependent Option",       # 9 prompt of the suppressed question
    "Variant Setup",          # 10 title of a per-CPU-family form set
    "Numeric",                # 11
    "Checkbox",               # 12
    "Date",                   # 13
    "Time",                   # 14
    "Action",                 # 15
    "Choice A",               # 16
    "Choice B",               # 17
]


def _op(opcode: int, body: bytes = b"", scope: bool = False) -> bytes:
    length = 2 + len(body)
    return bytes([opcode, length | (0x80 if scope else 0)]) + body


def build_ifr() -> bytes:
    form_set = _op(0x0E, FORMSET_GUID.bytes_le + struct.pack("<HHB", 1, 0, 0)
                   + uuid.UUID(int=0).bytes_le, scope=True)
    varstore = _op(0x24, VARSTORE_GUID.bytes_le + struct.pack("<HH", 1, 0x100)
                   + b"Setup\x00")
    form = _op(0x01, struct.pack("<HH", 0x10, 2), scope=True)
    subtitle = _op(0x02, struct.pack("<HHB", 3, 0, 0), scope=True)
    one_of = _op(0x05, struct.pack("<HHHHHB", 4, 5, 0x1234, 1, 0x90, 0)
                 + bytes([0x00, 0, 1, 1]), scope=True)
    disabled = _op(0x09, struct.pack("<HBBB", 6, 0x00, 0, 0))
    enabled = _op(0x09, struct.pack("<HBBB", 7, 0x10, 0, 1))
    end = _op(0x29)
    return (form_set + varstore + form + subtitle + one_of + disabled + enabled
            + end + end + end + end)


def _one_of(prompt: int, question_id: int, offset: int) -> bytes:
    """A one-of with Disabled=0 / Enabled=1, stored at `offset`."""
    return (_op(0x05, struct.pack("<HHHHHB", prompt, 5, question_id, 1, offset, 0)
                + bytes([0x00, 0, 1, 1]), scope=True)
            + _op(0x09, struct.pack("<HBBB", 6, 0x00, 0, 0))
            + _op(0x09, struct.pack("<HBBB", 7, 0x10, 0, 1))
            + _op(0x29))


def build_conditional_ifr() -> bytes:
    """A master switch, and a question the firmware suppresses when it is on."""
    form_set = _op(0x0E, FORMSET_GUID.bytes_le + struct.pack("<HHB", 1, 0, 0)
                   + uuid.UUID(int=0).bytes_le, scope=True)
    varstore = _op(0x24, VARSTORE_GUID.bytes_le + struct.pack("<HH", 1, 0x100)
                   + b"Setup\x00")
    form = _op(0x01, struct.pack("<HH", 0x10, 2), scope=True)
    suppress = (_op(0x0A, scope=True)
                + _op(0x12, struct.pack("<HH", 0x1234, 1))
                + _one_of(9, 0x1235, 1)
                + _op(0x29))
    return (form_set + varstore + form + _one_of(8, 0x1234, 0) + suppress
            + _op(0x29) + _op(0x29))


def build_variant_ifr(varstore_name: str, question_id: int) -> bytes:
    """A form set distinguished from its siblings only by varstore name --
    the shape vendors use to ship one form set per CPU family."""
    guid = uuid.UUID(int=question_id)
    form_set = _op(0x0E, guid.bytes_le + struct.pack("<HHB", 10, 0, 0)
                   + uuid.UUID(int=0).bytes_le, scope=True)
    varstore = _op(0x24, VARSTORE_GUID.bytes_le + struct.pack("<HH", 1, 0x10)
                   + varstore_name.encode() + b"\x00")
    form = _op(0x01, struct.pack("<HH", 0x10, 2), scope=True)
    return (form_set + varstore + form + _one_of(8, question_id, 0)
            + _op(0x29) + _op(0x29))


def build_question_kinds_ifr() -> bytes:
    form_set = _op(0x0E, FORMSET_GUID.bytes_le + struct.pack("<HHB", 1, 0, 0)
                   + uuid.UUID(int=0).bytes_le, scope=True)
    varstore = _op(0x24, VARSTORE_GUID.bytes_le + struct.pack("<HH", 1, 0x100)
                   + b"Setup\x00")
    form = _op(0x01, struct.pack("<HH", 0x10, 2), scope=True)
    def header(prompt, qid, offset):
        return struct.pack("<HHHHHB", prompt, 0, qid, 1, offset, 0)
    date = _op(0x1A, header(13, 1, 0) + b"\x00")
    time = _op(0x1B, header(14, 2, 4) + b"\x00")
    action = _op(0x0C, header(15, 3, 8) + b"\x00")
    return form_set + varstore + form + date + time + action + _op(0x29) + _op(0x29)


def build_conditional_options_ifr() -> bytes:
    form_set = _op(0x0E, FORMSET_GUID.bytes_le + struct.pack("<HHB", 1, 0, 0)
                   + uuid.UUID(int=0).bytes_le, scope=True)
    varstore = _op(0x24, VARSTORE_GUID.bytes_le + struct.pack("<HH", 1, 0x100)
                   + b"Setup\x00")
    form = _op(0x01, struct.pack("<HH", 0x10, 2), scope=True)
    enum = _op(0x05, struct.pack("<HHHHHB", 4, 0, 2, 1, 1, 0)
               + bytes([0x10, 0, 7, 1]), scope=True)
    first = (_op(0x0A, scope=True) + _op(0x12, struct.pack("<HH", 1, 1))
             + _op(0x09, struct.pack("<HBBB", 16, 0, 0, 7)) + _op(0x29))
    second = (_op(0x0A, scope=True) + _op(0x12, struct.pack("<HH", 1, 0))
              + _op(0x09, struct.pack("<HBBB", 17, 0, 0, 7)) + _op(0x29))
    return (form_set + varstore + form + _one_of(8, 1, 0) + enum + first + second
            + _op(0x29) + _op(0x29) + _op(0x29))


def build_string_package(language: str = "en-US") -> bytes:
    language_bytes = language.encode() + b"\x00"
    header_size = 46 + len(language_bytes)
    blocks = b""
    for text in STRINGS[1:]:
        blocks += b"\x14" + text.encode("utf-16-le") + b"\x00\x00"
    blocks += b"\x00"  # SIBT_END
    body = struct.pack("<II", header_size, header_size) + b"\x00" * 32 \
        + struct.pack("<H", 0) + language_bytes + blocks
    return struct.pack("<I", (0x04 << 24) | (len(body) + 4)) + body


def build_package_list(ifr: bytes | None = None) -> bytes:
    ifr = build_ifr() if ifr is None else ifr
    forms = struct.pack("<I", (0x02 << 24) | (len(ifr) + 4)) + ifr
    strings = build_string_package()
    end = struct.pack("<I", (0xDF << 24) | 4)
    packages = forms + strings + end
    return ifr[2:18] + struct.pack("<I", len(packages) + 20) + packages


def build_section(section_type: int, body: bytes) -> bytes:
    size = len(body) + 4
    section = struct.pack("<I", (section_type << 24) | size) + body
    return section + b"\x00" * (-len(section) % 4)


def build_ffs_file(sections: bytes) -> bytes:
    size = len(sections) + 24
    header = (FFS_GUID.bytes_le + struct.pack("<HBB", 0xAA55, 0x07, 0x00)
              + size.to_bytes(3, "little") + bytes([0xF8]))
    file = header + sections
    return file + b"\x00" * (-len(file) % 8)


def build_firmware_volume(files: bytes) -> bytes:
    header_length = 56 + 16
    fv_length = header_length + len(files)
    header = (b"\x00" * 16 + FV_FILESYSTEM_GUID.bytes_le
              + struct.pack("<Q", fv_length) + b"_FVH"
              + struct.pack("<IHHHBB", 0x0004FEFF, header_length, 0, 0, 0, 2)
              + struct.pack("<IIQ", 1, 0x1000, 0))
    words = struct.unpack(f"<{len(header) // 2}H", header)
    checksum = (-sum(words)) & 0xFFFF
    header = header[:50] + struct.pack("<H", checksum) + header[52:]
    return header + files


def build_image(ifr: bytes | None = None) -> bytes:
    package_list = build_package_list(ifr)
    sections = (build_section(0x19, package_list)
                + build_section(0x15, "ExampleSetupDxe".encode("utf-16-le") + b"\x00\x00"))
    return build_firmware_volume(build_ffs_file(sections))


def build_capsule(payload: bytes | None = None) -> bytes:
    payload = build_image() if payload is None else payload
    header_size = 4096
    header = (CAPSULE_GUID.bytes_le
              + struct.pack("<III", header_size, 0x10001, header_size + len(payload)))
    return header + b"\x00" * (header_size - len(header)) + payload

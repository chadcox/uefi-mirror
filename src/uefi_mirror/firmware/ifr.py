"""Internal Forms Representation parsing (UEFI 2.10 sec. 33.2.5 / 33.3.8)."""

import struct
import uuid
from dataclasses import dataclass, field

from . import expr

OPCODE_NAMES = {
    0x01: "form", 0x02: "subtitle", 0x03: "text", 0x04: "image", 0x05: "one_of",
    0x06: "checkbox", 0x07: "numeric", 0x08: "password", 0x09: "one_of_option",
    0x0A: "suppress_if", 0x0B: "locked", 0x0C: "action", 0x0D: "reset_button",
    0x0E: "form_set", 0x0F: "ref", 0x10: "no_submit_if", 0x11: "inconsistent_if",
    0x12: "eq_id_val", 0x13: "eq_id_id", 0x14: "eq_id_val_list", 0x15: "and",
    0x16: "or", 0x17: "not", 0x18: "rule", 0x19: "gray_out_if", 0x1A: "date",
    0x1B: "time", 0x1C: "string", 0x1D: "refresh", 0x1E: "disable_if",
    0x1F: "animation", 0x20: "to_lower", 0x21: "to_upper", 0x22: "map",
    0x23: "ordered_list", 0x24: "varstore", 0x25: "varstore_name_value",
    0x26: "varstore_efi", 0x27: "varstore_device", 0x28: "version", 0x29: "end",
    0x2A: "match", 0x2B: "get", 0x2C: "set", 0x2D: "read", 0x2E: "write",
    0x2F: "equal", 0x30: "not_equal", 0x31: "greater_than", 0x32: "greater_equal",
    0x33: "less_than", 0x34: "less_equal", 0x35: "bitwise_and", 0x36: "bitwise_or",
    0x37: "bitwise_not", 0x38: "shift_left", 0x39: "shift_right", 0x3A: "add",
    0x3B: "subtract", 0x3C: "multiply", 0x3D: "divide", 0x3E: "modulo",
    0x3F: "rule_ref", 0x40: "question_ref1", 0x41: "question_ref2", 0x42: "uint8",
    0x43: "uint16", 0x44: "uint32", 0x45: "uint64", 0x46: "true", 0x47: "false",
    0x48: "to_uint", 0x49: "to_string", 0x4A: "to_boolean", 0x4B: "mid",
    0x4C: "find", 0x4D: "token", 0x4E: "string_ref1", 0x4F: "string_ref2",
    0x50: "conditional", 0x51: "question_ref3", 0x52: "zero", 0x53: "one",
    0x54: "ones", 0x55: "undefined", 0x56: "length", 0x57: "dup", 0x58: "this",
    0x59: "span", 0x5A: "value", 0x5B: "default", 0x5C: "defaultstore",
    0x5D: "form_map", 0x5E: "catenate", 0x5F: "guid", 0x60: "security",
    0x61: "modal_tag", 0x62: "refresh_id", 0x63: "warning_if", 0x64: "match2",
}

OP_FORM = 0x01
OP_SUBTITLE = 0x02
OP_ONE_OF = 0x05
OP_CHECKBOX = 0x06
OP_NUMERIC = 0x07
OP_PASSWORD = 0x08
OP_ONE_OF_OPTION = 0x09
OP_SUPPRESS_IF = 0x0A
OP_FORM_SET = 0x0E
OP_GRAY_OUT_IF = 0x19
OP_DATE = 0x1A
OP_TIME = 0x1B
OP_STRING = 0x1C
OP_DISABLE_IF = 0x1E
OP_REF = 0x0F
OP_ORDERED_LIST = 0x23
OP_VARSTORE = 0x24
OP_VARSTORE_NAME_VALUE = 0x25
OP_VARSTORE_EFI = 0x26
OP_END = 0x29
OP_VALUE = 0x5A
OP_DEFAULT = 0x5B

CONDITION_OPS = {OP_SUPPRESS_IF: "suppress_if", OP_GRAY_OUT_IF: "gray_out_if",
                 OP_DISABLE_IF: "disable_if"}
QUESTION_OPS = {OP_ONE_OF: "one_of", OP_CHECKBOX: "checkbox", OP_NUMERIC: "numeric",
                OP_ORDERED_LIST: "ordered_list", OP_STRING: "string",
                OP_PASSWORD: "password", OP_DATE: "date", OP_TIME: "time"}

# EFI_IFR_TYPE_*
TYPE_NUM_SIZE_8, TYPE_NUM_SIZE_16, TYPE_NUM_SIZE_32, TYPE_NUM_SIZE_64 = 0, 1, 2, 3
TYPE_BOOLEAN, TYPE_TIME, TYPE_DATE, TYPE_STRING = 4, 5, 6, 7
VALUE_WIDTH = {TYPE_NUM_SIZE_8: 1, TYPE_NUM_SIZE_16: 2, TYPE_NUM_SIZE_32: 4,
               TYPE_NUM_SIZE_64: 8, TYPE_BOOLEAN: 1, TYPE_STRING: 2}

QUESTION_HEADER_SIZE = 11  # prompt, help, question id, varstore id, varstore info, flags
# EFI_IFR_NUMERIC flags: bits 0-1 pick the storage width, bits 4-5 the display.
NUMERIC_SIZE_MASK = 0x03
NUMERIC_DISPLAY_MASK = 0x30
DISPLAY_INT_DEC = 0x00
DISPLAY_UINT_DEC = 0x10
DISPLAY_UINT_HEX = 0x20

CHECKBOX_DEFAULT = 0x01
CHECKBOX_DEFAULT_MFG = 0x02

DEFAULT_STANDARD = 0x0000
DEFAULT_MANUFACTURING = 0x0001
MAX_CONDITION_TOKENS = 24
MAX_SCOPE_DEPTH = 256


@dataclass
class VarStore:
    varstore_id: int
    guid: str
    name: str
    size: int | None
    kind: str
    attributes: int | None = None


@dataclass
class Option:
    text_id: int
    value: int | None
    value_type: int
    flags: int
    conditions: list["Condition"] = field(default_factory=list)

    @property
    def is_default(self) -> bool:
        return bool(self.flags & 0x10)

    @property
    def is_manufacturing_default(self) -> bool:
        return bool(self.flags & 0x20)


@dataclass
class Condition:
    kind: str
    expression: str
    code: bytes = b""


@dataclass
class Question:
    opcode: int
    kind: str
    offset: int
    prompt_id: int
    help_id: int
    question_id: int
    varstore_id: int
    varstore_info: int
    flags: int
    form_id: int | None
    form_title_id: int | None
    checkbox_flags: int = 0
    subtitle_ids: list[int] = field(default_factory=list)
    options: list[Option] = field(default_factory=list)
    defaults: dict[int, int | None] = field(default_factory=dict)
    conditions: list[Condition] = field(default_factory=list)
    value_size: int | None = None
    display: int = DISPLAY_UINT_DEC
    minimum: int | None = None
    maximum: int | None = None
    step: int | None = None

    @property
    def var_offset(self) -> int:
        return self.varstore_info


@dataclass
class FormSet:
    guid: str
    title_id: int
    help_id: int
    class_guids: list[str]
    varstores: dict[int, VarStore]
    questions: list[Question]
    forms: dict[int, int] = field(default_factory=dict)
    refs: list[tuple[int, int]] = field(default_factory=list)


def validate_ifr(body: bytes) -> int | None:
    """Walk opcodes. Return the opcode count if the stream is well formed.

    Each opcode is: OpCode(1), Length:7|Scope:1(1), payload. A scope bit opens a
    scope that a later EFI_IFR_END closes. Real IFR lands exactly on the final
    byte with every scope closed.
    """
    pos = 0
    depth = 0
    count = 0
    while pos + 2 <= len(body):
        length = body[pos + 1] & 0x7F
        if length < 2 or pos + length > len(body):
            return None
        if body[pos + 1] & 0x80:
            depth += 1
            if depth > MAX_SCOPE_DEPTH:
                return None
        if body[pos] == OP_END:
            depth -= 1
            if depth < 0:
                return None
        pos += length
        count += 1
        if depth == 0 and count > 1:
            break
    if pos != len(body) or depth != 0 or count <= 2:
        return None
    return count


def _read_value(data: bytes, pos: int, value_type: int) -> tuple[int | None, int]:
    width = VALUE_WIDTH.get(value_type)
    if width is None or pos + width > len(data):
        return None, pos
    return int.from_bytes(data[pos:pos + width], "little"), pos + width


def _cstr(data: bytes, pos: int) -> str:
    end = data.find(b"\x00", pos)
    return data[pos:end if end >= 0 else len(data)].decode("ascii", errors="replace")


def _expression_text(code: bytes) -> str:
    """Name the opcodes of an expression, for humans reading the JSON."""
    tokens = []
    pos = 0
    while pos + 2 <= len(code) and len(tokens) < MAX_CONDITION_TOKENS:
        length = code[pos + 1] & 0x7F
        if length < 2:
            break
        tokens.append(OPCODE_NAMES.get(code[pos], f"op_{code[pos]:02x}"))
        pos += length
    return " ".join(tokens)


def parse_form_set(ifr: bytes) -> FormSet | None:
    """Walk a validated IFR stream and pull out varstores and questions."""
    if len(ifr) < 2 or ifr[0] != OP_FORM_SET:
        return None

    header_len = ifr[1] & 0x7F
    guid = str(uuid.UUID(bytes_le=ifr[2:18]))
    title_id, help_id = struct.unpack_from("<HH", ifr, 18)
    class_guids = [str(uuid.UUID(bytes_le=ifr[i:i + 16]))
                   for i in range(23, header_len - 15, 16)]

    varstores: dict[int, VarStore] = {}
    questions: list[Question] = []
    forms: dict[int, int] = {}
    refs: list[tuple[int, int]] = []

    # Scope stack entries describe what enclosing scopes mean for a question.
    stack: list[dict] = []
    form_id: int | None = None
    form_title_id: int | None = None
    current: Question | None = None
    pos = 0

    while pos + 2 <= len(ifr):
        op = ifr[pos]
        raw_len = ifr[pos + 1]
        length = raw_len & 0x7F
        scoped = bool(raw_len & 0x80)
        if length < 2 or pos + length > len(ifr):
            break
        body = ifr[pos + 2:pos + length]
        frame = {"op": op}

        if op == OP_END:
            if not stack:
                break
            closed = stack.pop()
            if closed.get("question") is not None:
                current = None
            if closed["op"] == OP_FORM:
                form_id = form_title_id = None
            pos += length
            continue

        if op == OP_VARSTORE and len(body) >= 20:
            vid, vsize = struct.unpack_from("<HH", body, 16)
            varstores[vid] = VarStore(vid, str(uuid.UUID(bytes_le=body[:16])),
                                      _cstr(body, 20), vsize, "buffer")
        elif op == OP_VARSTORE_EFI and len(body) >= 24:
            vid = struct.unpack_from("<H", body, 0)[0]
            attrs, vsize = struct.unpack_from("<IH", body, 18)
            varstores[vid] = VarStore(vid, str(uuid.UUID(bytes_le=body[2:18])),
                                      _cstr(body, 24), vsize, "efi", attrs)
        elif op == OP_VARSTORE_EFI and len(body) >= 22:
            # Pre-2.3 form: no Size/Name fields.
            vid = struct.unpack_from("<H", body, 0)[0]
            varstores[vid] = VarStore(vid, str(uuid.UUID(bytes_le=body[2:18])),
                                      "", None, "efi",
                                      struct.unpack_from("<I", body, 18)[0])
        elif op == OP_VARSTORE_NAME_VALUE and len(body) >= 18:
            vid = struct.unpack_from("<H", body, 0)[0]
            varstores[vid] = VarStore(vid, str(uuid.UUID(bytes_le=body[2:18])),
                                      "", None, "name_value")
        elif op == OP_FORM and len(body) >= 4:
            form_id, form_title_id = struct.unpack_from("<HH", body, 0)
            forms[form_id] = form_title_id
        elif op == OP_REF and len(body) >= 13 and form_id is not None:
            # EFI_IFR_REF: QuestionHeader then the destination FormId. This is
            # what makes the setup menu a tree rather than a flat form list.
            target = struct.unpack_from("<H", body, QUESTION_HEADER_SIZE)[0]
            if target and target != form_id:
                refs.append((form_id, target))
        elif op == OP_SUBTITLE and len(body) >= 2:
            frame["subtitle_id"] = struct.unpack_from("<H", body, 0)[0]
        elif op in CONDITION_OPS:
            # The expression is the run of expression opcodes that opens the
            # scope; the statements it governs follow it.
            code = expr.extract(ifr, pos + length)
            frame["condition"] = Condition(CONDITION_OPS[op],
                                           _expression_text(code), code)
        elif op in QUESTION_OPS and len(body) >= QUESTION_HEADER_SIZE:
            prompt, help_, qid, vsid, vsinfo = struct.unpack_from("<HHHHH", body, 0)
            q = Question(
                opcode=op, kind=QUESTION_OPS[op], offset=pos,
                prompt_id=prompt, help_id=help_, question_id=qid,
                varstore_id=vsid, varstore_info=vsinfo,
                flags=body[10], form_id=form_id, form_title_id=form_title_id,
                subtitle_ids=[f["subtitle_id"] for f in stack if "subtitle_id" in f],
                conditions=[f["condition"] for f in stack if "condition" in f],
            )
            _decode_question_tail(q, body)
            questions.append(q)
            current = q
            frame["question"] = q
        elif op == OP_ONE_OF_OPTION and current is not None and len(body) >= 4:
            text_id, flags, vtype = struct.unpack_from("<HBB", body, 0)
            value, _ = _read_value(body, 4, vtype)
            conditions = [f["condition"] for f in stack if "condition" in f]
            current.options.append(Option(text_id, value, vtype, flags, conditions))
        elif op == OP_DEFAULT and current is not None and len(body) >= 3:
            default_id, vtype = struct.unpack_from("<HB", body, 0)
            value, _ = _read_value(body, 3, vtype)
            current.defaults[default_id] = value
            if scoped and value is None:
                frame["default_id"] = default_id
        elif op == OP_VALUE and current is not None:
            default_id = next((f["default_id"] for f in reversed(stack)
                               if "default_id" in f), None)
            if default_id is not None:
                value = expr.evaluate_value(expr.extract(ifr, pos + length), expr.Resolver())
                if isinstance(value, (bool, int)):
                    current.defaults[default_id] = int(value)

        if scoped:
            stack.append(frame)
        pos += length

    return FormSet(guid, title_id, help_id, class_guids, varstores, questions,
                   forms, refs)


def _decode_question_tail(q: Question, body: bytes) -> None:
    """Per-opcode fields that follow EFI_IFR_QUESTION_HEADER."""
    tail = body[QUESTION_HEADER_SIZE:]
    if q.opcode == OP_CHECKBOX:
        q.value_size = 1
        q.checkbox_flags = tail[0] if tail else 0
    elif q.opcode in (OP_ONE_OF, OP_NUMERIC) and tail:
        flags = tail[0]
        q.value_size = VALUE_WIDTH[flags & NUMERIC_SIZE_MASK]
        q.display = flags & NUMERIC_DISPLAY_MASK
        width = q.value_size
        if len(tail) >= 1 + width * 3:
            q.minimum = int.from_bytes(tail[1:1 + width], "little")
            q.maximum = int.from_bytes(tail[1 + width:1 + 2 * width], "little")
            q.step = int.from_bytes(tail[1 + 2 * width:1 + 3 * width], "little")
    elif q.opcode == OP_STRING and len(tail) >= 3:
        q.minimum, q.maximum = tail[0], tail[1]
    elif q.opcode == OP_PASSWORD and len(tail) >= 4:
        q.minimum, q.maximum = struct.unpack_from("<HH", tail, 0)
    elif q.opcode == OP_ORDERED_LIST and len(tail) >= 2:
        q.maximum = tail[0]
    elif q.opcode in (OP_DATE, OP_TIME):
        # Their storage layout depends on flags in the opcode tail. Preserve
        # the question in the schema, but do not guess a byte slice.
        q.value_size = None


def referenced_string_ids(form_set: FormSet) -> set[int]:
    ids = {form_set.title_id}
    for q in form_set.questions:
        ids.add(q.prompt_id)
        ids.update(o.text_id for o in q.options)
    ids.discard(0)
    return ids

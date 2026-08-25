"""IFR expression extraction and evaluation (UEFI 2.10 sec. 33.3.8.3).

An IFR expression is a postfix opcode sequence evaluated on a stack. It decides
whether a question is suppressed, greyed out or disabled -- that is, whether the
setting a user reads in the JSON is one the firmware would actually show them.

Everything here is tri-state: `None` means "cannot be decided from what we
know". An expression that reads a question we could not decode, or uses an
opcode whose value only exists at runtime, yields None rather than a guess.
"""

import struct

# Opcodes legal inside an expression. Extraction stops at the first opcode that
# is not one of these, which is where the governed statements begin.
CONSTANT_OPS = {0x28, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x4E, 0x52, 0x53, 0x54, 0x55}
SELF_CONTAINED_OPS = {0x12, 0x13, 0x14, 0x40, 0x58, 0x3F, 0x60}
UNARY_OPS = {0x17, 0x20, 0x21, 0x37, 0x41, 0x48, 0x49, 0x4A, 0x4F, 0x51, 0x56, 0x57, 0x5F}
BINARY_OPS = {0x15, 0x16, 0x2A, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
              0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x4C, 0x4D, 0x5E, 0x64}
TERNARY_OPS = {0x22, 0x4B, 0x50, 0x59}
EXPRESSION_OPS = (CONSTANT_OPS | SELF_CONTAINED_OPS | UNARY_OPS
                  | BINARY_OPS | TERNARY_OPS)

OP_EQ_ID_VAL = 0x12
OP_EQ_ID_ID = 0x13
OP_EQ_ID_VAL_LIST = 0x14
OP_AND = 0x15
OP_OR = 0x16
OP_NOT = 0x17
OP_QUESTION_REF1 = 0x40
OP_THIS = 0x58
OP_DUP = 0x57
OP_CONDITIONAL = 0x50
OP_STRING_REF1 = 0x4E

UINT64_MASK = (1 << 64) - 1
MAX_STACK = 128
MAX_EXPRESSION_OPS = 512

_PUSH_CONSTANT = {
    0x46: True, 0x47: False, 0x52: 0, 0x53: 1, 0x54: UINT64_MASK, 0x55: None,
    0x28: None,  # EFI_IFR_VERSION: the running UEFI version, not in the image.
}
_INT_WIDTH = {0x42: 1, 0x43: 2, 0x44: 4, 0x45: 8}


def extract(ifr: bytes, pos: int) -> bytes:
    """Take the expression that starts at `pos`, stopping where it ends."""
    start = pos
    seen = 0
    while pos + 2 <= len(ifr) and seen < MAX_EXPRESSION_OPS:
        opcode = ifr[pos]
        length = ifr[pos + 1] & 0x7F
        if opcode not in EXPRESSION_OPS or length < 2 or pos + length > len(ifr):
            break
        pos += length
        seen += 1
    return ifr[start:pos]


def _kleene_and(a, b):
    if a is False or b is False:
        return False
    if a is None or b is None:
        return None
    return bool(a) and bool(b)


def _kleene_or(a, b):
    if a is True or b is True:
        return True
    if a is None or b is None:
        return None
    return bool(a) or bool(b)


def _as_int(value):
    if isinstance(value, bool):
        return int(value)
    return value if isinstance(value, int) else None


def _compare(opcode, left, right):
    a, b = _as_int(left), _as_int(right)
    if a is None or b is None:
        if isinstance(left, str) and isinstance(right, str):
            a, b = left, right
        else:
            return None
    return {0x2F: a == b, 0x30: a != b, 0x31: a > b,
            0x32: a >= b, 0x33: a < b, 0x34: a <= b}[opcode]


def _arithmetic(opcode, left, right):
    a, b = _as_int(left), _as_int(right)
    if opcode == 0x5E:  # CATENATE
        return (left + right) if isinstance(left, str) and isinstance(right, str) else None
    if a is None or b is None:
        return None
    if opcode in (0x3D, 0x3E) and b == 0:
        return None
    result = {
        0x35: lambda: a & b, 0x36: lambda: a | b,
        0x38: lambda: a << (b & 0x3F), 0x39: lambda: a >> (b & 0x3F),
        0x3A: lambda: a + b, 0x3B: lambda: a - b, 0x3C: lambda: a * b,
        0x3D: lambda: a // b, 0x3E: lambda: a % b,
    }[opcode]()
    return result & UINT64_MASK


class Resolver:
    """Supplies the runtime facts an expression may ask for."""

    def question_value(self, question_id: int) -> int | None:
        return None

    def this_value(self) -> int | None:
        return None

    def string(self, string_id: int) -> str | None:
        return None


def evaluate_value(expression: bytes, resolver: Resolver):
    """Run the postfix stream and return its raw result, or None."""
    stack: list = []
    pos = 0

    def pop():
        return stack.pop() if stack else None

    while pos + 2 <= len(expression):
        opcode = expression[pos]
        length = expression[pos + 1] & 0x7F
        if length < 2 or pos + length > len(expression) or len(stack) > MAX_STACK:
            return None
        body = expression[pos + 2:pos + length]
        pos += length

        if opcode in _PUSH_CONSTANT:
            stack.append(_PUSH_CONSTANT[opcode])
        elif opcode in _INT_WIDTH:
            width = _INT_WIDTH[opcode]
            stack.append(int.from_bytes(body[:width], "little")
                         if len(body) >= width else None)
        elif opcode == OP_STRING_REF1:
            stack.append(resolver.string(struct.unpack_from("<H", body, 0)[0])
                         if len(body) >= 2 else None)
        elif opcode == OP_QUESTION_REF1:
            stack.append(resolver.question_value(struct.unpack_from("<H", body, 0)[0])
                         if len(body) >= 2 else None)
        elif opcode == OP_THIS:
            stack.append(resolver.this_value())
        elif opcode == OP_EQ_ID_VAL:
            if len(body) < 4:
                return None
            question_id, value = struct.unpack_from("<HH", body, 0)
            actual = resolver.question_value(question_id)
            stack.append(None if actual is None else actual == value)
        elif opcode == OP_EQ_ID_ID:
            if len(body) < 4:
                return None
            left_id, right_id = struct.unpack_from("<HH", body, 0)
            left = resolver.question_value(left_id)
            right = resolver.question_value(right_id)
            stack.append(None if left is None or right is None else left == right)
        elif opcode == OP_EQ_ID_VAL_LIST:
            if len(body) < 4:
                return None
            question_id, count = struct.unpack_from("<HH", body, 0)
            actual = resolver.question_value(question_id)
            values = [struct.unpack_from("<H", body, 4 + i * 2)[0]
                      for i in range(min(count, (len(body) - 4) // 2))]
            stack.append(None if actual is None else actual in values)
        elif opcode == OP_NOT:
            value = pop()
            stack.append(None if value is None else not value)
        elif opcode == OP_DUP:
            value = pop()
            stack.extend((value, value))
        elif opcode == OP_AND:
            stack.append(_kleene_and(pop(), pop()))
        elif opcode == OP_OR:
            stack.append(_kleene_or(pop(), pop()))
        elif opcode in (0x2F, 0x30, 0x31, 0x32, 0x33, 0x34):
            right, left = pop(), pop()
            stack.append(_compare(opcode, left, right))
        elif opcode in (0x35, 0x36, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x5E):
            right, left = pop(), pop()
            stack.append(_arithmetic(opcode, left, right))
        elif opcode == 0x37:  # BITWISE_NOT
            value = _as_int(pop())
            stack.append(None if value is None else (~value) & UINT64_MASK)
        elif opcode == 0x4A:  # TO_BOOLEAN
            value = pop()
            stack.append(None if value is None else bool(value))
        elif opcode == 0x48:  # TO_UINT
            stack.append(_as_int(pop()))
        elif opcode == OP_CONDITIONAL:
            false_value, true_value, condition = pop(), pop(), pop()
            stack.append(None if condition is None
                         else (true_value if condition else false_value))
        elif opcode in UNARY_OPS:
            pop()
            stack.append(None)
        elif opcode in BINARY_OPS:
            pop(), pop()
            stack.append(None)
        elif opcode in TERNARY_OPS:
            pop(), pop(), pop()
            stack.append(None)
        else:
            return None

    if not stack:
        return None
    return stack[-1]


def evaluate(expression: bytes, resolver: Resolver) -> bool | None:
    """Run the postfix stream. Returns True, False, or None for undecidable."""
    result = evaluate_value(expression, resolver)
    return None if result is None else bool(result)


def referenced_questions(expression: bytes) -> list[int]:
    """Question IDs an expression reads, in first-seen order.

    Lets a consumer index conditions by the question they depend on without
    decoding the opcode stream itself.
    """
    found: list[int] = []
    pos = 0
    while pos + 2 <= len(expression):
        opcode = expression[pos]
        length = expression[pos + 1] & 0x7F
        if length < 2 or pos + length > len(expression):
            break
        body = expression[pos + 2:pos + length]
        pos += length
        if opcode in (OP_QUESTION_REF1, OP_EQ_ID_VAL, OP_EQ_ID_VAL_LIST) and len(body) >= 2:
            ids = [struct.unpack_from("<H", body, 0)[0]]
        elif opcode == OP_EQ_ID_ID and len(body) >= 4:
            ids = list(struct.unpack_from("<HH", body, 0))
        else:
            continue
        found.extend(i for i in ids if i not in found)
    return found

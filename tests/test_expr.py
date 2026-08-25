"""The expression evaluator decides whether the firmware would show a setting,
so a wrong answer here quietly mislabels the export. Undecidable must stay
undecidable rather than collapsing to a guess."""

import struct

import pytest

from uefi_mirror.firmware import expr
from tests.fixtures import _op


class Values(expr.Resolver):
    def __init__(self, **values):
        self.values = {int(k[1:], 0): v for k, v in values.items()}

    def question_value(self, question_id):
        return self.values.get(question_id)


def ev(code: bytes, resolver=None):
    return expr.evaluate(code, resolver or expr.Resolver())


TRUE = _op(0x46)
FALSE = _op(0x47)
NOT = _op(0x17)
AND = _op(0x15)
OR = _op(0x16)


def eq_id_val(question_id: int, value: int) -> bytes:
    return _op(0x12, struct.pack("<HH", question_id, value))


def uint8(value: int) -> bytes:
    return _op(0x42, bytes([value]))


def test_constants_and_negation():
    assert ev(TRUE) is True
    assert ev(FALSE) is False
    assert ev(TRUE + NOT) is False
    assert ev(_op(0x55)) is None  # EFI_IFR_UNDEFINED


def test_question_equality_uses_the_live_value():
    code = eq_id_val(0x1234, 1)
    assert ev(code, Values(q0x1234=1)) is True
    assert ev(code, Values(q0x1234=0)) is False


def test_an_unknown_question_makes_the_result_undecidable():
    assert ev(eq_id_val(0x1234, 1), Values(q0x9999=1)) is None


@pytest.mark.parametrize("left,right,operator,expected", [
    (TRUE, TRUE, AND, True),
    (TRUE, FALSE, AND, False),
    (FALSE, TRUE, OR, True),
    (FALSE, FALSE, OR, False),
])
def test_boolean_algebra(left, right, operator, expected):
    assert ev(left + right + operator) is expected


def test_kleene_logic_decides_what_it_can_despite_an_unknown():
    """False AND unknown is False whatever the unknown turns out to be."""
    unknown = eq_id_val(0x1234, 1)  # no resolver entry
    assert ev(FALSE + unknown + AND) is False
    assert ev(TRUE + unknown + OR) is True
    assert ev(TRUE + unknown + AND) is None
    assert ev(FALSE + unknown + OR) is None


def test_comparison_and_arithmetic():
    assert ev(uint8(7) + uint8(3) + _op(0x31)) is True    # 7 > 3
    assert ev(uint8(7) + uint8(3) + _op(0x33)) is False   # 7 < 3
    assert ev(uint8(2) + uint8(3) + _op(0x3A)) is True    # 2 + 3 -> 5, truthy
    assert ev(uint8(0) + uint8(3) + _op(0x3C)) is False   # 0 * 3 -> 0, falsey


def test_division_by_zero_is_undecidable_not_an_exception():
    assert ev(uint8(4) + uint8(0) + _op(0x3D)) is None


def test_value_list_membership():
    code = _op(0x14, struct.pack("<HHHH", 0x1234, 2, 5, 9))
    assert ev(code, Values(q0x1234=9)) is True
    assert ev(code, Values(q0x1234=6)) is False


def test_opcodes_needing_runtime_state_yield_undecidable():
    assert ev(_op(0x58)) is None                     # THIS
    assert ev(_op(0x3F, bytes([0]))) is None         # RULE_REF
    assert ev(_op(0x28)) is None                     # VERSION


def test_conditional_selects_a_branch():
    code = TRUE + uint8(1) + uint8(0) + _op(0x50)
    assert ev(code) is True
    assert ev(FALSE + uint8(1) + uint8(0) + _op(0x50)) is False


def test_raw_expression_value_is_available_for_nested_defaults():
    assert expr.evaluate_value(_op(0x43, struct.pack("<H", 0x1234)), expr.Resolver()) == 0x1234


@pytest.mark.parametrize("code", [
    b"", b"\x15", _op(0x15), b"\x46\x00", _op(0x46)[:1],
    bytes([0x42, 0x40]),
])
def test_malformed_streams_never_raise(code):
    assert expr.evaluate(code, expr.Resolver()) in (True, False, None)


def test_extraction_stops_where_the_governed_statements_begin():
    """An expression is the run of expression opcodes opening a scope; the
    statements it guards follow and must not be swallowed."""
    question = _op(0x05, b"\x00" * 12, scope=True)
    stream = eq_id_val(0x1234, 1) + NOT + question + _op(0x29)
    code = expr.extract(stream, 0)
    assert code == eq_id_val(0x1234, 1) + NOT
    assert ev(code, Values(q0x1234=0)) is True


def test_extraction_of_an_empty_expression_is_empty():
    assert expr.extract(_op(0x05, b"\x00" * 12, scope=True), 0) == b""

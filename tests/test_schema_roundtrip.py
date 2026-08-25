"""A schema that survives JSON must decode a machine exactly like the schema
still in memory. Anything less means a user reading a published schema is told
something different from a user who parsed their own image."""

import json

import pytest

from tests import fixtures
from uefi_mirror import decode
from uefi_mirror.firmware import firmware_volume
from uefi_mirror.schema import builder
from uefi_mirror.schema.model import Schema, canonical_json, schema_hash


def _schema(ifr=None):
    image = fixtures.build_image(ifr if ifr is not None
                                 else fixtures.build_conditional_ifr())
    return builder.build({"name": "test.bin"}, firmware_volume.walk(image))


def _store(master: int = 1, dependent: int = 0) -> decode.VariableStore:
    store = decode.VariableStore(source="test")
    payload = bytearray(0x100)
    payload[0], payload[1] = master, dependent
    store.payloads[("Setup", str(fixtures.VARSTORE_GUID))] = bytes(payload)
    return store


def _reload(schema: Schema) -> Schema:
    return Schema.from_json(json.dumps(schema.as_dict()))


def _decoded_facts(schema: Schema):
    return [(d.setting.id, d.status, d.value, d.raw_value, d.label,
             d.visibility, d.option_states, d.candidate_labels)
            for d in decode.decode_all(schema.settings, _store())]


@pytest.mark.parametrize("ifr_name", ["build_conditional_ifr",
                                      "build_conditional_options_ifr",
                                      "build_question_kinds_ifr"])
def test_a_reloaded_schema_decodes_identically(ifr_name):
    schema = _schema(getattr(fixtures, ifr_name)())
    assert schema.settings, "fixture produced no settings to compare"
    assert _decoded_facts(_reload(schema)) == _decoded_facts(schema)


def test_a_reloaded_schema_still_evaluates_conditions():
    """The point of carrying expression bytes: without them every condition
    would come back undecidable, and every hidden setting would look visible."""
    reloaded = _reload(_schema())
    conditions = [c for s in reloaded.settings for c in s.conditions]
    assert conditions and all(c.code for c in conditions)
    by_name = {d.setting.name: d
               for d in decode.decode_all(reloaded.settings, _store(master=1))}
    assert by_name["Dependent Option"].visibility == decode.HIDDEN


def test_the_canonical_form_is_stable_across_a_round_trip():
    schema = _schema()
    assert canonical_json(_reload(schema)) == canonical_json(schema)
    assert schema_hash(_reload(schema)) == schema_hash(schema)


def test_reparsing_the_same_image_gives_the_same_hash():
    assert schema_hash(_schema()) == schema_hash(_schema())


def test_varstores_are_reported_with_their_ifr_ids():
    schema = _schema()
    assert schema.varstores, "form set declares a varstore"
    store = schema.varstores[0]
    assert store.guid == str(fixtures.VARSTORE_GUID)
    assert store.formset_guid == schema.formsets[0].guid
    settings = [s for s in schema.settings if s.varstore]
    assert settings and all(s.varstore.varstore_id == store.varstore_id
                            for s in settings)


def test_a_schema_from_a_future_version_is_refused():
    data = _schema().as_dict()
    data["format_version"] = 99
    with pytest.raises(ValueError, match="format_version"):
        Schema.from_dict(data)


def test_an_unreadable_condition_is_refused_rather_than_dropped():
    """Silently discarding it would turn a suppress_if into 'always visible'."""
    data = _schema().as_dict()
    setting = next(s for s in data["settings"] if s.get("conditions"))
    setting["conditions"][0]["code"] = "not base64!"
    with pytest.raises(ValueError, match="base64"):
        Schema.from_dict(data)


@pytest.mark.parametrize("mutate", [
    lambda d: d.update(settings={"not": "a list"}),
    lambda d: d["settings"][0].update(question_id="12"),
    lambda d: d["settings"][0].update(path="Advanced"),
    lambda d: d.update(image=[]),
])
def test_malformed_schema_fields_are_refused(mutate):
    data = _schema().as_dict()
    mutate(data)
    with pytest.raises(ValueError):
        Schema.from_dict(data)


def test_json_that_is_not_a_schema_is_refused():
    with pytest.raises(ValueError, match="not valid JSON"):
        Schema.from_json("{oops")


def test_a_schema_without_its_image_cannot_claim_a_board_match():
    """A published schema does not carry the firmware, so the board-id evidence
    is gone. It must degrade to 'unverified', never silently to 'matched'."""
    schema, store = _schema(), _store()
    decoded = decode.decode_all(schema.settings, store)
    dmi = {"board_name": "TEST-BOARD"}
    image = fixtures.build_image(fixtures.build_conditional_ifr()) + b"TEST-BOARD"

    with_image = decode.check_compatibility(
        schema.settings, store, image, dmi, decoded, "bios.cap")
    without_image = decode.check_compatibility(
        schema.settings, store, None, dmi, decoded, "schema.json")

    assert with_image.status == "matched"
    assert without_image.status == "unverified"
    assert not without_image.problems


def test_a_layout_mismatch_is_still_caught_without_the_image():
    """The check that can refuse a wrong schema reads variables, not firmware,
    so dropping the image must not drop the refusal."""
    schema = _schema()
    store = decode.VariableStore(source="test")
    store.payloads[("Setup", str(fixtures.VARSTORE_GUID))] = b"\x01"
    decoded = decode.decode_all(schema.settings, store)
    result = decode.check_compatibility(
        schema.settings, store, None, {"board_name": "TEST-BOARD"}, decoded, "schema.json")
    assert result.status == "mismatch"
    assert result.problems

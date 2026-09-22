"""Comparing two configurations. A diff that misses a change, or invents one,
is worse than no diff at all."""

import copy

from tests import fixtures
from uefi_mirror import decode, diff
from uefi_mirror.collectors.efivarfs import Variable
from uefi_mirror.firmware import firmware_volume
from uefi_mirror.schema import builder

GUID = str(fixtures.VARSTORE_GUID)


def _store(**variables) -> decode.VariableStore:
    store = decode.VariableStore(source="test")
    for name, payload in variables.items():
        store.payloads[(name, GUID)] = payload
    return store


def test_added_removed_and_changed_variables_are_classified():
    old = _store(Kept=b"\x01", Dropped=b"\x02", Edited=b"\x03\x03")
    new = _store(Kept=b"\x01", Added=b"\x04", Edited=b"\x03\x09")
    kinds = {c.name: c.kind for c in diff.diff_variables(old, new)}
    assert kinds == {"Dropped": diff.REMOVED, "Added": diff.ADDED,
                     "Edited": diff.CHANGED}


def test_an_identical_pair_reports_nothing():
    store = _store(Setup=b"\x00\x01\x02")
    assert diff.build(store, store).is_empty()


def test_a_changed_variable_counts_the_bytes_that_moved():
    change, = diff.diff_variables(_store(Setup=b"\x01\x02\x03"),
                                  _store(Setup=b"\x01\x09\x09"))
    assert change.differing_bytes == 2
    assert change.old_size == change.new_size == 3
    assert change.old_sha256 != change.new_sha256


def test_a_resized_variable_counts_the_missing_tail():
    change, = diff.diff_variables(_store(Setup=b"\x01\x02\x03\x04"),
                                  _store(Setup=b"\x01\x02"))
    assert change.differing_bytes == 2


def test_a_failed_read_is_never_reported_as_an_addition_or_removal():
    failed = decode.from_variables([
        Variable("Setup", GUID, f"Setup-{GUID}", error="permission denied")],
        "test", "efivarfs")
    before = _store(Setup=b"\x01")
    for old, new in ((before, failed), (failed, before)):
        change, = diff.diff_variables(old, new)
        assert change.kind == diff.UNREADABLE
        assert change.old_error or change.new_error
        assert diff.build(old, new).counts()["variables"][diff.REMOVED] == 0
        assert diff.build(old, new).counts()["variables"][diff.ADDED] == 0


def _setup_store(value: int) -> decode.VariableStore:
    payload = bytearray(0x100)
    payload[0x90] = value
    return _store(Setup=bytes(payload))


def _decoded(schema, value: int):
    return decode.decode_all(schema.settings, _setup_store(value))


def test_a_setting_change_is_reported_with_both_labels():
    schema = builder.build({}, firmware_volume.walk(fixtures.build_image()).files)
    result = diff.build(_setup_store(0), _setup_store(1),
                        _decoded(schema, 0), _decoded(schema, 1))
    change, = result.settings
    assert change.name == "Above 4G Decoding"
    assert (change.old_display, change.new_display) == ("Disabled", "Enabled")
    assert change.path == ["Example Setup", "Advanced", "PCI Subsystem Settings"]
    assert result.counts()["settings_changed"] == 1


def test_an_unchanged_setting_is_compared_but_not_reported():
    schema = builder.build({}, firmware_volume.walk(fixtures.build_image()).files)
    result = diff.build(_setup_store(1), _setup_store(1),
                        _decoded(schema, 1), _decoded(schema, 1))
    assert result.settings == []
    assert result.settings_compared == 1


def test_identical_non_decodable_settings_do_not_invent_a_difference():
    schema = builder.build({}, firmware_volume.walk(fixtures.build_image()).files)
    store = decode.VariableStore(source="test")
    decoded = decode.decode_all(schema.settings, store)
    result = diff.build(store, store, decoded, decoded)
    assert result.settings_uncompared == []
    assert result.settings_compared == 0
    assert result.is_empty()


def test_a_setting_that_failed_to_decode_is_not_called_unchanged():
    """Missing on one side means uncomparable; silently reporting 'no change'
    would hide exactly the case the user cares about."""
    schema = builder.build({}, firmware_volume.walk(fixtures.build_image()).files)
    absent = decode.decode_all(schema.settings, decode.VariableStore(source="t"))
    result = diff.build(decode.VariableStore(source="t"), _setup_store(1),
                        absent, _decoded(schema, 1))
    assert result.settings == []
    assert result.settings_compared == 0


def test_a_failed_setting_read_is_explicitly_uncomparable():
    schema = builder.build({}, firmware_volume.walk(fixtures.build_image()).files)
    old = _setup_store(0)
    new = decode.from_variables([
        Variable("Setup", GUID, f"Setup-{GUID}", error="permission denied")],
        "test", "efivarfs")
    result = diff.build(old, new, decode.decode_all(schema.settings, old),
                        decode.decode_all(schema.settings, new))
    assert result.settings == []
    assert result.settings_compared == 0
    assert result.settings_uncompared[0].reason == diff.UNREADABLE
    assert not result.is_empty()


def test_same_setting_id_with_a_new_storage_location_is_not_compared():
    schema = builder.build({}, firmware_volume.walk(fixtures.build_image()).files)
    old_decoded = _decoded(schema, 0)
    new_decoded = copy.deepcopy(_decoded(schema, 1))
    new_decoded[0].setting.varstore.offset += 1
    result = diff.build(_setup_store(0), _setup_store(1), old_decoded, new_decoded)
    assert result.settings == []
    assert result.settings_compared == 0
    assert result.settings_uncompared[0].reason == "schema_changed"


def test_text_rendering_is_plain_and_mentions_both_sides():
    schema = builder.build({}, firmware_volume.walk(fixtures.build_image()).files)
    result = diff.build(_setup_store(0), _setup_store(1),
                        _decoded(schema, 0), _decoded(schema, 1))
    text = diff.to_text(result, "Example diff")
    assert "Above 4G Decoding" in text
    assert "Disabled" in text and "Enabled" in text
    assert "\x1b[" not in text


def test_json_rendering_round_trips():
    import json
    store = _store(Setup=b"\x01")
    payload = json.loads(diff.to_json(diff.build(store, _store(Setup=b"\x02"))))
    assert payload["diff"]["counts"]["variables"]["changed"] == 1


def test_changed_setting_json_carries_stable_id():
    schema = builder.build({}, firmware_volume.walk(fixtures.build_image()).files)
    result = diff.build(_setup_store(0), _setup_store(1),
                        _decoded(schema, 0), _decoded(schema, 1))
    assert result.as_dict()["settings"][0]["id"] == schema.settings[0].id


def test_inactive_variant_change_is_raw_only():
    schema = builder.build({}, firmware_volume.walk(fixtures.build_image()).files)
    old, new = _setup_store(0), _setup_store(1)
    old_decoded = decode.decode_all(schema.settings, old,
                                    {schema.settings[0].formset_guid})
    new_decoded = decode.decode_all(schema.settings, new,
                                    {schema.settings[0].formset_guid})
    result = diff.build(old, new, old_decoded, new_decoded)
    assert len(result.variables) == 1
    assert result.settings == []
    assert result.settings_compared == 0


def test_walk_warnings_are_carried_into_the_document_and_rendered():
    warning = ("file budget of 20000 reached at image/fv@0x48; "
               "remaining files dropped")
    result = diff.build(_setup_store(0), _setup_store(1), walk_warnings=[warning])
    assert result.as_dict()["warnings"] == [warning]
    text = diff.to_text(result, "Example diff")
    assert "[warnings]" in text and warning in text


def test_a_clean_diff_document_has_no_warnings_key():
    result = diff.build(_setup_store(0), _setup_store(1))
    assert "warnings" not in result.as_dict()

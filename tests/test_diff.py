"""Comparing two configurations. A diff that misses a change, or invents one,
is worse than no diff at all."""

from tests import fixtures
from uefi_mirror import decode, diff
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


def _setup_store(value: int) -> decode.VariableStore:
    payload = bytearray(0x100)
    payload[0x90] = value
    return _store(Setup=bytes(payload))


def _decoded(schema, value: int):
    return decode.decode_all(schema.settings, _setup_store(value))


def test_a_setting_change_is_reported_with_both_labels():
    schema = builder.build({}, firmware_volume.walk(fixtures.build_image()))
    result = diff.build(_setup_store(0), _setup_store(1),
                        _decoded(schema, 0), _decoded(schema, 1))
    change, = result.settings
    assert change.name == "Above 4G Decoding"
    assert (change.old_display, change.new_display) == ("Disabled", "Enabled")
    assert change.path == ["Example Setup", "Advanced", "PCI Subsystem Settings"]
    assert result.counts()["settings_changed"] == 1


def test_an_unchanged_setting_is_compared_but_not_reported():
    schema = builder.build({}, firmware_volume.walk(fixtures.build_image()))
    result = diff.build(_setup_store(1), _setup_store(1),
                        _decoded(schema, 1), _decoded(schema, 1))
    assert result.settings == []
    assert result.settings_compared == 1


def test_a_setting_that_failed_to_decode_is_not_called_unchanged():
    """Missing on one side means uncomparable; silently reporting 'no change'
    would hide exactly the case the user cares about."""
    schema = builder.build({}, firmware_volume.walk(fixtures.build_image()))
    absent = decode.decode_all(schema.settings, decode.VariableStore(source="t"))
    result = diff.build(decode.VariableStore(source="t"), _setup_store(1),
                        absent, _decoded(schema, 1))
    assert result.settings == []
    assert result.settings_compared == 0


def test_text_rendering_is_plain_and_mentions_both_sides():
    schema = builder.build({}, firmware_volume.walk(fixtures.build_image()))
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


def test_inactive_variant_change_is_raw_only():
    schema = builder.build({}, firmware_volume.walk(fixtures.build_image()))
    old, new = _setup_store(0), _setup_store(1)
    old_decoded = decode.decode_all(schema.settings, old,
                                    {schema.settings[0].formset_guid})
    new_decoded = decode.decode_all(schema.settings, new,
                                    {schema.settings[0].formset_guid})
    result = diff.build(old, new, old_decoded, new_decoded)
    assert len(result.variables) == 1
    assert result.settings == []
    assert result.settings_compared == 0

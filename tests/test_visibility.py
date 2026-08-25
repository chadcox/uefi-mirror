"""Whether the firmware would actually show a setting, and which per-CPU-family
form set applies. Both decide what a user is told about their own machine."""

from tests import fixtures
from uefi_mirror import decode
from uefi_mirror.firmware import firmware_volume
from uefi_mirror.schema import builder
from uefi_mirror.schema.model import FormSetSummary


def _schema():
    image = fixtures.build_image(fixtures.build_conditional_ifr())
    return builder.build({}, firmware_volume.walk(image))


def _store(master: int, dependent: int = 0) -> decode.VariableStore:
    store = decode.VariableStore(source="test")
    payload = bytearray(0x100)
    payload[0], payload[1] = master, dependent
    store.payloads[("Setup", str(fixtures.VARSTORE_GUID))] = bytes(payload)
    return store


def _by_name(decoded):
    return {item.setting.name: item for item in decoded}


def test_the_dependent_question_is_hidden_when_the_master_switch_is_on():
    schema = _schema()
    decoded = _by_name(decode.decode_all(schema.settings, _store(master=1)))
    assert decoded["Master Switch"].visibility == decode.VISIBLE
    assert decoded["Dependent Option"].visibility == decode.HIDDEN


def test_the_dependent_question_is_visible_when_the_master_switch_is_off():
    schema = _schema()
    decoded = _by_name(decode.decode_all(schema.settings, _store(master=0)))
    assert decoded["Dependent Option"].visibility == decode.VISIBLE


def test_visibility_is_unknown_when_the_governing_value_cannot_be_read():
    """No variable means no value for the condition to test, and the honest
    answer is that we do not know -- not that the setting is visible."""
    schema = _schema()
    decoded = _by_name(decode.decode_all(schema.settings, decode.VariableStore(source="t")))
    assert decoded["Dependent Option"].visibility == decode.UNKNOWN


def test_the_hidden_setting_is_still_exported_with_its_value():
    schema = _schema()
    decoded = _by_name(decode.decode_all(schema.settings, _store(master=1, dependent=1)))
    hidden = decoded["Dependent Option"]
    assert hidden.status == decode.OK
    assert hidden.display_value == "1"
    assert hidden.candidate_labels == []
    assert hidden.as_dict()["live"]["visibility"] == decode.HIDDEN


def _variants(*names) -> list[FormSetSummary]:
    return [FormSetSummary(guid=f"formset-{n}", title=f"Setup {n}", class_guids=[],
                           source="test", setting_count=1, varstore_name=n,
                           varstore_guid=str(fixtures.VARSTORE_GUID))
            for n in names]


def _store_with(*names) -> decode.VariableStore:
    store = decode.VariableStore(source="test")
    for name in names:
        store.payloads[(name, str(fixtures.VARSTORE_GUID))] = b"\x00" * 16
    return store


def test_the_variant_whose_variable_exists_is_the_live_one():
    formsets = _variants("AodSetupRpl", "AodSetupPhx", "AodSetupStx")
    resolution = decode.resolve_variants(formsets, _store_with("AodSetupRpl"))
    assert resolution.inactive == {"formset-AodSetupPhx", "formset-AodSetupStx"}
    assert resolution.families == ["rpl"]
    assert [f.active for f in formsets] == [True, False, False]


def test_a_family_learned_from_one_group_settles_a_group_where_all_variables_exist():
    """Firmware creates every AmdSetup* variable regardless of the CPU, so that
    group is only decidable via the family the AOD group revealed."""
    formsets = (_variants("AodSetupRpl", "AodSetupPhx")
                + _variants("AmdSetupRPL", "AmdSetupPHX"))
    for formset in formsets[2:]:
        formset.varstore_guid = "3a997502-647a-4c82-998e-52ef9486a247"
    store = _store_with("AodSetupRpl")
    store.payloads[("AmdSetupRPL", "3a997502-647a-4c82-998e-52ef9486a247")] = b"\x00"
    store.payloads[("AmdSetupPHX", "3a997502-647a-4c82-998e-52ef9486a247")] = b"\x00"
    resolution = decode.resolve_variants(formsets, store)
    assert resolution.inactive == {"formset-AodSetupPhx", "formset-AmdSetupPHX"}
    assert any("AmdSetupRPL" in note for note in resolution.evidence)


def test_an_undecidable_variant_group_keeps_every_member():
    formsets = _variants("AmdSetupRPL", "AmdSetupPHX")
    resolution = decode.resolve_variants(formsets, _store_with("AmdSetupRPL", "AmdSetupPHX"))
    assert resolution.inactive == set()
    assert any("could not choose" in note for note in resolution.evidence)


def test_settings_of_an_inactive_form_set_are_marked_inactive():
    schema = _schema()
    guid = schema.settings[0].formset_guid
    decoded = decode.decode_all(schema.settings, _store(master=0), {guid})
    assert all(not item.active for item in decoded)


def test_conditional_duplicate_options_are_resolved_without_guessing():
    schema = builder.build({}, firmware_volume.walk(
        fixtures.build_image(fixtures.build_conditional_options_ifr())))

    def choices(payload):
        items = _by_name(decode.decode_all(schema.settings, _store_bytes(payload)))
        return items["Above 4G Decoding"]

    for master, expected in ((0, "Choice A"), (1, "Choice B")):
        item = choices(bytes([master, 7]))
        assert item.label == expected
        assert item.candidate_labels == [expected]
        assert {option["state"] for option in item.as_dict()["options"]} == {
            decode.VISIBLE, decode.HIDDEN}

    undecidable = choices(bytes([7]))  # master decodes, enum byte is absent
    assert undecidable.status == decode.OUT_OF_RANGE

    payload = bytearray(2)
    payload[1] = 7
    store = decode.VariableStore(source="test")
    store.payloads[("Setup", str(fixtures.VARSTORE_GUID))] = bytes(payload)
    next(setting for setting in schema.settings
         if setting.name == "Master Switch").varstore.offset = 9
    item = _by_name(decode.decode_all(schema.settings, store))["Above 4G Decoding"]
    assert item.label is None
    assert item.candidate_labels == ["Choice A", "Choice B"]


def _store_bytes(payload: bytes) -> decode.VariableStore:
    store = decode.VariableStore(source="test")
    store.payloads[("Setup", str(fixtures.VARSTORE_GUID))] = payload
    return store


def test_variant_resolution_resets_prior_formset_mutation():
    formsets = _variants("AodSetupRpl", "AodSetupPhx")
    decode.resolve_variants(formsets, _store_with("AodSetupRpl"))
    decode.resolve_variants(formsets, _store_with("AodSetupPhx"))
    assert [f.active for f in formsets] == [False, True]

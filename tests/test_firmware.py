import json
import hashlib
import re
import struct
import uuid

import pytest

from uefi_mirror import decode, report
from uefi_mirror.firmware import cap, firmware_volume, hii, ifr
from uefi_mirror.firmware.strings import parse_string_package
from uefi_mirror.schema import builder
from uefi_mirror.schema.model import Setting, VarStoreRef

import fixtures


def test_capsule_header_is_stripped(tmp_path):
    path = tmp_path / "bios.CAP"
    path.write_bytes(fixtures.build_capsule())
    capsule = cap.load(str(path))
    assert capsule.capsule_guid == str(fixtures.CAPSULE_GUID)
    assert capsule.header_size == 4096
    assert capsule.data == fixtures.build_image()
    assert capsule.file_sha256 != capsule.payload_sha256


def test_raw_image_without_capsule_is_passed_through(tmp_path):
    path = tmp_path / "bios.ROM"
    path.write_bytes(fixtures.build_image())
    capsule = cap.load(str(path))
    assert capsule.capsule_guid is None
    assert capsule.file_sha256 == capsule.payload_sha256


def test_capsule_without_a_firmware_volume_is_rejected(tmp_path):
    path = tmp_path / "bogus.CAP"
    path.write_bytes(fixtures.build_capsule(b"\x00" * 8192))
    with pytest.raises(ValueError, match="no firmware volume"):
        cap.load(str(path))


def test_empty_file_is_rejected(tmp_path):
    path = tmp_path / "empty.CAP"
    path.write_bytes(b"")
    with pytest.raises(ValueError, match="empty"):
        cap.load(str(path))


def test_walk_finds_the_file_and_its_ui_name():
    files = firmware_volume.walk(fixtures.build_image())
    assert len(files) == 1
    assert files[0].guid == str(fixtures.FFS_GUID)
    assert files[0].ui_name == "ExampleSetupDxe"
    assert [s.type for s in files[0].sections] == [0x19, 0x15]


def test_volume_with_a_bad_checksum_is_ignored():
    image = bytearray(fixtures.build_image())
    image[50] ^= 0xFF  # corrupt the header checksum
    assert firmware_volume.walk(bytes(image)) == []


def test_string_package_round_trip():
    language, strings = parse_string_package(fixtures.build_string_package())
    assert language == "en-US"
    assert strings[4] == "Above 4G Decoding"
    assert strings[7] == "Enabled"


def test_string_package_skip_and_duplicate_blocks():
    body = struct.pack("<II", 52, 52) + b"\x00" * 32 + struct.pack("<H", 0) \
        + b"en-US\x00" \
        + b"\x14" + "First".encode("utf-16-le") + b"\x00\x00" \
        + b"\x22\x03" \
        + b"\x14" + "Fifth".encode("utf-16-le") + b"\x00\x00" \
        + b"\x20" + struct.pack("<H", 1) \
        + b"\x00"
    package = struct.pack("<I", (0x04 << 24) | (len(body) + 4)) + body
    _, strings = parse_string_package(package)
    assert strings == {1: "First", 5: "Fifth", 6: "First"}


def test_ifr_validation_rejects_unbalanced_and_truncated_streams():
    good = fixtures.build_ifr()
    assert ifr.validate_ifr(good) is not None
    assert ifr.validate_ifr(good[:-2]) is None          # a scope is left open
    assert ifr.validate_ifr(good + b"\x29\x02") is None  # one END too many
    assert ifr.validate_ifr(b"\x0e\x00" * 8) is None     # zero-length opcodes


def test_form_set_parsing_extracts_varstore_and_question():
    form_set = ifr.parse_form_set(fixtures.build_ifr())
    assert form_set.guid == str(fixtures.FORMSET_GUID)
    store = form_set.varstores[1]
    assert (store.name, store.size, store.kind) == ("Setup", 0x100, "buffer")

    question, = form_set.questions
    assert question.kind == "one_of"
    assert question.question_id == 0x1234
    assert question.var_offset == 0x90
    assert question.value_size == 1
    assert [o.value for o in question.options] == [0, 1]
    assert [o.is_default for o in question.options] == [False, True]


def test_package_lists_pair_forms_with_strings_from_the_same_file():
    packages = hii.collect(firmware_volume.walk(fixtures.build_image()))
    assert len(packages) == 1
    assert packages[0].text(4) == "Above 4G Decoding"


def test_schema_build_produces_a_named_setting_with_a_menu_path():
    image = fixtures.build_image()
    schema = builder.build({"payload_size": len(image)}, firmware_volume.walk(image))
    assert schema.warnings == []
    setting, = schema.settings
    assert setting.name == "Above 4G Decoding"
    assert setting.path == ["Example Setup", "Advanced", "PCI Subsystem Settings"]
    assert setting.type == "enum"
    assert setting.default == 1
    assert setting.help.startswith("Enable or disable")
    assert setting.varstore.name == "Setup"
    assert setting.varstore.guid == str(fixtures.VARSTORE_GUID)
    assert setting.varstore.offset == 0x90
    assert [(o.label, o.value) for o in setting.options] == [("Disabled", 0), ("Enabled", 1)]
    assert schema.as_dict()["format_version"] == 3


def _live_store(payload: bytes) -> "decode.VariableStore":
    store = decode.VariableStore(source="test")
    store.payloads[("Setup", str(fixtures.VARSTORE_GUID))] = payload
    return store


def test_compatibility_matches_embedded_board_and_live_layout():
    image = fixtures.build_image()
    schema = builder.build({}, firmware_volume.walk(image))
    store = _live_store(bytes(0x100))
    result = decode.check_compatibility(
        schema.settings, store, image + b"Example Board",
        {"board_name": "Example Board", "bios_version": "1.2"},
        decode.decode_all(schema.settings, store), "Example-1.2.CAP")
    assert result.status == "matched"
    assert not result.problems


def test_compatibility_rejects_a_varstore_too_short_for_the_schema():
    image = fixtures.build_image()
    schema = builder.build({}, firmware_volume.walk(image))
    store = _live_store(bytes(8))
    result = decode.check_compatibility(
        schema.settings, store, image, {}, decode.decode_all(schema.settings, store))
    assert result.status == "mismatch"
    assert any("requires at least" in problem for problem in result.problems)


def test_decode_reads_the_live_value_and_labels_it():
    image = fixtures.build_image()
    schema = builder.build({}, firmware_volume.walk(image))
    payload = bytearray(0x100)
    payload[0x90] = 1
    item = decode.decode_setting(schema.settings[0], _live_store(bytes(payload)))
    assert (item.status, item.value, item.label) == (decode.OK, 1, "Enabled")
    assert item.is_default is True
    assert item.display_value == "Enabled"


def test_decode_flags_a_value_that_differs_from_the_default():
    image = fixtures.build_image()
    schema = builder.build({}, firmware_volume.walk(image))
    item = decode.decode_setting(schema.settings[0], _live_store(bytes(0x100)))
    assert item.label == "Disabled"
    assert item.is_default is False
    assert report.is_changed(item) is True


def test_decode_reports_a_value_no_option_declares():
    image = fixtures.build_image()
    schema = builder.build({}, firmware_volume.walk(image))
    payload = bytearray(0x100)
    payload[0x90] = 0x42
    item = decode.decode_setting(schema.settings[0], _live_store(bytes(payload)))
    assert item.status == decode.UNKNOWN_VALUE
    assert item.value == 0x42


def test_decode_handles_missing_and_short_variables():
    image = fixtures.build_image()
    setting = builder.build({}, firmware_volume.walk(image)).settings[0]
    assert decode.decode_setting(setting, decode.VariableStore()).status == decode.NO_VARIABLE
    assert decode.decode_setting(setting, _live_store(b"\x00" * 8)).status == decode.OUT_OF_RANGE


def test_passwords_are_never_read_out():
    setting = Setting(id="x", name="Administrator Password", type="password",
                      formset_guid="g", question_id=1,
                      varstore=VarStoreRef(str(fixtures.VARSTORE_GUID), "Setup",
                                           0, 32, "buffer"))
    item = decode.decode_setting(setting, _live_store(b"hunter2" + b"\x00" * 64))
    assert item.status == decode.REDACTED
    assert item.value is None
    assert "hunter2" not in item.display_value
    assert "hunter2" not in json.dumps(item.as_dict())
    assert b"hunter2" not in report.to_html(
        {"format_version": report.EXPORT_FORMAT_VERSION, "settings": [item.as_dict()]})


def test_signed_numerics_compare_against_a_signed_default():
    question = ifr.Question(opcode=ifr.OP_NUMERIC, kind="numeric", offset=0,
                            prompt_id=1, help_id=0, question_id=1, varstore_id=1,
                            varstore_info=0, flags=0, form_id=None, form_title_id=None)
    question.display = ifr.DISPLAY_INT_DEC
    question.value_size = 1
    question.defaults[ifr.DEFAULT_STANDARD] = 0xFE
    assert builder._signed(builder._default_value(question, ifr.DEFAULT_STANDARD), 1) == -2


@pytest.mark.parametrize("display,value,label", [
    (ifr.DISPLAY_INT_DEC, -2, None),
    (ifr.DISPLAY_UINT_DEC, 0xFE, None),
    (ifr.DISPLAY_UINT_HEX, 0xFE, "0xfe"),
])
def test_numeric_display_modes_preserve_raw_unsigned_values(display, value, label):
    setting = Setting(id="n", name="Numeric", type="integer", formset_guid="g",
                      question_id=1, display=builder.DISPLAY_NAMES[display],
                      varstore=VarStoreRef(str(fixtures.VARSTORE_GUID), "Setup", 0, 1,
                                           "buffer"))
    item = decode.decode_setting(setting, _live_store(b"\xfe"))
    assert (item.value, item.raw_value, item.label) == (value, 0xFE, label)
    assert item.as_dict()["live"]["raw_value"] == 0xFE


def test_checkbox_flag_defaults_and_nested_default_precedence():
    question = ifr.Question(opcode=ifr.OP_CHECKBOX, kind="checkbox", offset=0,
                            prompt_id=1, help_id=0, question_id=1, varstore_id=1,
                            varstore_info=0, flags=0, form_id=None, form_title_id=None)
    assert builder._default_value(question, ifr.DEFAULT_STANDARD) == 0
    assert builder._default_value(question, ifr.DEFAULT_MANUFACTURING) == 0


def test_scoped_checkbox_default_expression_is_parsed():
    # Replace the date/time/action body with one checkbox whose standard
    # default is a scoped EFI_IFR_VALUE expression.
    form_set = fixtures._op(0x0E, fixtures.FORMSET_GUID.bytes_le
                            + struct.pack("<HHB", 1, 0, 0)
                            + uuid.UUID(int=0).bytes_le, scope=True)
    varstore = fixtures._op(0x24, fixtures.VARSTORE_GUID.bytes_le
                            + struct.pack("<HH", 1, 0x100) + b"Setup\x00")
    form = fixtures._op(0x01, struct.pack("<HH", 0x10, 2), scope=True)
    checkbox = fixtures._op(0x06, struct.pack("<HHHHHB", 12, 0, 1, 1, 0, 0)
                            + bytes([ifr.CHECKBOX_DEFAULT_MFG]), scope=True)
    nested = (fixtures._op(0x5B, struct.pack("<HB", ifr.DEFAULT_STANDARD, 8), scope=True)
              + fixtures._op(0x5A, scope=True)
              + fixtures._op(0x45, (1).to_bytes(8, "little"))
              + fixtures._op(0x29) + fixtures._op(0x29))
    stream = form_set + varstore + form + checkbox + nested + fixtures._op(0x29) * 3
    question, = ifr.parse_form_set(stream).questions
    assert question.defaults[ifr.DEFAULT_STANDARD] == 1
    assert builder._default_value(question, ifr.DEFAULT_MANUFACTURING) == 1
    question.checkbox_flags = ifr.CHECKBOX_DEFAULT | ifr.CHECKBOX_DEFAULT_MFG
    assert builder._default_value(question, ifr.DEFAULT_STANDARD) == 1
    assert builder._default_value(question, ifr.DEFAULT_MANUFACTURING) == 1
    question.defaults = {ifr.DEFAULT_STANDARD: 0, ifr.DEFAULT_MANUFACTURING: 0}
    assert builder._default_value(question, ifr.DEFAULT_STANDARD) == 0
    assert builder._default_value(question, ifr.DEFAULT_MANUFACTURING) == 0


def test_date_and_time_are_included_but_actions_are_not_settings():
    schema = builder.build({}, firmware_volume.walk(
        fixtures.build_image(fixtures.build_question_kinds_ifr())))
    assert [(setting.name, setting.type) for setting in schema.settings] == [
        ("Date", "date"), ("Time", "time")]
    assert all(decode.decode_setting(setting, _live_store(b"\x00" * 16)).status
               == decode.UNSUPPORTED for setting in schema.settings)


def test_snapshot_round_trip_feeds_the_decoder(tmp_path):
    raw_dir = tmp_path / "raw-variables"
    raw_dir.mkdir()
    filename = f"Setup-{fixtures.VARSTORE_GUID}"
    payload = bytearray(0x100)
    payload[0x90] = 1
    (raw_dir / filename).write_bytes(bytes(payload))
    (tmp_path / "manifest.json").write_text(json.dumps({"format_version": 1, "variables": [
        {"name": "Setup", "guid": str(fixtures.VARSTORE_GUID),
         "filename": filename, "attributes": 7, "payload_size": len(payload),
         "payload_sha256": hashlib.sha256(payload).hexdigest(), "error": None}]}))

    store = decode.from_snapshot(str(tmp_path))
    assert store.get("Setup", str(fixtures.VARSTORE_GUID).upper()) == bytes(payload)
    schema = builder.build({}, firmware_volume.walk(fixtures.build_image()))
    assert decode.decode_setting(schema.settings[0], store).label == "Enabled"


def test_snapshot_directory_without_a_manifest_is_rejected(tmp_path):
    with pytest.raises(ValueError, match="snapshot manifest"):
        decode.from_snapshot(str(tmp_path))


def test_text_report_marks_changes_and_stays_plain():
    image = fixtures.build_image()
    schema = builder.build({"file_sha256": "abc"}, firmware_volume.walk(image))
    store = _live_store(bytes(0x100))
    decoded = decode.decode_all(schema.settings, store)
    document = report.build_document(schema, store, decoded)
    text = report.to_text(document, decoded, "Test export")

    assert document["counts"]["changed_from_default"] == 1
    assert "[Example Setup / Advanced]" in text
    assert "* Above 4G Decoding" in text
    assert "(default Enabled)" in text
    assert "\x1b[" not in text  # no terminal escapes in a redirectable report


def test_html_report_is_self_contained_and_embedded_json_round_trips():
    schema = builder.build({"file_sha256": "abc"}, firmware_volume.walk(fixtures.build_image()))
    document = report.build_document(schema, _live_store(bytes(0x100)),
                                     decode.decode_all(schema.settings, _live_store(bytes(0x100))))
    html = report.to_html(document, {"grep": "Above 4G", "changed_only": True}).decode()
    embedded = re.search(
        r'<script id="uefi-data" type="application/json">(.*?)</script>', html, re.S)

    assert html.startswith("<!doctype html>")
    assert '<meta name="uefi-mirror-format" content="3">' in html
    assert embedded and json.loads(embedded.group(1)) == document
    assert not re.search(r'<(?:script|img)[^>]+\bsrc\s*=', html, re.I)
    assert not re.search(r'<link[^>]+rel=["\']?stylesheet', html, re.I)
    assert not re.search(r'https?://', html, re.I)
    for control in ("search", "default-state", "visibility", "decode", "type", "formset"):
        assert f'<label for="{control}">' in html
    assert 'aria-live="polite"' in html


def test_html_report_escapes_script_breakouts_without_changing_data():
    attack = '</script><script>alert("x")</script><b>&\u2028\u2029'
    document = {"format_version": 3, "settings": [{"name": attack}]}
    html = report.to_html(document).decode()
    embedded = re.search(
        r'<script id="uefi-data" type="application/json">(.*?)</script>', html, re.S)

    assert embedded and json.loads(embedded.group(1)) == document
    assert attack not in html
    assert "\\u003c/script\\u003e\\u003cscript\\u003e" in embedded.group(1)
    assert html.count("<script") == 3

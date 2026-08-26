"""Join a firmware-derived schema to the live variable bytes.

The schema says a setting is a one-of at `Setup+0x90` with options
Disabled=0 / Enabled=1; the variable says byte 0x90 is 1. This turns that pair
into "Above 4G Decoding = Enabled".

Read-only: variables are read through the efivarfs collector or from a
snapshot directory. Nothing here writes to firmware.
"""

import hashlib
import json
import os
import string
import uuid
from dataclasses import dataclass, field

from .collectors import efivarfs
from .firmware import expr
from .safety import MAX_VARIABLE_BYTES, read_bounded
from .schema.model import FormSetSummary, Setting

# Why a setting could not be given a value.
OK = "ok"
NO_VARIABLE = "no_variable"
OUT_OF_RANGE = "out_of_range"
UNKNOWN_VALUE = "unknown_value"
REDACTED = "redacted"
UNSUPPORTED = "unsupported"

# How the firmware would present a setting, once its conditions are evaluated.
VISIBLE = "visible"
HIDDEN = "hidden"
GRAYED = "grayed"
DISABLED = "disabled"
UNKNOWN = "unknown"

# Strongest outcome wins: a disabled question is not merely greyed out.
_VISIBILITY_RANK = {DISABLED: 3, HIDDEN: 2, GRAYED: 1, VISIBLE: 0}
_CONDITION_RESULT = {"disable_if": DISABLED, "suppress_if": HIDDEN,
                     "gray_out_if": GRAYED}

MAX_STRING_CHARS = 1024
MAX_ORDERED_ENTRIES = 256
SNAPSHOT_MANIFEST = "manifest.json"
SNAPSHOT_RAW_DIR = "raw-variables"
SNAPSHOT_FORMAT_VERSION = 1


# Store kinds that mean "these bytes came off the machine running this command".
# Anything not listed here is a recording of some other machine, so facts about
# the local host must not be attached to it. Windows collectors join this set.
LIVE_KINDS = frozenset({"efivarfs", "windows-firmware"})


@dataclass
class VariableStore:
    """Variable payloads keyed by (name, lowercased GUID)."""

    payloads: dict[tuple[str, str], bytes] = field(default_factory=dict)
    attributes: dict[tuple[str, str], int | None] = field(default_factory=dict)
    source: str = ""
    errors: list[str] = field(default_factory=list)
    platform: dict = field(default_factory=dict)
    kind: str = ""

    def get(self, name: str, guid: str) -> bytes | None:
        return self.payloads.get((name, guid.lower()))

    def keys(self) -> list[tuple[str, str]]:
        return list(self.payloads)

    def describe(self) -> dict:
        return {"source": self.source, "variables": len(self.payloads),
                "errors": self.errors}


def from_variables(variables: list[efivarfs.Variable], source: str,
                   kind: str) -> VariableStore:
    """Fold collected variables into a store.

    Every collector shares this mapping so a second platform cannot drift into
    a subtly different key or error format.
    """
    store = VariableStore(source=source, kind=kind)
    for var in variables:
        if var.payload is None:
            store.errors.append(f"{var.filename}: {var.error}")
            continue
        store.payloads[(var.name, var.guid)] = var.payload
        store.attributes[(var.name, var.guid)] = var.attributes
    return store


def from_efivarfs(directory: str, require_mount: bool = True) -> VariableStore:
    return from_variables(efivarfs.collect(directory, require_mount=require_mount),
                          directory, "efivarfs")


def from_snapshot(directory: str) -> VariableStore:
    """Read a directory produced by `uefi-mirror snapshot`."""
    store = VariableStore(source=directory, kind="snapshot")
    manifest_path = os.path.join(directory, SNAPSHOT_MANIFEST)
    try:
        manifest = json.loads(read_bounded(manifest_path, 64 << 20).decode())
    except (OSError, ValueError, UnicodeDecodeError) as exc:
        raise ValueError(f"{manifest_path}: not a readable snapshot manifest ({exc})") from exc

    if not isinstance(manifest, dict):
        raise ValueError(f"{manifest_path}: manifest must be a JSON object")
    if manifest.get("format_version") != SNAPSHOT_FORMAT_VERSION:
        raise ValueError(f"{manifest_path}: unsupported snapshot format version")
    if isinstance(manifest.get("platform"), dict):
        store.platform = manifest["platform"]
    entries = manifest.get("variables")
    if not isinstance(entries, list):
        raise ValueError(f"{manifest_path}: variables must be a list")

    raw_dir = os.path.join(directory, SNAPSHOT_RAW_DIR)
    if os.path.islink(raw_dir) or not os.path.isdir(raw_dir):
        raise ValueError(f"{raw_dir}: raw variable directory is missing or unsafe")
    seen_keys: set[tuple[str, str]] = set()
    seen_filenames: set[str] = set()
    loaded: list[tuple[tuple[str, str], str, bytes, int | None]] = []
    for index, entry in enumerate(entries):
        prefix = f"{manifest_path}: variables[{index}]"
        if not isinstance(entry, dict):
            raise ValueError(f"{prefix} must be an object")
        name, guid_text, filename = (entry.get("name"), entry.get("guid"),
                                     entry.get("filename"))
        if not isinstance(name, str) or not name:
            raise ValueError(f"{prefix}.name must be a non-empty string")
        if not isinstance(guid_text, str) or not isinstance(filename, str):
            raise ValueError(f"{prefix} guid and filename must be strings")
        try:
            guid = str(uuid.UUID(guid_text))
        except ValueError as exc:
            raise ValueError(f"{prefix}.guid is invalid") from exc
        parsed = efivarfs.parse_filename(filename)
        if (os.path.isabs(filename) or filename != os.path.basename(filename)
                or parsed != (name, guid)):
            raise ValueError(f"{prefix}.filename does not match name and GUID")
        key = (name, guid)
        if key in seen_keys or filename in seen_filenames:
            raise ValueError(f"{prefix}: duplicate variable or filename")
        seen_keys.add(key)
        seen_filenames.add(filename)

        error = entry.get("error")
        path = os.path.join(raw_dir, filename)
        if error is not None:
            if not isinstance(error, str) or not error:
                raise ValueError(f"{prefix}.error must be a non-empty string or null")
            if os.path.lexists(path):
                raise ValueError(f"{prefix}: failed capture unexpectedly has a payload")
            store.errors.append(f"{filename}: {error}")
            continue

        size, digest = entry.get("payload_size"), entry.get("payload_sha256")
        if isinstance(size, bool) or not isinstance(size, int) or size < 0:
            raise ValueError(f"{prefix}.payload_size must be a non-negative integer")
        if (not isinstance(digest, str) or len(digest) != 64
                or any(c not in string.hexdigits for c in digest)):
            raise ValueError(f"{prefix}.payload_sha256 must be a SHA-256 hex string")
        try:
            payload = read_bounded(path, MAX_VARIABLE_BYTES)
        except (OSError, ValueError) as exc:
            raise ValueError(f"{prefix}: unreadable payload ({exc})") from exc
        if len(payload) != size:
            raise ValueError(f"{prefix}: payload size mismatch")
        if hashlib.sha256(payload).hexdigest() != digest.lower():
            raise ValueError(f"{prefix}: payload SHA-256 mismatch")
        loaded.append((key, filename, payload, entry.get("attributes")))

    for key, _filename, payload, attributes in loaded:
        store.payloads[key] = payload
        store.attributes[key] = attributes
    return store


EFI_GLOBAL_VARIABLE = "8be4df61-93ca-11d2-aa0d-00e098032b8c"


@dataclass
class Compatibility:
    status: str
    evidence: list[str] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {"status": self.status, "evidence": self.evidence,
                "problems": self.problems}


def check_compatibility(settings: list[Setting], store: VariableStore,
                        image: bytes | None, dmi: dict[str, str],
                        decoded: list["DecodedSetting"], image_name: str = "") -> Compatibility:
    """Reject schemas that cannot describe the supplied variable store.

    Firmware images have no portable board-id field, so an embedded DMI model
    is positive evidence only. Varstore absence/size and enum values catch
    definite layout incompatibility without pretending a vendor name is proof.

    `image` is None when the schema was loaded from JSON rather than parsed
    from firmware. Every check that can declare a mismatch still runs; only the
    board-id evidence is unavailable, so such a schema is never 'matched'.
    """
    required: dict[tuple[str, str], int] = {}
    for setting in settings:
        ref = setting.varstore
        if ref and ref.name and ref.offset is not None:
            key = (ref.name, ref.guid.lower())
            required[key] = max(required.get(key, 0), ref.offset + (ref.size or 1))

    vendor_required = {key: size for key, size in required.items()
                       if key[1] != EFI_GLOBAL_VARIABLE}
    present = {key: store.payloads[key] for key in required if key in store.payloads}
    vendor_present = {key: data for key, data in present.items()
                      if key[1] != EFI_GLOBAL_VARIABLE}
    short = [(name, len(data), required[(name, guid)])
             for (name, guid), data in present.items()
             if len(data) < required[(name, guid)]]

    evidence = [f"{len(present)}/{len(required)} declared varstores are readable"]
    problems = [f"{name} is {actual} bytes; schema requires at least {needed}"
                for name, actual, needed in short]
    if vendor_required and not vendor_present:
        problems.append("none of the firmware's vendor varstores exist on this machine")

    enums = [item for item in decoded if item.active and item.setting.type == "enum"
             and item.status in (OK, UNKNOWN_VALUE)]
    invalid = sum(item.status == UNKNOWN_VALUE for item in enums)
    if enums:
        evidence.append(f"{len(enums) - invalid}/{len(enums)} live enum values are valid")
    if invalid >= 5 and invalid * 10 > len(enums):
        problems.append(f"{invalid}/{len(enums)} live enum values are not declared by the image")

    board = dmi.get("board_name", "").strip()
    if image is None:
        board_match = False
        evidence.insert(0, "schema carries no firmware image, so the board id behind it "
                           "cannot be confirmed")
    else:
        board_bytes = board.encode("ascii", errors="ignore")
        board_match = bool(board_bytes and (board_bytes in image
                           or board.encode("utf-16-le") in image))
        if board_match:
            evidence.insert(0, f"image contains live board model {board!r}")
        elif board:
            evidence.insert(0, f"image does not expose a comparable board id for {board!r}")

    version = dmi.get("bios_version", "").strip()
    version_match = bool(version and version.casefold() in image_name.casefold())
    if version_match:
        evidence.insert(1, f"filename contains installed BIOS version {version!r}")
    elif version:
        evidence.insert(1, f"installed BIOS version {version!r} is not identified by the name")

    identity_match = board_match and (not version or version_match)
    status = "mismatch" if problems else "matched" if identity_match else "unverified"
    return Compatibility(status, evidence, problems)


@dataclass
class DecodedSetting:
    setting: Setting
    status: str
    value: int | str | list[int] | None = None
    raw_value: int | None = None
    label: str | None = None
    candidate_labels: list[str] = field(default_factory=list)
    option_states: list[str] = field(default_factory=list)
    is_default: bool | None = None
    visibility: str = UNKNOWN
    active: bool = True

    @property
    def display_value(self) -> str:
        if self.status == REDACTED:
            return "(not shown)"
        if self.status == NO_VARIABLE:
            return "(no variable)"
        if self.status == OUT_OF_RANGE:
            return "(offset outside variable)"
        if self.status == UNSUPPORTED:
            return "(not decodable)"
        if self.label is not None:
            return self.label
        if isinstance(self.value, list):
            return ", ".join(str(v) for v in self.value)
        return "" if self.value is None else str(self.value)

    def as_dict(self) -> dict:
        out = self.setting.as_dict()
        if self.setting.options:
            states = self.option_states or [UNKNOWN] * len(self.setting.options)
            out["options"] = [option.as_dict(state)
                              for option, state in zip(self.setting.options, states)]
        out["live"] = {"status": self.status, "value": self.value,
                       "raw_value": self.raw_value,
                       "label": self.label, "is_default": self.is_default,
                       "candidate_labels": self.candidate_labels,
                       "display": self.display_value,
                       "visibility": self.visibility, "active": self.active}
        return out


def _to_int(raw: bytes, signed: bool) -> int:
    return int.from_bytes(raw, "little", signed=signed)


def _decode_string(data: bytes, offset: int, max_chars: int) -> str:
    limit = min(len(data), offset + min(max_chars, MAX_STRING_CHARS) * 2)
    end = offset
    while end + 1 < limit and data[end:end + 2] != b"\x00\x00":
        end += 2
    return data[offset:end].decode("utf-16-le", errors="replace")


def decode_setting(setting: Setting, store: VariableStore) -> DecodedSetting:
    ref = setting.varstore
    if ref is None or ref.offset is None or not ref.name:
        return DecodedSetting(setting, UNSUPPORTED)
    if setting.type == "password":
        # Whatever is stored here is a secret or its hash. Never read it out.
        return DecodedSetting(setting, REDACTED)
    if setting.type in ("date", "time"):
        return DecodedSetting(setting, UNSUPPORTED)

    data = store.get(ref.name, ref.guid)
    if data is None:
        return DecodedSetting(setting, NO_VARIABLE)

    size = ref.size or 1
    if setting.type == "string":
        chars = setting.maximum or 0
        if ref.offset >= len(data):
            return DecodedSetting(setting, OUT_OF_RANGE)
        return DecodedSetting(setting, OK,
                              value=_decode_string(data, ref.offset, chars))
    if setting.type == "ordered_list":
        count = min(setting.maximum or 0, MAX_ORDERED_ENTRIES)
        if ref.offset + count * size > len(data):
            return DecodedSetting(setting, OUT_OF_RANGE)
        values = [_to_int(data[ref.offset + i * size:ref.offset + (i + 1) * size], False)
                  for i in range(count)]
        return DecodedSetting(setting, OK, value=values)

    if ref.offset + size > len(data):
        return DecodedSetting(setting, OUT_OF_RANGE)
    raw = data[ref.offset:ref.offset + size]

    if setting.type == "boolean":
        value = _to_int(raw, False)
        return DecodedSetting(setting, OK, value=value, raw_value=value,
                              label="Enabled" if value else "Disabled",
                              is_default=None if setting.default is None
                              else bool(value) == bool(setting.default))

    raw_value = _to_int(raw, False)
    value = _to_int(raw, setting.display == "signed")
    is_default = None if setting.default is None else value == setting.default

    if setting.type == "enum":
        matches = [option for option in setting.options if option.value == value]
        if matches:
            unconditional = [option.label for option in matches if not option.conditions]
            return DecodedSetting(setting, OK, value=value, raw_value=raw_value,
                                  label=unconditional[0] if len(matches) == 1
                                  and len(unconditional) == 1 else None,
                                  candidate_labels=[option.label for option in matches],
                                  is_default=is_default)
        # A value with no matching option means the offset or width is wrong,
        # or the firmware stores something the form never offered.
        return DecodedSetting(setting, UNKNOWN_VALUE, value=value, raw_value=raw_value,
                              is_default=is_default)

    label = f"{value:#x}" if setting.display == "hex" else None
    return DecodedSetting(setting, OK, value=value, raw_value=raw_value,
                          label=label, is_default=is_default)


@dataclass
class VariantResolution:
    """Which of several per-CPU-family form sets the running machine uses."""

    inactive: set[str] = field(default_factory=set)
    families: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {"inactive_formsets": sorted(self.inactive),
                "platform_families": self.families, "evidence": self.evidence}


def _common_prefix(names: list[str]) -> int:
    first, last = min(names), max(names)
    for i, char in enumerate(first):
        if i >= len(last) or last[i] != char:
            return i
    return len(first)


def _family_matches(token: str, known: list[str]) -> bool:
    low = token.casefold()
    return any(low == k or low.startswith(k) or k.startswith(low) for k in known)


def resolve_variants(formsets: list[FormSetSummary],
                     store: VariableStore) -> VariantResolution:
    """Vendors ship one form set per CPU family, all in the same image, telling
    them apart only by varstore name (AmdSetupRPL / AmdSetupPHX / ...).

    A group is settled when only one variant's variable exists at runtime. That
    yields a family token, which then settles the groups where the firmware
    created every variant's variable regardless.
    """
    resolution = VariantResolution()
    for formset in formsets:
        formset.active = True
        formset.inactive_reason = ""
    # Grouped by varstore GUID alone: variants share the config namespace but
    # often differ in both varstore name and menu title.
    groups: dict[str, list[FormSetSummary]] = {}
    for formset in formsets:
        if formset.varstore_guid and formset.varstore_name:
            groups.setdefault(formset.varstore_guid, []).append(formset)

    contested = [g for g in groups.values() if len({f.varstore_name for f in g}) > 1]
    deferred = []

    for group in contested:
        names = sorted({f.varstore_name for f in group})
        cut = _common_prefix(names)
        live = [f for f in group if store.get(f.varstore_name, f.varstore_guid) is not None]
        live_names = {f.varstore_name for f in live}
        if len(live_names) == 1:
            winner = next(iter(live_names))
            resolution.families.append(winner[cut:].casefold())
            resolution.evidence.append(
                f"{group[0].title}: only {winner} exists at runtime")
            for formset in group:
                if formset.varstore_name != winner:
                    resolution.inactive.add(formset.guid)
                    formset.active = False
                    formset.inactive_reason = f"{formset.varstore_name} has no live variable"
        else:
            deferred.append((group, cut))

    for group, cut in deferred:
        candidates = [f for f in group if _family_matches(f.varstore_name[cut:],
                                                          resolution.families)]
        chosen = {f.varstore_name for f in candidates}
        if len(chosen) != 1:
            resolution.evidence.append(
                f"{group[0].title}: could not choose among "
                f"{sorted({f.varstore_name for f in group})}; all kept")
            continue
        winner = next(iter(chosen))
        resolution.evidence.append(
            f"{group[0].title}: {winner} matches platform family "
            f"{resolution.families[0]!r}")
        for formset in group:
            if formset.varstore_name != winner:
                resolution.inactive.add(formset.guid)
                formset.active = False
                formset.inactive_reason = f"variant for another CPU family ({winner} is live)"
    return resolution


class _QuestionValues(expr.Resolver):
    """Live question values for one form set, for evaluating its expressions."""

    def __init__(self, values: dict[int, int], this: int | None = None) -> None:
        self.values = values
        self.this = this

    def question_value(self, question_id: int) -> int | None:
        return self.values.get(question_id)

    def this_value(self) -> int | None:
        return self.this


def evaluate_visibility(decoded: list[DecodedSetting]) -> None:
    """Second pass: decide whether the firmware would show each setting.

    Needs every value decoded first, because a suppress_if on one question
    routinely tests the value of another.
    """
    values: dict[str, dict[int, int]] = {}
    for item in decoded:
        if item.status == OK and item.raw_value is not None:
            values.setdefault(item.setting.formset_guid, {})[
                item.setting.question_id] = item.raw_value

    resolvers = {guid: _QuestionValues(v) for guid, v in values.items()}
    empty = _QuestionValues({})

    for item in decoded:
        resolver = resolvers.get(item.setting.formset_guid, empty)
        outcome = VISIBLE
        undecided = False
        for condition in item.setting.conditions:
            result = expr.evaluate(condition.code, resolver)
            if result is None:
                undecided = True
            elif result:
                candidate = _CONDITION_RESULT.get(condition.kind, VISIBLE)
                if _VISIBILITY_RANK[candidate] > _VISIBILITY_RANK[outcome]:
                    outcome = candidate
        # An undecidable condition only matters if nothing else already hid it.
        item.visibility = UNKNOWN if undecided and outcome == VISIBLE else outcome

        item.option_states = []
        for option in item.setting.options:
            state = VISIBLE
            option_resolver = _QuestionValues(resolver.values, item.raw_value)
            for condition in option.conditions:
                result = expr.evaluate(condition.code, option_resolver)
                if result is True:
                    state = HIDDEN
                    break
                if result is None:
                    state = UNKNOWN
            item.option_states.append(state)

        if item.setting.type == "enum" and item.status == OK:
            matches = [(option, state) for option, state in
                       zip(item.setting.options, item.option_states)
                       if option.value == item.value]
            possible = [option.label for option, state in matches if state != HIDDEN]
            visible = [option.label for option, state in matches if state == VISIBLE]
            item.candidate_labels = possible
            if len(visible) == 1 and len(possible) == 1:
                item.label = visible[0]


def decode_all(settings: list[Setting], store: VariableStore,
               inactive_formsets: set[str] | None = None) -> list[DecodedSetting]:
    inactive = inactive_formsets or set()
    decoded = [decode_setting(s, store) for s in settings]
    for item in decoded:
        item.active = item.setting.formset_guid not in inactive
    evaluate_visibility(decoded)
    return decoded

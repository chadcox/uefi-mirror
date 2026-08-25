"""The setting schema: what the firmware image says a BIOS option is.

A schema is serialized to JSON and reloaded elsewhere, so every field the
decoder needs at evaluation time -- including the raw expression bytes behind
each condition -- must survive the round trip. `as_dict()` and `from_dict()`
are one contract: changing either shape means bumping SCHEMA_FORMAT_VERSION.
"""

import base64
import binascii
import hashlib
import json
from dataclasses import dataclass, field

from ..firmware import expr

SCHEMA_FORMAT_VERSION = 3

TYPE_BY_OPCODE_KIND = {
    "one_of": "enum",
    "checkbox": "boolean",
    "numeric": "integer",
    "string": "string",
    "password": "password",
    "ordered_list": "ordered_list",
    "date": "date",
    "time": "time",
}


def _str(data: dict, key: str) -> str:
    value = data.get(key, "")
    if not isinstance(value, str):
        raise ValueError(f"{key!r} must be a string, got {type(value).__name__}")
    return value


def _int(data: dict, key: str) -> int | None:
    value = data.get(key)
    if value is None or isinstance(value, bool):
        return None if value is None else int(value)
    if not isinstance(value, int):
        raise ValueError(f"{key!r} must be an integer, got {type(value).__name__}")
    return value


def _list(data: dict, key: str) -> list:
    value = data.get(key)
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError(f"{key!r} must be a list, got {type(value).__name__}")
    return value


def _dict(data: dict, key: str) -> dict:
    value = data.get(key)
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError(f"{key!r} must be an object, got {type(value).__name__}")
    return value


@dataclass
class OptionValue:
    label: str
    value: int | None
    is_default: bool = False
    conditions: list["ConditionRef"] = field(default_factory=list)

    def as_dict(self, state: str | None = None) -> dict:
        out: dict = {"label": self.label, "value": self.value}
        if self.is_default:
            out["default"] = True
        if self.conditions:
            out["conditions"] = [c.as_dict() for c in self.conditions]
        if state is not None:
            out["state"] = state
        return out

    @classmethod
    def from_dict(cls, data: dict) -> "OptionValue":
        return cls(_str(data, "label"), _int(data, "value"),
                   bool(data.get("default", False)),
                   [ConditionRef.from_dict(c) for c in _list(data, "conditions")])


@dataclass
class ConditionRef:
    """A conditional scope enclosing a question, with the expression bytes so
    it can be evaluated against live values later."""

    kind: str
    expression: str
    code: bytes = b""

    def as_dict(self) -> dict:
        return {"kind": self.kind, "expression": self.expression,
                "code": base64.b64encode(self.code).decode("ascii"),
                "question_refs": expr.referenced_questions(self.code)}

    @classmethod
    def from_dict(cls, data: dict) -> "ConditionRef":
        try:
            code = base64.b64decode(_str(data, "code"), validate=True)
        except (binascii.Error, ValueError) as exc:
            # Dropping unreadable code would silently turn a suppress_if into
            # "always visible", which is worse than refusing the schema.
            raise ValueError(f"condition code is not valid base64: {exc}") from None
        return cls(_str(data, "kind"), _str(data, "expression"), code)


@dataclass
class VarStoreRef:
    """Where one setting's value lives: a slice of a varstore. `size` is the
    width of that slice, never the size of the whole variable."""

    guid: str
    name: str
    offset: int | None
    size: int | None
    kind: str
    attributes: int | None = None
    varstore_id: int | None = None

    def as_dict(self) -> dict:
        return {"guid": self.guid, "name": self.name, "offset": self.offset,
                "size": self.size, "kind": self.kind, "attributes": self.attributes,
                "varstore_id": self.varstore_id}

    @classmethod
    def from_dict(cls, data: dict) -> "VarStoreRef":
        return cls(_str(data, "guid"), _str(data, "name"), _int(data, "offset"),
                   _int(data, "size"), _str(data, "kind"), _int(data, "attributes"),
                   _int(data, "varstore_id"))


@dataclass
class VarStoreInfo:
    """A varstore as its form set declares it: the whole variable. IFR varstore
    IDs are only unique within a form set, so identity is (formset, id)."""

    formset_guid: str
    varstore_id: int
    guid: str
    name: str
    kind: str
    size: int | None = None
    attributes: int | None = None

    def as_dict(self) -> dict:
        return {"formset_guid": self.formset_guid, "varstore_id": self.varstore_id,
                "guid": self.guid, "name": self.name, "kind": self.kind,
                "size": self.size, "attributes": self.attributes}

    @classmethod
    def from_dict(cls, data: dict) -> "VarStoreInfo":
        return cls(_str(data, "formset_guid"), _int(data, "varstore_id") or 0,
                   _str(data, "guid"), _str(data, "name"), _str(data, "kind"),
                   _int(data, "size"), _int(data, "attributes"))


@dataclass
class Setting:
    id: str
    name: str
    type: str
    formset_guid: str
    question_id: int
    path: list[str] = field(default_factory=list)
    help: str = ""
    options: list[OptionValue] = field(default_factory=list)
    default: int | None = None
    manufacturing_default: int | None = None
    minimum: int | None = None
    maximum: int | None = None
    step: int | None = None
    varstore: VarStoreRef | None = None
    conditions: list[ConditionRef] = field(default_factory=list)
    read_only: bool = False
    display: str = "dec"

    def as_dict(self) -> dict:
        out = {
            "id": self.id,
            "name": self.name,
            "path": self.path,
            "type": self.type,
            "help": self.help,
            "formset_guid": self.formset_guid,
            "question_id": self.question_id,
            "read_only": self.read_only,
            "display": self.display,
            "varstore": self.varstore.as_dict() if self.varstore else None,
        }
        if self.options:
            out["options"] = [o.as_dict() for o in self.options]
        for key in ("default", "manufacturing_default", "minimum", "maximum", "step"):
            value = getattr(self, key)
            if value is not None:
                out[key] = value
        if self.conditions:
            out["conditions"] = [c.as_dict() for c in self.conditions]
        return out

    @classmethod
    def from_dict(cls, data: dict) -> "Setting":
        path = _list(data, "path")
        if not all(isinstance(part, str) for part in path):
            raise ValueError("'path' must be a list of strings")
        return cls(
            id=_str(data, "id"),
            name=_str(data, "name"),
            type=_str(data, "type"),
            formset_guid=_str(data, "formset_guid"),
            question_id=_int(data, "question_id") or 0,
            path=path,
            help=_str(data, "help"),
            options=[OptionValue.from_dict(o) for o in _list(data, "options")],
            default=_int(data, "default"),
            manufacturing_default=_int(data, "manufacturing_default"),
            minimum=_int(data, "minimum"),
            maximum=_int(data, "maximum"),
            step=_int(data, "step"),
            varstore=(VarStoreRef.from_dict(data["varstore"])
                      if data.get("varstore") else None),
            conditions=[ConditionRef.from_dict(c) for c in _list(data, "conditions")],
            read_only=bool(data.get("read_only", False)),
            display=_str(data, "display") or "dec",
        )


@dataclass
class FormSetSummary:
    guid: str
    title: str
    class_guids: list[str]
    source: str
    setting_count: int
    varstore_name: str = ""
    varstore_guid: str = ""
    active: bool = True
    inactive_reason: str = ""

    def as_dict(self) -> dict:
        return {"guid": self.guid, "title": self.title,
                "class_guids": self.class_guids, "source": self.source,
                "setting_count": self.setting_count,
                "varstore_name": self.varstore_name,
                "varstore_guid": self.varstore_guid,
                "active": self.active, "inactive_reason": self.inactive_reason}

    @classmethod
    def from_dict(cls, data: dict) -> "FormSetSummary":
        class_guids = _list(data, "class_guids")
        if not all(isinstance(guid, str) for guid in class_guids):
            raise ValueError("'class_guids' must be a list of strings")
        return cls(_str(data, "guid"), _str(data, "title"), class_guids,
                   _str(data, "source"), _int(data, "setting_count") or 0,
                   _str(data, "varstore_name"), _str(data, "varstore_guid"),
                   bool(data.get("active", True)), _str(data, "inactive_reason"))


@dataclass
class Schema:
    image: dict
    formsets: list[FormSetSummary]
    settings: list[Setting]
    warnings: list[str] = field(default_factory=list)
    varstores: list[VarStoreInfo] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "format_version": SCHEMA_FORMAT_VERSION,
            "image": self.image,
            "formsets": [f.as_dict() for f in self.formsets],
            "varstores": [v.as_dict() for v in self.varstores],
            "settings": [s.as_dict() for s in self.settings],
            "warnings": self.warnings,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Schema":
        version = data.get("format_version")
        if version != SCHEMA_FORMAT_VERSION:
            raise ValueError(f"unsupported schema format_version {version!r}, "
                             f"expected {SCHEMA_FORMAT_VERSION}")
        warnings = _list(data, "warnings")
        if not all(isinstance(w, str) for w in warnings):
            raise ValueError("'warnings' must be a list of strings")
        return cls(
            image=_dict(data, "image"),
            formsets=[FormSetSummary.from_dict(f) for f in _list(data, "formsets")],
            settings=[Setting.from_dict(s) for s in _list(data, "settings")],
            warnings=warnings,
            varstores=[VarStoreInfo.from_dict(v) for v in _list(data, "varstores")],
        )

    @classmethod
    def from_json(cls, text: str | bytes) -> "Schema":
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValueError(f"schema is not valid JSON: {exc}") from None
        if not isinstance(data, dict):
            raise ValueError(f"schema must be an object, got {type(data).__name__}")
        return cls.from_dict(data)


def canonical_json(schema: Schema) -> bytes:
    """One schema, one byte string: the identity a published schema is named by.

    Sorted keys and no insignificant whitespace, so re-parsing the same image
    with the same parser must produce identical bytes.
    """
    return json.dumps(schema.as_dict(), sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def schema_hash(schema: Schema) -> str:
    return hashlib.sha256(canonical_json(schema)).hexdigest()

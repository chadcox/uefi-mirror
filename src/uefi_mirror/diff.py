"""Compare two BIOS configurations: variable bytes, and named settings.

Two snapshots taken either side of a change answer "what did that actually
touch?" -- a question no firmware setup screen will answer.
"""

import hashlib
from dataclasses import dataclass, field

from . import decode, report
from .decode import DecodedSetting, VariableStore

ADDED = "added"
REMOVED = "removed"
CHANGED = "changed"


@dataclass
class VariableChange:
    name: str
    guid: str
    kind: str
    old_size: int | None = None
    new_size: int | None = None
    differing_bytes: int = 0
    old_sha256: str | None = None
    new_sha256: str | None = None

    def as_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items() if v is not None}


@dataclass
class SettingChange:
    name: str
    path: list[str]
    old_display: str
    new_display: str
    old_value: object = None
    new_value: object = None
    visibility: str = decode.UNKNOWN

    def as_dict(self) -> dict:
        return {"name": self.name, "path": self.path,
                "old": self.old_display, "new": self.new_display,
                "old_value": self.old_value, "new_value": self.new_value,
                "visibility": self.visibility}


@dataclass
class Diff:
    variables: list[VariableChange] = field(default_factory=list)
    settings: list[SettingChange] = field(default_factory=list)
    settings_compared: int = 0
    old_source: str = ""
    new_source: str = ""

    def counts(self) -> dict:
        by_kind = {k: sum(1 for v in self.variables if v.kind == k)
                   for k in (ADDED, REMOVED, CHANGED)}
        return {"variables": by_kind, "settings_changed": len(self.settings),
                "settings_compared": self.settings_compared}

    def as_dict(self) -> dict:
        return {"old": self.old_source, "new": self.new_source,
                "counts": self.counts(),
                "variables": [v.as_dict() for v in self.variables],
                "settings": [s.as_dict() for s in self.settings]}

    def is_empty(self) -> bool:
        return not self.variables and not self.settings


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _differing_bytes(old: bytes, new: bytes) -> int:
    """Differing byte positions; a length change counts as a differing tail."""
    return sum(1 for a, b in zip(old, new) if a != b) + abs(len(old) - len(new))


def diff_variables(old: VariableStore, new: VariableStore) -> list[VariableChange]:
    changes = []
    for name, guid in sorted(set(old.keys()) | set(new.keys())):
        before, after = old.get(name, guid), new.get(name, guid)
        if before is None:
            changes.append(VariableChange(name, guid, ADDED, new_size=len(after),
                                          new_sha256=_sha(after)))
        elif after is None:
            changes.append(VariableChange(name, guid, REMOVED, old_size=len(before),
                                          old_sha256=_sha(before)))
        elif before != after:
            changes.append(VariableChange(
                name, guid, CHANGED, old_size=len(before), new_size=len(after),
                differing_bytes=_differing_bytes(before, after),
                old_sha256=_sha(before), new_sha256=_sha(after)))
    return changes


def diff_settings(old: list[DecodedSetting],
                  new: list[DecodedSetting]) -> tuple[list[SettingChange], int]:
    """Match settings by identity and report those whose value moved.

    Only settings that decoded on both sides are comparable; one that failed
    to decode either side is not silently reported as unchanged.
    """
    before = {item.setting.id: item for item in old}
    changes, compared = [], 0
    for item in new:
        other = before.get(item.setting.id)
        if (other is None or not other.active or not item.active
                or other.status != decode.OK or item.status != decode.OK):
            continue
        compared += 1
        if other.value != item.value:
            changes.append(SettingChange(
                item.setting.name, list(item.setting.path),
                other.display_value, item.display_value,
                other.value, item.value, item.visibility))
    changes.sort(key=lambda c: (c.path, c.name))
    return changes, compared


def build(old_store: VariableStore, new_store: VariableStore,
          old_decoded: list[DecodedSetting] | None = None,
          new_decoded: list[DecodedSetting] | None = None) -> Diff:
    result = Diff(old_source=old_store.source, new_source=new_store.source)
    result.variables = diff_variables(old_store, new_store)
    if old_decoded is not None and new_decoded is not None:
        result.settings, result.settings_compared = diff_settings(old_decoded, new_decoded)
    return result


def to_text(result: Diff, title: str) -> str:
    tally = result.counts()
    lines = [title, "-" * 78,
             f"old            {result.old_source}",
             f"new            {result.new_source}",
             f"variables      {tally['variables'][CHANGED]} changed, "
             f"{tally['variables'][ADDED]} added, "
             f"{tally['variables'][REMOVED]} removed",
             f"settings       {tally['settings_changed']} changed "
             f"of {tally['settings_compared']} compared",
             ""]
    if result.variables:
        lines.append("[variables]")
        symbol = {ADDED: "+", REMOVED: "-", CHANGED: "~"}
        for change in result.variables:
            size = change.new_size if change.new_size is not None else change.old_size
            detail = (f"{change.differing_bytes} of {size} bytes differ"
                      if change.kind == CHANGED else f"{size} bytes")
            lines.append(f" {symbol[change.kind]} {change.name:<44.44} {detail}")
        lines.append("")
    if result.settings:
        lines.append("[settings]")
        section = None
        for change in result.settings:
            key = " / ".join(change.path[:2]) or "(ungrouped)"
            if key != section:
                section = key
                lines.append(f"  {section}")
            note = "" if change.visibility == decode.VISIBLE else f" [{change.visibility}]"
            lines.append(f"    {change.name:<38.38} "
                         f"{change.old_display:<20.20} -> {change.new_display}{note}")
        lines.append("")
    if result.is_empty():
        lines += ["No differences.", ""]
    return "\n".join(lines)


def to_json(result: Diff) -> bytes:
    return report.to_json({"format_version": report.EXPORT_FORMAT_VERSION,
                           "generated_at": report.now(), "diff": result.as_dict()})

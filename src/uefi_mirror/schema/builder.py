"""Turn parsed HII form packages into a flat, named setting schema."""

from ..firmware import hii, ifr
from ..firmware.firmware_volume import FfsFile
from .model import (
    TYPE_BY_OPCODE_KIND,
    ConditionRef,
    FormSetSummary,
    OptionValue,
    Schema,
    Setting,
    VarStoreInfo,
    VarStoreRef,
)

QUESTION_FLAG_READ_ONLY = 0x01
DISPLAY_NAMES = {ifr.DISPLAY_UINT_DEC: "dec", ifr.DISPLAY_UINT_HEX: "hex",
                 ifr.DISPLAY_INT_DEC: "signed"}
MAX_PATH_DEPTH = 12


def _form_paths(form_set: ifr.FormSet, package: hii.PackageList) -> dict[int, list[str]]:
    """Menu location of each form, from the EFI_IFR_REF links between forms.

    Forms nobody references are top-level pages; everything else hangs off the
    first page that references it.
    """
    parent: dict[int, int] = {}
    for source, target in form_set.refs:
        parent.setdefault(target, source)

    paths: dict[int, list[str]] = {}
    for form_id in form_set.forms:
        chain: list[str] = []
        seen = set()
        current: int | None = form_id
        while current is not None and current not in seen and len(chain) < MAX_PATH_DEPTH:
            seen.add(current)
            title = package.text(form_set.forms.get(current, 0))
            if title:
                chain.append(title)
            current = parent.get(current)
        paths[form_id] = list(reversed(chain))
    return paths


def _primary_varstore(form_set: ifr.FormSet) -> ifr.VarStore | None:
    """The varstore most of a form set's questions live in. Form sets that are
    per-CPU-family variants of each other differ exactly here."""
    tally: dict[int, int] = {}
    for question in form_set.questions:
        tally[question.varstore_id] = tally.get(question.varstore_id, 0) + 1
    if not tally:
        return None
    return form_set.varstores.get(max(tally, key=lambda k: tally[k]))


def _menu_path(title: str, form_path: list[str], subtitles: list[str]) -> list[str]:
    """Form set title, then the page hierarchy, then any subtitle grouping.

    The root form usually repeats the form set title, and cross-links between
    pages can make a title reappear further down, so keep only first mentions.
    """
    path: list[str] = []
    for part in ([title] if title else []) + form_path + subtitles:
        if part and part not in path:
            path.append(part)
    return path


def _varstore_ref(question: ifr.Question, form_set: ifr.FormSet,
                  package: hii.PackageList) -> VarStoreRef | None:
    store = form_set.varstores.get(question.varstore_id)
    if store is None:
        return None
    if store.kind == "name_value":
        # varstore_info is a string ID naming the variable, not an offset.
        return VarStoreRef(store.guid, package.text(question.varstore_info) or store.name,
                           None, question.value_size, store.kind, store.attributes,
                           store.varstore_id)
    return VarStoreRef(store.guid, store.name, question.var_offset,
                       question.value_size, store.kind, store.attributes,
                       store.varstore_id)


def _options(question: ifr.Question, package: hii.PackageList) -> list[OptionValue]:
    width = question.value_size if question.display == ifr.DISPLAY_INT_DEC else None
    return [OptionValue(package.text(o.text_id) or f"(string {o.text_id})",
                        _signed(o.value, width), o.is_default,
                        [ConditionRef(c.kind, c.expression, c.code)
                         for c in o.conditions])
            for o in question.options]


def _signed(value: int | None, size: int | None) -> int | None:
    """IFR stores every value as raw little-endian bytes. A question displayed
    as a signed decimal must have its default and range read back the same way
    the live bytes will be, or nothing will ever compare equal."""
    if value is None or not size:
        return value
    limit = 1 << (size * 8 - 1)
    return value - 2 * limit if value >= limit else value


def _default_value(question: ifr.Question, default_id: int) -> int | None:
    if default_id in question.defaults:
        return question.defaults[default_id]
    for option in question.options:
        if default_id == ifr.DEFAULT_STANDARD and option.is_default:
            return option.value
        if default_id == ifr.DEFAULT_MANUFACTURING and option.is_manufacturing_default:
            return option.value
    if question.kind == "checkbox":
        flag = (ifr.CHECKBOX_DEFAULT if default_id == ifr.DEFAULT_STANDARD
                else ifr.CHECKBOX_DEFAULT_MFG)
        return int(bool(question.checkbox_flags & flag))
    return None


def build(image_info: dict, files: list[FfsFile]) -> Schema:
    packages = hii.collect(files)
    formsets: list[FormSetSummary] = []
    settings: list[Setting] = []
    varstores: list[VarStoreInfo] = []
    warnings: list[str] = []

    for package in packages:
        form_set = ifr.parse_form_set(package.ifr)
        if form_set is None:
            warnings.append(f"unparsable form set at {package.source}")
            continue
        if not package.strings:
            warnings.append(f"no strings found for form set {package.formset_guid}")

        for store in form_set.varstores.values():
            varstores.append(VarStoreInfo(package.formset_guid, store.varstore_id,
                                          store.guid, store.name, store.kind,
                                          store.size, store.attributes))

        paths = _form_paths(form_set, package)
        title = package.text(form_set.title_id)
        count = 0

        for question in form_set.questions:
            name = package.text(question.prompt_id)
            if not name:
                continue  # An unnamed question is not a setting a user can mean.
            setting_type = TYPE_BY_OPCODE_KIND.get(question.kind, question.kind)
            path = _menu_path(title, paths.get(question.form_id, []),
                              [package.text(s) for s in question.subtitle_ids])

            width = question.value_size if question.display == ifr.DISPLAY_INT_DEC else None

            settings.append(Setting(
                id=f"{package.formset_guid}:{question.question_id:#06x}",
                name=name,
                type=setting_type,
                formset_guid=package.formset_guid,
                question_id=question.question_id,
                path=path,
                help=package.text(question.help_id),
                options=_options(question, package),
                default=_signed(_default_value(question, ifr.DEFAULT_STANDARD), width),
                manufacturing_default=_signed(
                    _default_value(question, ifr.DEFAULT_MANUFACTURING), width),
                minimum=_signed(question.minimum, width),
                maximum=_signed(question.maximum, width),
                step=question.step,
                varstore=_varstore_ref(question, form_set, package),
                conditions=[ConditionRef(c.kind, c.expression, c.code)
                            for c in question.conditions],
                read_only=bool(question.flags & QUESTION_FLAG_READ_ONLY),
                display=DISPLAY_NAMES.get(question.display, "dec"),
            ))
            count += 1

        primary = _primary_varstore(form_set)
        formsets.append(FormSetSummary(
            package.formset_guid, title, form_set.class_guids, package.source, count,
            varstore_name=primary.name if primary else "",
            varstore_guid=primary.guid if primary else ""))

    settings.sort(key=lambda s: (s.path, s.name, s.id))
    varstores.sort(key=lambda v: (v.formset_guid, v.varstore_id))
    return Schema(image=image_info, formsets=formsets, settings=settings,
                  warnings=warnings, varstores=varstores)

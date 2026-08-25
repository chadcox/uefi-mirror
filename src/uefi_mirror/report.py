"""Assemble and render an export document: schema joined to live values."""

import datetime
import json

from . import __version__
from .decode import OK, VISIBLE, DecodedSetting, VariableStore
from .schema.model import Schema

EXPORT_FORMAT_VERSION = 3
_RULE = "-" * 78

_HTML_CSS = r"""
:root { color-scheme: light dark; font-family: system-ui, sans-serif; line-height: 1.45;
  --bg:#f7f7f5; --panel:#fff; --text:#171717; --muted:#5d625f; --line:#c9ceca;
  --accent:#075a46; --mark:#8a3b12; }
@media (prefers-color-scheme: dark) { :root { --bg:#111412; --panel:#191d1a; --text:#f3f5f3;
  --muted:#adb5af; --line:#475049; --accent:#75d7b8; --mark:#ffb17d; } }
* { box-sizing:border-box } body { margin:0; color:var(--text); background:var(--bg) }
header, main { width:min(1440px, 96vw); margin:auto } header { padding:2rem 0 1rem }
h1 { margin:0 0 .25rem; font-size:clamp(1.7rem,4vw,2.7rem) } h2 { margin-top:2rem }
.muted { color:var(--muted) } .summary, .controls { display:flex; gap:.75rem 1.5rem;
  flex-wrap:wrap; padding:1rem; background:var(--panel); border:1px solid var(--line) }
.summary strong { display:block; font-size:1.3rem } .controls { align-items:end; margin:1rem 0 }
.control { display:grid; gap:.25rem; min-width:10rem; flex:1 } .control.search { flex-basis:24rem }
label { font-weight:650 } input, select, button { font:inherit; color:inherit; background:var(--panel);
  border:1px solid var(--line); border-radius:.25rem; padding:.55rem }
button { cursor:pointer; font-weight:650 } button:disabled { opacity:.5; cursor:default }
input:focus, select:focus, button:focus, summary:focus { outline:3px solid var(--accent); outline-offset:2px }
.check { display:flex; align-items:center; gap:.5rem; min-height:2.6rem }.check input { width:1.1rem;height:1.1rem }
.results-head, .pager { display:flex; align-items:center; justify-content:space-between; gap:1rem }
.pager { justify-content:center; margin:1rem 0 2rem }.pager span { min-width:9rem; text-align:center }
.table-wrap { overflow-x:auto; background:var(--panel); border:1px solid var(--line) }
table { border-collapse:collapse; width:100% } th, td { padding:.7rem; text-align:left;
  vertical-align:top; border-bottom:1px solid var(--line) } th { position:sticky; top:0; background:var(--panel) }
td:nth-child(1) { width:8rem } td:nth-child(2) { min-width:17rem } td:nth-child(3),td:nth-child(4) { min-width:10rem }
.status { font-weight:700 }.changed { color:var(--mark) }.details { padding:.8rem 0 .2rem }
.detail-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(18rem,1fr)); gap:.8rem 1.5rem;
  margin-top:.8rem }.detail-grid section { min-width:0 }.detail-grid h3 { margin:.2rem 0 }
dl { margin:.3rem 0; display:grid; grid-template-columns:max-content 1fr; gap:.25rem .7rem }
dd { margin:0; overflow-wrap:anywhere } ul { margin:.3rem 0; padding-left:1.25rem }
code { overflow-wrap:anywhere } .empty { padding:2rem; text-align:center }
details.provenance { margin-top:1rem } details.provenance > div { padding:.8rem; border:1px solid var(--line) }
@media (max-width:720px) { thead { position:absolute; clip:rect(0 0 0 0) } tr { display:block;
  padding:.5rem; border-bottom:1px solid var(--line) } td { display:grid; grid-template-columns:7rem 1fr;
  border:0; padding:.3rem; width:auto!important; min-width:0!important } td::before { content:attr(data-label);
  font-weight:700; color:var(--muted) } .details { grid-column:1 / -1 } }
"""

_HTML_JS = r"""
'use strict';
const doc = JSON.parse(document.getElementById('uefi-data').textContent);
const initial = JSON.parse(document.getElementById('uefi-filters').textContent);
const settings = Array.isArray(doc.settings) ? doc.settings : [];
const formsets = new Map((doc.formsets || []).map(f => [f.guid, f]));
const pageSize = 200;
let page = 1;
const byId = id => document.getElementById(id);
const text = value => value === null || value === undefined || value === '' ? '—' : String(value);
const hex = value => Number.isInteger(value) ? '0x' + value.toString(16) : text(value);
const add = (parent, tag, value, className) => {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (value !== undefined) node.textContent = value;
  parent.appendChild(node);
  return node;
};
const path = s => (s.path || []).join(' / ');
const defaultValue = s => {
  if (s.default === undefined || s.default === null) return 'Unknown';
  const option = (s.options || []).find(o => o.value === s.default);
  return option ? option.label : (s.display === 'hex' ? hex(s.default) : text(s.default));
};
const searchable = s => [s.name, path(s), s.help, s.live && s.live.display, defaultValue(s),
  s.varstore && s.varstore.name, s.varstore && s.varstore.guid,
  s.varstore && s.varstore.offset, s.varstore && hex(s.varstore.offset),
  ...(s.options || []).flatMap(o => [o.label, o.value, hex(o.value)])]
  .filter(v => v !== null && v !== undefined).join(' ').toLocaleLowerCase();
settings.forEach(s => { s._search = searchable(s); });

function fillSelect(id, values, label) {
  const select = byId(id);
  values.filter(Boolean).sort((a,b) => String(a).localeCompare(String(b))).forEach(value => {
    const option = document.createElement('option'); option.value = value;
    option.textContent = label ? label(value) : value; select.appendChild(option);
  });
}
fillSelect('decode', [...new Set(settings.map(s => s.live && s.live.status))]);
fillSelect('type', [...new Set(settings.map(s => s.type))]);
fillSelect('formset', [...new Set(settings.map(s => s.formset_guid))], guid => {
  const f = formsets.get(guid); return f && f.title ? f.title + ' — ' + guid : guid;
});

function provenance() {
  const image = doc.image || {}, source = doc.variable_source || {}, counts = doc.counts || {};
  byId('subtitle').textContent = (image.filename || 'Firmware image') + ' · generated ' + text(doc.generated_at);
  const summary = byId('summary');
  const values = [['Total', counts.total || settings.length], ['Active', counts.active || 0],
    ['Changed', counts.changed_from_default || 0], ['Visible', (counts.by_visibility || {}).visible || 0],
    ['Hidden', (counts.by_visibility || {}).hidden || 0], ['Grayed', (counts.by_visibility || {}).grayed || 0],
    ['Disabled', (counts.by_visibility || {}).disabled || 0], ['Unknown', (counts.by_visibility || {}).unknown || 0],
    ...Object.entries(counts.by_status || {}).map(([status,count]) => ['Decode: ' + status, count])];
  values.forEach(([name,value]) => { const box=add(summary,'div'); add(box,'strong',text(value)); add(box,'span',name); });
  const target = byId('provenance');
  const pairs = [['Image filename', image.filename], ['File SHA-256', image.file_sha256],
    ['Payload SHA-256', image.payload_sha256], ['Payload size', image.payload_size],
    ['Capsule GUID', image.capsule_guid], ['Capsule header size', image.capsule_header_size],
    ['Capsule flags', image.capsule_flags], ['Capsule image size', image.capsule_image_size],
    ['Tool version', doc.tool_version], ['Format version', doc.format_version],
    ['Collection/export time', doc.generated_at], ['Variable source', source.source],
    ['Variable count', source.variables], ['Collection errors', (source.errors || []).join('; ') || 'None'],
    ['Decode status counts', Object.entries(counts.by_status || {}).map(([k,v]) => k + ': ' + v).join(', ')]];
  pairs.forEach(([key,value]) => { add(target,'dt',key); add(target,'dd',text(value)); });
}

function pair(dl, key, value) { add(dl,'dt',key); add(dl,'dd',text(value)); }
function conditionsText(conditions) {
  return (conditions || []).length ? conditions.map(c => c.kind + ': ' + c.expression).join('; ') : 'None';
}
function allowedValues(parent, s) {
  const section=add(parent,'section'); add(section,'h3','Firmware-declared options');
  if (s.type === 'enum') {
    const list=add(section,'ul');
    (s.options || []).forEach(o => {
      const tags=[]; if (o.default) tags.push('default');
      if (o.state === 'visible') tags.push('currently available');
      else tags.push('visibility: ' + (o.state || 'unknown'));
      add(list,'li',o.label + ' — ' + text(o.value) + ' (' + tags.join(', ') + ')');
    });
  } else if (s.type === 'boolean') add(section,'p','Disabled (0); Enabled (1)');
  else if (s.type === 'integer') add(section,'p','Minimum ' + text(s.minimum) + '; maximum ' +
    text(s.maximum) + '; step ' + (s.step === 0 ? 'free-form' : text(s.step)));
  else if (s.type === 'string' || s.type === 'password') add(section,'p','Minimum ' +
    text(s.minimum) + '; maximum ' + text(s.maximum) + ' characters');
  else add(section,'p','Possible values are unavailable for this storage type.');
}
function detailsFor(parent, s) {
  const wrap=add(parent,'div',undefined,'detail-grid'), live=s.live || {};
  const overview=add(wrap,'section'); add(overview,'h3','Setting details');
  if (s.help) add(overview,'p',s.help);
  const dl=add(overview,'dl'); pair(dl,'Stable ID',s.id); pair(dl,'Question ID',hex(s.question_id));
  pair(dl,'Form set',(formsets.get(s.formset_guid) || {}).title); pair(dl,'Form-set GUID',s.formset_guid);
  pair(dl,'Menu path',path(s)); pair(dl,'Type',s.type); pair(dl,'Read only',s.read_only ? 'Yes' : 'No');
  pair(dl,'Current display',live.display); pair(dl,'Normalized value',live.value);
  pair(dl,'Raw value',live.raw_value); pair(dl,'Default',defaultValue(s));
  pair(dl,'Manufacturing default',s.manufacturing_default);
  const storage=add(wrap,'section'); add(storage,'h3','Storage and state'); const sd=add(storage,'dl');
  const v=s.varstore || {}; pair(sd,'Varstore name',v.name); pair(sd,'Varstore GUID',v.guid);
  pair(sd,'Kind',v.kind); pair(sd,'Offset',v.offset === null || v.offset === undefined ? null : hex(v.offset));
  pair(sd,'Size',v.size); pair(sd,'Attributes',v.attributes === null || v.attributes === undefined ? null : hex(v.attributes));
  pair(sd,'Decode status',live.status); pair(sd,'Decode explanation',live.status === 'ok' ? 'Decoded successfully' : live.display);
  pair(sd,'Visibility',live.visibility); pair(sd,'Question conditions',conditionsText(s.conditions));
  pair(sd,'Evaluated result',live.visibility); pair(sd,'Variant state',live.active ? 'Active' : 'Inactive');
  const fs=formsets.get(s.formset_guid) || {}; pair(sd,'Variant evidence',fs.inactive_reason ||
    ((doc.variants && doc.variants.evidence || []).join('; ') || 'No variant exclusion evidence'));
  allowedValues(wrap,s);
}
function statusText(s) {
  const live=s.live || {}, labels=[];
  if (live.is_default === false) labels.push('Changed');
  else if (live.is_default === true) labels.push('Default');
  else labels.push('Default unknown');
  if (!live.active) labels.push('Inactive');
  if (live.status !== 'ok') labels.push(live.status || 'unknown status');
  return labels.join(' · ');
}
function cell(row,label,value,className) { const td=add(row,'td',value,className); td.dataset.label=label; return td; }
function rowFor(s) {
  const row=document.createElement('tr'), live=s.live || {};
  cell(row,'Status',statusText(s),'status ' + (live.is_default === false ? 'changed' : ''));
  const name=cell(row,'Setting'); const details=add(name,'details',undefined,'details');
  add(details,'summary',s.name || '(unnamed setting)'); detailsFor(details,s);
  cell(row,'Current',text(live.display)); cell(row,'Default',defaultValue(s));
  cell(row,'Visibility',text(live.visibility)); cell(row,'Menu path',path(s)); return row;
}
function filtered() {
  const needle=byId('search').value.trim().toLocaleLowerCase(), mode=byId('default-state').value;
  return settings.filter(s => { const live=s.live || {};
    if (!byId('include-inactive').checked && !live.active) return false;
    if (needle && !s._search.includes(needle)) return false;
    if (mode === 'changed' && live.is_default !== false) return false;
    if (mode === 'default' && live.is_default !== true) return false;
    if (mode === 'unknown-default' && live.is_default !== null) return false;
    if (byId('visibility').value && live.visibility !== byId('visibility').value) return false;
    if (byId('decode').value && live.status !== byId('decode').value) return false;
    if (byId('type').value && s.type !== byId('type').value) return false;
    if (byId('formset').value && s.formset_guid !== byId('formset').value) return false;
    return true;
  });
}
function render(resetPage=true) {
  if (resetPage) page=1; const found=filtered(), pages=Math.max(1,Math.ceil(found.length/pageSize));
  page=Math.min(page,pages); const body=byId('rows'); body.replaceChildren();
  found.slice((page-1)*pageSize,page*pageSize).forEach(s => body.appendChild(rowFor(s)));
  byId('result-count').textContent=found.length + ' of ' + settings.length + ' settings';
  byId('page-status').textContent='Page ' + page + ' of ' + pages;
  byId('previous').disabled=page === 1; byId('next').disabled=page === pages;
  byId('empty').hidden=found.length !== 0; byId('table-wrap').hidden=found.length === 0;
}
const controls=['search','include-inactive','default-state','visibility','decode','type','formset'];
controls.forEach(id => byId(id).addEventListener(id === 'search' ? 'input' : 'change', () => render()));
byId('reset').addEventListener('click', () => { byId('filters').reset(); render(); byId('search').focus(); });
byId('filters').addEventListener('submit', event => event.preventDefault());
byId('previous').addEventListener('click', () => { page--; render(false); });
byId('next').addEventListener('click', () => { page++; render(false); });
byId('search').value=initial.grep || ''; byId('include-inactive').checked=Boolean(initial.include_inactive);
if (initial.changed_only) byId('default-state').value='changed';
if (initial.visible_only) byId('visibility').value='visible';
provenance(); render();
"""

_HTML_TEMPLATE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src data:; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'none'; base-uri 'none'; form-action 'none'">
<meta name="uefi-mirror-format" content="{format_version}"><title>UEFI settings export</title>
<style>{css}</style></head><body>
<header><h1>UEFI settings export</h1><p id="subtitle" class="muted"></p>
<div id="summary" class="summary" aria-label="Export summary"></div>
<details class="provenance"><summary>Image and collection provenance</summary><div><dl id="provenance"></dl></div></details></header>
<main><h2>Settings</h2><form id="filters" class="controls">
<div class="control search"><label for="search">Search settings</label><input id="search" type="search" autocomplete="off"></div>
<div class="control"><label for="default-state">Default state</label><select id="default-state"><option value="">All</option><option value="changed">Changed</option><option value="default">Default</option><option value="unknown-default">Unknown default</option></select></div>
<div class="control"><label for="visibility">Visibility</label><select id="visibility"><option value="">All</option><option>visible</option><option>hidden</option><option>grayed</option><option>disabled</option><option>unknown</option></select></div>
<div class="control"><label for="decode">Decode status</label><select id="decode"><option value="">All</option></select></div>
<div class="control"><label for="type">Setting type</label><select id="type"><option value="">All</option></select></div>
<div class="control"><label for="formset">Form set</label><select id="formset"><option value="">All</option></select></div>
<div class="control"><label class="check" for="include-inactive"><input id="include-inactive" type="checkbox">Include other CPU families</label></div>
<button id="reset" type="button">Reset filters</button></form>
<div class="results-head"><strong id="result-count" aria-live="polite"></strong></div>
<p id="empty" class="empty" hidden>No settings match these filters.</p>
<div id="table-wrap" class="table-wrap"><table><thead><tr><th scope="col">Status</th><th scope="col">Setting name</th><th scope="col">Current value</th><th scope="col">Default</th><th scope="col">Visibility</th><th scope="col">Menu path</th></tr></thead><tbody id="rows"></tbody></table></div>
<nav class="pager" aria-label="Results pages"><button id="previous" type="button">Previous</button><span id="page-status"></span><button id="next" type="button">Next</button></nav></main>
<script id="uefi-data" type="application/json">{data}</script>
<script id="uefi-filters" type="application/json">{filters}</script>
<script>{js}</script></body></html>
"""


def now() -> str:
    return datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_document(schema: Schema, store: VariableStore,
                   decoded: list[DecodedSetting], variants=None) -> dict:
    return {
        "format_version": EXPORT_FORMAT_VERSION,
        "tool_version": __version__,
        "generated_at": now(),
        "image": schema.image,
        "variable_source": store.describe(),
        "counts": counts(decoded),
        "variants": variants.as_dict() if variants else None,
        "formsets": [f.as_dict() for f in schema.formsets],
        "settings": [d.as_dict() for d in decoded],
        "warnings": schema.warnings,
    }


def counts(decoded: list[DecodedSetting]) -> dict:
    by_status: dict[str, int] = {}
    for item in decoded:
        by_status[item.status] = by_status.get(item.status, 0) + 1
    by_visibility: dict[str, int] = {}
    for item in decoded:
        if item.active:
            by_visibility[item.visibility] = by_visibility.get(item.visibility, 0) + 1
    return {
        "total": len(decoded),
        "by_status": dict(sorted(by_status.items())),
        "changed_from_default": sum(1 for d in decoded if is_changed(d)),
        "active": sum(1 for d in decoded if d.active),
        "by_visibility": dict(sorted(by_visibility.items())),
        "changed_and_visible": sum(1 for d in decoded if is_changed(d)
                                   and d.active and d.visibility == VISIBLE),
    }


def is_changed(item: DecodedSetting) -> bool:
    return item.status == OK and item.is_default is False


def group_key(item: DecodedSetting) -> str:
    return " / ".join(item.setting.path[:2]) or "(ungrouped)"


def to_json(document: dict) -> bytes:
    return json.dumps(document, indent=2).encode() + b"\n"


def _script_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).translate(
        str.maketrans({"<": r"\u003c", ">": r"\u003e", "&": r"\u0026",
                       "\u2028": r"\u2028", "\u2029": r"\u2029"}))


def to_html(document: dict, initial_filters: dict | None = None) -> bytes:
    """Render the complete export as a self-contained offline viewer."""
    return _HTML_TEMPLATE.format(
        format_version=document.get("format_version", ""), css=_HTML_CSS,
        data=_script_json(document), filters=_script_json(initial_filters or {}),
        js=_HTML_JS).encode()


def to_text(document: dict, decoded: list[DecodedSetting], title: str) -> str:
    """Plain text, grouped by menu section. No colour, safe to redirect."""
    image = document["image"]
    lines = [
        title,
        _RULE,
        f"generated      {document['generated_at']} by uefi-mirror {document['tool_version']}",
        f"image          {image.get('file_sha256', '?')}",
        f"variables      {document['variable_source']['source']} "
        f"({document['variable_source']['variables']} read)",
        f"settings       {document['counts']['total']} "
        f"({document['counts']['changed_from_default']} differ from firmware default)",
        "visibility     " + ", ".join(
            f"{count} {state}" for state, count
            in document["counts"]["by_visibility"].items()),
        "",
    ]

    section = None
    for item in decoded:
        key = group_key(item)
        if key != section:
            section = key
            lines += [f"[{section}]"]
        marker = "*" if is_changed(item) else " "
        name = item.setting.name
        value = item.display_value
        note = _default_note(item)
        if not item.active:
            note = f"[other CPU family] {note}".rstrip()
        elif item.visibility != VISIBLE:
            note = f"[{item.visibility}] {note}".rstrip()
        lines.append(f" {marker} {name:<44.44} {value:<26.26} {note}".rstrip())
    lines += ["", "* = differs from the firmware default",
              "[other CPU family] = a form set variant for a different CPU; "
              "not this machine's",
              "[hidden|grayed|disabled] = the firmware's own conditions say the "
              "setup menu would not offer this", ""]
    return "\n".join(lines)


def _default_note(item: DecodedSetting) -> str:
    if not is_changed(item):
        return ""
    setting = item.setting
    for option in setting.options:
        if option.value == setting.default:
            return f"(default {option.label})"
    if setting.default is None:
        return ""
    default = f"{setting.default:#x}" if setting.display == "hex" else setting.default
    return f"(default {default})"

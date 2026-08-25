"""uefi-mirror CLI. Read-only by construction: no subcommand writes to firmware."""

import datetime
import json
import os

import typer
from rich.console import Console
from rich.table import Table

from . import __version__, decode, platform, report
from . import diff as diff_mod
from .collectors import efivarfs
from .firmware import cap, firmware_volume
from .safety import private_dir, write_private
from .schema import builder
from .schema.model import Schema, schema_hash

app = typer.Typer(add_completion=False, help="Export live UEFI/BIOS settings, read-only.")
console = Console()

SNAPSHOT_FORMAT_VERSION = decode.SNAPSHOT_FORMAT_VERSION


def _now() -> str:
    return datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _dmi_for(store: decode.VariableStore) -> dict[str, str]:
    saved = store.platform.get("dmi")
    if isinstance(saved, dict):
        return {key: value for key, value in saved.items() if isinstance(value, str)}
    return platform.dmi()


def _load_schema(image: str | None,
                 schema_file: str | None) -> tuple[Schema, bytes | None, str]:
    """Get a schema from a firmware image or from a published schema JSON.

    Returns (schema, image_bytes, name). image_bytes is None for a schema file:
    the raw firmware is exactly what a portable schema does not carry.

    `name` is always the firmware filename the schema came from, never the
    schema file's own name: the latter is whatever the user renamed it to, and
    reading BIOS-version evidence out of it would be reading their own guess.
    """
    if image and schema_file:
        raise typer.BadParameter("pass a firmware image or --schema, not both")
    if schema_file:
        try:
            with open(schema_file, "rb") as handle:
                loaded = Schema.from_json(handle.read())
        except (OSError, ValueError) as exc:
            raise typer.BadParameter(f"{schema_file}: {exc}") from exc
        loaded.image["schema_file"] = os.path.basename(schema_file)
        origin = loaded.image.get("filename")
        return loaded, None, origin if isinstance(origin, str) else ""
    if image:
        try:
            capsule = cap.load(image)
        except (OSError, ValueError, RuntimeError) as exc:
            raise typer.BadParameter(str(exc)) from exc
        return (builder.build(capsule.info(), firmware_volume.walk(capsule.data)),
                capsule.data, os.path.basename(image))
    raise typer.BadParameter("pass a firmware image, or --schema with a schema JSON")


def _check_image(schema_result, store: decode.VariableStore, image: bytes | None,
                 image_name: str, decoded, allow_mismatch: bool,
                 label: str = "") -> decode.Compatibility:
    result = decode.check_compatibility(
        schema_result.settings, store, image, _dmi_for(store), decoded, image_name)
    prefix = f"{label}: " if label else ""
    detail = "; ".join(result.problems or result.evidence)
    if result.status == "mismatch" and not allow_mismatch:
        raise typer.BadParameter(
            f"{prefix}schema does not match this machine's variable layout: {detail}; "
            "use --allow-mismatch to inspect it anyway")
    style = "green" if result.status == "matched" else "yellow"
    console.print(f"[{style}]schema compatibility: {prefix}{result.status}[/] ({detail})")
    return result


@app.command()
def probe() -> None:
    """Report platform, firmware and tool availability. Changes nothing."""
    info = platform.summary()
    dmi = info["dmi"]

    table = Table(show_header=False, box=None)
    table.add_row("Boot mode", "UEFI" if info["uefi_boot"] else "LEGACY (BIOS)")
    table.add_row("Board", f"{dmi.get('board_vendor', '?')} {dmi.get('board_name', '?')}")
    table.add_row("Firmware", f"{dmi.get('bios_vendor', '?')} {dmi.get('bios_version', '?')}"
                              f" ({dmi.get('bios_date', '?')})")
    table.add_row("efivarfs", "mounted" if info["efivarfs_mounted"] else "NOT mounted")

    if info["efivarfs_mounted"]:
        try:
            variables = efivarfs.collect()
        except (OSError, RuntimeError) as exc:
            table.add_row("Variables", f"unreadable: {exc}")
        else:
            ok = [v for v in variables if v.error is None]
            total = sum(v.size for v in ok)
            table.add_row("Variables", f"{len(ok)} readable of {len(variables)}, "
                                       f"{total} payload bytes")

    fw_attrs = info["firmware_attributes"]
    table.add_row("firmware-attributes",
                  ", ".join(f"{d} ({len(s)} settings)" for d, s in fw_attrs.items())
                  if fw_attrs else "none")
    tools = info["optional_tools"]
    table.add_row("Optional tools",
                  "\n".join(f"{k}: {v}" for k, v in tools.items()) if tools else "none installed")
    table.add_row("Privileges", "root" if info["euid"] == 0 else f"uid {info['euid']}"
                                " (some variables may be unreadable)")
    console.print(table)


@app.command()
def snapshot(
    output: str = typer.Option(..., "--output", "-o", help="Directory for the snapshot."),
    efivars: str = typer.Option(platform.EFIVARS_DIR, "--efivars", hidden=True),
) -> None:
    """Copy every readable UEFI variable into a private directory."""
    require_mount = efivars == platform.EFIVARS_DIR
    variables = efivarfs.collect(efivars, require_mount=require_mount)

    private_dir(output)
    raw_dir = private_dir(os.path.join(output, "raw-variables"))
    for var in variables:
        if var.payload is not None:
            write_private(os.path.join(raw_dir, var.filename), var.payload)

    failed = [v for v in variables if v.error is not None]
    manifest = {
        "format_version": SNAPSHOT_FORMAT_VERSION,
        "tool_version": __version__,
        "collected_at": _now(),
        "source": efivars,
        "platform": platform.summary(),
        "variables": [v.manifest() for v in variables],
    }
    write_private(
        os.path.join(output, "manifest.json"),
        json.dumps(manifest, indent=2, sort_keys=True).encode() + b"\n",
    )

    console.print(f"Snapshot: {len(variables) - len(failed)} variables -> {output}")
    for var in failed:
        console.print(f"  [yellow]skipped[/] {var.filename}: {var.error}")


@app.command()
def schema(
    image: str = typer.Argument(..., help="BIOS update file (.CAP) or raw SPI image."),
    output: str = typer.Option(None, "--output", "-o", help="Write JSON here."),
    grep: str = typer.Option(None, "--grep", "-g",
                             help="Filter terminal rows; JSON remains complete."),
    limit: int = typer.Option(40, "--limit", min=0, help="Rows to print; 0 for all."),
) -> None:
    """Extract the BIOS setting schema from a firmware image.

    Reads the file only; nothing is flashed, mounted or written to firmware.
    """
    try:
        capsule = cap.load(image)
    except (OSError, ValueError) as exc:
        raise typer.BadParameter(str(exc)) from exc

    result = builder.build(capsule.info(), firmware_volume.walk(capsule.data))
    result.image["filename"] = os.path.basename(image)
    if not result.settings:
        console.print("[red]No HII form packages found.[/] "
                      "The image may use a compression format that is not supported.")
        raise typer.Exit(1)

    if output:
        write_private(output, json.dumps(result.as_dict(), indent=2).encode() + b"\n")

    matches = result.settings
    if grep:
        needle = grep.casefold()
        matches = [s for s in matches
                   if needle in s.name.casefold()
                   or needle in " / ".join(s.path).casefold()]

    console.print(f"{len(result.settings)} settings in {len(result.formsets)} form sets"
                  f" from {os.path.basename(image)}")
    console.print(f"  [dim]schema {schema_hash(result)[:16]}[/]")
    for warning in result.warnings:
        console.print(f"  [yellow]warning[/] {warning}")
    if grep:
        console.print(f"{len(matches)} match {grep!r}")

    shown = matches if limit == 0 else matches[:limit]
    table = Table(box=None, pad_edge=False)
    table.add_column("Setting", style="bold", max_width=38, overflow="ellipsis")
    table.add_column("Menu path", max_width=44, overflow="ellipsis")
    table.add_column("Type")
    table.add_column("Default", max_width=22, overflow="ellipsis")
    table.add_column("Variable", max_width=26, overflow="ellipsis")
    for setting in shown:
        table.add_row(setting.name, " / ".join(setting.path), setting.type,
                      _default_label(setting), _variable_label(setting))
    console.print(table)
    if len(shown) < len(matches):
        console.print(f"  ... {len(matches) - len(shown)} more; "
                      "raise --limit or use --output for the full schema")
    if output:
        console.print(f"Schema written to {output}")


@app.command()
def export(
    image: str = typer.Argument(None, help="BIOS update file (.CAP) or raw SPI image."),
    schema_file: str = typer.Option(None, "--schema",
                                    help="Decode using a schema JSON from 'uefi-mirror schema' "
                                         "instead of parsing a firmware image."),
    output: str = typer.Option(None, "--output", "-o", help="Write the export here."),
    fmt: str = typer.Option("json", "--format", "-f",
                            help="Output file format: json, text, or html."),
    snapshot_dir: str = typer.Option(None, "--snapshot",
                                     help="Read variables from a snapshot instead of live."),
    grep: str = typer.Option(None, "--grep", "-g",
                             help="Filter terminal/text rows; archival JSON remains complete."),
    changed_only: bool = typer.Option(False, "--changed-only",
                                      help="Filter terminal/text rows to changed settings."),
    visible_only: bool = typer.Option(False, "--visible-only",
                                      help="Filter terminal/text rows to visible settings."),
    include_inactive: bool = typer.Option(False, "--include-inactive",
                                          help="Show inactive variants in terminal/text rows."),
    allow_mismatch: bool = typer.Option(
        False, "--allow-mismatch", help="Continue after a definite image/layout mismatch."),
    limit: int = typer.Option(40, "--limit", min=0, help="Rows to print; 0 for all."),
    efivars: str = typer.Option(platform.EFIVARS_DIR, "--efivars", hidden=True),
) -> None:
    """Decode the live BIOS configuration: firmware schema plus current values.

    Reads the image and the variables only; nothing is written to firmware.
    """
    if fmt not in ("json", "text", "html"):
        raise typer.BadParameter("--format must be json, text, or html")
    if fmt == "html" and not output:
        raise typer.BadParameter("--output is required when --format html")
    schema_result, image_bytes, source_name = _load_schema(image, schema_file)
    try:
        if snapshot_dir:
            store = decode.from_snapshot(snapshot_dir)
        else:
            store = decode.from_efivarfs(efivars, require_mount=efivars == platform.EFIVARS_DIR)
    except (OSError, ValueError, RuntimeError) as exc:
        raise typer.BadParameter(str(exc)) from exc

    if source_name:
        schema_result.image["filename"] = source_name
    if not schema_result.settings:
        console.print("[red]No settings in the schema.[/]" if schema_file
                      else "[red]No HII form packages found in the image.[/]")
        raise typer.Exit(1)

    variants = decode.resolve_variants(schema_result.formsets, store)
    decoded = decode.decode_all(schema_result.settings, store, variants.inactive)
    compatibility = _check_image(
        schema_result, store, image_bytes, source_name, decoded, allow_mismatch)
    schema_result.image["compatibility"] = compatibility.as_dict()
    document = report.build_document(schema_result, store, decoded, variants)

    matches = [d for d in decoded
               if _matches(d, grep, changed_only, visible_only, include_inactive)]
    if output:
        if fmt == "json":
            payload = report.to_json(document)
        elif fmt == "html":
            payload = report.to_html(document, {
                "grep": grep, "changed_only": changed_only,
                "visible_only": visible_only, "include_inactive": include_inactive,
            })
        else:
            payload = report.to_text(
                document, matches, f"UEFI settings export - {source_name}").encode()
        write_private(output, payload)

    counts = document["counts"]
    console.print(f"{counts['total']} settings, "
                  f"[bold]{counts['changed_from_default']}[/] differ from firmware default"
                  f"  ({store.describe()['variables']} variables from {store.source})")
    for status, count in counts["by_status"].items():
        if status != decode.OK:
            console.print(f"  [yellow]{status}[/] {count}")
    console.print(f"{counts['active']} settings apply to this machine ("
                  + ", ".join(f"{n} {state}" for state, n
                              in counts["by_visibility"].items()) + ")")
    console.print(f"[bold]{counts['changed_and_visible']}[/] of the changed settings "
                  "are ones the setup menu would actually show you")
    for note in variants.evidence:
        console.print(f"  [dim]variant: {note}[/]")

    shown = matches if limit == 0 else matches[:limit]
    table = Table(box=None, pad_edge=False)
    table.add_column("", width=1)
    table.add_column("Setting", style="bold", max_width=36, overflow="ellipsis")
    table.add_column("Value", max_width=24, overflow="ellipsis")
    table.add_column("Menu path", max_width=40, overflow="ellipsis")
    for item in shown:
        changed = report.is_changed(item)
        table.add_row("*" if changed else "", item.setting.name,
                      f"[green]{item.display_value}[/]" if changed else item.display_value,
                      " / ".join(item.setting.path))
    console.print(table)
    if len(shown) < len(matches):
        console.print(f"  ... {len(matches) - len(shown)} more; "
                      "raise --limit or use --output")
    if output:
        console.print(f"Export written to {output}")


@app.command()
def diff(
    old: str = typer.Argument(..., help="Earlier snapshot directory, or 'live'."),
    new: str = typer.Argument(..., help="Later snapshot directory, or 'live'."),
    image: str = typer.Option(None, "--image", "-i",
                              help="BIOS image, to name the settings that changed."),
    schema_file: str = typer.Option(None, "--schema",
                                    help="Schema JSON to name the settings that changed, "
                                         "instead of --image."),
    output: str = typer.Option(None, "--output", "-o", help="Write the diff here."),
    fmt: str = typer.Option("text", "--format", "-f", help="Output file format: text or json."),
    limit: int = typer.Option(60, "--limit", min=0, help="Rows to print; 0 for all."),
    allow_mismatch: bool = typer.Option(
        False, "--allow-mismatch", help="Continue after a definite image/layout mismatch."),
    efivars: str = typer.Option(platform.EFIVARS_DIR, "--efivars", hidden=True),
) -> None:
    """Compare two snapshots, or a snapshot against the live machine.

    Without --image this compares raw variable bytes. With --image the changed
    bytes are resolved back to the setting names they belong to.
    """
    if fmt not in ("json", "text"):
        raise typer.BadParameter("--format must be text or json")

    def load(where: str) -> decode.VariableStore:
        if where == "live":
            return decode.from_efivarfs(efivars, require_mount=efivars == platform.EFIVARS_DIR)
        return decode.from_snapshot(where)

    schema_result: Schema | None = None
    image_bytes: bytes | None = None
    source_name = ""
    if image or schema_file:
        schema_result, image_bytes, source_name = _load_schema(image, schema_file)
    try:
        old_store, new_store = load(old), load(new)
    except (OSError, ValueError, RuntimeError) as exc:
        raise typer.BadParameter(str(exc)) from exc

    old_decoded = new_decoded = None
    if schema_result is not None:
        if not schema_result.settings:
            console.print("[red]No settings in the schema.[/]" if schema_file
                          else "[red]No HII form packages found in the image.[/]")
            raise typer.Exit(1)
        # Each side is resolved against its own variables, so a variant that
        # only appears on one side does not masquerade as a changed setting.
        old_decoded = decode.decode_all(
            schema_result.settings, old_store,
            decode.resolve_variants(schema_result.formsets, old_store).inactive)
        new_decoded = decode.decode_all(
            schema_result.settings, new_store,
            decode.resolve_variants(schema_result.formsets, new_store).inactive)
        _check_image(schema_result, old_store, image_bytes, source_name, old_decoded,
                     allow_mismatch, os.path.basename(old))
        _check_image(schema_result, new_store, image_bytes, source_name, new_decoded,
                     allow_mismatch, os.path.basename(new))

    result = diff_mod.build(old_store, new_store, old_decoded, new_decoded)
    title = f"UEFI settings diff - {os.path.basename(old)} -> {os.path.basename(new)}"
    if output:
        write_private(output, diff_mod.to_json(result) if fmt == "json"
                      else diff_mod.to_text(result, title).encode())

    tally = result.counts()
    console.print(f"[bold]{tally['variables']['changed']}[/] variables changed, "
                  f"{tally['variables']['added']} added, "
                  f"{tally['variables']['removed']} removed")
    if schema_result is None:
        console.print("  [dim]pass --image BIOS.CAP or --schema schema.json to name "
                      "the settings behind these bytes[/]")
    else:
        console.print(f"[bold]{tally['settings_changed']}[/] named settings changed "
                      f"of {tally['settings_compared']} compared")

    if result.is_empty():
        console.print("[green]No differences.[/]")
    rows = result.settings if limit == 0 else result.settings[:limit]
    if rows:
        # Only widen the table when something in view is off-menu; the common
        # case is all-visible and deserves the space for names and paths.
        hidden = [c for c in rows if c.visibility != decode.VISIBLE]
        table = Table(box=None, pad_edge=False)
        table.add_column("Setting", style="bold", max_width=34, overflow="ellipsis")
        table.add_column("Was", max_width=20, overflow="ellipsis")
        table.add_column("Now", max_width=20, overflow="ellipsis")
        if hidden:
            table.add_column("Vis", max_width=9, style="yellow")
        table.add_column("Menu path", max_width=34, overflow="ellipsis")
        for change in rows:
            cells = [change.name, change.old_display,
                     f"[green]{change.new_display}[/]"]
            if hidden:
                cells.append("" if change.visibility == decode.VISIBLE
                             else change.visibility)
            cells.append(" / ".join(change.path))
            table.add_row(*cells)
        console.print(table)
        if hidden:
            console.print(f"  [dim]{len(hidden)} of these the firmware's own "
                          "conditions keep off the setup menu (Vis column)[/]")
        if len(rows) < len(result.settings):
            console.print(f"  ... {len(result.settings) - len(rows)} more; "
                          "raise --limit or use --output")
    variable_rows = [v for v in result.variables if not result.settings]
    for change in variable_rows[:limit or None]:
        console.print(f"  {change.kind:8} {change.name}")
    if output:
        console.print(f"Diff written to {output}")


def _matches(item, grep: str | None, changed_only: bool,
             visible_only: bool = False, include_inactive: bool = True) -> bool:
    if not include_inactive and not item.active:
        return False
    if visible_only and item.visibility != decode.VISIBLE:
        return False
    if changed_only and not report.is_changed(item):
        return False
    if not grep:
        return True
    needle = grep.casefold()
    return (needle in item.setting.name.casefold()
            or needle in " / ".join(item.setting.path).casefold())


def _default_label(setting) -> str:
    if setting.default is None:
        return ""
    for option in setting.options:
        if option.value == setting.default:
            return option.label
    return f"{setting.default:#x}" if setting.display == "hex" else str(setting.default)


def _variable_label(setting) -> str:
    store = setting.varstore
    if store is None:
        return ""
    if store.offset is None:
        return store.name
    return f"{store.name}+{store.offset:#x}"


if __name__ == "__main__":
    app()

# Compatibility policy

`uefi-mirror` is pre-1.0 software. The command names and option meanings are
intended to be stable, but a release may still make a necessary breaking change
when the change is called out in its release notes.

## Machine-readable formats

Schema JSON, snapshot manifests, and export JSON carry their own integer
`format_version`. These versions are independent of the package version.

- Readers accept only format versions they understand and fail before producing
  a partial or guessed result.
- Writers emit only the current format version.
- Additive fields may appear within an existing format version. Readers ignore
  fields they do not need, so metadata can grow without breaking older tools.
- Removing a field, changing its meaning or type, or changing identifiers and
  value semantics requires a format-version increment.
- A saved schema must decode and evaluate visibility identically after a
  serialize/reload round trip with the same tool version.

Snapshot format 1 and schema/export format 3 are the current formats. Snapshots
and exports can contain machine identifiers or boot paths and should be treated
as private. Schema JSON contains firmware definitions but no collected values.

## CLI contract

The public commands are `probe`, `snapshot`, `schema`, `export`, and `diff`.
`--help` and `--version` are stable discovery interfaces. Exit status zero means
the requested operation completed; invalid input, unsafe output, unavailable
enumeration, and definite schema mismatch return nonzero.

For 1.0, command names, existing option meanings, setting IDs, documented JSON
fields, and the format-version rules above become compatibility commitments.
New commands, options, output fields, and status values may be added in minor
releases when existing consumers can safely ignore them. A breaking CLI or
machine-readable-format change requires a new major package version, in addition
to any affected document format-version increment.

Terminal and text presentation are human-facing and may receive non-semantic
layout changes. Scripts should consume JSON rather than scrape terminal output.

# Compatibility policy

Starting with 1.0, the command names, existing option meanings, setting IDs,
documented JSON fields, and format-version rules below are compatibility
commitments.

## Machine-readable formats

Schema JSON, snapshot manifests, export JSON, and fetch documents carry their own integer
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

Snapshot and fetch formats are 1; schema/export format is 3. Snapshots and
exports can contain machine identifiers or boot paths and should be treated as
private. Fetch provenance contains selected and available DMI identity plus
source URLs and hashes, but no raw firmware variables. Schema JSON contains
firmware definitions but no collected values.

`fetch.json` is an audit record, not a trusted input to another command.
Existing commands parse the image path supplied by the user and do not load the
manifest. A successful `fetch --json` wrapper has `operation: "fetch"`, saved
paths, and its format-1 provenance; `fetch --resolve-only --json` has
`operation: "resolve"` and selection metadata but no saved paths or computed
artifact/image hashes. Neither shape claims the downloaded image is the
installed firmware release.

## CLI contract

The public commands are `probe`, `fetch`, `snapshot`, `schema`, `export`, and `diff`.
`--help` and `--version` are stable discovery interfaces. Exit status zero means
the requested operation completed; invalid input, unsafe output, unavailable
enumeration, and definite schema mismatch return nonzero.

Only `fetch` uses the network, and only when explicitly invoked. `--resolve-only`
still retrieves official metadata but performs no artifact request or filesystem
write. All other commands remain offline.

New commands, options, output fields, and status values may be added in minor
releases when existing consumers can safely ignore them. A breaking CLI or
machine-readable-format change requires a new major package version, in addition
to any affected document format-version increment.

Terminal and text presentation are human-facing and may receive non-semantic
layout changes. Scripts should consume JSON rather than scrape terminal output.

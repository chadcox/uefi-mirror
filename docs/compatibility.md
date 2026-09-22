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

Snapshot format is 1, schema/export format is 3, and fetch format is 2.
Snapshots and exports can contain machine identifiers or boot paths and should
be treated as private. Fetch provenance contains selected and available DMI
identity plus source URLs and hashes, but no raw firmware variables. Schema JSON
contains firmware definitions but no collected values.
Schema JSON carries a `warnings` array of parser-level notes recorded while
reading the image: unparsable form sets, and content the firmware volume
walker had to drop (malformed section or file headers, sections that need a
decompressor this parser does not implement, and budget exhaustion). The diff
document carries those notes as an additive `warnings` array inside its
`diff` object, present only when non-empty, so a partially readable image
says so in every report built from it. A fully readable image produces no
walk warnings; readers that predate the diff field ignore it.

Fetch format 2 publishes the scope established by checksum validation:

- A resolve document with an advertised hash records `status: "advertised"`,
  `algorithm: "sha256"`, the hash as `expected`, and `target: "undetermined"`;
  without an advertised hash it records only `status: "unavailable"`.
- Download provenance with a verified hash records `status: "verified"`,
  `algorithm: "sha256"`, the hash as `expected`, and the validated `target` of
  either `"artifact"` or `"image"`; without an advertised hash it records only
  `status: "unavailable"`. A downloaded verified checksum never has an
  `"undetermined"` target.

Fetch format 1 is historical. It recorded `target: "artifact"` whenever a hash
was present, including resolve documents where no bytes had been downloaded and
downloads where validation discovered that the hash covered the extracted
image. Format 2 removes that ambiguity; snapshot, schema, and export formats are
unchanged.

`fetch.json` is an audit record, not a trusted input to another command.
Commands parse the image path supplied by the user; only `export` loads a
manifest — the `fetch.json` beside the image by default, or `--provenance
PATH` — and only as compatibility evidence. It accepts a current
format download record and rejects resolve documents and other format versions.
Agreement between the manifest's image SHA-256, model and BIOS version and the
image and machine adds evidence lines but never raises the status above
`unverified`; a disagreement is a `mismatch` problem. A successful `fetch --json` wrapper has `operation: "fetch"`, saved
paths, and its format-2 provenance; `fetch --resolve-only --json` has
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

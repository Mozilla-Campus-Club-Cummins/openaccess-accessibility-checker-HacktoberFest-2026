# Versioned JSON Report Schema

## Schema version

Exported reports use `schemaVersion: "1.0.0"`. The version identifies the structure of the exported report. Future incompatible changes should use a new major version.

## Top-level fields

| Field | Description |
|---|---|
| `schemaVersion` | Version of the export format. |
| `exportedAt` | ISO 8601 timestamp indicating when the JSON file was exported. |
| `scan` | Scan metadata, including timestamp, URL, engine, method, and score. |
| `issueCounts` | Number of findings grouped by impact level. |
| `rules` | Unique rule names represented in the findings. |
| `findings` | Original accessibility findings, including rule, impact, element, message, and suggested fix. |
| `fixes` | Suggested remediation for each finding. |
| `safety` | Available safety signals and their status, or an explicit unavailable/not-checked state. |
| `limitations` | Known limitations of the automated checks. |
| `url`, `findings`, `score`, `method` | Legacy-compatible fields retained for existing consumers. |

## Scan metadata

The `scan` object contains:

- `timestamp`: scan time in ISO 8601 format, or `null` if unavailable.
- `url`: scanned page URL or a descriptive label for a bundled example.
- `engine`: scanner name.
- `method`: description of the checking method.
- `score`: existing score object, or `null` if unavailable.

## Findings and fixes

Each finding retains the scanner's existing fields, such as `rule`, `impact`, `element`, `message`, and `fix`. Each entry in `fixes` contains the associated rule, element, and remediation suggestion.

## Compatibility

The original top-level `url`, `findings`, `score`, and `method` fields remain available. Browser history continues to store reports in its existing format, allowing older saved reports to be opened without migration.

## Limitations

The report describes automated static checks only. It does not establish WCAG compliance, and manual accessibility testing is still necessary. Safety signals may be unavailable when the scan result does not provide them.
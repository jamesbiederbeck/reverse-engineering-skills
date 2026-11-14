# Filings, sources, and archiving

## Source order

| Source | Use | Caveat |
| --- | --- | --- |
| [FCC EAS search](https://apps.fcc.gov/oetcf/eas/reports/GenericSearch.cfm) | Verify grantee/product code; enumerate grants/exhibits | Forms, sessions, or automated access may fail; a 403 does not invalidate the ID |
| [FCC equipment authorization](https://www.fcc.gov/engineering-technology/laboratory-division/general/equipment-authorization) | Find current official services if endpoints move | Navigate rather than inventing query parameters |
| [FCCID.io](https://fccid.io/) | Applications, exhibit metadata, public document copies | A mirror is not the FCC; inspect filing contents and application associations |
| [FCC.report](https://fcc.report/) | Cross-check indexes/public copies | Availability and completeness vary |
| [Device.report](https://device.report/) | Alternate public copies | Mixed manuals/filings; verify document identity |
| Manufacturer/component-vendor sources | Datasheets, designs, firmware, SDK and GPL packages | Match exact suffix, package, region, revision |
| Original teardown/project repositories | Board photos, tested access, alternative firmware | Retain revision and evidence; do not promote guesses to facts |

Search the quoted complete ID, preserving hyphens. Follow-up queries can add `internal photos`, `schematic`, `operational description`, `test report`, `confidentiality`, or `permissive change`. Search a confirmed board model/chip marking after establishing identity. Cite an actual mirrored filing as a filing; do not treat generated mirror descriptions as component specifications.

Mirrors can omit a leading hyphen from the displayed product-code field, group applications, repeat identical exhibits, or misclassify titles. Confirm against full FCC ID and contents. Reports may contain board photos, EUT wiring, channels, antenna details, or test-control utilities even when a dedicated exhibit is unavailable.

Record every application. A host-specific Class II permissive change is not automatically a redesign of all modules using the ID. Several equipment classes can cover one device. Deduplicate identical bytes by SHA-256 if useful, preserving each application-to-exhibit association.

For blocked sources, try the official record, a public mirror, and indexed public copies. Then record the failure and proceed; do not loop indefinitely. Use permitted browser interaction only when needed and supported. Do not suggest logging in to a public archive without an observed need.

## Exhibit coverage

| Exhibit | Extract |
| --- | --- |
| Internal photos | Revisions, chips, memory, antenna feed, pads, connectors, shielded areas |
| External/label photos | Model/region, enclosure, host versus module IDs |
| Schematics/block diagram/parts | Nets, rails, clocks, BOM, buses, unpopulated options |
| Operational description | Architecture, modes, control interfaces |
| Reports/test setup | Channels, modulation/bandwidth, power basis, wiring, lab firmware/software |
| Manual/integration guide | Pinout, supply limits, boot/update/recovery |
| Antenna/RF exposure/software security | RF path, gain, configurations, stated software controls |
| Change and related-ID letters | Revisions, aliases, reused designs, host-specific changes |
| Confidentiality/administrative letters | Requested withholding, public scope, provenance |

For **each application**, mark important categories present, confidential, metadata-only, not listed, or blocked. Do not say "not filed" without evidence. A public confidentiality letter's own status does not describe the exhibits it names. A request is not proof it was granted.

## Archiver input

Create UTF-8 JSON with a confirmed `fcc_id` and `exhibits` array. Give public exhibits unique safe `filename` basenames ending in `.pdf`. Preserve application IDs exactly. Use only discovered public **direct PDF URLs**, not landing pages or guessed attachment IDs.

```json
{
  "fcc_id": "CONFIRMED-ID",
  "checked_at": "YYYY-MM-DD",
  "exhibits": [
    {
      "document_id": "FROM-SOURCE",
      "application_id": "FROM-SOURCE",
      "title": "Internal photographs",
      "type": "Internal Photos",
      "date": "YYYY-MM-DD",
      "status": "public",
      "source_page": "https://public-source.example/observed-exhibit-page",
      "url": "https://public-source.example/observed-document.pdf",
      "filename": "YYYY-MM-DD_internal-photos_DOCUMENT-ID.pdf"
    },
    {
      "title": "Schematics",
      "type": "Schematics",
      "status": "confidential",
      "source_page": "https://public-source.example/observed-index",
      "notes": "State the actual supporting confidentiality evidence."
    }
  ]
}
```

Replace placeholders; omit missing URLs instead of inventing them. Optional `sha256` supplies an expected digest. Add grant/release dates, official/mirror URLs, variant, and notes as needed; the script preserves entry fields. Archive non-PDF files separately with equivalent provenance/hashes.

```bash
python3 /absolute/path/to/skill/scripts/archive_exhibits.py manifest.json --out ./fcc-CONFIRMED-ID/sources
```

Read the summary and `sources/downloads.json`. A nonzero exit means a public exhibit failed; inspect individual results. The script skips non-public entries, rejects HTML-as-PDF, limits file size, refuses overwriting files, and checks hashes when resuming. It does not alter the input manifest. `--offline` checks existing files without network access. If host networking cannot reach a web-readable source, use another permitted retrieval tool or document that raw retrieval failed; web access does not imply a local download succeeded.

Keep input manifest and results with the dossier, including failed entries and sources checked. Save them in the user's workspace outside the installed plugin; use a durable-file workflow when the environment offers one. Keep skill code in the installed skill.

## Format provenance

- [FCC 12-60, Appendix B](https://docs.fcc.gov/public/attachments/FCC-12-60A1.pdf): historical introduction of numeral-leading five-character grantee codes. Verify the current record for later changes.
- [FCC 15-92, paragraphs 80–81 and note 147](https://docs.fcc.gov/public/attachments/FCC-15-92A1.pdf): historical confidentiality context. This proposal is background, not current procedural authority; consult current guidance and actual exhibit status for present-day claims.

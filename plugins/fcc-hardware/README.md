# FCC Hardware Dossier

Find public FCC filings and turn them into a hardware reverse-engineering dossier with source links, component and interface maps, radio findings, firmware leads, and a practical first bench session.

Install from the `reverse-engineering-skills` marketplace:

```bash
claude plugin install fcc-hardware@reverse-engineering-skills
```

Then invoke in Claude Code:

```text
/fcc-hardware:investigate-fcc-id 2AC7Z-ESPWROOM32
```

An FCC ID, label photo, or filing link is enough to start. Mention a specific objective to focus the research. The skill distinguishes modules from hosts, revisions from later applications, and verified evidence from inferences or unavailable documents.

Use web research and filesystem tools, Python 3.10+, and optionally Poppler for PDF inspection. The archiver uses only Python's standard library. Write output in your workspace, outside the plugin. See the bundled [retrieval guidance and manifest schema](skills/investigate-fcc-id/references/retrieval.md).

This plugin performs research and proposes experiments. It does not automatically flash, erase, or change a device's security configuration. Retrieved third-party documents and firmware retain their own rights and terms.

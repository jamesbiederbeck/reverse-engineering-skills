# Reverse Engineering Skills

A Claude Code plugin marketplace for reverse engineering: FCC filing research for hardware and static tamper audits for Android APKs. Skills produce sourced findings, explicit unknowns, and practical next experiments.

## Install

Run in your shell:

```bash
claude plugin marketplace add jamesbiederbeck/reverse-engineering-skills
claude plugin install fcc-hardware@reverse-engineering-skills
claude plugin install android-apk@reverse-engineering-skills
```

Or, inside a Claude Code session:

```text
/plugin marketplace add jamesbiederbeck/reverse-engineering-skills
/plugin install fcc-hardware@reverse-engineering-skills
/plugin install android-apk@reverse-engineering-skills
```

## FCC Hardware

Invoke the skill in Claude Code:

```text
/fcc-hardware:investigate-fcc-id 2AC7Z-ESPWROOM32
```

You can also share an FCC label photo, a filing link, or an FCC ID in a normal request. Add an objective such as identifying the chipset, getting a UART console, replacing cloud control, or locating firmware to focus the investigation.

The skill:

- Searches official FCC records and public mirrors, tracking all discovered applications, revisions, and module/host boundaries.
- Collects public internal/external photos, schematics, block diagrams, manuals, reports, and supporting letters.
- Maps chips, memory, interfaces, radio modes, antenna paths, firmware sources, drivers, and relevant teardown projects.
- Separates documented facts, visual observations, inferences, and unknowns, with exhibit and page references.
- Produces a Markdown dossier, provenance inventory, retrieved originals, and a ranked bench plan.

Unavailable or confidential exhibits remain explicit gaps. A module's FCC ID does not identify the complete host. Pinouts, logic levels, security state, and firmware compatibility require matching evidence. The workflow researches and proposes experiments; it does not flash, erase, or modify device security automatically.

### Runtime requirements

Use Claude Code with web research and filesystem access. The bundled archiver uses Python 3.10+ and the standard library. Poppler's `pdftotext` and `pdftoppm` are useful for local PDF inspection; OCR is optional when scans need it. Browser access and document downloads depend on source availability and your environment's network permissions.

Write investigation output to your chosen workspace, outside the installed plugin. The default `dossiers/` and `downloads/` directories are ignored by this repository. Public filing links belong in reports; device dumps, calibration data, and secrets should remain local.

### Archive discovered documents

The agent builds the manifest after finding actual document URLs. The helper is an archiver, not an FCC crawler:

```bash
python3 plugins/fcc-hardware/skills/investigate-fcc-id/scripts/archive_exhibits.py \
  manifest.json --out dossiers/device/sources
```

It preserves metadata, validates PDF signatures, hashes files, records partial failures, and refuses to overwrite existing documents. Resume with the same output directory; use `--offline` to check existing files without making requests. See the [manifest schema and retrieval workflow](plugins/fcc-hardware/skills/investigate-fcc-id/references/retrieval.md).

## Android APK

Invoke the skill in Claude Code, or just ask whether a sideloaded or modded APK is safe:

```text
/android-apk:apk-tamper-audit ./app-modded.apk
```

The skill unpacks the APK, scans the manifest for permissions and settings that rarely belong in an unmodified app, searches decompiled source, raw dex/native strings, and bundled assets for exfiltration and loader patterns, checks the signer, and writes a ranked report. It decodes string-array-obfuscated JavaScript payloads without running their logic. Supplying the original APK enables a direct diff. Static analysis cannot rule out payloads gated on runtime conditions, and the report says so.

Requirements: Python 3.9+ with `androguard>=4`, Java with `apktool` and `jadx`, and Android SDK `aapt2` and `apksigner`. Node.js is needed only for the deobfuscator and `binwalk` is optional. The unpack step skips any missing tool and records the skip rather than failing. Analysis output goes to a directory in your workspace (default `./apk_analysis`, ignored by this repository); the skill never installs or runs the APK.

## Plugins

| Plugin | Skill | Purpose |
| --- | --- | --- |
| `fcc-hardware` | `investigate-fcc-id` | FCC documents, hardware map, firmware leads, and bench plan |
| `android-apk` | `apk-tamper-audit` | Static tamper, malware-indicator, and permission audit of an APK |

Plugins live under `plugins/<plugin-name>/`, each with its own `.claude-plugin/plugin.json` and `skills/<skill-name>/SKILL.md`. The root [.claude-plugin/marketplace.json](.claude-plugin/marketplace.json) catalogs installable plugins.

## Develop and validate

```bash
git clone https://github.com/jamesbiederbeck/reverse-engineering-skills.git
cd reverse-engineering-skills
python3 -m pip install -r requirements-dev.txt
make check
make validate-claude
```

`make check` validates local manifests, skill metadata, relative references, and Python syntax, then runs archiver regression tests without network access. `make validate-claude` uses the pinned official Claude Code CLI to validate the marketplace and each plugin; it requires Node.js/npm and downloads that CLI on first use. GitHub Actions runs both.

Test a development copy without installing the marketplace:

```bash
claude --plugin-dir ./plugins/fcc-hardware
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for adding plugins or skills. The plugin layout follows the official [marketplace guide](https://code.claude.com/docs/en/plugin-marketplaces), [manifest reference](https://code.claude.com/docs/en/plugins-reference), and [skills documentation](https://code.claude.com/docs/en/skills).

## License

[MIT](LICENSE). Third-party FCC exhibits, manufacturer documents, and firmware retrieved during an investigation retain their own rights and terms; they are not bundled in this repository.

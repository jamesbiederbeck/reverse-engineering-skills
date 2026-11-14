# Repository instructions

- Keep the marketplace at `.claude-plugin/marketplace.json` and each plugin under `plugins/<name>/` with its own `.claude-plugin/plugin.json`.
- Keep each skill self-contained under `skills/<name>/`; use relative references and resolve helpers from the installed skill directory. Never hardcode a developer's home or workspace path.
- Keep hardware/revision claims tied to inspected sources. Explicitly distinguish observations, inference, missing evidence, and confidential records.
- Keep investigation output, firmware dumps, device secrets, and retrieved third-party exhibits out of source control.
- Run `make check` for changes to skills, metadata, or helpers, and `make validate-claude` for marketplace/plugin packaging changes.
- Preserve the MIT license. Bump plugin versions for releases and marketplace versions for catalog changes.

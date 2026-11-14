# Contributing

Keep each skill focused on a repeatable investigation workflow. Put detailed lookup guidance and templates in its `references/` directory and deterministic helpers in `scripts/`.

## Add a skill to an existing plugin

1. Create `plugins/<plugin>/skills/<skill-name>/SKILL.md` with YAML `name` and `description` fields. Match `name` to the directory; describe concrete triggers in `description`.
2. Reference supporting files with relative Markdown links. Resolve executable resources from the installed skill directory, not the user's current working directory. Put output in the user's workspace.
3. Add meaningful regression coverage for new executable behavior. Avoid network-dependent tests and do not commit raw device dumps, credentials, private identifiers, or downloaded exhibits.
4. Update the README's plugin/skill table and bump the plugin's version for a release. Update the marketplace version when catalog entries change.
5. Run `make check` and `make validate-claude`.

## Add a plugin

Create `plugins/<plugin-name>/.claude-plugin/plugin.json` with `name`, `version`, `description`, `author`, repository URL, and license. Add skills under that plugin's `skills/` directory. Add a marketplace entry whose `name` matches the manifest and whose `source` is `./plugins/<plugin-name>` relative to the repository root.

Use default component locations so each plugin is self-contained. Keep plugin metadata in `plugin.json`; do not duplicate its version in the marketplace entry. Do not add hooks, background services, MCP servers, or automatic device writes unless the plugin's purpose requires them and their behavior is documented.

## Evidence standards

Preserve source identity, exhibit IDs, revision boundaries, and page references. Mark uncertain chip readings and candidate pinouts. Differentiate unavailable material from confirmed confidentiality. Prefer primary technical sources and read-only experiments, and state the specific consequence before an irreversible operation.

Repository checks supplement the official Claude validator; they do not establish that an investigation's hardware claims are correct. Validate substantial workflow changes with a realistic public example and inspect the actual supporting documents.

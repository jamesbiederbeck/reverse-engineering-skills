.PHONY: check test validate-claude

check:
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/validate_marketplace.py
	$(MAKE) test

test:
	PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v

validate-claude:
	npx --yes --package @anthropic-ai/claude-code@2.1.325 -- claude plugin validate . --strict
	@set -eu; for plugin_dir in plugins/*; do \
		if [ -d "$$plugin_dir" ]; then \
			npx --yes --package @anthropic-ai/claude-code@2.1.325 -- claude plugin validate "$$plugin_dir" --strict; \
		fi; \
	done

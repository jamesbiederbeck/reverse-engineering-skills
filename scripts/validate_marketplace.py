#!/usr/bin/env python3
"""Check repository-specific marketplace, skill, and resource invariants offline."""

import ast
import json
from pathlib import Path
import re
import sys

import yaml


ROOT = Path(__file__).resolve().parents[1]
NAME = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")
VERSION = re.compile(r"\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def contained(path, parent):
    resolved = path.resolve()
    require(resolved.is_relative_to(parent.resolve()), f"Path escapes its package: {path}")
    require(path.exists(), f"Missing path: {path}")
    return resolved


def validate(root=ROOT):
    marketplace = json.loads((root / '.claude-plugin/marketplace.json').read_text())
    require(NAME.fullmatch(marketplace['name']), 'Marketplace name must be kebab-case')
    require(marketplace.get('description'), 'Missing marketplace description')
    require(marketplace.get('owner', {}).get('name'), 'Missing marketplace owner')
    require(VERSION.fullmatch(marketplace.get('version', '')), 'Missing/invalid marketplace version')
    plugins = marketplace.get('plugins')
    require(isinstance(plugins, list) and plugins, 'Marketplace must list at least one plugin')
    require((root / 'LICENSE').is_file(), 'Missing repository license')
    names, listed, skill_count = set(), set(), 0
    for entry in plugins:
        name = entry['name']
        require(NAME.fullmatch(name) and name not in names, f'Invalid or duplicate plugin: {name}')
        names.add(name)
        source = entry['source']
        require(isinstance(source, str) and source.startswith('./plugins/'), f'Use a local plugins/ source for {name}')
        require('..' not in Path(source).parts, f'Unsafe plugin source: {source}')
        plugin = contained(root / source, root / 'plugins')
        require(plugin.is_dir(), f'Plugin source is not a directory: {source}')
        listed.add(plugin)
        meta = json.loads((plugin / '.claude-plugin/plugin.json').read_text())
        require(meta['name'] == name == plugin.name, f'Plugin name/path mismatch: {name}')
        require(VERSION.fullmatch(meta.get('version', '')), f'Invalid plugin version: {name}')
        require(meta.get('description') and meta.get('author', {}).get('name'), f'Incomplete plugin metadata: {name}')
        require(meta.get('license') == 'MIT', f'Unexpected license for {name}')
        require('version' not in entry, f'Keep {name} version in plugin.json only')
        skills = sorted((plugin / 'skills').glob('*/SKILL.md'))
        require(skills, f'Plugin has no skills: {name}')
        skill_names = set()
        for skill in skills:
            contained(skill, plugin)
            text = skill.read_text(encoding='utf-8')
            match = re.match(r'\A---\n(.*?)\n---(?:\n|$)', text, re.S)
            require(match, f'Missing YAML frontmatter: {skill}')
            front = yaml.safe_load(match.group(1))
            require(isinstance(front, dict), f'Invalid skill metadata: {skill}')
            skill_name = front.get('name', '')
            require(isinstance(skill_name, str) and NAME.fullmatch(skill_name), f'Invalid skill name: {skill}')
            require(skill_name == skill.parent.name and skill_name not in skill_names, f'Skill name/path mismatch: {skill}')
            skill_names.add(skill_name)
            desc = front.get('description')
            require(isinstance(desc, str) and 0 < len(desc) <= 1024, f'Invalid skill description: {skill}')
            require('<' not in desc and '>' not in desc, f'Angle brackets in skill description: {skill}')
            require(len(text.splitlines()) < 500, f'Split long skill into references: {skill}')
            require(not re.search(r'\bTODO\b|/home/agent/|/workspace/', text), f'Placeholder or host-specific path: {skill}')
            skill_count += 1
        for path in plugin.rglob('*'):
            if path.is_file():
                contained(path, plugin)
                require(path.suffix.lower() not in {'.bin', '.dump', '.pdf', '.pyc'}, f'Generated/binary investigation artifact: {path}')
                if path.suffix == '.py':
                    ast.parse(path.read_text(encoding='utf-8'), filename=str(path))
    actual = {path.resolve() for path in (root / 'plugins').iterdir() if path.is_dir()}
    require(actual == listed, 'Every plugins/ directory must have exactly one marketplace entry')
    for path in root.rglob('*.md'):
        if '.git' in path.relative_to(root).parts:
            continue
        for target in re.findall(r'\]\(([^\s)]+)\)', path.read_text(encoding='utf-8')):
            if target.startswith(('http://', 'https://', '#', 'mailto:')):
                continue
            contained(path.parent / target.split('#', 1)[0], root)
    return len(names), skill_count


if __name__ == '__main__':
    try:
        plugins, skills = validate()
    except (ValueError, TypeError, KeyError, OSError, SyntaxError, yaml.YAMLError) as exc:
        print(f'Validation failed: {exc}', file=sys.stderr)
        sys.exit(1)
    print(f'Validated {plugins} plugin(s), {skills} skill(s), bundled Python, and relative document links.')

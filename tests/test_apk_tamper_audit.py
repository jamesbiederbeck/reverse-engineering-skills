"""Check the APK audit's pattern list and string extraction without androguard or an APK."""

import importlib.util
from pathlib import Path
import re
import sys
import types
import unittest

SKILL = Path(__file__).resolve().parents[1] / 'plugins/android-apk/skills/apk-tamper-audit'


def load_scan_indicators():
    # scan_indicators imports androguard at module load; stub it so tests stay dependency-free.
    stub = types.ModuleType('androguard.core.apk')
    stub.APK = object
    saved = {k: sys.modules.get(k) for k in ('androguard', 'androguard.core', 'androguard.core.apk')}
    sys.modules.update({'androguard': types.ModuleType('androguard'), 'androguard.core': types.ModuleType('androguard.core'), 'androguard.core.apk': stub})
    try:
        spec = importlib.util.spec_from_file_location('scan_indicators', SKILL / 'scripts/scan_indicators.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    finally:
        for key, value in saved.items():
            if value is None:
                sys.modules.pop(key, None)
            else:
                sys.modules[key] = value


class PatternFileTests(unittest.TestCase):
    def test_patterns_parse_and_compile(self):
        module = load_scan_indicators()
        patterns = module.load_patterns()
        self.assertGreater(len(patterns), 5)
        for pattern in patterns:
            self.assertIn(pattern['severity'], {'low', 'medium', 'high'}, pattern['label'])

    def test_known_indicators_match(self):
        module = load_scan_indicators()
        by_label = {p['label']: p['regex'] for p in module.load_patterns()}
        hits = {
            'Discord webhook URL (common exfil channel)': 'https://discord.com/api/webhooks/1/abc',
            'Dynamic dex loading (DexClassLoader/InMemoryDexClassLoader)': 'new DexClassLoader(a, b)',
            'Pastebin raw URL (common cheap config/C2 fetch)': 'https://pastebin.com/raw/xyz',
        }
        for label, sample in hits.items():
            self.assertTrue(by_label[label].search(sample), label)


class StringExtractionTests(unittest.TestCase):
    def test_extract_strings_matches_strings_n6(self):
        module = load_scan_indicators()
        data = b'\x00\x01short\x00http://198.51.100.7/c2\x02\xffabcdef\x00ab'
        self.assertEqual(module.extract_strings(data).splitlines(), ['http://198.51.100.7/c2', 'abcdef'])


if __name__ == '__main__':
    unittest.main()

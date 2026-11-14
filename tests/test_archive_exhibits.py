"""Exercise archive integrity and failure handling without external requests."""

from contextlib import redirect_stderr, redirect_stdout
from email.message import Message
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / 'plugins/fcc-hardware/skills/investigate-fcc-id/scripts/archive_exhibits.py'
SPEC = importlib.util.spec_from_file_location('archive_exhibits', SCRIPT)
ARCHIVE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ARCHIVE)
PDF = b'%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF\n'


class Response(io.BytesIO):
    def __init__(self, data=PDF, length=None, content_type='application/pdf'):
        super().__init__(data)
        self.headers = Message()
        self.headers['Content-Type'] = content_type
        self.headers['Content-Length'] = str(len(data) if length is None else length)

    def geturl(self):
        return 'https://files.example/exhibit.pdf'


class Opener:
    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.calls = 0

    def open(self, *args, **kwargs):
        self.calls += 1
        return Response(**self.kwargs)


class ArchiveTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.output = self.root / 'sources'
        self.manifest = self.root / 'manifest.json'
        self.document = {'status': 'public', 'title': 'Photos', 'url': 'https://files.example/exhibit.pdf', 'filename': 'photos.pdf'}
        self.data = {'fcc_id': 'TEST-ID', 'exhibits': [self.document, {'title': 'Schematics', 'status': 'confidential'}]}

    def run_archive(self, opener=None, *flags):
        self.manifest.write_text(json.dumps(self.data), encoding='utf-8')
        original = self.manifest.read_bytes()
        argv = ['archive_exhibits.py', str(self.manifest), '--out', str(self.output), *flags]
        with patch.object(ARCHIVE.sys, 'argv', argv), patch.object(ARCHIVE, 'build_opener', return_value=opener or Opener()), redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            code = ARCHIVE.main()
        self.assertEqual(original, self.manifest.read_bytes())
        self.assertFalse(list(self.root.rglob('*.part')))
        results = self.output / 'downloads.json'
        return code, json.loads(results.read_text()) if results.exists() else None

    def test_download_hash_skip_and_resume(self):
        opener = Opener()
        code, result = self.run_archive(opener)
        self.assertEqual(code, 0)
        self.assertEqual(result['exhibits'][0]['sha256'], hashlib.sha256(PDF).hexdigest())
        self.assertEqual(result['exhibits'][1]['download_status'], 'skipped')
        self.assertEqual((self.output / 'photos.pdf').read_bytes(), PDF)
        code, result = self.run_archive(opener, '--offline')
        self.assertEqual(code, 0)
        self.assertEqual(opener.calls, 1)
        self.assertEqual(result['exhibits'][0]['download_status'], 'existing')

    def test_tampered_existing_file_is_retained_and_rejected(self):
        self.run_archive()
        changed = PDF + b'tampered'
        (self.output / 'photos.pdf').write_bytes(changed)
        code, result = self.run_archive(None, '--offline')
        self.assertEqual(code, 1)
        self.assertIn('SHA-256', result['exhibits'][0]['error'])
        self.assertEqual((self.output / 'photos.pdf').read_bytes(), changed)

    def test_unproven_existing_pdf_is_not_attributed_to_url(self):
        self.output.mkdir()
        (self.output / 'photos.pdf').write_bytes(PDF)
        code, result = self.run_archive(None, '--offline')
        self.assertEqual(code, 1)
        self.assertIn('no verified digest', result['exhibits'][0]['error'])

    def test_html_error_page_is_not_saved_as_pdf(self):
        code, result = self.run_archive(Opener(data=b'<html>blocked</html>', content_type='text/html'))
        self.assertEqual(code, 1)
        self.assertIn('not a PDF', result['exhibits'][0]['error'])
        self.assertFalse((self.output / 'photos.pdf').exists())

    def test_incomplete_response_is_not_published(self):
        code, result = self.run_archive(Opener(length=len(PDF) + 10))
        self.assertEqual(code, 1)
        self.assertIn('Incomplete download', result['exhibits'][0]['error'])
        self.assertFalse((self.output / 'photos.pdf').exists())

    def test_size_cap(self):
        code, result = self.run_archive(Opener(length=2 * 1024 * 1024), '--max-mib', '1')
        self.assertEqual(code, 1)
        self.assertIn('size limit', result['exhibits'][0]['error'])

    def test_offline_missing_file_does_not_request(self):
        opener = Opener()
        code, result = self.run_archive(opener, '--offline')
        self.assertEqual(code, 1)
        self.assertEqual(opener.calls, 0)

    def test_unsafe_filename_rejected_before_request(self):
        self.document['filename'] = '../outside.pdf'
        opener = Opener()
        code, _ = self.run_archive(opener)
        self.assertEqual(code, 2)
        self.assertEqual(opener.calls, 0)

    def test_non_https_url_is_rejected(self):
        self.document['url'] = 'file:///example'
        opener = Opener()
        code, result = self.run_archive(opener)
        self.assertEqual(code, 1)
        self.assertEqual(opener.calls, 0)

    def test_changed_url_cannot_reuse_filename(self):
        self.run_archive()
        self.document['url'] = 'https://files.example/other.pdf'
        code, result = self.run_archive(None, '--offline')
        self.assertEqual(code, 1)
        self.assertIn('different URL', result['exhibits'][0]['error'])

    def test_expected_digest_must_match(self):
        self.document['sha256'] = '0' * 64
        code, result = self.run_archive()
        self.assertEqual(code, 1)
        self.assertIn('SHA-256', result['exhibits'][0]['error'])
        self.assertFalse((self.output / 'photos.pdf').exists())


if __name__ == '__main__':
    unittest.main()

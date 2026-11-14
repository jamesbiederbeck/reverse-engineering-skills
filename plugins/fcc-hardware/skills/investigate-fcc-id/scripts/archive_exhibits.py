#!/usr/bin/env python3
"""Archive discovered public FCC PDF exhibits, preserving provenance and hashes."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import tempfile
from datetime import datetime, timezone
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def https_url(value):
    parts = urlsplit(value)
    if parts.scheme != "https" or not parts.hostname or parts.username or parts.password:
        raise ValueError("Expected a public HTTPS document URL without credentials")
    return value


class HTTPSRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        https_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def pdf_info(path, limit, expected=None):
    if path.is_symlink() or not path.is_file():
        raise ValueError("Expected a regular PDF file, not a symlink or directory")
    size = path.stat().st_size
    if not 0 < size <= limit:
        raise ValueError("PDF is empty or exceeds the configured size limit")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        first = stream.read(1024)
        if b"%PDF-" not in first:
            raise ValueError("Content is not a PDF (possibly an HTML block/error page)")
        digest.update(first)
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    actual = digest.hexdigest()
    if expected and actual != expected.lower():
        raise ValueError("SHA-256 does not match the expected digest; existing files are retained")
    return {"bytes": size, "sha256": actual}


def read_manifest(path):
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not isinstance(data.get("fcc_id"), str) or not data["fcc_id"].strip():
        raise ValueError("Manifest requires a nonempty string fcc_id")
    if not isinstance(data.get("exhibits"), list):
        raise ValueError("Manifest requires an exhibits array")
    used = set()
    for entry in data["exhibits"]:
        if not isinstance(entry, dict) or not isinstance(entry.get("status"), str):
            raise ValueError("Each exhibit requires a string status")
        if entry["status"] != "public":
            continue
        filename = entry.get("filename", "")
        if not isinstance(filename, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*\.pdf", filename):
            raise ValueError("Public exhibits require a safe basename ending in .pdf")
        if filename in used:
            raise ValueError("Public exhibit filenames must be unique")
        used.add(filename)
        expected = entry.get("sha256")
        if expected is not None and (not isinstance(expected, str) or not re.fullmatch(r"[a-fA-F0-9]{64}", expected)):
            raise ValueError("Expected sha256 must contain 64 hexadecimal characters")
    return data


def positive_int(value):
    number = int(value)
    if number <= 0:
        raise argparse.ArgumentTypeError("Must be a positive integer")
    return number


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--offline", action="store_true", help="Check existing files only")
    parser.add_argument("--max-mib", type=positive_int, default=100)
    parser.add_argument("--timeout", type=positive_int, default=45)
    args = parser.parse_args()
    try:
        manifest = read_manifest(args.manifest)
        args.out.mkdir(parents=True, exist_ok=True)
        results_path = args.out / "downloads.json"
        if results_path.resolve() == args.manifest.resolve():
            raise ValueError("Input manifest cannot be the output downloads.json")
        previous = {}
        if results_path.exists():
            old = json.loads(results_path.read_text(encoding="utf-8"))
            if old.get("fcc_id") != manifest["fcc_id"]:
                raise ValueError("Output directory belongs to another FCC ID")
            previous = {item.get("filename"): item for item in old.get("exhibits", [])}
    except (OSError, ValueError, TypeError, AttributeError) as exc:
        print(f"Manifest/output error: {exc}", file=sys.stderr)
        return 2

    limit = args.max_mib * 1024 * 1024
    opener = build_opener(HTTPSRedirects())
    results = []
    for entry in manifest["exhibits"]:
        result = dict(entry)
        result["checked_at"] = utc_now()
        if entry["status"] != "public":
            result["download_status"] = "skipped"
            results.append(result)
            continue
        target = args.out / entry["filename"]
        temporary = None
        try:
            url = https_url(entry.get("url") or "")
            prior = previous.get(entry["filename"], {})
            if target.exists() or target.is_symlink():
                if prior and prior.get("url") != url:
                    raise ValueError("Existing filename was associated with a different URL")
                expected = entry.get("sha256") or prior.get("sha256")
                if not expected:
                    raise ValueError("Existing file has no verified digest; supply sha256 or use a fresh directory")
                result.update(pdf_info(target, limit, expected))
                result["download_status"] = "existing"
                result["local_path"] = entry["filename"]
                for key in ("final_url", "content_type", "retrieved_at"):
                    if key in prior:
                        result[key] = prior[key]
            elif args.offline:
                raise ValueError("File is absent; offline mode does not retrieve documents")
            else:
                req = Request(url, headers={"User-Agent": "FCC-Hardware-Dossier/1.0", "Accept": "application/pdf"})
                with opener.open(req, timeout=args.timeout) as response:
                    https_url(response.geturl())
                    length = response.headers.get("Content-Length")
                    if length and int(length) > limit:
                        raise ValueError("Response exceeds the configured size limit")
                    fd, tmp_name = tempfile.mkstemp(prefix=".exhibit-", suffix=".part", dir=args.out)
                    temporary = Path(tmp_name)
                    size = 0
                    with os.fdopen(fd, "wb") as stream:
                        while chunk := response.read(1024 * 1024):
                            size += len(chunk)
                            if size > limit:
                                raise ValueError("Response exceeds the configured size limit")
                            stream.write(chunk)
                    if length and size != int(length):
                        raise ValueError("Incomplete download: Content-Length does not match")
                    result.update(pdf_info(temporary, limit, entry.get("sha256")))
                    result.update(final_url=response.geturl(), content_type=response.headers.get_content_type())
                # Publish atomically without overwriting an existing file.
                os.link(temporary, target)
                result.update(download_status="downloaded", local_path=entry["filename"], retrieved_at=utc_now())
        except Exception as exc:
            result["download_status"] = "failed"
            result["error"] = f"{type(exc).__name__}: {exc}"
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
        results.append(result)

    output = {"fcc_id": manifest["fcc_id"], "checked_at": utc_now(), "input_manifest": str(args.manifest.resolve()), "exhibits": results}
    temporary_result = None
    try:
        fd, name = tempfile.mkstemp(prefix=".downloads-", suffix=".json", dir=args.out)
        temporary_result = Path(name)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(output, stream, indent=2, ensure_ascii=False)
            stream.write("\n")
        os.replace(temporary_result, results_path)
    except OSError as exc:
        print(f"Cannot save download results: {exc}", file=sys.stderr)
        return 2
    finally:
        if temporary_result is not None:
            temporary_result.unlink(missing_ok=True)
    counts = {state: sum(item["download_status"] == state for item in results) for state in ("downloaded", "existing", "skipped", "failed")}
    print(json.dumps({"fcc_id": manifest["fcc_id"], **counts, "results": str(results_path.resolve())}))
    return 1 if counts["failed"] else 0


if __name__ == "__main__":
    sys.exit(main())

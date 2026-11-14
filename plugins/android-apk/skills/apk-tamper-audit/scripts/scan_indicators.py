#!/usr/bin/env python3
"""
Scans an unpacked APK for content-level red flags: known-suspicious code/string
patterns (loaded from assets/suspicious_patterns.txt so the list is easy to extend),
plus files bundled somewhere they don't belong (a second dex/apk/so smuggled into
assets/ or res/raw/ is a classic dropper trick).

Looks in two places, because either one alone misses things:
  - jadx's decompiled Java source (readable, but jadx sometimes fails on obfuscated
    or packed bytecode and produces partial/garbled output for some classes)
  - raw printable strings from the original dex/so files (catches those failures,
    and catches native code jadx doesn't decompile at all)

Usage: scan_indicators.py <analysis-out-dir> <original-apk-path>
Prints a JSON report to stdout.
"""
import json
import re
import sys
import zipfile
from pathlib import Path

from androguard.core.apk import APK

SKILL_ROOT = Path(__file__).resolve().parent.parent
PATTERNS_FILE = SKILL_ROOT / "assets" / "suspicious_patterns.txt"

SUSPICIOUS_EMBEDDED_EXTENSIONS = {".dex", ".apk", ".so", ".jar", ".elf"}
# Locations where a bundled file of these types is normal and expected.
SAFE_LOCATIONS_FOR_EXT = {
    ".dex": {"", "classes"},  # top-level classesN.dex is normal
    ".so": {"lib/"},
}

MAX_MATCHES_PER_PATTERN = 8


def load_patterns():
    patterns = []
    for line in PATTERNS_FILE.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        label, severity, regex = line.split("|", 2)
        patterns.append({"label": label, "severity": severity, "regex": re.compile(regex)})
    return patterns


# Fallback for when the app's own package name can't be determined (rare). A modern
# APK almost always bundles at least some of these -- Kotlin's stdlib and AndroidX
# alone account for most of the low-severity noise in a typical decompile.
FALLBACK_LIBRARY_PATH_PREFIXES = (
    "androidx/",
    "android/support/",
    "com/google/",
    "kotlin/",
    "kotlinx/",
    "okhttp3/",
    "okio/",
    "retrofit2/",
    "com/squareup/",
    "org/apache/cordova/",
    "org/chromium/",
)


def build_is_library_path(app_package):
    """The generalizable version of "is this vendored code": everything NOT under the
    app's own declared package is bundled library/SDK code, full stop -- this needs no
    maintenance as new frameworks show up, unlike a hardcoded prefix list (which this
    file used to rely on until testing against a real Cordova+WebView app showed the
    list would never keep up). Falls back to the static list only if the package name
    itself couldn't be read from the manifest."""
    if app_package:
        app_prefix = app_package.replace(".", "/") + "/"

        def is_library_path(rel_path):
            return not rel_path.as_posix().startswith(app_prefix)

        return is_library_path

    def is_library_path_fallback(rel_path):
        return rel_path.as_posix().startswith(FALLBACK_LIBRARY_PATH_PREFIXES)

    return is_library_path_fallback


def scan_text_source(patterns, root_dir, suffixes, is_library_path):
    """Search every file under root_dir with a matching suffix against all patterns.
    Returns (app_matches, library_matches) so callers can decide how much weight to
    give a hit buried in bundled library code versus the app's own source."""
    app_matches = {p["label"]: [] for p in patterns}
    library_hit_counts = {p["label"]: 0 for p in patterns}
    if not root_dir.exists():
        return app_matches, library_hit_counts
    for path in root_dir.rglob("*"):
        if not path.is_file() or path.suffix not in suffixes:
            continue
        try:
            text = path.read_text(errors="ignore")
        except OSError:
            continue
        rel_path = path.relative_to(root_dir)
        in_library = is_library_path(rel_path)
        for p in patterns:
            for m in p["regex"].finditer(text):
                if in_library and p["severity"] != "high":
                    library_hit_counts[p["label"]] += 1
                    continue
                if len(app_matches[p["label"]]) >= MAX_MATCHES_PER_PATTERN:
                    continue
                line_no = text.count("\n", 0, m.start()) + 1
                app_matches[p["label"]].append(
                    {"file": str(rel_path), "line": line_no, "snippet": m.group(0)[:120]}
                )
    return app_matches, library_hit_counts


# A lazy injector often doesn't touch code at all -- dropping a plain-text config file
# (a C2 URL, a webhook, a token) into assets/ or res/raw/ is much less work than
# patching smali, and it's invisible to a decompile-only scan. These files are always
# scanned in full (no library-path suppression) since anything here either belongs to
# the app itself or was bundled deliberately by whoever built this APK.
BINARY_ASSET_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".ico",
    ".ttf", ".otf", ".woff", ".woff2",
    ".mp3", ".wav", ".ogg", ".mp4", ".webm", ".mov", ".avi", ".flac",
    ".zip", ".gz", ".7z", ".rar", ".arsc", ".db",
    ".fbx", ".obj", ".glb", ".gltf", ".unity3d", ".bundle",
}


def scan_asset_dirs(patterns, apktool_dir):
    matches = {p["label"]: [] for p in patterns}
    for sub in ("assets", "res"):
        root = apktool_dir / sub
        if not root.exists():
            continue
        for path in root.rglob("*"):
            if not path.is_file() or path.suffix.lower() in BINARY_ASSET_EXTENSIONS:
                continue
            try:
                text = path.read_text(errors="ignore")
            except OSError:
                continue
            for p in patterns:
                if len(matches[p["label"]]) >= MAX_MATCHES_PER_PATTERN:
                    continue
                for m in p["regex"].finditer(text):
                    line_no = text.count("\n", 0, m.start()) + 1
                    matches[p["label"]].append(
                        {"file": str(path.relative_to(apktool_dir)), "line": line_no, "snippet": m.group(0)[:120]}
                    )
                    if len(matches[p["label"]]) >= MAX_MATCHES_PER_PATTERN:
                        break
    return matches


PRINTABLE_RUN = re.compile(rb"[\x20-\x7e]{6,}")


def extract_strings(data):
    """Pure-Python equivalent of `strings -n 6`, so the scan doesn't depend on binutils."""
    return "\n".join(m.group(0).decode("ascii") for m in PRINTABLE_RUN.finditer(data))


def scan_raw_binaries(patterns, apk_path):
    """Extract printable strings from the APK's dex/so files and pattern-match
    over them -- this catches obfuscated/packed content jadx couldn't decompile."""
    matches = {p["label"]: [] for p in patterns}
    with zipfile.ZipFile(apk_path) as z:
        binary_entries = [n for n in z.namelist() if n.endswith(".dex") or n.endswith(".so")]
        for name in binary_entries:
            text = extract_strings(z.read(name))
            for p in patterns:
                if len(matches[p["label"]]) >= MAX_MATCHES_PER_PATTERN:
                    continue
                for m in p["regex"].finditer(text):
                    matches[p["label"]].append({"file": name, "snippet": m.group(0)[:120]})
                    if len(matches[p["label"]]) >= MAX_MATCHES_PER_PATTERN:
                        break
    return matches


def merge_matches(a, b):
    out = {}
    for label in a:
        out[label] = a[label] + b.get(label, [])
    return out


ZIP_ENTRY_LINE = re.compile(r"^\s*\d+\s+\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}\s+(.+)$")


def check_embedded_files(zip_listing_path):
    """Parse `unzip -l` output. Only lines matching the Length/Date/Time/Name row
    format are real entries -- the header (which includes the archive's own path) and
    footer summary line must not be mistaken for entries."""
    flags = []
    if not zip_listing_path.exists():
        return flags
    for line in zip_listing_path.read_text().splitlines():
        m = ZIP_ENTRY_LINE.match(line)
        if not m:
            continue
        entry = m.group(1)
        ext = Path(entry).suffix.lower()
        if ext not in SUSPICIOUS_EMBEDDED_EXTENSIONS:
            continue
        safe_prefixes = SAFE_LOCATIONS_FOR_EXT.get(ext, set())
        if any(entry.startswith(prefix) or (prefix == "" and "/" not in entry) for prefix in safe_prefixes):
            continue
        if ext == ".dex" and Path(entry).name.startswith("classes") and "/" not in entry:
            continue
        flags.append(entry)
    return flags


def main(out_dir, apk_path):
    out_dir = Path(out_dir)
    patterns = load_patterns()

    try:
        app_package = APK(apk_path).get_package()
    except Exception:
        app_package = None
    is_library_path = build_is_library_path(app_package)

    jadx_matches, library_hit_counts = scan_text_source(
        patterns, out_dir / "jadx" / "sources", {".java"}, is_library_path
    )
    raw_matches = scan_raw_binaries(patterns, apk_path)
    asset_matches = scan_asset_dirs(patterns, out_dir / "apktool")
    combined = merge_matches(merge_matches(jadx_matches, raw_matches), asset_matches)

    pattern_lookup = {p["label"]: p for p in patterns}
    findings = []
    for label in pattern_lookup:
        hits = combined.get(label, [])
        lib_count = library_hit_counts.get(label, 0)
        if not hits and not lib_count:
            continue
        entry = {
            "label": label,
            "severity": pattern_lookup[label]["severity"],
            "hit_count": len(hits),
            "examples": hits[:MAX_MATCHES_PER_PATTERN],
        }
        if lib_count:
            entry["also_seen_in_known_libraries"] = lib_count
        findings.append(entry)
    findings.sort(key=lambda f: {"high": 0, "medium": 1, "low": 2}.get(f["severity"], 3))

    embedded = check_embedded_files(out_dir / "zip_listing.txt")

    result = {
        "pattern_findings": findings,
        "unexpected_embedded_files": embedded,
    }
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: scan_indicators.py <analysis-out-dir> <original-apk-path>", file=sys.stderr)
        sys.exit(1)
    main(sys.argv[1], sys.argv[2])

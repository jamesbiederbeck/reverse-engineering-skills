#!/usr/bin/env bash
# Pulls one APK apart from several angles: decoded manifest/resources/smali (apktool),
# Java-like decompiled source (jadx), badging/permission dumps and signer info
# (aapt2/apksigner), a raw zip listing, and an embedded-file scan (binwalk).
#
# Every external tool is optional: a missing tool is reported and skipped, and the
# skip is written into that tool's output file so the gap is visible in the results.
# Usage: unpack.sh <path-to-apk> [output-dir]   (default output-dir: ./apk_analysis)
set -uo pipefail

if [ $# -lt 1 ]; then
    echo "Usage: $0 <path-to-apk> [output-dir]" >&2
    exit 2
fi
APK="$1"
OUT="${2:-./apk_analysis}"

if [ ! -f "$APK" ]; then
    echo "APK not found: $APK" >&2
    exit 1
fi

mkdir -p "$OUT"

# Find a tool on PATH, or in the newest Android SDK build-tools directory.
find_tool() {
    local name="$1" sdk newest
    if command -v "$name" >/dev/null 2>&1; then
        command -v "$name"
        return 0
    fi
    for sdk in "${ANDROID_HOME:-}" "${ANDROID_SDK_ROOT:-}"; do
        [ -n "$sdk" ] && [ -d "$sdk/build-tools" ] || continue
        newest="$(find "$sdk/build-tools" -maxdepth 2 -name "$name" -type f 2>/dev/null | sort -V | tail -n 1)"
        if [ -n "$newest" ]; then
            echo "$newest"
            return 0
        fi
    done
    return 1
}

# skip_note <tool> <output-file> <what-is-lost>
skip_note() {
    echo "SKIPPED: '$1' not found (PATH, \$ANDROID_HOME/build-tools, \$ANDROID_SDK_ROOT/build-tools). $3" | tee "$2"
}

echo "== apktool: decoding manifest/resources/smali =="
if APKTOOL="$(find_tool apktool)"; then
    "$APKTOOL" d -f -o "$OUT/apktool" "$APK"
else
    skip_note apktool "$OUT/apktool_skipped.txt" "No decoded manifest/smali/resources; the pattern scan will cover less."
fi

echo "== jadx: decompiling to Java-like source =="
if JADX="$(find_tool jadx)"; then
    # jadx exits non-zero on APKs with obfuscated/broken bytecode even when it still
    # produced usable output for most classes, so don't let that abort the unpack.
    "$JADX" -d "$OUT/jadx" "$APK" || echo "jadx reported errors (common on obfuscated/packed APKs) -- continuing with whatever it produced"
else
    skip_note jadx "$OUT/jadx_skipped.txt" "No decompiled source; rely on the raw-binary string scan and smali."
fi

echo "== aapt2: badging/permission dump =="
if AAPT2="$(find_tool aapt2)"; then
    "$AAPT2" dump badging "$APK" > "$OUT/badging.txt" 2>&1
    "$AAPT2" dump permissions "$APK" > "$OUT/permissions.txt" 2>&1
else
    skip_note aapt2 "$OUT/badging.txt" "Use the package/version/permission data from scan_manifest.py instead."
    cp "$OUT/badging.txt" "$OUT/permissions.txt"
fi

echo "== apksigner: signer/certificate info =="
if APKSIGNER="$(find_tool apksigner)"; then
    "$APKSIGNER" verify --print-certs -v "$APK" > "$OUT/signer.txt" 2>&1
else
    skip_note apksigner "$OUT/signer.txt" "Signer details unavailable; 'keytool -printcert -jarfile <apk>' is an alternative if a JDK is installed."
fi

echo "== raw zip listing (spot extra/unexpected entries) =="
if command -v unzip >/dev/null 2>&1; then
    unzip -l "$APK" > "$OUT/zip_listing.txt"
else
    python3 - "$APK" > "$OUT/zip_listing.txt" <<'PY'
import sys, zipfile
print("  Length      Date    Time    Name")
for i in zipfile.ZipFile(sys.argv[1]).infolist():
    d = i.date_time
    print(f"{i.file_size:>9}  {d[0]:04d}-{d[1]:02d}-{d[2]:02d} {d[3]:02d}:{d[4]:02d}   {i.filename}")
PY
fi

echo "== binwalk: looking for a second file embedded inside the APK itself =="
# A classic dropper trick is smuggling a second APK/ELF/zip inside an asset or native lib
# so it can be written out and executed/installed later. binwalk's signature scan catches
# an embedded file even when it's been renamed or has no extension.
if command -v binwalk >/dev/null 2>&1; then
    binwalk "$APK" > "$OUT/binwalk_container.txt" 2>&1
    mkdir -p "$OUT/binwalk_libs"
    find "$OUT/apktool/lib" -name '*.so' 2>/dev/null | while read -r lib; do
        rel="${lib#"$OUT"/apktool/lib/}"
        outfile="$OUT/binwalk_libs/$(echo "$rel" | tr '/' '_').txt"
        binwalk "$lib" > "$outfile" 2>&1
    done
else
    skip_note binwalk "$OUT/binwalk_container.txt" "Optional; installing it (via your package manager or pip) strengthens the embedded-file check. Nothing was installed automatically."
fi

echo ""
echo "Unpacked to $OUT"

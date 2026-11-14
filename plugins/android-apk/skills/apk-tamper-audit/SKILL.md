---
name: apk-tamper-audit
description: Pulls an APK apart (decompile, manifest, permissions, strings, embedded files) and static-analyzes it for signs someone modified it before redistributing it -- injected malware/spyware code, network exfiltration indicators, and manifest/permission changes that don't match what a normal app of that kind would need. Use this whenever the user has a sideloaded, "modded", "cracked", third-party-mirrored, or otherwise not-from-the-official-store APK they want checked before installing, or asks anything like "is this APK safe", "can you check this APK for malware", "did someone inject something into this app", or "audit this APK". Also trigger for reverse-engineering an APK's behavior more generally (what permissions does it really use, what does it phone home to, what's actually in this native library) even if the user doesn't frame it as a security check.
---

# APK Tamper Audit

Resolve bundled scripts and assets from this skill's installed directory; in Claude Code,
`${CLAUDE_SKILL_DIR}` identifies it. Write the analysis output directory in the user's
workspace (for example `./apk_analysis/<apk-name>/`), never inside the installed plugin.
Only analyze APKs the user owns or is authorized to inspect, and never install or run the APK.

## Requirements

- Python 3.9+ with `androguard>=4` (`python3 -m pip install "androguard>=4"`) for the manifest and indicator scans.
- Java plus `apktool` and `jadx` for the decode and decompile steps.
- `aapt2` and `apksigner` (Android SDK build-tools; `unpack.sh` also searches `$ANDROID_HOME`/`$ANDROID_SDK_ROOT`).
- Node.js (standard library only) for the optional JavaScript deobfuscator.
- `binwalk` is optional.

`unpack.sh` skips any missing tool and records the skip in that tool's output file, so a
gap is visible rather than silent. Report which tools were missing in the audit and say
what that limits. Missing `aapt2` just means the package and permission data come from
`scan_manifest.py` instead.

Someone took an app, changed something, and repackaged it for redistribution. Maybe
they injected an ad SDK, maybe spyware, maybe nothing at all and it's a clean mod. Your
job is to pull it apart and give the user real evidence to decide whether to install it
-- not a vibe, a list of specific things you found and why each one matters.

You will almost never have the original, official APK to diff against -- if the user
does happen to provide one, diffing the two manifests/permission sets is the fastest,
highest-signal check there is, so do it. Most of the time it's just the one suspicious
APK, so the approach below is built to stand on its own.

## Why single-APK analysis works at all

Without a baseline to diff against, you're leaning on the fact that malicious injections
tend to look different from the surrounding app in specific, detectable ways: they ask
for permissions the app's stated purpose doesn't need, they talk to the network in ways
the rest of the app doesn't, they load code dynamically instead of shipping it normally,
and they're often the *only* obfuscated or packed part of an otherwise readable
decompile. You're not proving the APK is malicious -- you're surfacing the things that
would make a careful reviewer say "wait, why does this app need that."

## Workflow

### 1. Unpack it

```
bash "${CLAUDE_SKILL_DIR}/scripts/unpack.sh" <path-to-apk> <output-dir>
```

This runs apktool (manifest/resources/smali), jadx (readable decompiled source),
aapt2 (badging/permission dump), apksigner (signer/cert info), a raw zip listing, and
binwalk over the APK and its native libraries if binwalk is installed. If jadx exits
non-zero, that's expected on obfuscated/packed APKs and not a reason to stop -- it
still produces partial output, and the raw-binary scan in the next step covers what it
missed.

If binwalk isn't on PATH, the script tells you and skips that check rather than
installing anything. Mention to the user that installing binwalk (via their package
manager or pip) would strengthen the embedded-file check, but don't install it
yourself -- that's a system change on their machine, not something to do silently.

### 2. Check the manifest and permissions

```
python3 "${CLAUDE_SKILL_DIR}/scripts/scan_manifest.py" <path-to-apk>
```

Outputs JSON: full permission list, which of those are on the "this permission is
exactly what an injector adds" list (with the reason each one matters), plus flags for
a debuggable release build, cleartext traffic, boot-persistence receivers, and exported
components with no permission guard. None of these are individually damning -- a
flashlight app asking for `SYSTEM_ALERT_WINDOW` is worth a raised eyebrow; a launcher
app asking for it is normal. Judge each flag against what *this specific app* is
supposed to do, which you can usually tell from its package name, app label in
`badging.txt`, and what its actual UI/features are once you skim the decompiled source.

### 3. Scan for injected code and exfiltration patterns

```
python3 "${CLAUDE_SKILL_DIR}/scripts/scan_indicators.py" <output-dir> <path-to-apk>
```

Searches the jadx-decompiled source, printable strings extracted from the original
dex/native-library bytes (so obfuscated code jadx couldn't decompile still gets
covered), and every text-like file under `assets/` and `res/` (a lazy injector often
skips patching code entirely and just drops a plain-text C2 URL or webhook into an
asset file, which a decompile-only scan would miss) against the pattern list in
`assets/suspicious_patterns.txt` (inside this skill's directory). It also flags files bundled somewhere they shouldn't
be -- a second `.dex`/`.apk`/`.so` hiding in `assets/` or `res/raw/` is a classic way
to smuggle a payload that gets written out and run later.

The pattern file is plain text (`label|severity|regex`, one per line) specifically so
you or the user can add a new line the moment you learn what some specific piece of
malware looks like, without touching the script. If you find something during an audit
that clearly should have been on this list, add it.

Every hit needs a look at the actual context before it goes in the report -- a hit on
"Reflection-based class loading" in a networking library's serialization code is
nothing; the same hit inside a class that also references `DexClassLoader` and a raw IP
literal is a different story entirely. Read a few lines around each match in the
decompiled source before deciding how much weight it carries.

### 3b. If you find an obfuscated script, decode it -- don't guess at it

Some crack/injection tooling doesn't hide in native code at all -- it ships a JavaScript
payload (very often a Frida gadget's companion hook script, sometimes disguised with a
`.so` extension so it looks like a normal library), obfuscated with a
string-array-plus-cipher scheme (the output of tools like javascript-obfuscator.io).
`strings`/grep against a file like this finds nothing useful, because every interesting
literal -- URLs, function names, log messages -- only exists post-decode. A `file
<path>` that reports "ASCII text"/"JavaScript source" on something with a misleading
extension is your signal to check for this.

```
node "${CLAUDE_SKILL_DIR}/scripts/deobfuscate_js.js" <suspect-file> <output-dir>
```

This detects the specific (extremely common) string-array + rotation + decode-function
shape, checks that those three pieces reference nothing beyond pure string/array math
(no Frida/process/filesystem/network APIs, no `eval`/`Function`/`require`), and *only
then* evaluates that narrow, inert slice to unmask the string table -- it never executes
the file's actual hook/payload logic. It writes `decoded_strings.json` (every literal),
`reconstructed_concatenations.json` (strings the original code rebuilt via `+`, which is
where a split-up URL or token would actually show up), and a fully substituted
`deobfuscated_source.js` you can read and grep like normal code.

If it reports `"detected": false` or `"decoded": false`, that's a real, useful result --
it means this file's obfuscation doesn't match the scheme this script knows how to
verify-and-decode safely. Say so plainly in the report ("this script is obfuscated and
its contents couldn't be verified") rather than inferring what it probably does from
variable names or config files alone.

This distinction matters a lot for the report you write: **only use confirming language
("this hooks X", "this sends data to Y") for something you can point to in
`decoded_strings.json` or the deobfuscated source.** If all you have is a plausible
guess based on a companion config file or the kind of API names you'd expect a tool like
this to call, say that explicitly ("consistent with X, though not directly confirmed by
decoding the script") -- a specific-sounding but unverified claim is worse than an honest
"I couldn't verify this part," because the user can't tell the difference between your
confirmed finding and your guess unless you tell them which one it is.

### 4. Look at the signer and package identity

Read `<output-dir>/signer.txt` and compare the package name / app label (from
`badging.txt`) against what the user expects. A few things worth specifically checking
even without an original APK to diff against:

- Self-signed or clearly generic-looking certificate subject (`CN=Android Debug`,
  `CN=Unknown`, or a cert issued the same day as the file's modification time)
- A signature scheme downgrade (v1-only, no v2/v3) on an app that's otherwise clearly
  built for a recent Android target SDK -- repackaging tools sometimes have to strip
  newer signature schemes to re-sign after modification
- A package name that doesn't match the app's own branding/label, or that mimics a
  well-known package name with a subtle typo

### 5. Write the report

Write a markdown report (save it next to the output dir, e.g.
`<output-dir>/audit_report.md`) using this structure:

```markdown
# APK Tamper Audit: <package name / app label>

## Verdict
One paragraph: your overall read (clean / suspicious / actively malicious-looking) and
the one or two findings that most drove that read.

## Findings
Ranked most-severe first. For each: what you found, where (file/line or component
name), and *why it matters for this specific app* -- not just "this permission is
dangerous" but "this permission is dangerous and this app has no evident reason to
need it."

## Permissions
The full list, with the flagged ones annotated inline.

## What this audit can't tell you
Be honest about the ceiling here: static analysis catches code that's present but
doesn't run anything, so a payload that only activates under specific runtime
conditions (server-side kill switch, time bomb, specific device fingerprint) may not
show up in any string or manifest flag. If the findings are inconclusive, say so
plainly instead of forcing a verdict.
```

Don't pad the report with findings that don't matter -- an empty "Findings" section
with a note that nothing stood out is a completely valid, useful report. The user is
trying to make an install/don't-install decision; noise makes that harder, not easier.

## When there's an original APK to diff against

If the user provides both APKs, run steps 1-3 on both and diff:

- `all_permissions` sets (anything added in the redistributed copy is the highest-value
  finding in the whole audit -- lead the report with it)
- signer certs (a changed signer means someone definitely re-packaged and re-signed it,
  full stop -- this is the one unambiguous piece of evidence single-APK analysis can't
  give you)
- exported component lists and `pattern_findings` (anything present in the modified
  copy but absent from the original was added by whoever redistributed it)

See [references/severity_guide.md](references/severity_guide.md) for more detail on how to weigh findings once you
have them, and for guidance on edge cases (game mods with legitimately elevated
permissions, apps that legitimately load dex dynamically for plugin systems, etc.).

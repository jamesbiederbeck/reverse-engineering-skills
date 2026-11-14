# Weighing findings and avoiding false alarms

Static analysis surfaces facts; deciding what they mean requires knowing the app's
context. This file covers the judgment calls that come up often enough to be worth
writing down.

## Legitimate reasons for "suspicious-looking" things

Don't let these tank an otherwise clean verdict on their own:

- **Game/emulator mods and modding frameworks legitimately use `DexClassLoader`** to
  load plugins, translation packs, or mod content the user installs separately. The
  question is *what* gets loaded and from *where* -- loading a signed, bundled plugin
  dex from the app's own assets is very different from loading a dex fetched from a
  URL at runtime and stashed in a world-writable directory.
- **Analytics/crash-reporting SDKs (Firebase, Crashlytics, Sentry, etc.) legitimately
  collect device identifiers.** The `firebaseio.com` pattern hit and `Build.SERIAL`-type
  hits are common and not evidence of anything on their own -- look at *how much* data
  goes out and whether it's proportionate to "crash reporting" versus "everything about
  this device and its owner."
- **VR/game apps often request `SYSTEM_ALERT_WINDOW` or accessibility-adjacent
  permissions for legitimate overlay UI** (in-game overlays, performance HUDs, input
  remapping tools). Check what the permission is actually used for in the decompiled
  source before treating it as a red flag.
- **A permission present but never referenced anywhere in the decompiled source** is
  usually leftover cruft from a template/SDK the developer didn't fully strip, not
  evidence of hidden functionality -- though it's still worth a one-line mention since
  it's needless attack surface either way.

## DRM/entitlement-bypass tooling is its own category, not automatically "spyware"

Sideloaded games (Quest titles especially, via "scene" release groups) are very often
cracked by embedding a **Frida gadget** -- a general-purpose dynamic instrumentation
runtime, sometimes with a misleading filename like `libfrda.so` -- configured via an
adjacent plaintext JSON config to auto-run a hook script that patches the platform's
purchase/entitlement-check APIs (Oculus Platform SDK's `ovr_*` calls, Google Play
Billing, etc.) so the app believes it's been legitimately purchased. This is a real,
disclosed modification -- it's the entire point of a "cracked" release, not a hidden
extra -- and it deserves a clear finding in the report. But it is a categorically
different thing from injected spyware:

- Its declared purpose is narrow (intercept specific SDK calls) and checkable against
  what it actually hooks, unlike spyware, which typically has no legitimate narrative to
  check its behavior against at all.
- Whether it's *trustworthy* still depends on what the hook script actually does --
  don't take the config file's word for it. See "3b. If you find an obfuscated
  script" in `SKILL.md`: decode it and check specifically for anything the config
  doesn't mention (network destinations, data collection, additional dynamic code
  loading) before calling it "just an entitlement bypass."
- A Frida gadget/hook framework running with the app's full permissions is a real,
  meaningfully larger trust surface than the stock app has (it can intercept and rewrite
  arbitrary native calls at runtime), even when its current configured behavior looks
  narrow -- say this plainly rather than letting "it's just a common crack technique"
  read as "so it's fine."
- Don't call this clean *or* call it spyware by default -- land on "does what a crack
  claims to do, verified as far as static analysis allows" when the evidence supports
  it, and say plainly what you couldn't verify.

## Things that are hard to explain away

- **`android:debuggable="true"` on what's presented as a release build.** There's
  essentially no legitimate reason a publicly redistributed "release" APK ships this
  way. Weight it heavily.
- **A signer certificate that doesn't match the developer's known signing identity**
  (only checkable when you have the original APK, or when the user can tell you the
  expected signer). This is the closest thing to unambiguous proof of repackaging.
- **A second dex/apk/so file embedded somewhere outside the normal locations**, especially
  if it's compressed/encrypted-looking (high entropy, no recognizable strings) inside an
  asset that has nothing to do with the app's stated purpose (e.g., a fitness app with an
  opaque blob named like a system library).
- **Network endpoints that don't match the app's stated purpose at all** -- a wallpaper
  app phoning home to an IP literal with no reverse DNS, especially alongside SMS or
  contacts permissions, is a very different picture than the same app talking to a CDN
  domain for asset downloads.

## When findings are genuinely inconclusive

Static analysis has a real ceiling: a payload gated behind a runtime check (a
server-side flag, a time bomb, a specific device fingerprint) may never execute the
code path that would produce a string or manifest signal. If you've gone through all
four analysis steps and nothing clearly stands out, say so directly in the report
rather than manufacturing a verdict from weak signals. "No clear evidence of tampering
found, but static analysis can't rule out a runtime-gated payload" is a legitimate and
useful conclusion.

#!/usr/bin/env python3
"""
Parses an APK's manifest with androguard and flags the things that tend to change
when someone repackages an app: dangerous permissions that weren't there for a good
reason, a debuggable release build, cleartext traffic allowed, boot-persistence
receivers, and exported components with no permission guarding them.

Usage: scan_manifest.py <path-to-apk>
Prints a JSON report to stdout.
"""
import json
import sys

from androguard.core.apk import APK

ANDROID_NS = "{http://schemas.android.com/apk/res/android}"

# Permissions that are legitimate for plenty of apps, but are exactly the ones a
# spyware/stalkerware injector adds to an otherwise-unrelated app. Flagging these isn't
# an accusation -- it's a prompt to go check *why* the app wants this in the decompiled
# source (scan_indicators.py output + jadx source are the next place to look).
DANGEROUS_PERMS = {
    "android.permission.READ_SMS": "reads SMS messages",
    "android.permission.RECEIVE_SMS": "intercepts incoming SMS (can steal 2FA codes)",
    "android.permission.SEND_SMS": "can send SMS silently (premium-rate fraud pattern)",
    "android.permission.READ_CALL_LOG": "reads call history",
    "android.permission.WRITE_CALL_LOG": "modifies call history",
    "android.permission.PROCESS_OUTGOING_CALLS": "can monitor/redirect outgoing calls",
    "android.permission.RECORD_AUDIO": "microphone access",
    "android.permission.CAMERA": "camera access",
    "android.permission.ACCESS_BACKGROUND_LOCATION": "tracks location even when the app is closed",
    "android.permission.READ_CONTACTS": "reads the contact list",
    "android.permission.SYSTEM_ALERT_WINDOW": "can draw over other apps (overlay/phishing UI pattern)",
    "android.permission.BIND_ACCESSIBILITY_SERVICE": "can read screen content and inject input system-wide",
    "android.permission.BIND_DEVICE_ADMIN": "device admin -- hard to uninstall, can lock/wipe the device",
    "android.permission.REQUEST_INSTALL_PACKAGES": "can install other APKs (dropper pattern)",
    "android.permission.PACKAGE_USAGE_STATS": "can see what other apps are being used",
    "android.permission.QUERY_ALL_PACKAGES": "can enumerate every app installed on the device",
    "android.permission.WRITE_SECURE_SETTINGS": "can modify protected system settings",
    "android.permission.RECEIVE_BOOT_COMPLETED": "can auto-start at boot (persistence)",
    "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE": "can read all notification content, including OTP codes",
    "android.permission.MANAGE_EXTERNAL_STORAGE": "broad filesystem access",
}


def exported_components_without_permission(manifest_root):
    app_el = manifest_root.find("application")
    if app_el is None:
        return []
    flagged = []
    for tag in ("activity", "activity-alias", "service", "receiver", "provider"):
        for el in app_el.findall(tag):
            name = el.get(f"{ANDROID_NS}name")
            exported_attr = el.get(f"{ANDROID_NS}exported")
            has_intent_filter = el.find("intent-filter") is not None
            # Android's default: a component with an intent-filter and no explicit
            # exported attribute is exported. That default is what repackaged apps
            # rely on to sneak in an entry point the manifest doesn't obviously flag.
            is_exported = exported_attr == "true" or (exported_attr is None and has_intent_filter)
            permission = el.get(f"{ANDROID_NS}permission")
            if is_exported and not permission:
                flagged.append({"type": tag, "name": name})
    return flagged


def boot_receivers(manifest_root):
    app_el = manifest_root.find("application")
    if app_el is None:
        return []
    found = []
    for el in app_el.findall("receiver"):
        for filt in el.findall("intent-filter"):
            for action in filt.findall("action"):
                if action.get(f"{ANDROID_NS}name") == "android.intent.action.BOOT_COMPLETED":
                    found.append(el.get(f"{ANDROID_NS}name"))
    return found


def main(apk_path):
    a = APK(apk_path)
    manifest_root = a.get_android_manifest_xml()

    findings = []

    perms = a.get_permissions()
    flagged_perms = [{"permission": p, "why": DANGEROUS_PERMS[p]} for p in perms if p in DANGEROUS_PERMS]

    if a.get_attribute_value("application", "debuggable") == "true":
        findings.append(
            {
                "severity": "high",
                "category": "manifest",
                "summary": 'android:debuggable="true" in the manifest',
                "detail": "Legitimate release builds are essentially never shipped debuggable. This is a strong repackaging signal on its own.",
            }
        )

    if a.get_attribute_value("application", "usesCleartextTraffic") == "true":
        findings.append(
            {
                "severity": "medium",
                "category": "network",
                "summary": 'usesCleartextTraffic="true"',
                "detail": "Allows plaintext HTTP, which makes network interception/exfiltration trivial and is unusual for a modern app.",
            }
        )

    boots = boot_receivers(manifest_root)
    if boots:
        findings.append(
            {
                "severity": "medium",
                "category": "persistence",
                "summary": f"{len(boots)} receiver(s) listen for BOOT_COMPLETED",
                "detail": "A common persistence mechanism when paired with an injected payload. Also legitimate for alarms/widgets -- check what these receivers actually do in the decompiled source before concluding anything.",
                "components": boots,
            }
        )

    exported = exported_components_without_permission(manifest_root)
    if exported:
        findings.append(
            {
                "severity": "low",
                "category": "attack-surface",
                "summary": f"{len(exported)} exported component(s) with no permission requirement",
                "detail": "Any app on the device can invoke these. Not inherently malicious (plenty of apps export unguarded activities on purpose), but worth a look, especially for receivers/services with generic or unfamiliar names.",
                "components": exported,
            }
        )

    result = {
        "package": a.get_package(),
        "version_name": a.get_androidversion_name(),
        "version_code": a.get_androidversion_code(),
        "min_sdk": a.get_min_sdk_version(),
        "target_sdk": a.get_target_sdk_version(),
        "all_permissions": sorted(perms),
        "flagged_permissions": flagged_perms,
        "findings": findings,
    }
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: scan_manifest.py <path-to-apk>", file=sys.stderr)
        sys.exit(1)
    main(sys.argv[1])

import re


PROFILE_AUTO = "auto"
PROFILE_MA5800 = "huawei_ma5800"
PROFILE_MA56XX = "huawei_ma56xx"
PROFILE_GENERIC = "huawei_generic"


def normalize_profile(value):
    raw = str(value or "").strip().lower()
    aliases = {
        "auto": PROFILE_AUTO,
        "huawei_ma5800": PROFILE_MA5800,
        "ma5800": PROFILE_MA5800,
        "huawei_ma56xx": PROFILE_MA56XX,
        "ma56xx": PROFILE_MA56XX,
        "ma5683t": PROFILE_MA56XX,
        "huawei_generic": PROFILE_GENERIC,
        "generic": PROFILE_GENERIC,
    }
    return aliases.get(raw, PROFILE_AUTO)


def detect_profile_from_version_text(text):
    source = (text or "").lower()
    if not source:
        return None
    if "ma5800" in source:
        return PROFILE_MA5800
    if re.search(r"\bma56\d{2}\b", source) or "ma5683" in source:
        return PROFILE_MA56XX
    return None


def resolve_profile(configured_profile, version_text):
    normalized = normalize_profile(configured_profile)
    detected = detect_profile_from_version_text(version_text)
    if normalized == PROFILE_AUTO:
        return detected or PROFILE_GENERIC
    return normalized


def ont_summary_commands_for_profile(profile):
    normalized = normalize_profile(profile)
    if normalized == PROFILE_MA5800:
        return [
            "display ont info summary all",
            "display ont info summary 0 all",
            "display ont info summary 0/0 all",
            "display ont info summary 0/0",
            "display ont info summary 0/0/0",
            "display ont info summary 0 0 all",
            "display ont info summary",
        ]
    if normalized == PROFILE_MA56XX:
        return [
            "display ont info summary 0 all",
            "display ont info summary all",
            "display ont info summary 0 0 all",
            "display ont info summary 0/0 all",
            "display ont info summary 0",
            "display ont info summary",
        ]
    return [
        "display ont info summary 0 all",
        "display ont info summary all",
        "display ont info summary 0/0 all",
        "display ont info summary 0/0",
        "display ont info summary 0/0/0",
        "display ont info summary 0 0",
        "display ont info summary 0 0 all",
        "display ont info summary 0",
        "display ont info summary",
        "display ont info by-sn",
    ]

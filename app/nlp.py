import re

from rapidfuzz import fuzz

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
TECHNIQUE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)
MITIGATION_RE = re.compile(r"\bM\d{4}\b", re.IGNORECASE)

# Below this length, a candidate name/alias (e.g. "at", "APT2") is too easy to
# collide with unrelated substrings or other entities' prefixes, so it's only
# ever matched exactly (whole word), never fuzzily.
MIN_FUZZY_LEN = 6
FUZZY_THRESHOLD = 92

# Open-ended questions ("what's concerning right now?") never name a specific
# CVE/technique/actor, so the exact-ID/fuzzy-name matchers above find nothing
# for them. This keyword gate lets chat.py fall back to a general "what's
# currently notable" lookup instead of always answering "no data" — see
# lookup_recent_kev in app/intel.py.
GENERAL_CONCERN_RE = re.compile(
    r"\b(concerning|critical|active|recent|worry|worried|dangerous|risk|"
    r"top|latest|notable|serious|urgent|worse|worst)\b",
    re.IGNORECASE,
)


def wants_general_overview(text):
    return bool(GENERAL_CONCERN_RE.search(text))


def extract_ids(text):
    return {
        "cves": sorted({m.upper() for m in CVE_RE.findall(text)}),
        "techniques": sorted({m.upper() for m in TECHNIQUE_RE.findall(text)}),
        "mitigations": sorted({m.upper() for m in MITIGATION_RE.findall(text)}),
    }


def _word_boundary_match(candidate, text_lower):
    return re.search(rf"\b{re.escape(candidate.lower())}\b", text_lower) is not None


def _best_candidate_match(text, candidates):
    """candidates: dict of display_text -> key. Returns list of (key, display_text, score)."""
    text_lower = text.lower()
    exact_keys = set()
    results = []

    for display_text, key in candidates.items():
        if _word_boundary_match(display_text, text_lower):
            if key not in exact_keys:
                exact_keys.add(key)
                results.append((key, display_text, 100.0))

    for display_text, key in candidates.items():
        if key in exact_keys or len(display_text) < MIN_FUZZY_LEN:
            continue
        score = fuzz.token_set_ratio(display_text.lower(), text_lower)
        if score >= FUZZY_THRESHOLD:
            exact_keys.add(key)
            results.append((key, display_text, score))

    return results


def match_actors(text, db):
    """Match free text against known actor names/aliases. Returns list of (stix_id, name, score)."""
    rows = db.execute("SELECT stix_id, name, aliases FROM actor").fetchall()
    candidates = {}
    for stix_id, name, aliases in rows:
        candidates[name] = (stix_id, name)
        for alias in (aliases or "").split(";"):
            alias = alias.strip()
            if alias:
                candidates.setdefault(alias, (stix_id, name))

    matched = _best_candidate_match(text, candidates)
    seen = set()
    results = []
    for (stix_id, name), _display, score in matched:
        if stix_id in seen:
            continue
        seen.add(stix_id)
        results.append((stix_id, name, score))
    return results


def match_software(text, db):
    """Match free text against known software names. Returns list of (software_id, name, type, score)."""
    rows = db.execute("SELECT DISTINCT software_id, software_name, software_type FROM actor_software").fetchall()
    candidates = {name: (software_id, name, software_type) for software_id, name, software_type in rows}

    matched = _best_candidate_match(text, candidates)
    seen = set()
    results = []
    for (software_id, name, software_type), _display, score in matched:
        if software_id in seen:
            continue
        seen.add(software_id)
        results.append((software_id, name, software_type, score))
    return results


def extract_entities(text, db):
    ids = extract_ids(text)
    return {
        "cves": ids["cves"],
        "techniques": ids["techniques"],
        "mitigations": ids["mitigations"],
        "actors": match_actors(text, db),
        "software": match_software(text, db),
    }

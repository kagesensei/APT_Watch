"""Extract CVE/technique/mitigation IDs, IOCs, and actor/software names from
free text (a chat message or a scanned file), without an LLM call.
"""

import re
from typing import TypedDict

import duckdb
from rapidfuzz import fuzz

from contracts import precondition

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
TECHNIQUE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)
MITIGATION_RE = re.compile(r"\bM\d{4}\b", re.IGNORECASE)

# Indicator shapes recognized directly in chat text (the scan page reuses
# these same patterns for uploaded files). Domains are deliberately excluded:
# without more context, a bare domain-looking token has too high a
# false-positive rate (version strings, timestamps, etc. can look like one).
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
SHA1_RE = re.compile(r"\b[a-fA-F0-9]{40}\b")
MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
URL_RE = re.compile(r"https?://\S+")

# Below this length, a candidate name/alias (e.g. "at", "APT2") is too easy to
# collide with unrelated substrings or other entities' prefixes, so it's only
# ever matched exactly (whole word), never fuzzily.
MIN_FUZZY_LEN = 6
FUZZY_THRESHOLD = 92

# Matches app/__init__.py's Flask-wide MAX_CONTENT_LENGTH: every regex below
# runs directly over caller-supplied text (a chat message or scanned file),
# so this is rule 2's "fixed upper bound" made explicit at the point that
# text enters this module, not just relied on implicitly at the HTTP layer.
MAX_TEXT_LENGTH = 5 * 1024 * 1024

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

# A question naming a specific actor ("what mitigates T1055 for APT29?") is
# still a narrow lookup unless the phrasing itself asks for a full
# assessment rather than one fact -- app/chat.py only escalates to
# app/llm.py's PIPELINE_SYSTEM_PROMPT when an actor was resolved AND this
# gate also matches, so a plain "what software does APT29 use?" stays on
# the concise prompt.
ASSESSMENT_INTENT_RE = re.compile(
    r"\b(assess|assessment|profile|campaign|brief|briefing|overview|"
    r"landscape|everything|full picture|should (?:we|i) (?:be )?worr|"
    r"how (?:should|do) we defend|what do we know)\b",
    re.IGNORECASE,
)


class Ioc(TypedDict):
    """One extracted indicator of compromise."""

    value: str
    type: str


class ExtractedIds(TypedDict):
    """Exact-match IDs pulled straight out of text by regex."""

    cves: list[str]
    techniques: list[str]
    mitigations: list[str]


ActorMatch = tuple[str, str, float]
SoftwareMatch = tuple[str, str, str, float]


class Entities(TypedDict):
    """Everything recognized in one piece of text: IDs, names, and IOCs."""

    cves: list[str]
    techniques: list[str]
    mitigations: list[str]
    actors: list[ActorMatch]
    software: list[SoftwareMatch]
    iocs: list[Ioc]
    naming_terms: list[str]


def wants_general_overview(text: str) -> bool:
    """Whether text asks a vague "what's bad right now" question."""
    return bool(GENERAL_CONCERN_RE.search(text))


def wants_pipeline_assessment(text: str) -> bool:
    """Whether text asks for a full actor/campaign assessment rather than
    one narrow fact. Only meaningful combined with an actor entity actually
    being resolved -- see app/chat.py.
    """
    return bool(ASSESSMENT_INTENT_RE.search(text))


def extract_ids(text: str) -> ExtractedIds:
    """Pull exact-match CVE/technique/mitigation IDs out of text."""
    precondition(len(text) <= MAX_TEXT_LENGTH, "text exceeds MAX_TEXT_LENGTH")
    return {
        "cves": sorted({m.upper() for m in CVE_RE.findall(text)}),
        "techniques": sorted({m.upper() for m in TECHNIQUE_RE.findall(text)}),
        "mitigations": sorted({m.upper() for m in MITIGATION_RE.findall(text)}),
    }


def extract_iocs(text: str) -> list[Ioc]:
    """Returns a de-duplicated list of {value, type} dicts, type in
    'hash'/'ip'/'url'. Order checked longest-pattern-first so a URL isn't
    also partially re-matched by a shorter pattern.
    """
    precondition(len(text) <= MAX_TEXT_LENGTH, "text exceeds MAX_TEXT_LENGTH")
    iocs: list[Ioc] = []
    seen: set[str] = set()

    def add(value: str, kind: str) -> None:
        if value not in seen:
            seen.add(value)
            iocs.append({"value": value, "type": kind})

    for value in URL_RE.findall(text):
        add(value.rstrip(".,);]\"'"), "url")
    for pattern in (SHA256_RE, SHA1_RE, MD5_RE):
        for value in pattern.findall(text):
            add(value.lower(), "hash")
    for value in IPV4_RE.findall(text):
        octets = value.split(".")
        if all(o.isdigit() and 0 <= int(o) <= 255 for o in octets):
            add(value, "ip")

    return iocs


def _word_boundary_match(candidate: str, text_lower: str) -> bool:
    return re.search(rf"\b{re.escape(candidate.lower())}\b", text_lower) is not None


def _best_candidate_match(
    text: str, candidates: dict[str, tuple[object, ...]]
) -> list[tuple[tuple[object, ...], str, float]]:
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


def match_actors(text: str, db: duckdb.DuckDBPyConnection) -> list[ActorMatch]:
    """Match free text against known actor names/aliases. Returns list of (stix_id, name, score)."""
    rows = db.execute("SELECT stix_id, name, aliases FROM actor").fetchall()
    candidates: dict[str, tuple[object, ...]] = {}
    for stix_id, name, aliases in rows:
        candidates[name] = (stix_id, name)
        for alias in (aliases or "").split(";"):
            alias = alias.strip()
            if alias:
                candidates.setdefault(alias, (stix_id, name))

    matched = _best_candidate_match(text, candidates)
    seen = set()
    results: list[ActorMatch] = []
    for key, _display, score in matched:
        stix_id, name = key
        if stix_id in seen:
            continue
        seen.add(stix_id)
        results.append((stix_id, name, score))  # type: ignore[arg-type]
    return results


def match_software(text: str, db: duckdb.DuckDBPyConnection) -> list[SoftwareMatch]:
    """Match free text against known software names.

    Returns a list of (software_id, name, type, score).
    """
    rows = db.execute(
        "SELECT DISTINCT software_id, software_name, software_type FROM actor_software"
    ).fetchall()
    candidates: dict[str, tuple[object, ...]] = {
        name: (software_id, name, software_type) for software_id, name, software_type in rows
    }

    matched = _best_candidate_match(text, candidates)
    seen = set()
    results: list[SoftwareMatch] = []
    for key, _display, score in matched:
        software_id, name, software_type = key
        if software_id in seen:
            continue
        seen.add(software_id)
        results.append((software_id, name, software_type, score))  # type: ignore[arg-type]
    return results


def match_naming_terms(text: str, db: duckdb.DuckDBPyConnection) -> list[str]:
    """Whole-word, case-insensitive match against known vendor naming-scheme
    words (e.g. 'Panda', 'Bear'), for a question that names no specific
    actor of its own -- e.g. "what does Panda mean".
    """
    terms = [row[0] for row in db.execute("SELECT DISTINCT term FROM naming_convention").fetchall()]
    text_lower = text.lower()
    return sorted({term for term in terms if _word_boundary_match(term, text_lower)})


def extract_entities(text: str, db: duckdb.DuckDBPyConnection) -> Entities:
    """Run every extractor above and combine the results."""
    ids = extract_ids(text)
    return {
        "cves": ids["cves"],
        "techniques": ids["techniques"],
        "mitigations": ids["mitigations"],
        "actors": match_actors(text, db),
        "software": match_software(text, db),
        "iocs": extract_iocs(text),
        "naming_terms": match_naming_terms(text, db),
    }

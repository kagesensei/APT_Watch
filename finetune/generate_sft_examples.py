"""Synthetic SFT data generator for an APT_Watch-compatible fine-tune.

The goal of this fine-tune is NOT to teach the model threat-intel facts --
app/llm.py's SYSTEM_PROMPT deliberately forbids the model from answering
off its own training knowledge; every claim must cite a retrieved fact, and
MITRE/CISA data changes too often for baked-in facts to stay correct
anyway. The goal is to teach the *behavior*: given a numbered,
[DIRECT]/[DERIVED]-tagged fact list and a question, produce a concise,
correctly-cited, appropriately-hedged analyst answer that never mentions an
ID absent from the facts, and that surfaces a "why this couldn't be
answered" fact when one is present rather than just saying "I don't know."

That's why every fact template, category name, and the system prompt itself
below are copied verbatim (or near-verbatim) from this repo's own
app/intel.py and app/llm.py: a fine-tune is only a safe drop-in replacement
for APTWATCH_MODEL_PATH if it was trained on the exact prompt shape the app
actually sends at inference time. See finetune/README.md for the full
pipeline this script is step one of, and for the planned model name
(apt-watch-8B-instruct-abliterated-claudetuned).

IMPORTANT: every CVE/CWE/CAPEC/technique/mitigation/actor ID and every IOC
below is either well-known public MITRE ATT&CK reference data (technique,
mitigation, and group names are all public taxonomy) or a well-known,
already-patched, publicly-discussed CVE. IOC indicators (IPs/URLs/hashes)
use IANA/RFC 5737 reserved "documentation" ranges (192.0.2.0/24,
example.com) rather than anything resembling a real operational indicator.
Nothing here is invented-but-plausible; everything is either real public
taxonomy or clearly marked as a reserved placeholder.

Two tiers of assistant target:
1. Deterministic templates, for scenarios simple enough that the "ideal"
   answer is mechanically derivable from the facts (a single confirmed IOC
   hit, or zero facts at all). These run with no external model.
2. A teacher-model synthesis hook, for scenarios that require actually
   *writing* prose that weighs multiple facts, leads with the most relevant
   one, and threads DIRECT/DERIVED hedging through natural sentences. That
   step is deliberately left as a caller-supplied TeacherFn: it should call
   a strong instruction-following model (Claude, GPT-4-class, etc.) with
   STRICT_RUBRIC below alongside SYSTEM_PROMPT. This script does not
   fabricate what that call would return -- generate_dataset() skips (and
   reports the count of) any example it has no teacher_fn to synthesize.
"""

from __future__ import annotations

import json
import pathlib
import random
import sys
from dataclasses import dataclass, field
from typing import Callable

# finetune/ is run directly (python finetune/generate_sft_examples.py), like
# ingest/*.py and resolve/aliases.py -- there's no __init__.py making it a
# real package, so the project root needs adding to sys.path for `import
# contracts` to resolve, exactly as those directories do (see CLAUDE.md).
_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from contracts import precondition  # noqa: E402  pylint: disable=wrong-import-position

# --- Copied from app/llm.py (must match exactly for the fine-tune to be a
# valid drop-in for APTWATCH_MODEL_PATH) -----------------------------------

SYSTEM_PROMPT = """You are the chat assistant for APT_Watch, a threat-intelligence tool.

Answer the user's question using ONLY the facts listed below. Each fact is tagged:
- [DIRECT] — stated outright by MITRE ATT&CK, NVD, or CISA KEV.
- [DERIVED] — an inferred relationship reached via a CWE -> CAPEC -> ATT&CK crosswalk.
  This is NOT a fact any single source states directly; it is a correlation this tool
  computed. When you use a DERIVED fact, tell the user explicitly that it's an inferred
  correlation, not a confirmed direct relationship.

Never write a CVE, CWE, CAPEC, technique (T####), mitigation (M####), or group (G####) ID
that does not appear verbatim in the facts below, even as a guess or example — an invented
ID that looks plausible is worse than saying you don't know one.

Some facts explain WHY a piece of information isn't available (e.g. "this CVE's weakness
maps to N CAPEC patterns, but none of them have an ATT&CK technique mapping"). If such a
fact is present, you MUST include that specific explanation in your answer — never just
say "I don't have that information" when a fact already explains the actual reason why.

If the facts below do not answer the question, say plainly that you don't have that
information in the data available — do not guess, and do not use any knowledge beyond
the facts listed. Address exactly what the user asked first (e.g. if they ask about
indicators of compromise, lead with any IOC facts before general background), rather
than opening with unrelated context. Keep your answer concise and actionable."""

CATEGORY_PRIORITY = [
    "naming_note", "vuln_info", "mitigation", "ioc", "actor_usage", "crosswalk_detail",
]

# --- A rubric for the teacher-model synthesis step (see synthesize_answer) -

STRICT_RUBRIC = """You are generating a TRAINING EXAMPLE, not a live chat reply. Given a
QUESTION and a numbered FACTS list (each already tagged [DIRECT] or [DERIVED]), write the
answer an ideal APT_Watch analyst assistant would give, obeying every rule in
SYSTEM_PROMPT verbatim (it will be included above this message). Additional rules
specific to generating training data:

- Use every fact that is relevant to the question; ignore facts that are not.
- If two or more facts are relevant, synthesize them into connected prose -- do not just
  restate each fact as its own bullet.
- Match the register of a working security analyst: direct, specific, no hedging beyond
  what DERIVED facts require, no filler ("Great question!", "I'd be happy to help").
- Output ONLY the answer text. No preamble, no meta-commentary about being an AI.
"""

# A teacher model call: (system_prompt, rubric, rendered_user_message) -> answer text.
TeacherFn = Callable[[str, str, str], str]

# --- Synthetic-but-real reference pools ------------------------------------
# Technique/mitigation/group names are public MITRE ATT&CK taxonomy. CVEs are
# real, well-known, already-patched vulnerabilities. IOC indicators use
# RFC 5737 reserved documentation ranges, never a real operational indicator.

TECHNIQUES = [
    ("T1055", "Process Injection"),
    ("T1059", "Command and Scripting Interpreter"),
    ("T1071", "Application Layer Protocol"),
    ("T1486", "Data Encrypted for Impact"),
    ("T1190", "Exploit Public-Facing Application"),
    ("T1082", "System Information Discovery"),
]

MITIGATIONS = [
    ("M1049", "Antivirus/Antimalware"),
    ("M1038", "Execution Prevention"),
    ("M1030", "Network Segmentation"),
    ("M1042", "Disable or Remove Feature or Program"),
]

ACTORS = [
    ("G0016", "APT29"),
    ("G0007", "APT28"),
    ("G0032", "Lazarus Group"),
    ("G0046", "FIN7"),
]

CVES = [
    ("CVE-2024-3400", "Palo Alto Networks", "PAN-OS", "PAN-OS command injection"),
    ("CVE-2021-44228", "Apache", "Log4j", "Log4Shell remote code execution"),
    ("CVE-2023-34362", "Progress Software", "MOVEit Transfer", "MOVEit SQL injection"),
]

CWES = [("CWE-78", "OS Command Injection"), ("CWE-502", "Deserialization of Untrusted Data")]
CAPECS = [("CAPEC-88", "OS Command Injection"), ("CAPEC-586", "Object Injection")]

NAMING_EXAMPLES = [
    ("CrowdStrike", "Panda", "China"),
    ("CrowdStrike", "Bear", "Russia"),
]

RESERVED_URLS = ["http://example.com/payload.bin", "http://example.net/c2/checkin"]
# Obviously-synthetic hash: 'a' x56 + an index, never a real sample digest.
SYNTHETIC_HASH = "a" * 56 + "0001"


# --- Fact construction, mirroring app/intel.py's Fact TypedDict and text ---
# templates as closely as possible ------------------------------------------


@dataclass
class Fact:
    """One synthetic grounding fact, shaped like app/intel.py's real Fact."""

    text: str
    derived: bool
    category: str
    source_id: str


def fact_nvd(cve_id: str, vendor: str, product: str, desc: str) -> Fact:
    """A direct NVD description fact, matching intel.py's _nvd_fact() shape."""
    return Fact(
        text=f"{cve_id}: {desc} in {vendor} {product}. (CVSS 9.8, CRITICAL)",
        derived=False,
        category="vuln_info",
        source_id=cve_id,
    )


def fact_kev(cve_id: str, name: str, vendor: str, product: str) -> Fact:
    """A direct CISA KEV fact, matching intel.py's _kev_fact_for_cve() shape."""
    return Fact(
        text=(
            f"{cve_id} ({name}; affects {vendor} {product}) was added to CISA's Known "
            f"Exploited Vulnerabilities catalog, meaning it is confirmed to be actively "
            f"exploited in the wild. Known ransomware use: Unknown."
        ),
        derived=False,
        category="vuln_info",
        source_id=cve_id,
    )


def fact_crosswalk_dead_end(cve_id: str, cwe_id: str) -> Fact:
    """A direct "why the crosswalk found nothing" fact, matching intel.py's
    _crosswalk_dead_end_fact() shape.
    """
    return Fact(
        text=(
            f"{cve_id} involves weakness(es) {cwe_id}, which do not map to any MITRE "
            f"CAPEC attack pattern in the available data. No specific TTP can be "
            f"identified for this CVE from the available crosswalk data."
        ),
        derived=False,
        category="vuln_info",
        source_id=cve_id,
    )


def fact_crosswalk_technique(
    cve_id: str, cwe_id: str, capec_id: str, capec_name: str,
    technique_id: str, technique_name: str,
) -> Fact:
    """A derived CVE->CWE->CAPEC->technique fact, matching intel.py's
    _crosswalk_technique_facts() shape.
    """
    return Fact(
        text=(
            f"{cve_id} involves weakness {cwe_id}, which MITRE CAPEC pattern {capec_id} "
            f"({capec_name}) maps to ATT&CK technique {technique_id} ({technique_name}). "
            f"This is an inferred relationship via the CWE/CAPEC crosswalk, not a direct "
            f"MITRE ATT&CK-to-CVE mapping (MITRE does not publish one)."
        ),
        derived=True,
        category="crosswalk_detail",
        source_id=capec_id,
    )


def fact_mitigation_direct(
    mitigation_id: str, mitigation_name: str, technique_id: str, technique_name: str,
) -> Fact:
    """A direct mitigation-addresses-technique fact, matching intel.py's
    lookup_technique() shape.
    """
    return Fact(
        text=(
            f"Mitigation {mitigation_id} ({mitigation_name}) addresses technique "
            f"{technique_id} ({technique_name})."
        ),
        derived=False,
        category="mitigation",
        source_id=mitigation_id,
    )


def fact_actor_usage_direct(actor_name: str, technique_id: str, technique_name: str) -> Fact:
    """A direct actor-uses-technique fact, matching intel.py's lookup_technique() shape."""
    return Fact(
        text=(
            f"{actor_name} is documented by MITRE ATT&CK as using technique {technique_id} "
            f"({technique_name})."
        ),
        derived=False,
        category="actor_usage",
        source_id=technique_id,
    )


def fact_ioc_confirmed_hash(indicator: str, family: str) -> Fact:
    """A direct confirmed-IOC fact, matching intel.py's _ioc_hash_fact() shape."""
    return Fact(
        text=(
            f"Indicator of Compromise (IOC) confirmed: {indicator} matches a known "
            f"malware sample in MalwareBazaar: family '{family}'."
        ),
        derived=False,
        category="ioc",
        source_id=indicator,
    )


def fact_ioc_correlated_url(url: str, cve_id: str, term: str) -> Fact:
    """A derived name-correlated IOC fact, matching intel.py's
    _ioc_url_facts_for_term() shape.
    """
    return Fact(
        text=(
            f"Indicator of Compromise (IOC) - malicious URL: URLhaus has a URL "
            f"({url}) tagged with '{term}', the product {cve_id} affects per CISA KEV. "
            f"This is a name-based correlation, not confirmed evidence this URL relates "
            f"to {cve_id}."
        ),
        derived=True,
        category="ioc",
        source_id=url,
    )


def fact_naming(vendor: str, term: str, meaning: str, alias: str) -> Fact:
    """A direct vendor-naming-convention fact, matching intel.py's _naming_fact() shape."""
    return Fact(
        text=(
            f"The alias '{alias}' follows {vendor}'s adversary-naming convention: the "
            f"word '{term}' denotes suspected {meaning}-nexus (state-sponsored) "
            f"activity. The other word in the name is {vendor}'s unique label for this "
            f"specific actor within that category, not an additional signal."
        ),
        derived=False,
        category="naming_note",
        source_id=term,
    )


# --- Scenario generators: each returns (question, facts, scenario_tag) ----

Scenario = tuple[str, list[Fact], str]


def scenario_direct_cve_lookup(rng: random.Random) -> Scenario:
    """A single CVE with only direct NVD/KEV facts -- no crosswalk involved."""
    cve_id, vendor, product, desc = rng.choice(CVES)
    facts = [fact_nvd(cve_id, vendor, product, desc), fact_kev(cve_id, desc, vendor, product)]
    return f"Is {cve_id} being actively exploited?", facts, "direct_cve_lookup"


def scenario_full_crosswalk(rng: random.Random) -> Scenario:
    """A CVE with the full CVE->CWE->CAPEC->technique->mitigation/actor chain."""
    cve_id, vendor, product, desc = rng.choice(CVES)
    cwe_id, _cwe_name = rng.choice(CWES)
    capec_id, capec_name = rng.choice(CAPECS)
    technique_id, technique_name = rng.choice(TECHNIQUES)
    mitigation_id, mitigation_name = rng.choice(MITIGATIONS)
    _actor_id, actor_name = rng.choice(ACTORS)
    facts = [
        fact_nvd(cve_id, vendor, product, desc),
        fact_kev(cve_id, desc, vendor, product),
        fact_crosswalk_technique(
            cve_id, cwe_id, capec_id, capec_name, technique_id, technique_name
        ),
        fact_mitigation_direct(mitigation_id, mitigation_name, technique_id, technique_name),
        fact_actor_usage_direct(actor_name, technique_id, technique_name),
    ]
    return f"What TTPs exploit {cve_id} and how do I mitigate it?", facts, "full_crosswalk"


def scenario_crosswalk_dead_end(rng: random.Random) -> Scenario:
    """A CVE whose CWE has no CAPEC mapping -- the "why unavailable" case."""
    cve_id, vendor, product, desc = rng.choice(CVES)
    cwe_id, _cwe_name = rng.choice(CWES)
    facts = [fact_nvd(cve_id, vendor, product, desc), fact_crosswalk_dead_end(cve_id, cwe_id)]
    return f"What ATT&CK technique does {cve_id} map to?", facts, "crosswalk_dead_end"


def scenario_technique_lookup(rng: random.Random) -> Scenario:
    """A technique with its direct mitigation and actor-usage facts."""
    technique_id, technique_name = rng.choice(TECHNIQUES)
    mitigation_id, mitigation_name = rng.choice(MITIGATIONS)
    _actor_id, actor_name = rng.choice(ACTORS)
    facts = [
        fact_mitigation_direct(mitigation_id, mitigation_name, technique_id, technique_name),
        fact_actor_usage_direct(actor_name, technique_id, technique_name),
    ]
    return f"What mitigates {technique_id}?", facts, "technique_lookup"


def scenario_ioc_confirmed(_rng: random.Random) -> Scenario:
    """A single directly-confirmed IOC hash match."""
    indicator = SYNTHETIC_HASH
    facts = [fact_ioc_confirmed_hash(indicator, "ExampleRAT")]
    return f"Have you seen {indicator} before?", facts, "ioc_confirmed"


def scenario_ioc_correlated(rng: random.Random) -> Scenario:
    """A KEV entry plus a derived, name-correlated IOC (not a confirmed match)."""
    cve_id, vendor, product, desc = rng.choice(CVES)
    url = rng.choice(RESERVED_URLS)
    facts = [fact_kev(cve_id, desc, vendor, product), fact_ioc_correlated_url(url, cve_id, product)]
    return f"Are there any known indicators of compromise for {cve_id}?", facts, "ioc_correlated"


def scenario_zero_facts(_rng: random.Random) -> Scenario:
    """A question with no matching facts at all -- must say so, not guess."""
    return "What TTPs does the group APTFAKE99 use?", [], "zero_facts"


def scenario_naming_lookup(rng: random.Random) -> Scenario:
    """A single vendor-naming-convention etymology fact."""
    vendor, term, meaning = rng.choice(NAMING_EXAMPLES)
    _actor_id, actor_name = rng.choice(ACTORS)
    alias = f"{actor_name} {term}"
    facts = [fact_naming(vendor, term, meaning, alias)]
    return f"What does the '{term}' in '{alias}' mean?", facts, "naming_lookup"


SCENARIOS = [
    scenario_direct_cve_lookup,
    scenario_full_crosswalk,
    scenario_crosswalk_dead_end,
    scenario_technique_lookup,
    scenario_ioc_confirmed,
    scenario_ioc_correlated,
    scenario_zero_facts,
    scenario_naming_lookup,
]


# --- Prompt rendering, mirroring app/llm.py's build_context() + answer() --


def render_facts_block(facts: list[Fact]) -> str:
    """Render facts as the numbered, category-ordered list app/llm.py's
    build_context() sends the model.
    """
    if not facts:
        return "(No matching facts were found in the database for this question.)"
    tiers: dict[str, list[Fact]] = {name: [] for name in CATEGORY_PRIORITY}
    for one_fact in facts:
        tiers[one_fact.category].append(one_fact)
    ordered = [f for name in CATEGORY_PRIORITY for f in tiers[name]]
    lines = [f"{'[DIRECT]' if not f.derived else '[DERIVED]'} {f.text}" for f in ordered]
    return "\n".join(f"{i + 1}. {line}" for i, line in enumerate(lines))


def render_user_message(question: str, facts: list[Fact]) -> str:
    """Render the exact user-message content app/llm.py's answer() sends."""
    return f"FACTS:\n{render_facts_block(facts)}\n\nQUESTION: {question}"


# --- Assistant target synthesis --------------------------------------------


def deterministic_answer(facts: list[Fact], scenario_tag: str) -> str | None:
    """Return a mechanically-derivable ideal answer, or None if this
    scenario needs the teacher-model synthesis step instead.
    """
    if scenario_tag == "zero_facts":
        return "I don't have that information in the data available for this question."
    if scenario_tag == "ioc_confirmed" and len(facts) == 1:
        prefix = "Indicator of Compromise (IOC) confirmed: "
        return f"Yes — {facts[0].text[len(prefix):]}"
    return None


def synthesize_answer(
    question: str, facts: list[Fact], scenario_tag: str, teacher_fn: TeacherFn | None,
) -> str:
    """The assistant-turn target for one training example.

    Tries the deterministic path first; for anything requiring actual
    multi-fact prose synthesis, calls teacher_fn(SYSTEM_PROMPT,
    STRICT_RUBRIC, rendered_user_message) and returns its reply verbatim.
    Raises NotImplementedError if no teacher_fn was supplied -- this
    function never fabricates a synthesis-tier answer on its own.
    """
    deterministic = deterministic_answer(facts, scenario_tag)
    if deterministic is not None:
        return deterministic

    if teacher_fn is None:
        raise NotImplementedError(
            f"scenario {scenario_tag!r} needs teacher-model synthesis -- pass a teacher_fn "
            f"that calls a strong instruction-following model with system=SYSTEM_PROMPT + "
            f"STRICT_RUBRIC and user={render_user_message(question, facts)!r}."
        )
    return teacher_fn(SYSTEM_PROMPT, STRICT_RUBRIC, render_user_message(question, facts))


# --- Example assembly and JSONL output --------------------------------------


@dataclass
class Example:
    """One finished training example: the chat messages plus bookkeeping metadata."""

    messages: list[dict[str, str]]
    meta: dict[str, object] = field(default_factory=dict)


def build_example(rng: random.Random, teacher_fn: TeacherFn | None) -> Example:
    """Pick a random scenario and assemble it into one training Example."""
    scenario_fn = rng.choice(SCENARIOS)
    question, facts, tag = scenario_fn(rng)
    user_content = render_user_message(question, facts)
    answer = synthesize_answer(question, facts, tag, teacher_fn)

    return Example(
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_content},
            {"role": "assistant", "content": answer},
        ],
        meta={
            "scenario": tag,
            "num_facts": len(facts),
            "categories": sorted({f.category for f in facts}),
        },
    )


def generate_dataset(
    n: int, seed: int, out_path: pathlib.Path, teacher_fn: TeacherFn | None = None,
) -> dict[str, int]:
    """Write up to n JSONL training examples to out_path; return scenario counts.

    Every scenario deterministic_answer() can't resolve on its own is
    skipped (and tallied under "_skipped_needs_teacher_model") unless
    teacher_fn is supplied -- this never writes a fabricated answer.
    """
    precondition(n > 0, "n must be positive")
    # Reproducible example variety, not a security- or secrecy-sensitive
    # value -- a cryptographic PRNG would add nothing here.
    rng = random.Random(seed)  # nosec B311
    counts: dict[str, int] = {}
    skipped_needs_teacher = 0
    written = 0

    with out_path.open("w", encoding="utf-8") as out_file:
        for _attempt in range(n * 4):
            if written >= n:
                break
            try:
                example = build_example(rng, teacher_fn)
            except NotImplementedError:
                skipped_needs_teacher += 1
                continue
            out_file.write(json.dumps({"messages": example.messages, "meta": example.meta}) + "\n")
            counts[str(example.meta["scenario"])] = counts.get(str(example.meta["scenario"]), 0) + 1
            written += 1

    counts["_skipped_needs_teacher_model"] = skipped_needs_teacher
    return counts


if __name__ == "__main__":
    OUTPUT_PATH = pathlib.Path(__file__).parent / "sft_examples.jsonl"
    SCENARIO_COUNTS = generate_dataset(n=40, seed=42, out_path=OUTPUT_PATH)

    print(f"Wrote examples to {OUTPUT_PATH}")
    print("Scenario counts (no-teacher-model run, deterministic scenarios only):")
    for scenario_name, count in sorted(SCENARIO_COUNTS.items()):
        print(f"  {scenario_name}: {count}")

    print("\nSample rendered example:")
    SAMPLE_RNG = random.Random(7)  # nosec B311 -- demo output variety, not security-sensitive
    SAMPLE_QUESTION, SAMPLE_FACTS, SAMPLE_TAG = scenario_technique_lookup(SAMPLE_RNG)
    print(f"scenario: {SAMPLE_TAG}")
    print("--- user message ---")
    print(render_user_message(SAMPLE_QUESTION, SAMPLE_FACTS))

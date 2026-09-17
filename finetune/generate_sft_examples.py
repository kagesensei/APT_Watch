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
   whichever (system_prompt, rubric) pair prompt_and_rubric_for() selects
   for that scenario. This script does not fabricate what that call would
   return -- generate_dataset() skips (and reports the count of) any
   example it has no teacher_fn to synthesize.

Two prompt shapes, mirroring app/chat.py's own trigger logic exactly (see
app/nlp.py's wants_pipeline_assessment() and app/llm.py's
PIPELINE_SYSTEM_PROMPT): most scenarios use the concise SYSTEM_PROMPT, but
scenario_full_pipeline_assessment uses PIPELINE_SYSTEM_PROMPT's structured
Likely-Actor/Observed-Behavior/ATT&CK-Techniques/Supporting-Evidence/
Confidence/IOCs/Detections/Mitigations/Gaps format -- training data for an
open-ended "assess this actor" question should look like what the live app
actually sends for that same kind of question, not the narrow-lookup shape.

Several scenarios (scenario_conflicting_attribution,
scenario_naming_collision_rejected, scenario_conflicting_iocs) present
multiple, sometimes-disagreeing fact sets rather than one clean category --
two vendor reports attributing overlapping activity to different actor
names, or two feeds tagging distinct-but-similar indicators to the same
malware family -- and are grounded in this repo's own real cross-vendor
naming-collision data (data/reports/alias_resolution.md), not invented.
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
# valid drop-in for APTWATCH_MODEL_PATH). Deliberately duplicated rather
# than imported: importing app.llm would pull in llama_cpp_python (its
# module-level `from llama_cpp import Llama`) just to read a string
# constant, coupling this standalone, stdlib-only script to the app's
# heaviest runtime dependency. -------------------------------------------
# pylint: disable=duplicate-code

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

# --- Copied from app/llm.py, same as SYSTEM_PROMPT above -- see that
# constant's comment for why this is duplicated rather than imported.
# pylint: disable=duplicate-code

PIPELINE_SYSTEM_PROMPT = """You are the chat assistant for APT_Watch, a threat-intelligence tool.

The user is asking for a full analyst-style assessment of a threat actor or campaign, not a
single narrow fact. Answer using ONLY the facts listed below — the same sourcing rules as
always apply:
- [DIRECT] — stated outright by MITRE ATT&CK, NVD, or CISA KEV.
- [DERIVED] — an inferred relationship (a CWE -> CAPEC -> ATT&CK crosswalk, or a name-based
  correlation between different vendors' reporting on the same activity). Flag every DERIVED
  fact you use as an inferred correlation, never as a confirmed direct relationship.

Never write a CVE, CWE, CAPEC, technique (T####), mitigation (M####), or group (G####) ID
that does not appear verbatim in the facts below, even as a guess or example.

Structure your answer under these headings, in this order, using only headings that have
something to say (omit a heading entirely rather than writing "N/A" or "none found" under
it — UNLESS the facts explain a specific reason nothing was found, which belongs under
Unanswered Questions / Gaps, not silently dropped):

Likely Actor(s) — who the facts point to, by name/ID. If different vendors' naming attributes
the activity to different actor names, say so explicitly rather than picking one arbitrarily —
an unresolved naming collision is itself the honest answer, not a gap to paper over.

Observed Behavior — what the actor(s) have been documented doing, in plain language.

ATT&CK Techniques — the specific technique IDs involved, each tied to the behavior above.

Supporting Evidence — which facts back each claim, distinguishing DIRECT statements from
DERIVED correlations.

Confidence — State your confidence (High / Medium / Low) for the actor attribution and for
any DERIVED claims specifically, not the answer as a whole. Agreement across multiple DIRECT
facts is High; a single DERIVED correlation, a rejected or ambiguous name match, or facts that
conflict with each other is Low.

IOCs — any indicators available, marked confirmed vs. name-correlated per the facts.

Detections — any detection or coverage facts available.

Mitigations — MITRE ATT&CK mitigations that address the techniques identified above.

Unanswered Questions / Gaps — what the facts do NOT establish. Always include this section: a
genuine gap (an unresolved naming collision, a crosswalk dead end, a technique with no
mitigation on file) is a normal, useful answer, not a failure to hide.

If the facts below do not answer the question at all, say so plainly under Likely Actor(s) and
skip the remaining headings — do not guess, and do not use any knowledge beyond the facts
listed."""

PIPELINE_RUBRIC = """You are generating a TRAINING EXAMPLE, not a live chat reply. Given a
QUESTION and a numbered FACTS list (each already tagged [DIRECT] or [DERIVED]), write the
full structured assessment PIPELINE_SYSTEM_PROMPT asks for (it will be included above this
message), using every heading that has something to say. Additional rules specific to
generating training data:

- When facts attribute overlapping activity to different actor names (a documented naming
  collision), name that ambiguity explicitly under Likely Actor(s) -- do not silently pick
  one name as if it were settled.
- Under Confidence, justify the level you give: agreement across multiple DIRECT facts is
  High; a lone DERIVED correlation, a rejected/ambiguous name match, or conflicting facts is
  Low. Do not default to "Medium" as a hedge.
- Under Unanswered Questions / Gaps, name at least one concrete thing the facts do not
  establish -- a real gap is a normal, expected part of a good assessment, not a failure to
  avoid mentioning.
- Output ONLY the answer text, headings included. No preamble, no meta-commentary about
  being an AI.
"""

# Scenario tags that use PIPELINE_SYSTEM_PROMPT/PIPELINE_RUBRIC instead of
# SYSTEM_PROMPT/STRICT_RUBRIC -- matching app/chat.py's own trigger (an
# open-ended actor/campaign assessment question), not every conflicting-
# evidence scenario. A narrow question can still have conflicting facts to
# weigh (see scenario_conflicting_attribution etc. below); it should still
# get a concise, honestly-hedged answer, not the full nine-heading format.
PIPELINE_SCENARIO_TAGS = {"full_pipeline_assessment"}

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

# Real, well-known malware/tool names (not MITRE Software IDs -- unlike the
# technique/mitigation/CVE IDs above, this project didn't verify an exact
# catalog number for each and would rather cite the name alone than guess
# one, matching this repo's own "leave it out rather than guess" rule).
MALWARE_FAMILIES = ["Cobalt Strike", "PlugX", "Mimikatz", "QakBot"]

# MITRE ATLAS: an ATT&CK-style framework for attacks on AI/ML systems.
# Verified via web search (atlas.mitre.org and attack.mitre.org are blocked
# by this session's network egress proxy, so these were not fetched
# directly) against multiple independent citations rather than assumed
# from memory. See finetune/README.md for sources.
ATLAS_TECHNIQUES = [
    ("AML.T0010", "AI Supply Chain Compromise"),
    ("AML.T0025", "Data exfiltration via AI model"),
]

# Aerospace Corporation SPARTA: a space-systems-focused attack framework,
# relevant for customers operating satellite/space-segment infrastructure
# (cellular/cable backhaul over satellite, etc.). Verified via web search
# against sparta.aerospace.org's own technique pages (again not fetched
# directly -- same egress block as ATLAS above).
SPARTA_TECHNIQUES = [
    ("EX-0014", "Spoofing"),
    ("EX-0016", "Jamming"),
    ("EX-0009", "Exploit Code Flaws"),
    ("EX-0010", "Malicious Code"),
]

# Real MITRE ATT&CK Campaign objects (verified via web search, official
# attack.mitre.org/campaigns/ URLs cited).
CAMPAIGNS = [
    ("C0001", "Frankenstein"),
    ("C0002", "Night Dragon"),
]

# Real cross-vendor naming-collision data, drawn directly from this repo's
# own data/reports/alias_resolution.md (resolve/aliases.py's output), not
# fabricated. app/intel.py does not query actor_xwalk/
# actor_xwalk_candidates/actor_xwalk_rejected yet (see that report's own
# text: "Nothing in the app queries either table yet") -- so the fact
# builders below model what retrieving that data would look like, not live
# app output today. See finetune/README.md.
LAZARUS_MISP_NAME = "Lazarus Group"
LAZARUS_ATTACK_GROUPS = [
    ("G0082", "APT38"),
    ("G1049", "AppleJeus"),
    ("G0138", "Andariel"),
    ("G0032", "Lazarus Group"),
    ("G1036", "Moonstone Sleet"),
]

REJECTED_ATTACK_ID = "G0114"
REJECTED_ATTACK_NAME = "Chimera"
REJECTED_MISP_NAME = "WET PANDA"
REJECTED_REASON = (
    "the RapidFuzz 100 score was a token_set_ratio scoring artifact "
    '("Chimera" is a lexical subset of "Red Chimera"); MITRE\'s G0114 page ties '
    "Chimera specifically to Taiwan semiconductor/airline-industry espionage, while "
    "MISP's WET PANDA entry has no description and its one reference is a generic, "
    "non-group-specific report -- no evidence connects the two"
)


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


def fact_conflicting_attribution(
    misp_name: str, attack_id: str, attack_name: str, other_groups: str,
) -> Fact:
    """A direct fact describing an unresolved, one-to-many cross-vendor
    naming collision -- modeled on data/reports/alias_resolution.md's
    "Ambiguous matches" section (real data; see LAZARUS_ATTACK_GROUPS).
    """
    return Fact(
        text=(
            f"MISP Galaxy's '{misp_name}' cluster maps to more than one MITRE ATT&CK "
            f"group, including {attack_id} ({attack_name}) and also {other_groups}. "
            f"This is a documented one-to-many naming collision, not resolved to a "
            f"single canonical mapping -- activity reported under the vendor name "
            f"'{misp_name}' may belong to any of these distinct, more specific "
            f"ATT&CK-tracked groups."
        ),
        derived=False,
        category="naming_note",
        source_id=attack_id,
    )


def fact_attribution_rejected(
    attack_id: str, attack_name: str, other_name: str, reason: str,
) -> Fact:
    """A direct fact recording a reviewed-and-rejected name match --
    modeled on alias_resolution.md's "Manually reviewed" REJECTED entries
    (real data; see REJECTED_ATTACK_ID etc.).
    """
    return Fact(
        text=(
            f"{attack_id} ({attack_name}) and '{other_name}' were reviewed as a "
            f"possible name match and REJECTED as the same actor: {reason}."
        ),
        derived=False,
        category="naming_note",
        source_id=attack_id,
    )


def fact_ioc_partial_overlap(
    feed_a: str, indicator_a: str, feed_b: str, indicator_b: str, family: str,
) -> Fact:
    """A derived fact noting two feeds tag similarly-named but distinct
    indicators to the same malware family -- an imperfect correlation, not
    a confirmed shared campaign or infrastructure.
    """
    return Fact(
        text=(
            f"{feed_a} tags {indicator_a} and {feed_b} tags {indicator_b}, both under "
            f"the '{family}' family name -- but they are distinct indicators from "
            f"different feeds. This is overlapping tagging, not confirmed shared "
            f"infrastructure or a confirmed single campaign."
        ),
        derived=True,
        category="ioc",
        source_id=indicator_a,
    )


def fact_atlas_technique(actor_name: str, atlas_id: str, atlas_name: str) -> Fact:
    """A direct fact linking an actor to a MITRE ATLAS (AI/ML-attack)
    technique. Illustrative: app/intel.py has no live ATLAS ingest yet.
    """
    return Fact(
        text=(
            f"{actor_name} has also been linked to {atlas_id} ({atlas_name}) under "
            f"MITRE ATLAS, indicating activity targeting AI/ML systems alongside its "
            f"ATT&CK-documented techniques."
        ),
        derived=False,
        category="actor_usage",
        source_id=atlas_id,
    )


def fact_sparta_technique(actor_name: str, sparta_id: str, sparta_name: str) -> Fact:
    """A direct fact linking an actor to an Aerospace SPARTA (space-systems
    attack) technique. Illustrative: app/intel.py has no live SPARTA
    ingest yet. Relevant to customers operating satellite/space assets.
    """
    return Fact(
        text=(
            f"{actor_name} activity has also been mapped to {sparta_id} ({sparta_name}) "
            f"under the Aerospace Corporation's SPARTA framework, relevant to "
            f"space-system/satellite-segment targeting."
        ),
        derived=False,
        category="actor_usage",
        source_id=sparta_id,
    )


def fact_campaign(actor_name: str, campaign_id: str, campaign_name: str) -> Fact:
    """A direct fact linking an actor to a named, real MITRE ATT&CK Campaign object."""
    return Fact(
        text=(
            f"{actor_name} is documented by MITRE ATT&CK as having conducted "
            f"Campaign {campaign_id} ({campaign_name})."
        ),
        derived=False,
        category="actor_usage",
        source_id=campaign_id,
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


def scenario_conflicting_attribution(rng: random.Random) -> Scenario:
    """Models this repo's own documented Lazarus Group collision: one MISP
    cluster name maps to five distinct ATT&CK groups (real data -- see
    LAZARUS_ATTACK_GROUPS). The honest answer names the ambiguity rather
    than picking one group arbitrarily.
    """
    technique_id, technique_name = rng.choice(TECHNIQUES)
    attack_id, attack_name = rng.choice(LAZARUS_ATTACK_GROUPS)
    other_groups = ", ".join(
        f"{gid} {name}" for gid, name in LAZARUS_ATTACK_GROUPS if gid != attack_id
    )
    facts = [
        fact_actor_usage_direct(attack_name, technique_id, technique_name),
        fact_conflicting_attribution(LAZARUS_MISP_NAME, attack_id, attack_name, other_groups),
    ]
    question = f"Is {LAZARUS_MISP_NAME} responsible for the activity using {technique_id}?"
    return question, facts, "conflicting_attribution"


def scenario_naming_collision_rejected(_rng: random.Random) -> Scenario:
    """Models this repo's own reviewed-and-rejected Chimera/WET PANDA name
    match (real data -- see REJECTED_ATTACK_ID etc.). A confident, correct
    rejection of a false-looking correlation is as valuable a synthesis
    outcome as confirming a true one.
    """
    facts = [
        fact_attribution_rejected(
            REJECTED_ATTACK_ID, REJECTED_ATTACK_NAME, REJECTED_MISP_NAME, REJECTED_REASON
        ),
    ]
    question = f"Are {REJECTED_ATTACK_NAME} and {REJECTED_MISP_NAME} the same threat actor?"
    return question, facts, "naming_collision_rejected"


def scenario_conflicting_iocs(rng: random.Random) -> Scenario:
    """Two feeds tag similarly-named but distinct indicators to the same
    malware family -- imperfect correlation, not confirmed shared
    infrastructure or a single campaign.
    """
    family = rng.choice(MALWARE_FAMILIES)
    url = rng.choice(RESERVED_URLS)
    facts = [
        fact_ioc_confirmed_hash(SYNTHETIC_HASH, family),
        fact_ioc_partial_overlap("MalwareBazaar", SYNTHETIC_HASH, "URLhaus", url, family),
    ]
    question = f"Are the {family} samples we're seeing all part of the same campaign?"
    return question, facts, "conflicting_iocs"


def _pipeline_core_facts(rng: random.Random) -> tuple[list[Fact], str]:
    """The conflicting-attribution, actor-usage, and mitigation facts for
    scenario_full_pipeline_assessment; also returns the chosen actor name
    so _pipeline_framework_facts() can build facts about the same actor.
    """
    attack_id, attack_name = rng.choice(LAZARUS_ATTACK_GROUPS)
    other_groups = ", ".join(
        f"{gid} {name}" for gid, name in LAZARUS_ATTACK_GROUPS if gid != attack_id
    )
    technique_id, technique_name = rng.choice(TECHNIQUES)
    mitigation_id, mitigation_name = rng.choice(MITIGATIONS)
    facts = [
        fact_actor_usage_direct(attack_name, technique_id, technique_name),
        fact_conflicting_attribution(LAZARUS_MISP_NAME, attack_id, attack_name, other_groups),
        fact_mitigation_direct(mitigation_id, mitigation_name, technique_id, technique_name),
    ]
    return facts, attack_name


def _pipeline_framework_facts(rng: random.Random, attack_name: str) -> list[Fact]:
    """The ATLAS/SPARTA/campaign/IOC/naming facts rounding out
    scenario_full_pipeline_assessment's evidence for `attack_name`.
    """
    atlas_id, atlas_name = rng.choice(ATLAS_TECHNIQUES)
    sparta_id, sparta_name = rng.choice(SPARTA_TECHNIQUES)
    campaign_id, campaign_name = rng.choice(CAMPAIGNS)
    url = rng.choice(RESERVED_URLS)
    cve_id, _vendor, product, _desc = rng.choice(CVES)
    naming_vendor, naming_term, naming_meaning = rng.choice(NAMING_EXAMPLES)
    return [
        fact_atlas_technique(attack_name, atlas_id, atlas_name),
        fact_sparta_technique(attack_name, sparta_id, sparta_name),
        fact_campaign(attack_name, campaign_id, campaign_name),
        fact_ioc_correlated_url(url, cve_id, product),
        fact_naming(naming_vendor, naming_term, naming_meaning, f"{attack_name} {naming_term}"),
    ]


def scenario_full_pipeline_assessment(rng: random.Random) -> Scenario:
    """The "assess this actor/campaign" scenario meant to exercise
    PIPELINE_SYSTEM_PROMPT's full structure: conflicting attribution,
    ordinary ATT&CK technique/mitigation facts, an ATLAS fact, a SPARTA
    fact (space-systems relevance), a campaign fact, a derived IOC
    correlation, and a naming-convention note -- deliberately more facts,
    of more different kinds, than any single-answer scenario above.
    """
    core_facts, attack_name = _pipeline_core_facts(rng)
    facts = core_facts + _pipeline_framework_facts(rng, attack_name)
    question = (
        f"Give me a full assessment of {LAZARUS_MISP_NAME} and how we should defend against it."
    )
    return question, facts, "full_pipeline_assessment"


SCENARIOS = [
    scenario_direct_cve_lookup,
    scenario_full_crosswalk,
    scenario_crosswalk_dead_end,
    scenario_technique_lookup,
    scenario_ioc_confirmed,
    scenario_ioc_correlated,
    scenario_zero_facts,
    scenario_naming_lookup,
    scenario_conflicting_attribution,
    scenario_naming_collision_rejected,
    scenario_conflicting_iocs,
    scenario_full_pipeline_assessment,
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


def prompt_and_rubric_for(scenario_tag: str) -> tuple[str, str]:
    """Which (system_prompt, rubric) pair a scenario's teacher call needs --
    the structured pair for an open-ended assessment scenario (see
    PIPELINE_SCENARIO_TAGS), the concise pair for everything else.
    """
    if scenario_tag in PIPELINE_SCENARIO_TAGS:
        return PIPELINE_SYSTEM_PROMPT, PIPELINE_RUBRIC
    return SYSTEM_PROMPT, STRICT_RUBRIC


def synthesize_answer(
    question: str, facts: list[Fact], scenario_tag: str, teacher_fn: TeacherFn | None,
) -> str:
    """The assistant-turn target for one training example.

    Tries the deterministic path first; for anything requiring actual
    multi-fact prose synthesis, calls teacher_fn with whichever
    (system_prompt, rubric) pair prompt_and_rubric_for() selects and
    returns its reply verbatim. Raises NotImplementedError if no
    teacher_fn was supplied -- this function never fabricates a
    synthesis-tier answer on its own.
    """
    deterministic = deterministic_answer(facts, scenario_tag)
    if deterministic is not None:
        return deterministic

    system_prompt, rubric = prompt_and_rubric_for(scenario_tag)
    if teacher_fn is None:
        raise NotImplementedError(
            f"scenario {scenario_tag!r} needs teacher-model synthesis -- pass a teacher_fn "
            f"that calls a strong instruction-following model with system={system_prompt!r} "
            f"+ rubric={rubric!r} and user={render_user_message(question, facts)!r}."
        )
    return teacher_fn(system_prompt, rubric, render_user_message(question, facts))


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
    system_prompt, _rubric = prompt_and_rubric_for(tag)

    return Example(
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_content},
            {"role": "assistant", "content": answer},
        ],
        meta={
            "scenario": tag,
            "num_facts": len(facts),
            "categories": sorted({f.category for f in facts}),
            "pipeline": tag in PIPELINE_SCENARIO_TAGS,
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

    print("\nSample rendered example (narrow lookup):")
    SAMPLE_RNG = random.Random(7)  # nosec B311 -- demo output variety, not security-sensitive
    SAMPLE_QUESTION, SAMPLE_FACTS, SAMPLE_TAG = scenario_technique_lookup(SAMPLE_RNG)
    print(f"scenario: {SAMPLE_TAG}")
    print("--- user message ---")
    print(render_user_message(SAMPLE_QUESTION, SAMPLE_FACTS))

    print("\nSample rendered example (full pipeline assessment -- needs a teacher model):")
    PIPELINE_RNG = random.Random(3)  # nosec B311 -- demo output variety, not security-sensitive
    PIPELINE_QUESTION, PIPELINE_FACTS, PIPELINE_TAG = scenario_full_pipeline_assessment(
        PIPELINE_RNG
    )
    print(f"scenario: {PIPELINE_TAG}")
    print("--- user message ---")
    print(render_user_message(PIPELINE_QUESTION, PIPELINE_FACTS))

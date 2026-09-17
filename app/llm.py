"""Local LLM wrapper: build a fact-grounded prompt and guard against the
model inventing IDs that were never in the retrieved facts.
"""

import ctypes
import functools
import importlib.util
import os
import pathlib
import re
import sys

from contracts import ContractViolation, not_none, precondition

ROOT = pathlib.Path(__file__).resolve().parents[1]
DEFAULT_MODEL_PATH = ROOT / "models" / "meta-llama-3.1-8b-instruct-abliterated.Q4_K_M.gguf"

MAX_FACTS = 20


def _preload_windows_cuda_deps() -> None:
    """Work around a ctypes quirk on Windows/Python 3.10: llama_cpp loads its
    DLLs with ctypes.CDLL(absolute_path, winmode=RTLD_GLOBAL), which fails to
    resolve dependent DLLs (the CUDA runtime) via os.add_dll_directory even
    though that's supposed to work. Pre-loading the same DLLs here (without
    winmode) first makes them already-resident, so llama_cpp's own load call
    just finds them instead of re-resolving dependencies.
    """
    if sys.platform != "win32":
        return

    # mypy special-cases a literal `sys.platform` comparison: on the Linux
    # runner this and CI both run on, it statically treats the check above
    # as always-true and everything below as dead code. It isn't -- this
    # runs fine on an actual Windows machine, which is the whole point of
    # the platform guard above.
    spec = importlib.util.find_spec("llama_cpp")  # type: ignore[unreachable]
    if not spec or not spec.submodule_search_locations:
        return
    lib_dir = pathlib.Path(spec.submodule_search_locations[0]) / "lib"
    if not (lib_dir / "ggml-cuda.dll").exists():
        return  # CPU-only build, no CUDA deps to work around

    for pkg in ("nvidia.cuda_runtime", "nvidia.cublas"):
        pkg_spec = importlib.util.find_spec(pkg)
        if pkg_spec and pkg_spec.submodule_search_locations:
            bin_dir = pathlib.Path(pkg_spec.submodule_search_locations[0]) / "bin"
            if bin_dir.exists():
                os.add_dll_directory(str(bin_dir))

    os.add_dll_directory(str(lib_dir))

    for name in (
        "ggml-base.dll", "ggml-cpu.dll", "ggml-cuda.dll", "ggml.dll", "llama.dll", "llava.dll",
    ):
        dll_path = lib_dir / name
        if dll_path.exists():
            try:
                ctypes.CDLL(str(dll_path))
            except OSError:
                pass  # let llama_cpp's own import raise a clearer error


_preload_windows_cuda_deps()

# The DLL preload above must run before this import (that's the whole point
# of _preload_windows_cuda_deps), so it cannot be moved to the top of the
# file with the other imports.
from llama_cpp import Llama  # noqa: E402  pylint: disable=wrong-import-position,wrong-import-order
from llama_cpp.llama_types import (  # noqa: E402  pylint: disable=wrong-import-position,wrong-import-order
    ChatCompletionRequestMessage,
)

# Module-level import is deferred past the DLL preload above, so app.intel
# (which has no such constraint) is imported here rather than at the top,
# for a single clear "everything above this line is DLL setup" boundary.
from . import intel  # noqa: E402  pylint: disable=wrong-import-position


@functools.lru_cache(maxsize=1)
def get_llm() -> Llama:
    """Load the GGUF model once per process and cache it -- loading an 8B
    model is far too expensive to repeat per request, so this is the one
    piece of module-lifetime mutable state in the app, deliberately kept to
    a single cached singleton rather than a bare module-global.
    """
    model_path = os.environ.get("APTWATCH_MODEL_PATH", str(DEFAULT_MODEL_PATH))
    if not pathlib.Path(model_path).exists():
        raise FileNotFoundError(
            f"No LLM model found at {model_path}. Set APTWATCH_MODEL_PATH or place "
            "the GGUF file at the default location (see README)."
        )
    return Llama(
        model_path=model_path,
        n_gpu_layers=int(os.environ.get("APTWATCH_MODEL_GPU_LAYERS", "-1")),
        n_ctx=int(os.environ.get("APTWATCH_MODEL_CTX", "8192")),
        verbose=False,
    )


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

# Used for open-ended "assess this actor/campaign" questions instead of
# SYSTEM_PROMPT above -- see app/chat.py's pipeline-trigger logic (an actor
# entity resolved AND the question text signals assessment intent, per
# app/nlp.py's wants_pipeline_assessment()). A narrow factual lookup ("what
# mitigates T1055?") should stay on the concise SYSTEM_PROMPT above; forcing
# every actor question through nine headings would bury a one-line answer.
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


def _system_prompt_for(pipeline: bool) -> str:
    """Pick the narrow-lookup or full-assessment system prompt."""
    return PIPELINE_SYSTEM_PROMPT if pipeline else SYSTEM_PROMPT


# Regexes for the ID guardrail below: any of these patterns appearing in the
# model's answer must also appear somewhere in the facts it was given, or the
# model has fabricated an identifier despite the system prompt telling it not
# to (observed in testing with this model on abliterated 8B checkpoints).
ID_PATTERNS = [
    re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE),
    re.compile(r"CWE-\d+", re.IGNORECASE),
    re.compile(r"CAPEC-\d+", re.IGNORECASE),
    re.compile(r"\bT\d{4}(?:\.\d{3})?\b"),
    re.compile(r"\bM\d{4}\b"),
    re.compile(r"\bG\d{4}\b"),
]


def _ids_in_text(text: str) -> set[str]:
    ids: set[str] = set()
    for pattern in ID_PATTERNS:
        ids.update(m.upper() for m in pattern.findall(text))
    return ids


def allowed_ids(facts: list["intel.Fact"]) -> set[str]:
    """Every ID a reply is allowed to mention: each fact's own source id,
    plus any ID pattern already present in that fact's own text.
    """
    allowed: set[str] = set()
    for fact in facts:
        allowed.add(fact["source"]["id"].upper())
        allowed.update(_ids_in_text(fact["text"]))
    return allowed


def _check_for_fabricated_ids(reply: str, facts: list["intel.Fact"]) -> str:
    unverified = _ids_in_text(reply) - allowed_ids(facts)
    if not unverified:
        return reply
    return (
        reply
        + "\n\n⚠️ Verification warning: this answer mentioned "
        + ", ".join(sorted(unverified))
        + " — that identifier was NOT found in the retrieved data. Treat that "
        "specific claim as unverified; it may be fabricated."
    )


MAX_PER_TIER = 8

# Priority order for context-budget allocation, most important first. Every
# fact in app/intel.py carries an explicit "category" for this — inferring
# priority from derived/dataset alone let one numerous category (e.g.
# actor_usage facts reached via the CWE/CAPEC crosswalk, often 40+ per CVE)
# silently crowd out a smaller, more directly relevant one (mitigations, or
# IOC correlations) before the fact cap. Each tier gets its own reserved
# slice of the budget instead of competing in one shared pool.
CATEGORY_PRIORITY = [
    "naming_note", "vuln_info", "mitigation", "ioc", "actor_usage", "crosswalk_detail",
]


def build_context(facts: list["intel.Fact"]) -> str:
    """Render facts as a numbered, priority-tiered, budget-capped list for
    the prompt -- see CATEGORY_PRIORITY and MAX_PER_TIER above for why.
    """
    if not facts:
        return "(No matching facts were found in the database for this question.)"

    tiers: dict[str, list["intel.Fact"]] = {name: [] for name in CATEGORY_PRIORITY}
    for fact in facts:
        tiers.setdefault(fact.get("category", "actor_usage"), []).append(fact)

    # Within vuln_info, a "why this couldn't be answered" coverage note is the
    # single most load-bearing fact for a TTP/APT-style question that dead-
    # ends — put it first so it isn't just one line among several similar-
    # looking KEV/NVD facts (models attend more reliably to earlier context).
    tiers["vuln_info"].sort(key=lambda f: 0 if f["source"]["dataset"] == "APT_Watch" else 1)

    selected = []
    for tier_name in CATEGORY_PRIORITY:
        selected.extend(tiers[tier_name][:MAX_PER_TIER])
    selected = selected[:MAX_FACTS]
    omitted = len(facts) - len(selected)

    lines = [
        f"{'[DIRECT]' if not f['derived'] else '[DERIVED]'} {f['text']}" for f in selected
    ]
    if omitted > 0:
        lines.append(f"(...{omitted} additional lower-priority facts omitted for brevity...)")
    return "\n".join(f"{i + 1}. {line}" for i, line in enumerate(lines))


def answer(question: str, facts: list["intel.Fact"], pipeline: bool = False) -> str:
    """Ask the local LLM to answer `question` grounded only in `facts`.

    `pipeline=True` selects PIPELINE_SYSTEM_PROMPT's structured, multi-
    section assessment format instead of the default concise/cited one --
    see app/chat.py for what decides which questions set this.
    """
    precondition(bool(question), "question must not be empty")
    llm = get_llm()
    context = build_context(facts)
    messages: list[ChatCompletionRequestMessage] = [
        {"role": "system", "content": _system_prompt_for(pipeline)},
        {"role": "user", "content": f"FACTS:\n{context}\n\nQUESTION: {question}"},
    ]
    result = llm.create_chat_completion(messages=messages, temperature=0.2, max_tokens=900)
    if not isinstance(result, dict):
        raise ContractViolation("non-streaming call must return a single response, not a stream")
    content = result["choices"][0]["message"]["content"]
    reply = not_none(content, "LLM response must include message content").strip()
    return _check_for_fabricated_ids(reply, facts)

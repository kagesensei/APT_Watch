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
    # The unreachable suppression is intentionally unused on Windows.
    spec = importlib.util.find_spec("llama_cpp")  # type: ignore[unreachable, unused-ignore]
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
from .prompts import (  # noqa: E402  pylint: disable=wrong-import-position
    ASSESSMENT_CATEGORY_PRIORITY, CATEGORY_PRIORITY, PIPELINE_SYSTEM_PROMPT, SYSTEM_PROMPT,
)


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


def build_context(facts: list["intel.Fact"], pipeline: bool = False) -> str:
    """Render facts as a numbered, priority-tiered, budget-capped list for
    the prompt -- see CATEGORY_PRIORITY and MAX_PER_TIER above for why.
    """
    if not facts:
        return "(No matching facts were found in the database for this question.)"

    priority = ASSESSMENT_CATEGORY_PRIORITY if pipeline else CATEGORY_PRIORITY
    per_tier = 4 if pipeline else MAX_PER_TIER
    tiers: dict[str, list["intel.Fact"]] = {name: [] for name in priority}
    for fact in facts:
        tiers.setdefault(fact.get("category", "actor_usage"), []).append(fact)

    # Within vuln_info, a "why this couldn't be answered" coverage note is the
    # single most load-bearing fact for a TTP/APT-style question that dead-
    # ends — put it first so it isn't just one line among several similar-
    # looking KEV/NVD facts (models attend more reliably to earlier context).
    tiers["vuln_info"].sort(key=lambda f: 0 if f["source"]["dataset"] == "APT_Watch" else 1)

    selected = []
    for tier_name in priority:
        selected.extend(tiers[tier_name][:per_tier])
    selected = selected[:MAX_FACTS]
    omitted = len(facts) - len(selected)

    def label(fact: "intel.Fact") -> str:
        return fact.get("evidence_kind", "DERIVED" if fact["derived"] else "DIRECT")

    lines = [f"[{label(f)}] {f['text']}" for f in selected]
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
    context = build_context(facts, pipeline=pipeline)
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

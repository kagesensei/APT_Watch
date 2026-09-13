import ctypes
import importlib.util
import os
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
DEFAULT_MODEL_PATH = ROOT / "models" / "meta-llama-3.1-8b-instruct-abliterated.Q4_K_M.gguf"

MAX_FACTS = 20


def _preload_windows_cuda_deps():
    """Work around a ctypes quirk on Windows/Python 3.10: llama_cpp loads its
    DLLs with ctypes.CDLL(absolute_path, winmode=RTLD_GLOBAL), which fails to
    resolve dependent DLLs (the CUDA runtime) via os.add_dll_directory even
    though that's supposed to work. Pre-loading the same DLLs here (without
    winmode) first makes them already-resident, so llama_cpp's own load call
    just finds them instead of re-resolving dependencies.
    """
    if sys.platform != "win32":
        return

    spec = importlib.util.find_spec("llama_cpp")
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

    for name in ("ggml-base.dll", "ggml-cpu.dll", "ggml-cuda.dll", "ggml.dll", "llama.dll", "llava.dll"):
        dll_path = lib_dir / name
        if dll_path.exists():
            try:
                ctypes.CDLL(str(dll_path))
            except OSError:
                pass  # let llama_cpp's own import raise a clearer error


_preload_windows_cuda_deps()

from llama_cpp import Llama  # noqa: E402  (must follow the DLL preload above)

_llm = None


def get_llm():
    global _llm
    if _llm is None:
        model_path = os.environ.get("APTWATCH_MODEL_PATH", str(DEFAULT_MODEL_PATH))
        if not pathlib.Path(model_path).exists():
            raise FileNotFoundError(
                f"No LLM model found at {model_path}. Set APTWATCH_MODEL_PATH or place "
                "the GGUF file at the default location (see README)."
            )
        _llm = Llama(
            model_path=model_path,
            n_gpu_layers=int(os.environ.get("APTWATCH_MODEL_GPU_LAYERS", "-1")),
            n_ctx=int(os.environ.get("APTWATCH_MODEL_CTX", "8192")),
            verbose=False,
        )
    return _llm


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

If the facts below do not answer the question, say plainly that you don't have that
information in the data available — do not guess, and do not use any knowledge beyond
the facts listed. Address exactly what the user asked first (e.g. if they ask about
indicators of compromise, lead with any IOC facts before general background), rather
than opening with unrelated context. Keep your answer concise and actionable."""

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


def _ids_in_text(text):
    ids = set()
    for pattern in ID_PATTERNS:
        ids.update(m.upper() for m in pattern.findall(text))
    return ids


def allowed_ids(facts):
    allowed = set()
    for f in facts:
        allowed.add(f["source"]["id"].upper())
        allowed.update(_ids_in_text(f["text"]))
    return allowed


def _check_for_fabricated_ids(reply, facts):
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
CATEGORY_PRIORITY = ["vuln_info", "mitigation", "ioc", "actor_usage", "crosswalk_detail"]


def build_context(facts):
    if not facts:
        return "(No matching facts were found in the database for this question.)"

    tiers = {name: [] for name in CATEGORY_PRIORITY}
    for f in facts:
        tiers.setdefault(f.get("category", "actor_usage"), []).append(f)

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


def answer(question, facts):
    llm = get_llm()
    context = build_context(facts)
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": f"FACTS:\n{context}\n\nQUESTION: {question}"},
    ]
    result = llm.create_chat_completion(messages=messages, temperature=0.2, max_tokens=900)
    reply = result["choices"][0]["message"]["content"].strip()
    return _check_for_fabricated_ids(reply, facts)

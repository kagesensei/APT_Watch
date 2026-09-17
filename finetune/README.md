# finetune/

A fine-tune of APT_Watch's own chat model, scoped narrowly: not to teach it
threat-intel facts (see "Why not fact fine-tuning" below), but to make it
better at the one behavior `app/llm.py`'s `SYSTEM_PROMPT` already demands of
whatever model sits behind `APTWATCH_MODEL_PATH` -- turning a numbered,
`[DIRECT]`/`[DERIVED]`-tagged fact list into a concise, correctly-cited,
appropriately-hedged analyst answer that never mentions an ID absent from
the facts.

**Base model:** the same one `app/llm.py` already loads --
[`mlabonne/Meta-Llama-3.1-8B-Instruct-abliterated-GGUF`](https://huggingface.co/mlabonne/Meta-Llama-3.1-8B-Instruct-abliterated-GGUF).
**Planned result:** `apt-watch-8B-instruct-abliterated-claudetuned`, published
to Hugging Face once trained, and usable as a drop-in `APTWATCH_MODEL_PATH`.

## Why not fact fine-tuning

`app/llm.py`'s system prompt forbids the model from answering off its own
training knowledge -- every claim must cite a retrieved fact, because
MITRE ATT&CK/CISA KEV data changes constantly and baked-in facts would go
stale (and reintroduce the exact hallucination risk `_check_for_fabricated_ids`
exists to catch). So this fine-tune's training data teaches *response
discipline* against a fact list, never facts themselves: every fact
template, category name (`naming_note`, `vuln_info`, `mitigation`, `ioc`,
`actor_usage`, `crosswalk_detail`), and the system prompt itself in
`generate_sft_examples.py` are copied verbatim from `app/intel.py` and
`app/llm.py`, so the training format matches exactly what the app sends at
inference time.

## Two prompt shapes, matching the live app exactly

`app/llm.py` now has two system prompts, and `app/chat.py` decides which one
a question gets: the original concise `SYSTEM_PROMPT` for narrow factual
lookups ("what mitigates T1055?"), and a new `PIPELINE_SYSTEM_PROMPT` for
open-ended "assess this actor/campaign" questions, which asks for a
structured answer under nine headings (Likely Actor(s), Observed Behavior,
ATT&CK Techniques, Supporting Evidence, Confidence, IOCs, Detections,
Mitigations, Unanswered Questions / Gaps). The trigger
(`app/chat.py`'s `_wants_pipeline_assessment`) requires **both** a resolved
actor entity **and** assessment-intent phrasing (`app/nlp.py`'s
`ASSESSMENT_INTENT_RE`) -- naming an actor in an otherwise narrow question
("what software does APT29 use?") stays on the concise prompt.

This generator mirrors that split exactly: `PIPELINE_SYSTEM_PROMPT` and a
matching `PIPELINE_RUBRIC` are copied verbatim from `app/llm.py` (same
duplication rationale as `SYSTEM_PROMPT`), and `prompt_and_rubric_for(tag)`
picks the right pair per scenario via `PIPELINE_SCENARIO_TAGS`. Training
data for a pipeline-shaped question needs to *look like* what the app
actually sends for that kind of question -- otherwise the fine-tune learns
the wrong response shape for exactly the case it matters most for.

## Pipeline status

| Stage | Status |
|---|---|
| 1. Synthetic training-data generator | **Done.** `generate_sft_examples.py`, tested (`tests/test_generate_sft_examples.py`, 39 cases), and wired into `preflight.py`/CI like every other package here. |
| 2. Teacher-model synthesis for multi-fact examples | **Stubbed, not run.** See below. |
| 3. QLoRA fine-tune + GGUF export | **Not started.** Documented plan only -- needs a GPU this session doesn't have. |
| 4. Point `APTWATCH_MODEL_PATH` at the result / publish to Hugging Face | **Not started.** |

### Stage 1: generate the dataset

```bash
python finetune/generate_sft_examples.py
```

Writes `finetune/sft_examples.jsonl` (gitignored -- it's generated output,
same as `data/cti.duckdb`), one `{"messages": [...], "meta": {...}}` row per
example, in the exact chat-message shape `app/llm.py`'s `answer()` sends
(`meta.pipeline` records which of the two prompt shapes above was used).

Twelve scenario generators, three groups:

- **Single-source lookups** (the original eight): a direct CVE/KEV lookup,
  the full CVE->CWE->CAPEC->technique->mitigation/actor crosswalk, the
  crosswalk "dead end" explanation case, technique/mitigation lookup, a
  confirmed vs. a name-correlated IOC, zero-facts, and naming-convention
  etymology.
- **Conflicting-evidence scenarios**, still on the concise prompt (a narrow
  question can still have conflicting facts to weigh honestly, without
  needing the full nine-heading structure):
  - `scenario_conflicting_attribution` / `scenario_naming_collision_rejected`
    are grounded in this repo's own real, already-published data --
    `data/reports/alias_resolution.md`'s documented collision where MISP
    Galaxy's single "Lazarus Group" cluster maps to five distinct ATT&CK
    groups (G0082 APT38, G1049 AppleJeus, G0138 Andariel, G0032 Lazarus
    Group, G1036 Moonstone Sleet), and its reviewed-and-**rejected**
    Chimera/WET PANDA name collision. Not invented data.
  - `scenario_conflicting_iocs`: two feeds tagging distinct-but-similar
    indicators to the same malware family name -- overlapping tagging, not
    confirmed shared infrastructure.
- **`scenario_full_pipeline_assessment`**: the one scenario on
  `PIPELINE_SYSTEM_PROMPT`, combining the Lazarus collision above with
  ordinary technique/mitigation facts, an IOC correlation, a naming note,
  and three enriched-pool facts (see below) into one deliberately
  fact-dense "assess this actor" question.

Enriched reference pools beyond the original CVE/technique/mitigation/actor
sets: real, well-known malware/tool names (Cobalt Strike, PlugX, Mimikatz,
QakBot -- names only, no invented catalog ID); **MITRE ATLAS** techniques
(AML.T0010 AI Supply Chain Compromise, AML.T0025 Data exfiltration via AI
model); **Aerospace Corporation SPARTA** techniques (EX-0014 Spoofing,
EX-0016 Jamming, EX-0009 Exploit Code Flaws, EX-0010 Malicious Code) --
relevant to customers operating satellite/space-segment infrastructure;
and real **MITRE ATT&CK Campaign** objects (C0001 Frankenstein, C0002 Night
Dragon). `atlas.mitre.org`, `attack.mitre.org`, and `sparta.aerospace.org`
were blocked by this session's network egress proxy, so these IDs were
verified via web search against independent citations rather than fetched
directly or assumed from memory -- see the comments above each pool in
`generate_sft_examples.py` for what was checked. The ATLAS/SPARTA fact
builders are explicitly commented as illustrative: `app/intel.py` has no
live ingest for either framework yet, so these model what a future
retrieval over that data would look like, not current live app output.

Of the twelve, two (`zero_facts`, single-fact `ioc_confirmed`) have a
genuinely mechanical ideal answer and are written with no external model.
The other ten -- including every conflicting-evidence scenario and the
full-pipeline scenario -- need actual prose synthesis and are **skipped**
(tallied under `_skipped_needs_teacher_model` in the printed summary)
unless you supply a `teacher_fn` -- `generate_dataset()` never fabricates a
synthesis-tier answer on its own.

### Stage 2: wire in a teacher model

`synthesize_answer()` takes an optional `teacher_fn: Callable[[system_prompt,
rubric, user_message], answer]`. Call `generate_dataset(..., teacher_fn=...)`
with something like:

```python
import anthropic

client = anthropic.Anthropic()  # reads ANTHROPIC_API_KEY

def claude_teacher(system_prompt: str, rubric: str, user_content: str) -> str:
    response = client.messages.create(
        model="claude-sonnet-5",  # or whichever model you want to distill from
        max_tokens=900,
        system=f"{system_prompt}\n\n{rubric}",
        messages=[{"role": "user", "content": user_content}],
    )
    return response.content[0].text
```

`STRICT_RUBRIC` in `generate_sft_examples.py` tells the teacher this is a
training example (not a live reply), to synthesize multiple relevant facts
into connected prose rather than restating each as a bullet, and to output
only the answer text. Not run in this session -- needs an API key and
real spend, which is the user's call, not something to do silently.

### Stage 3: QLoRA fine-tune + GGUF export (not started)

Plan, not yet executed:

1. Generate a few thousand examples via stage 1+2 (the current 12 scenario
   generators, each parameterized over the reference pools, give enough
   combinatorial variety for this; add more scenarios/pools before scaling
   much past that to avoid the model memorizing the fixed pools instead of
   generalizing the behavior).
2. QLoRA fine-tune `mlabonne/Meta-Llama-3.1-8B-Instruct-abliterated` (the
   full-precision base the GGUF above was quantized from) with something
   like [Unsloth](https://github.com/unslothai/unsloth) or
   [Axolotl](https://github.com/axolotl-ai-cloud/axolotl) -- either handles
   Llama 3.1's chat template directly, which matters here since training
   data must match `app/llm.py`'s exact system+user message shape.
3. Merge the LoRA adapter and export to GGUF (`llama.cpp`'s
   `convert_hf_to_gguf.py`), quantized the same way as the current model
   (`Q4_K_M`, for parity with the ~4.9GB/8GB-GPU footprint documented in the
   root README).
4. **Before treating a checkpoint as production-ready:** run it against
   `app/llm.py`'s own `_check_for_fabricated_ids`/`allowed_ids` logic on a
   held-out set of (facts, question) pairs it was never trained on --
   the fine-tune only earns its place in `APTWATCH_MODEL_PATH` if it
   fabricates *fewer* IDs than the current base model, not just different
   prose. A fine-tune that writes nicer sentences but hallucinates more
   IDs would be a regression, not an upgrade.

### Stage 4: point the app at it / publish (not started)

Set `APTWATCH_MODEL_PATH` to the exported GGUF locally to try it against the
real app -- **the app-side routing is already live and doesn't need
anything further**: `app/chat.py` already decides per-question whether to
send `SYSTEM_PROMPT` or `PIPELINE_SYSTEM_PROMPT` (see "Two prompt shapes"
above), so a fine-tuned checkpoint trained on both shapes drops straight
in. Publishing to Hugging Face as
`apt-watch-8B-instruct-abliterated-claudetuned` is a separate, explicit
step for whenever the user decides the checkpoint in step 3.4 above is
actually worth shipping.

## Tests

```bash
pytest tests/test_generate_sft_examples.py tests/test_llm.py tests/test_nlp.py tests/test_routes_chat.py -v
```

`tests/test_generate_sft_examples.py` (39 cases) covers fact rendering
(numbering, `[DIRECT]`/`[DERIVED]` tagging, category ordering), every
scenario generator's output shape, the deterministic-vs-teacher-needed
answer split, `synthesize_answer()`'s teacher_fn wiring,
`generate_dataset()`'s end-to-end behavior (including that it never writes
a synthesis-tier example without a teacher_fn), that `build_example()` puts
the *same* prompt into the training message that was used to ask the
teacher for it, and that the Lazarus/Chimera collision data actually
matches `data/reports/alias_resolution.md`. The other three files gained
coverage for the new live-app routing itself: `PIPELINE_SYSTEM_PROMPT`
selection and that the fabrication guard still scans a full structured
answer correctly (`test_llm.py`), `wants_pipeline_assessment()`
(`test_nlp.py`), and the actor+intent trigger end-to-end against the real
ingested database (`test_routes_chat.py`).

`finetune/generate_sft_examples.py` is included in `preflight.py` and
`.github/workflows/ci.yml`'s pylint/bandit steps, same as `app/`, `ingest/`,
and `resolve/`; `mypy .` already covers it since mypy runs on the whole repo.

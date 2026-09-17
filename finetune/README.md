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

## Pipeline status

| Stage | Status |
|---|---|
| 1. Synthetic training-data generator | **Done.** `generate_sft_examples.py`, tested (`tests/test_generate_sft_examples.py`, 23 cases), and wired into `preflight.py`/CI like every other package here. |
| 2. Teacher-model synthesis for multi-fact examples | **Stubbed, not run.** See below. |
| 3. QLoRA fine-tune + GGUF export | **Not started.** Documented plan only -- needs a GPU this session doesn't have. |
| 4. Point `APTWATCH_MODEL_PATH` at the result / publish to Hugging Face | **Not started.** |

### Stage 1: generate the dataset

```bash
python finetune/generate_sft_examples.py
```

Writes `finetune/sft_examples.jsonl` (gitignored -- it's generated output,
same as `data/cti.duckdb`), one `{"messages": [...], "meta": {...}}` row per
example, in the exact chat-message shape `app/llm.py`'s `answer()` sends.

Eight scenario generators cover the fact shapes seen in `app/intel.py`:
a direct CVE/KEV lookup, the full CVE->CWE->CAPEC->technique->
mitigation/actor crosswalk, the crosswalk "dead end" explanation case,
technique/mitigation lookup, a confirmed vs. a name-correlated IOC,
zero-facts, and naming-convention etymology. Every ID used is either real
public MITRE ATT&CK taxonomy or a well-known, already-patched CVE (Log4Shell,
MOVEit, the PAN-OS one this repo's own root README already uses as an
example); IOC indicators use RFC 5737 reserved documentation ranges, never
anything resembling a real operational indicator.

Two scenarios (`zero_facts`, single-fact `ioc_confirmed`) have a genuinely
mechanical ideal answer and are written with no external model. The other
six need actual prose synthesis and are **skipped** (tallied under
`_skipped_needs_teacher_model` in the printed summary) unless you supply a
`teacher_fn` -- `generate_dataset()` never fabricates a synthesis-tier
answer on its own.

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

1. Generate a few thousand examples via stage 1+2 (the current 8 scenario
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
real app. Publishing to Hugging Face as `apt-watch-8B-instruct-abliterated-claudetuned`
is a separate, explicit step for whenever the user decides the checkpoint
in step 3.4 above is actually worth shipping.

## Tests

```bash
pytest tests/test_generate_sft_examples.py -v
```

Covers fact rendering (numbering, `[DIRECT]`/`[DERIVED]` tagging, category
ordering), every scenario generator's output shape, the deterministic-vs-
teacher-needed answer split, `synthesize_answer()`'s teacher_fn wiring, and
`generate_dataset()`'s end-to-end behavior (including that it never writes
a synthesis-tier example without a teacher_fn).

`finetune/generate_sft_examples.py` is included in `preflight.py` and
`.github/workflows/ci.yml`'s pylint/bandit steps, same as `app/`, `ingest/`,
and `resolve/`; `mypy .` already covers it since mypy runs on the whole repo.

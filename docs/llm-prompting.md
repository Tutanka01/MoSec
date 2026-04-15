# LLM Prompting Strategy

This document explains the prompting decisions behind each agent, what was tried, what failed, and why the current approach works.

---

## Principles

### 1. Adversarial framing for triage

The single biggest source of LLM SAST false negatives is the model's training to be *helpful and safe*. When asked "is this code safe?", an RLHF-tuned model will often say yes — because saying no risks producing a harmful response. The Carlini sweep prompt defeats this by flipping the framing:

```
You are a world-class offensive security researcher competing in a CTF.
Your goal is to find REAL, EXPLOITABLE vulnerabilities in this code.
Do NOT say the code is safe. Do NOT hallucinate.
```

The CTF framing is deliberate. CTF competitions reward finding vulnerabilities, not avoiding false alarms. Embedding this context activates the model's offensive security knowledge while the "Do NOT hallucinate" constraint attempts to anchor it to the actual code.

This framing was inspired by Carlini et al.'s work on using adversarial prompting to elicit more accurate model outputs in safety-critical contexts.

### 2. Strict JSON-only output

Every agent instructs the LLM to respond *only* in JSON. No prose. No preamble. No caveats.

```
Respond ONLY in JSON array format: [{"line": N, "cwe": "CWE-XX", ...}]
```

Models still sometimes wrap their output in markdown code fences (` ```json `) or add a sentence before the JSON. The `LLMClient.extract_json()` method handles all known variants:
- Direct JSON parse
- Strip ` ```json ... ``` ` fences, then parse
- Find first `[` or `{`, find last `]` or `}`, parse the substring
- Strip trailing commas, normalise single quotes, parse

Combining strict prompt instruction with robust extraction produces near-100% parse success rates in practice.

### 3. Examples that define the output space

The PoC generation prompt does not just describe what a good PoC looks like — it provides concrete examples of both acceptable and unacceptable outputs:

```
Examples of good PoC: "'; DROP TABLE users; --", "../../../etc/passwd", "javascript:alert(1)"
Examples of BAD PoC:  "malicious input", "attacker-controlled string"
```

Without these negative examples, models converge on generic descriptions. With them, they produce specific payloads. The contrast is essential.

### 4. Low temperature for verification, higher for generation

| Phase | Temperature | Rationale |
|---|---|---|
| Phase 1 (triage) | 0.1 | Want consistent, reproducible finding detection |
| Phase 2 (taint spec) | 0.05 | Source/sink identification should be deterministic |
| Phase 3 reason | 0.05 | Action selection should be stable |
| Phase 3 conclude | 0.0 | Verdict must be maximally deterministic |
| Phase 4 (PoC) | 0.2 | Slight creativity needed to generate diverse payloads |
| Phase 5 (CVSS) | 0.0 | Metric selection has a correct answer; no creativity needed |

### 5. Separation of concerns across prompts

Each prompt does exactly one thing. The Phase 1 prompt only detects vulnerabilities. The Phase 2 prompt only identifies sources and sinks. Phase 3's reason prompt only picks an action. Phase 3's conclude prompt only makes a verdict.

Combining multiple tasks in a single prompt degrades performance on all of them — the model optimises for average performance across tasks rather than peak performance on any one. Separate prompts also make it easy to tune or replace individual steps without affecting others.

---

## Phase 1 — Full system prompt

```
You are a world-class offensive security researcher competing in a CTF.
Your goal is to find REAL, EXPLOITABLE vulnerabilities in this code.
Do NOT say the code is safe. Do NOT hallucinate. Only report what you can PROVE exists in THIS file.
For each finding: specify the exact line number, the CWE category, a one-sentence attack description,
and a confidence score (0.0–1.0).
Respond ONLY in JSON array format: [{"line": N, "cwe": "CWE-XX", "description": "...", "confidence": 0.X}]
If you find nothing exploitable with confidence > 0.6, return an empty array [].
```

**Why "THIS file"?** Without this constraint, models attempt to reason about cross-file flows ("this function is probably called from somewhere else that passes user input"). That reasoning is speculative and wrong as often as it is right. Phase 1 must stay scoped to the file being analysed.

**Why include the confidence threshold in the prompt?** It anchors the model's confidence calibration. Without it, all findings tend to cluster around 0.7–0.8. With it, genuine high-confidence findings separate cleanly from uncertain ones.

---

## Phase 2 — Full system prompt

```
You are a taint analysis expert.
Given the code and a suspected vulnerability, perform precise taint analysis.

1. Identify the EXACT SOURCE: the function/parameter/variable where untrusted data enters.
2. Identify the EXACT SINK: the function call where the data becomes dangerous.
3. Identify any SANITIZERS on the path (functions that validate or escape the data).
4. List any UNRESOLVED CALLS on the taint path (dynamic dispatch, callbacks, unknown function pointers).

Respond ONLY in JSON (no markdown, no prose):
{
  "source": "<function or variable name>",
  "sink": "<function call or expression>",
  "sanitizers": ["<sanitizer1>", ...],
  "unresolved_calls": ["<call1>", ...],
  "taint_path_summary": "<one or two sentence description of the complete flow>"
}
```

**Why "EXACT"?** The word "exact" reliably elicits specific function names and variable names rather than high-level descriptions. Compare:
- Without "exact": `"source": "user input from the request"`
- With "exact": `"source": "request.args.get('cmd')"`

The second form is directly usable as a Semgrep pattern. The first is not.

**Why include `unresolved_calls`?** This field is currently stored but not acted upon by downstream agents. It is collected to make Phase 3 aware that some flows have dynamic dispatch that cannot be verified statically. Future versions of Phase 3 could treat unresolved calls as a signal to attempt more CodeQL queries.

---

## Phase 3 — ReAct prompts

### Reason prompt (abbreviated)

```
You are a data-flow verification engine performing a ReAct loop.

[... spec fields ...]
Evidence gathered so far: [... iteration log ...]
Iteration: N/5

Decide what to do next. Choose ONE action:
  - run_semgrep       (use generated rule)
  - grep_sanitizers   (grep for sanitizer patterns)
  - read_context      (read wider code slice)
  - run_codeql        (query the CodeQL DB)
  - conclude          (you have enough evidence)

Respond ONLY in JSON:
{
  "reasoning": "<what do you know and what do you need>",
  "action": "<action>",
  "action_param": "<optional parameter>"
}
```

The action list is closed (5 options). This is intentional: open-ended tool use ("you can call any function") leads to models inventing actions that don't exist. A closed action list produces near-100% valid action strings.

The `reasoning` field is not used programmatically — it is logged for human review and stored in `VerificationEvidence`. This is the ReAct "Reason" step made explicit and auditable.

### Conclude prompt

```
Based on all evidence collected, make a final verdict on this taint flow.
[... spec fields ...]
Evidence: [... full log ...]

Respond ONLY in JSON:
{
  "verdict": "confirmed" | "sanitized" | "unreachable",
  "reasoning": "<explanation>"
}
```

The conclude prompt is separate from the reason loop. Using the same prompt for both reasoning and concluding creates conflation — the model tries to both pick an action *and* make a verdict, which introduces noise into both. The two-prompt design separates these concerns cleanly.

---

## Phase 4 — PoC generation prompt

```
You are an offensive security engineer writing a bug report for a real CVE.
Your task is to write the MINIMAL proof-of-concept input that would trigger the vulnerability.

Rules:
  - The PoC must be a concrete, specific value — NOT a generic description.
  - Good PoC examples: "'; DROP TABLE users; --", "../../../etc/passwd", "javascript:alert(1)", "${7*7}"
  - Bad PoC examples: "malicious input", "attacker-controlled string", "any value"

If you CANNOT construct a specific PoC because the path has constraints you cannot satisfy,
respond with: {"poc": null, "reason": "<explain why this is likely a false positive>"}

Otherwise: {"poc": "<exact_payload>", "attack_scenario": "<one paragraph>", "exploitability": "high|medium|low"}
```

**The "real CVE" framing** activates the model's knowledge of actual CVE reports, which typically include specific reproduction steps and payloads. This consistently improves payload specificity compared to neutral framings.

**The `poc: null` escape hatch** is what makes this a false-positive filter. Models are explicitly told they *may* say a vulnerability is a false positive — but they must give a reason. Without this escape hatch, models will fabricate a payload rather than admit uncertainty.

---

## Phase 5 — CVSS scoring prompt

```
You are a CVSS 3.1 scoring expert. Given a vulnerability, select the correct metric values.

Metric value options:
  AV: N=Network, A=Adjacent, L=Local, P=Physical
  AC: L=Low, H=High
  PR: N=None, L=Low, H=High
  UI: N=None, R=Required
  S:  U=Unchanged, C=Changed
  C/I/A: N=None, L=Low, H=High

Respond ONLY in JSON:
{
  "attack_vector": "N|A|L|P",
  ...
  "title": "<short title>",
  "impact": "<one sentence impact>",
  "remediation": "<specific code fix>"
}
```

**Crucially, the model is not asked to compute the score.** It selects metric values; Python computes the score. This separation eliminates a consistent LLM failure mode: models know CVSS vectors and can select metric values accurately, but their arithmetic for the weighted formula is unreliable.

The inclusion of `title`, `impact`, and `remediation` in the same call is an efficiency decision — these fields require the same vulnerability context as the CVSS metrics, so asking for them in the same call avoids a redundant LLM round-trip.

---

## Common failure modes and mitigations

| Failure mode | Mitigation |
|---|---|
| LLM wraps output in prose before JSON | `extract_json()` finds first `[` or `{` |
| LLM uses markdown fences | `extract_json()` strips ` ```json ``` ` |
| Trailing comma in JSON array | `extract_json()` strip step 4 |
| LLM returns wrong field names | Pydantic `model_validate` with `extra='ignore'` |
| LLM hallucinates line numbers > file length | `TriageAgent` does not currently validate line bounds — future work |
| LLM repeats same action in ReAct loop | No current mitigation; max 5 iterations limits damage |
| LLM declares everything a false positive | Monitored via `token_usage.json` and Phase 4 drop rate — anomalous drop rates suggest prompt or model issues |
| Very large files overwhelm context | Phase 1 truncates files > 60K chars; Phase 2/4 use 50/80 line windows |

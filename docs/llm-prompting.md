# LLM Prompting Strategy

This document explains the prompting decisions behind each agent, what was tried, what failed, and why the current approach works.

---

## Principles

### 1. Adversarial framing for triage

The single biggest source of LLM SAST false negatives is the model's training to be *helpful and safe*. When asked "is this code safe?", an RLHF-tuned model will often say yes. The Carlini sweep prompt defeats this by flipping the framing:

```
You are a world-class offensive security researcher competing in a CTF.
Your goal is to find REAL, EXPLOITABLE vulnerabilities in this code.
Do NOT say the code is safe. Do NOT hallucinate.
```

The CTF framing activates the model's offensive security knowledge. The "Do NOT hallucinate" constraint anchors it to the actual code.

### 2. Strict JSON-only output

Every agent instructs the LLM to respond *only* in JSON. `LLMClient.extract_json()` handles all known failure modes:
1. Direct JSON parse
2. Strip ` ```json ... ``` ` fences, then parse
3. Find first `[` or `{`, find last `]` or `}`, parse the substring
4. Strip trailing commas, normalise single quotes, parse

### 3. AST grounding before LLM reasoning (new)

Phase 2 now extracts AST candidates before calling the LLM. The principle: **AST proposes, LLM disposes**. The LLM selects from a structured list of grounded positions rather than inventing source/sink names. This eliminates a whole class of hallucinations where the model describes a plausible but non-existent function.

### 4. Separation of concerns across prompts

Each prompt does exactly one thing. The Phase 3 reason prompt only picks an action. The VerifierAgent uses three distinct prompts — one for proposing, one for falsifying, one for deciding. Combining multiple tasks in a single prompt degrades performance on all of them.

### 5. Low temperature for verification, higher for generation

| Phase | Temperature | Rationale |
|---|---|---|
| Phase 1 (triage) | 0.1 | Consistent, reproducible finding detection |
| Phase 2 (taint spec) | 0.05 | Source/sink identification should be deterministic |
| Phase 3 reason | 0.05 | Action selection should be stable |
| Phase 3 VerifierAgent propose | 0.1 | Slight variation for self-consistency runs |
| Phase 3 VerifierAgent falsify | 0.2 | Adversarial creativity needed |
| Phase 3 VerifierAgent decide | 0.0 | Verdict must be maximally deterministic |
| Phase 4 (PoC) | 0.2 | Creativity needed to generate diverse payloads |
| Phase 5 (CVSS) | 0.0 | Metric selection has a correct answer |

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

**Why "THIS file"?** Without this constraint, models attempt cross-file reasoning that is speculative and wrong as often as it is right.

**Why include the confidence threshold in the prompt?** Without it, all findings cluster around 0.7–0.8. With it, genuine high-confidence findings separate cleanly from uncertain ones.

---

## Phase 2 — Full system prompt (updated with AST grounding)

```
You are a taint analysis expert.
Given the code and AST-extracted candidate sources/sinks, perform precise taint analysis.

Your task:
1. Select the BEST SOURCE from the candidates list.
2. Select the BEST SINK from the candidates list.
3. Identify any SANITIZERS on the path.
4. List any UNRESOLVED CALLS on the taint path.
5. State the sink_kind: "call", "method_call", "property_assignment", or "subscript_assignment".

If no candidates are provided or none fit, infer from the code — but prefer candidates.

Respond ONLY in JSON:
{
  "source": "<exact source from candidates>",
  "sink": "<exact sink from candidates>",
  "sink_kind": "call|method_call|property_assignment|subscript_assignment",
  "sanitizers": [...],
  "unresolved_calls": [...],
  "taint_path_summary": "<one or two sentences>",
  "source_line": <int or null>,
  "sink_line": <int or null>
}
```

**Why ask for `sink_kind`?** This value drives the Semgrep pattern template selection in `generate_semgrep_rule()`. A property assignment like `innerHTML = x` requires a completely different Semgrep pattern than a method call like `cursor.execute(x)`.

**Why provide candidates?** The LLM can no longer produce `user['id'](...)` (invalid Semgrep) because the candidate shows the correct expression structure and kind. The LLM confirms or adjusts, it does not invent.

---

## Phase 3 — ReAct reason prompt (updated)

```
You are a data-flow verification engine performing a ReAct loop.

Context: [spec fields]

Evidence gathered so far:
[iteration log — full summaries from StructuredEvidence, never truncated]

Actions already performed (DO NOT repeat these with the same parameters):
[played set]

Iteration: N/5

Rules:
  1. Only conclude when you have definitive evidence.
  2. Do NOT repeat an action with the same parameters.
  3. Your reasoning must be at least one full sentence.
  4. Your confidence (0.0–1.0) must reflect the current state of evidence.

Respond ONLY in valid JSON:
{
  "reasoning": "<at least one full sentence>",
  "action": "run_semgrep|grep_sanitizers|read_context|run_codeql|conclude",
  "action_param": "<optional>",
  "confidence": <0.0-1.0>
}
```

**Why surface played actions?** Without this, models repeatedly request `read_context` on the same 80-line window. With it, the model is forced to either try a different action or conclude.

**Why require `confidence`?** The VerifierAgent can weight evidence items by the model's self-reported confidence during the Propose stage.

**Why validate with Pydantic?** Unknown action strings (e.g. `"run_bandit"`) are caught and substituted with `"conclude"` rather than silently burning an iteration. On validation failure, the prompt is retried once with the error message shown to the model.

---

## Phase 3 — VerifierAgent prompts (new)

### Propose prompt

```
You are a security analyst making an initial verdict on a taint flow.

Finding: [spec fields]

Evidence:
[full evidence log from StructuredEvidence]

State your INITIAL verdict and reasoning. Be concrete — cite specific
evidence items by their iteration numbers.

Respond ONLY in JSON:
{"verdict": "confirmed|sanitized|unreachable", "reasoning": "<cite evidence>"}
```

### Falsify prompt

```
You are a skeptical red-team reviewer. Your colleague has proposed the
following verdict. Your job is to find weaknesses in the reasoning.

Proposed verdict: [verdict]
Reasoning: [reasoning]

[finding context + full evidence]

List AT LEAST 2 concrete reasons the proposed verdict could be incorrect.
If you genuinely cannot find any weakness, respond with: "NONE — verdict appears solid."

Respond ONLY in JSON:
{"rebuttals": ["<reason 1>", "<reason 2>", ...]}
```

The Falsify step cannot produce a verdict — it can only surface weaknesses. This separation ensures the adversarial critique does not contaminate the final decision with its own framing.

### Decide prompt

```
You are the final arbiter of a taint-flow verdict.

Initial verdict: [verdict]
Initial reasoning: [reasoning]

Skeptical rebuttals:
[rebuttal list]

[finding context + evidence summary]

RULES:
  1. "confirmed" — only if there is AFFIRMATIVE evidence that untrusted data
                   flows to the sink AND no effective sanitizer is on the path.
  2. "sanitized" — only if you have positive evidence a real sanitizer
                   interrupts the taint path.
  3. "unreachable" — default when evidence is ambiguous, sparse, or contradicted.

Respond ONLY in JSON:
{"verdict": "confirmed|sanitized|unreachable", "reasoning": "<final explanation>"}
```

**Why "unreachable" as the default?** The burden of proof is on confirmation. The model must find positive evidence that a flow exists. Ambiguity or missing evidence means the vulnerability cannot be confirmed — not that it is confirmed by default.

**Why separate prompts for three stages?** VulnSage (Zhang et al., 2025) showed that "ThinkAndVerify" — a hypothesis followed by adversarial verification — beats single-prompt CoT by 8-12 F1 points on a benchmark of real CVEs. The Propose-Falsify-Decide structure is the direct implementation of this finding.

---

## Phase 4 — PoC generation prompt

```
You are an offensive security engineer writing a bug report for a real CVE.
Your task is to write the MINIMAL proof-of-concept input that would trigger the vulnerability.

Rules:
  - The PoC must be a concrete, specific value — NOT a generic description.
  - Good PoC: "'; DROP TABLE users; --", "../../../etc/passwd", "javascript:alert(1)", "${7*7}"
  - Bad PoC: "malicious input", "attacker-controlled string", "any value"

If you CANNOT construct a specific PoC because the path has constraints you cannot satisfy:
  {"poc": null, "reason": "<explain why this is a false positive>"}

Otherwise:
  {"poc": "<exact_payload>", "attack_scenario": "<one paragraph>", "exploitability": "high|medium|low"}
```

The `poc: null` escape hatch is what makes Phase 4 a false-positive filter. Models are explicitly allowed to declare a false positive — but they must give a reason. Without this escape hatch, models fabricate payloads rather than admit uncertainty.

---

## Phase 5 — CVSS scoring prompt

The LLM selects eight metric values (AV, AC, PR, UI, S, C, I, A) plus title, impact summary, and remediation advice in a single call. Python computes the CVSS score analytically — the model is never asked to perform the weighted arithmetic.

---

## Common failure modes and current mitigations

| Failure mode | Mitigation |
|---|---|
| LLM wraps output in prose before JSON | `extract_json()` finds first `[` or `{` |
| LLM uses markdown fences | `extract_json()` strips ` ```json ``` ` |
| Trailing comma in JSON array | `extract_json()` strip step 4 |
| Unknown action in ReAct loop | `ReActStep` validation → substituted with `"conclude"` |
| LLM repeats same action | Action dedup in `played` set → DEDUP observation injected |
| LLM hallucinated source/sink name | AST candidates in Phase 2 prompt → LLM selects from grounded list |
| Invalid Semgrep rule generated | `semgrep --validate` before write → fallback pattern-regex rule |
| LLM declares everything confirmed | Falsify stage forces adversarial critique; decide stage defaults to unreachable |
| LLM failure → false positive | `VerifierAgent._decide()` is fail-closed → returns `"unreachable"` on any exception |
| Very large files overwhelm context | Phase 1: truncate > 60K chars; Phase 2/4: ±50/80 line windows |

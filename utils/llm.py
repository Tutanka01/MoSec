"""
LLM client wrapper — OpenAI-compatible API, exponential-backoff retry,
robust JSON extraction, per-call token accounting.
"""

from __future__ import annotations

import json
import logging
import re
import time
from typing import Any

from openai import APIConnectionError, APIStatusError, OpenAI, RateLimitError

logger = logging.getLogger(__name__)


class LLMError(Exception):
    """Raised when the LLM call fails after all retries."""


class EmptyResponseError(ValueError):
    """Raised when the LLM returns a non-null but empty response body.

    Distinct from a JSON parse error: the model produced no output at all,
    which typically indicates a context-length overflow, a model refusal,
    or a transient server issue.  Callers can catch this specifically to
    emit a targeted warning rather than a generic "JSON extraction failed".
    """


class LLMClient:
    """Thin wrapper around the OpenAI SDK targeting a local llama-server."""

    def __init__(self, base_url: str, api_key: str, model: str) -> None:
        self.model = model
        self._client = OpenAI(base_url=base_url, api_key=api_key or "x")
        self.total_prompt_tokens: int = 0
        self.total_completion_tokens: int = 0

    # ------------------------------------------------------------------
    # Core call
    # ------------------------------------------------------------------

    def chat(
        self,
        messages: list[dict[str, str]],
        max_tokens: int = 4096,
        temperature: float = 0.1,
        max_retries: int = 3,
        retry_base_delay: float = 2.0,
    ) -> tuple[str, dict[str, int]]:
        """
        Send a chat request.  Returns (content_str, usage_dict).
        Raises LLMError after *max_retries* failed attempts.

        An empty response from the model is treated as a transient failure
        and retried (up to max_retries).  If still empty after all retries,
        the empty string is returned with a WARNING — callers must handle it.
        """
        last_exc: Exception | None = None
        for attempt in range(max_retries):
            try:
                response = self._client.chat.completions.create(
                    model=self.model,
                    messages=messages,  # type: ignore[arg-type]
                    max_tokens=max_tokens,
                    temperature=temperature,
                )
                content = response.choices[0].message.content or ""
                usage: dict[str, int] = {}
                if response.usage:
                    usage = {
                        "prompt_tokens": response.usage.prompt_tokens,
                        "completion_tokens": response.usage.completion_tokens,
                        "total_tokens": response.usage.total_tokens,
                    }
                    self.total_prompt_tokens += usage.get("prompt_tokens", 0)
                    self.total_completion_tokens += usage.get("completion_tokens", 0)

                # Treat an empty response as a soft failure and retry.
                # Causes: context overflow, model refusal, transient server hiccup.
                if not content.strip():
                    if attempt < max_retries - 1:
                        wait = retry_base_delay ** (attempt + 1)
                        logger.warning(
                            "LLM empty response (attempt %d/%d) — retrying in %.1fs",
                            attempt + 1,
                            max_retries,
                            wait,
                        )
                        time.sleep(wait)
                        continue
                    else:
                        logger.warning(
                            "LLM empty response after %d attempt(s) — giving up",
                            max_retries,
                        )
                        return content, usage

                logger.debug("LLM call ok | model=%s tokens=%s", self.model, usage)
                return content, usage

            except (RateLimitError, APIConnectionError, APIStatusError) as exc:
                last_exc = exc
                wait = retry_base_delay ** (attempt + 1)
                logger.warning(
                    "LLM call failed (attempt %d/%d): %s — retrying in %.1fs",
                    attempt + 1,
                    max_retries,
                    exc,
                    wait,
                )
                if attempt < max_retries - 1:
                    time.sleep(wait)
            except Exception as exc:
                # Non-transient errors: log and re-raise immediately
                logger.error("LLM call non-transient error: %s", exc)
                raise LLMError(str(exc)) from exc

        raise LLMError(f"LLM failed after {max_retries} attempts: {last_exc}")

    # ------------------------------------------------------------------
    # JSON extraction
    # ------------------------------------------------------------------

    def extract_json(self, text: str) -> Any:
        """
        Extract a JSON value from an LLM response that may be wrapped in
        markdown fences, have prose before/after, or contain partial JSON.

        Raises ValueError if no valid JSON can be found.
        Raises EmptyResponseError (subclass of ValueError) if *text* is empty.
        """
        text = text.strip()

        # Distinguish "empty response" from "unparseable JSON" — they have
        # different root causes and different remediation paths.
        if not text:
            raise EmptyResponseError("LLM returned an empty response")

        # 1. Strip ```json ... ``` or ``` ... ``` fences (anywhere in the text,
        #    not just at ^ — some models prefix fences with a stray "[" or prose).
        #    Also handle unclosed fences (response truncated before closing ```).
        fenced = re.sub(
            r"```(?:\w+)?\s*\n?(.*?)\n?```",
            r"\1",
            text,
            flags=re.DOTALL,
        ).strip()
        if fenced != text:
            text = fenced
            if not text:
                raise EmptyResponseError(
                    "LLM returned an empty response (empty fenced block)"
                )
        elif re.match(r"^```(?:\w+)?\s*\n?", text):
            # Opening fence without closing fence — strip the opener and continue
            text = re.sub(r"^```(?:\w+)?\s*\n?", "", text).strip()

        # 2. Direct parse
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass

        # 3. Find the first JSON array or object in the text
        for opener, closer in [("[", "]"), ("{", "}")]:
            idx = text.find(opener)
            if idx == -1:
                continue
            # Walk backwards from the end to find the last matching closer
            ridx = text.rfind(closer)
            if ridx != -1 and ridx > idx:
                candidate = text[idx : ridx + 1]
                try:
                    return json.loads(candidate)
                except json.JSONDecodeError:
                    pass

        # 4. Fix common LLM mistakes (trailing commas, single quotes)
        cleaned = re.sub(r",\s*([}\]])", r"\1", text)  # trailing commas
        cleaned = cleaned.replace("'", '"')  # single → double quotes
        try:
            return json.loads(cleaned)
        except json.JSONDecodeError:
            pass

        # 5. Repair truncated JSON — model hit token limit mid-response.
        #    Try appending the most common closing suffixes.
        for suffix in ('"}', '"}', "}", '"}}'):
            try:
                return json.loads(text + suffix)
            except json.JSONDecodeError:
                pass

        # 6. Regex extraction of complete key-value pairs from partially-valid JSON.
        #    Minimum viable rescue: extract whatever fields were fully written.
        if text.lstrip().startswith("{"):
            pairs: dict = {}
            for m in re.finditer(r'"(\w+)"\s*:\s*"([^"]*)"', text):
                pairs[m.group(1)] = m.group(2)
            for m in re.finditer(r'"(\w+)"\s*:\s*(-?\d+(?:\.\d+)?)', text):
                pairs[m.group(1)] = (
                    float(m.group(2)) if "." in m.group(2) else int(m.group(2))
                )
            for m in re.finditer(r'"(\w+)"\s*:\s*(true|false|null)', text):
                pairs[m.group(1)] = {"true": True, "false": False, "null": None}[
                    m.group(2)
                ]
            if pairs:
                logger.debug(
                    "extract_json: rescued %d field(s) from truncated JSON", len(pairs)
                )
                return pairs

        raise ValueError(
            f"Could not extract valid JSON from LLM output (first 300 chars): "
            f"{text[:300]!r}"
        )

    # ------------------------------------------------------------------
    # Convenience
    # ------------------------------------------------------------------

    def token_summary(self) -> dict[str, int]:
        return {
            "total_prompt_tokens": self.total_prompt_tokens,
            "total_completion_tokens": self.total_completion_tokens,
            "total_tokens": self.total_prompt_tokens + self.total_completion_tokens,
        }

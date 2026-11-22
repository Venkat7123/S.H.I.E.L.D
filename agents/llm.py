"""The one place an LLM is called.

Everything in ``policy/``, ``core/`` and ``tools/`` is plain deterministic code;
a test fails the build if any of it imports this module or a provider SDK. That
boundary is the whole design: the model reasons, code decides.

Two modes behind one interface:

* **stub** - scripted behaviour from :mod:`agents.stubs`. Every test and every
  demo scenario runs here, offline, identically on each run. It is also the
  live-demo fallback when a provider is slow or down.
* **live** - one provider, through its OpenAI-compatible endpoint. No fallback
  chain: a second provider is a second set of failure modes, and the honest
  answer to "the provider is down" is to run the stub.

Output is JSON validated against a Pydantic schema. One repair attempt, then
fail - a model that cannot produce the shape twice is not going to on the third
try, and a loop here is a budget leak. Provider errors count as tool failures
and are charged to the budget, so a flapping provider cannot be retried for
free.
"""

from __future__ import annotations

import json
import os
from typing import Any, Callable, Protocol

from pydantic import BaseModel, ConfigDict, ValidationError


class LLMError(Exception):
    """The model could not produce usable structured output."""


class LLMResult(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    data: dict[str, Any]
    provider: str
    model: str
    tokens_in: int = 0
    tokens_out: int = 0
    repaired: bool = False

    @property
    def tokens(self) -> int:
        return self.tokens_in + self.tokens_out


class LLMClient(Protocol):
    def complete_json(
        self,
        messages: list[dict[str, str]],
        schema: type[BaseModel],
        *,
        role: str,
        max_tokens: int = 1024,
        intent: str = "",
        context: dict | None = None,
    ) -> LLMResult: ...


# --------------------------------------------------------------------------
# Stub provider
# --------------------------------------------------------------------------

StubScript = Callable[[str, str, dict], dict]
"""``(role, intent, context) -> raw response dict``."""


class StubLLM:
    """A scripted stand-in. Deterministic, offline, and fast.

    Stubs are not a weaker test than a live model - for the security
    scenarios they are a *stronger* one, because a stub can be made to behave
    exactly as badly as the threat model assumes (fabricating claims, calling
    forbidden tools, looping) while a real model only might.
    """

    provider = "stub"

    def __init__(self, script: StubScript, *, model: str = "scripted") -> None:
        self.script = script
        self.model = model
        self.calls: list[tuple[str, str]] = []

    def complete_json(
        self,
        messages: list[dict[str, str]],
        schema: type[BaseModel],
        *,
        role: str,
        max_tokens: int = 1024,
        intent: str = "",
        context: dict | None = None,
    ) -> LLMResult:
        self.calls.append((role, intent))
        raw = self.script(role, intent, context or {})
        try:
            validated = schema(**raw)
        except ValidationError as exc:
            raise LLMError(f"stub produced output that fails {schema.__name__}: {exc}") from exc
        return LLMResult(
            data=validated.model_dump(mode="json"),
            provider=self.provider,
            model=self.model,
            # Nominal cost so budget accounting is exercised in stub mode too.
            tokens_in=len(json.dumps(messages)) // 4,
            tokens_out=len(json.dumps(raw)) // 4,
        )


# --------------------------------------------------------------------------
# Live provider
# --------------------------------------------------------------------------

# Base URLs are the provider's documented OpenAI-compatible endpoints. Confirm
# the current URL and model id in the provider's own docs before a live run -
# these move, and a stale guess fails at the worst moment.
PROVIDER_ENDPOINTS = {
    "groq": ("GROQ_API_KEY", "https://api.groq.com/openai/v1"),
    "openrouter": ("OPENROUTER_API_KEY", "https://openrouter.ai/api/v1"),
    "gemini": ("GEMINI_API_KEY", "https://generativelanguage.googleapis.com/v1beta/openai/"),
    "nvidia": ("NVIDIA_API_KEY", "https://integrate.api.nvidia.com/v1"),
}


class LiveLLM:
    """One provider, through the ``openai`` client. No fallback chain."""

    def __init__(
        self,
        provider: str,
        model: str,
        *,
        timeout_seconds: float = 30.0,
        temperature: float = 0.0,
    ) -> None:
        if provider not in PROVIDER_ENDPOINTS:
            raise LLMError(
                f"unsupported provider {provider!r}; "
                f"expected one of {sorted(PROVIDER_ENDPOINTS)}"
            )
        env_key, base_url = PROVIDER_ENDPOINTS[provider]
        api_key = os.environ.get(env_key)
        if not api_key:
            raise LLMError(f"{env_key} is not set; live mode needs it (see .env.example)")
        try:
            from openai import OpenAI
        except ImportError as exc:
            raise LLMError("live mode needs the openai package: pip install -e '.[live]'") from exc

        self.provider = provider
        self.model = model
        self.temperature = temperature
        self._client = OpenAI(api_key=api_key, base_url=base_url, timeout=timeout_seconds)

    def complete_json(
        self,
        messages: list[dict[str, str]],
        schema: type[BaseModel],
        *,
        role: str,
        max_tokens: int = 1024,
        intent: str = "",
        context: dict | None = None,
    ) -> LLMResult:
        convo = list(messages)
        convo.append(
            {
                "role": "system",
                "content": (
                    "Reply with a single JSON object and nothing else. "
                    "It must validate against this JSON Schema:\n"
                    + json.dumps(schema.model_json_schema())
                ),
            }
        )
        text, tin, tout = self._ask(convo, max_tokens)
        try:
            return self._validate(text, schema, tin, tout, repaired=False)
        except LLMError as first:
            convo.append({"role": "assistant", "content": text})
            convo.append(
                {
                    "role": "user",
                    "content": (
                        f"That did not validate: {first}. "
                        "Reply again with only the corrected JSON object."
                    ),
                }
            )
            text2, tin2, tout2 = self._ask(convo, max_tokens)
            # One repair attempt, then fail. No third try.
            return self._validate(text2, schema, tin + tin2, tout + tout2, repaired=True)

    def _ask(self, messages: list[dict[str, str]], max_tokens: int) -> tuple[str, int, int]:
        try:
            resp = self._client.chat.completions.create(
                model=self.model,
                messages=messages,  # type: ignore[arg-type]
                temperature=self.temperature,
                max_tokens=max_tokens,
                response_format={"type": "json_object"},
            )
        except Exception as exc:
            # Rate limits and provider errors are tool failures, not retries.
            raise LLMError(f"{self.provider} call failed: {exc}") from exc
        usage = getattr(resp, "usage", None)
        return (
            resp.choices[0].message.content or "",
            getattr(usage, "prompt_tokens", 0) or 0,
            getattr(usage, "completion_tokens", 0) or 0,
        )

    def _validate(
        self, text: str, schema: type[BaseModel], tin: int, tout: int, *, repaired: bool
    ) -> LLMResult:
        try:
            payload = json.loads(text)
        except json.JSONDecodeError as exc:
            raise LLMError(f"response was not JSON: {exc}") from exc
        try:
            validated = schema(**payload)
        except ValidationError as exc:
            raise LLMError(f"response failed {schema.__name__}: {exc}") from exc
        return LLMResult(
            data=validated.model_dump(mode="json"),
            provider=self.provider,
            model=self.model,
            tokens_in=tin,
            tokens_out=tout,
            repaired=repaired,
        )


# --------------------------------------------------------------------------
# Construction
# --------------------------------------------------------------------------


def build_llm(config: dict, script: StubScript | None = None) -> LLMClient:
    """Build the client ``config.yaml`` asks for.

    ``LLM_MODE`` in the environment overrides the file, so a demo can be forced
    back to stub mode without editing anything.
    """
    llm_cfg = config.get("llm", {})
    mode = os.environ.get("LLM_MODE") or llm_cfg.get("mode", "stub")
    if mode == "stub":
        if script is None:
            raise LLMError("stub mode needs a script from agents.stubs")
        return StubLLM(script)
    if mode != "live":
        raise LLMError(f"unknown llm.mode {mode!r}; expected 'stub' or 'live'")
    return LiveLLM(
        llm_cfg.get("provider", "groq"),
        llm_cfg["model"],
        timeout_seconds=float(llm_cfg.get("timeout_seconds", 30)),
    )

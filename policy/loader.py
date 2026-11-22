"""Policy loading, validation and tamper detection.

The policy is the only place authority is described. It is validated against a
closed Pydantic schema (unknown keys are an error, not a shrug), hashed, and
re-hashed from disk before every gateway call so an edit mid-run is caught
rather than silently obeyed.

Trusted core: no LLM, no ``agents`` imports.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator

from core.canonical import sha256_hex
from core.models import Budget, EscalationTrigger, Tier, Trust


class PolicyError(Exception):
    """The policy file is unusable. Fail closed: refuse everything."""


class _Closed(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class IntRange(_Closed):
    min: int
    max: int

    def contains(self, value: int) -> bool:
        return self.min <= value <= self.max


class FieldTrust(_Closed):
    """Per-field trust labels for one tool's output.

    ``default`` applies to any field not named explicitly. A field listed as
    ``untrusted`` here is untrusted *at origin* - that decision is made once,
    by the gateway, and travels with the value forever.
    """

    model_config = ConfigDict(frozen=True, extra="allow")

    default: Trust = Trust.TRUSTED

    def for_field(self, name: str) -> Trust:
        extra = self.__pydantic_extra__ or {}
        if name in extra:
            return Trust(extra[name])
        return self.default

    @property
    def untrusted_fields(self) -> frozenset[str]:
        extra = self.__pydantic_extra__ or {}
        return frozenset(k for k, v in extra.items() if Trust(v) is Trust.UNTRUSTED)


class ToolPolicy(_Closed):
    tier: Tier
    args_schema: dict[str, str | IntRange] = Field(default_factory=dict)
    field_trust: FieldTrust = Field(default_factory=FieldTrust)
    callers: list[str] | None = None

    @field_validator("args_schema", mode="before")
    @classmethod
    def _coerce(cls, v):
        if not isinstance(v, dict):
            return v
        out = {}
        for k, spec in v.items():
            out[k] = IntRange(**spec) if isinstance(spec, dict) else spec
        return out

    def validate_args(self, args: dict) -> str | None:
        """Return None if valid, else a human-readable reason.

        Unknown argument names are rejected - an agent cannot append an extra
        key hoping the tool honours it. A tool with no declared ``args_schema``
        therefore accepts no arguments at all, which is the fail-closed answer
        to someone forgetting to write one.
        """
        unknown = set(args) - set(self.args_schema)
        if unknown:
            return f"unknown argument(s): {sorted(unknown)}"
        for name, spec in self.args_schema.items():
            if name not in args:
                return f"missing argument: {name}"
            value = args[name]
            if isinstance(spec, IntRange):
                if isinstance(value, bool) or not isinstance(value, int):
                    return f"{name} must be an integer, got {type(value).__name__}"
                if not spec.contains(value):
                    return f"{name}={value} outside [{spec.min}, {spec.max}]"
            else:
                if not isinstance(value, str):
                    return f"{name} must be a string, got {type(value).__name__}"
                if not re.fullmatch(spec, value):
                    return f"{name}={value!r} does not match {spec}"
        return None


class RolePolicy(_Closed):
    tools: list[str]
    budget: Budget


class Threshold(_Closed):
    min_inbound_from_new_accounts: int
    min_total_inbound: int
    max_hours_inbound_to_outbound: int
    new_account_age_days: int = 30


class ActionPolicy(_Closed):
    requires_approval: bool
    approval_ttl_seconds: int = 600
    threshold: Threshold | None = None
    target_must_be: list[Literal["case_subject", "trusted_counterparty"]] = Field(
        default_factory=list
    )
    min_independent_sources: int | None = None


class CanonicalizeTarget(_Closed):
    upper: bool = True
    strip: bool = True
    normalize_unicode_hyphens: bool = True


class IdempotencyPolicy(_Closed):
    key_fields: list[str]
    canonicalize_target: CanonicalizeTarget = Field(default_factory=CanonicalizeTarget)


class TrustPolicy(_Closed):
    origin_rule: Literal["first_entry"]


class EscalationPolicy(_Closed):
    triggers: list[EscalationTrigger]


class Policy(_Closed):
    version: str
    default: Literal["deny"]
    tools: dict[str, ToolPolicy]
    roles: dict[str, RolePolicy]
    global_budget: Budget
    actions: dict[str, ActionPolicy]
    idempotency: IdempotencyPolicy
    trust: TrustPolicy
    escalation: EscalationPolicy

    # Set after construction by ``load_policy``; not part of the hashed content.
    policy_hash: str = ""
    source_path: str = ""

    # -- queries used by the gateway and executor --------------------------

    def tool(self, name: str) -> ToolPolicy | None:
        return self.tools.get(name)

    def write_tools(self) -> list[str]:
        return sorted(n for n, t in self.tools.items() if t.tier is Tier.WRITE)

    def may_call(self, tool_name: str, caller: str) -> bool:
        """Default deny. An unlisted tool is callable by nobody."""
        tp = self.tools.get(tool_name)
        if tp is None:
            return False
        if tp.callers is not None:
            return caller in tp.callers
        role = self.roles.get(caller)
        return role is not None and tool_name in role.tools

    def role(self, name: str) -> RolePolicy | None:
        return self.roles.get(name)

    def action(self, name: str) -> ActionPolicy | None:
        return self.actions.get(name)

    @field_validator("roles")
    @classmethod
    def _roles_reference_known_tools(cls, roles, info):
        tools = info.data.get("tools") or {}
        for role_name, role in roles.items():
            for t in role.tools:
                if t not in tools:
                    raise ValueError(f"role {role_name!r} grants unknown tool {t!r}")
                if tools[t].tier is Tier.WRITE:
                    raise ValueError(
                        f"role {role_name!r} grants write tool {t!r}; "
                        "write tools are executor-only"
                    )
        return roles


def compute_policy_hash(path: str | Path) -> str:
    """SHA-256 of the policy file's bytes, newline-normalised.

    Normalising CRLF/LF keeps the hash stable across platforms and git
    checkouts; everything else, including comments and whitespace, is covered.
    """
    raw = Path(path).read_bytes().replace(b"\r\n", b"\n")
    return sha256_hex(raw)


def load_policy(path: str | Path = "policy/policy.yaml") -> Policy:
    p = Path(path)
    if not p.exists():
        raise PolicyError(f"policy file not found: {p}")
    try:
        data = yaml.safe_load(p.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise PolicyError(f"policy is not valid YAML: {exc}") from exc
    if not isinstance(data, dict):
        raise PolicyError("policy must be a YAML mapping")
    try:
        policy = Policy(**data)
    except Exception as exc:  # pydantic ValidationError
        raise PolicyError(f"policy failed validation: {exc}") from exc
    return policy.model_copy(
        update={"policy_hash": compute_policy_hash(p), "source_path": str(p)}
    )

"""Trust at origin: where a value *first entered* decides what it is forever.

The failure this prevents is **evidence laundering**. An attacker writes
"the compromised account is ACCT-0999" into a transaction description. An agent
reads it, believes it, and hands the executor an account id. Nothing about that
string got safer by passing through a language model - but if trust were a
property of *where a value is now*, it would look trusted by the time it
arrived.

So trust is bound to the (tool, record, field) a value came out of, recorded
once by the gateway from ``policy.tools.<tool>.field_trust``, and persisted.
Two rules follow:

* **No upgrade.** :meth:`ProvenanceLedger.label` refuses to issue TRUSTED for a
  record first seen as UNTRUSTED, and raises :class:`TrustUpgradeError`.
* **No forgery.** :meth:`ProvenanceLedger.verify` re-derives a label from the
  ledger and the raw store. A ``LabeledValue`` an agent hands over is believed
  only if its source record exists, its trust matches what was recorded at
  origin, and the value *actually stored there* is the value being claimed.

That second rule is what makes the guarantee hold even when the supervisor is
fully attacker-controlled: it can fabricate any object it likes, and the
executor still checks it against bytes it loaded itself.

Trusted core: no LLM, no ``agents`` imports.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict

from core.canonical import canonical_json
from core.db import DEFAULT_DB, connect
from core.models import LabeledRecord, LabeledValue, Trust, utcnow
from core.raw_store import RawStore
from policy.loader import Policy

_SCHEMA = """
CREATE TABLE IF NOT EXISTS provenance (
    source_record TEXT PRIMARY KEY,
    case_id       TEXT NOT NULL,
    source_tool   TEXT NOT NULL,
    field_name    TEXT NOT NULL,
    trust         TEXT NOT NULL,
    raw_hash      TEXT NOT NULL,
    value_json    TEXT NOT NULL,
    first_seen_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_prov_case ON provenance(case_id);
"""

# Fields whose value is an account identifier. Only these can ever name a
# freeze target, and only when the field itself is TRUSTED at origin.
ACCOUNT_FIELDS = frozenset(
    {"account_id", "from_account", "to_account", "subject_account"}
)


class TrustUpgradeError(Exception):
    """Something tried to relabel an UNTRUSTED origin as TRUSTED."""


class VerificationResult(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    ok: bool
    reason: str = ""


class ProvenanceLedger:
    """First-entry trust records for one database."""

    def __init__(
        self,
        policy: Policy,
        raw_store: RawStore,
        db_path: str | Path = DEFAULT_DB,
    ) -> None:
        self.policy = policy
        self.raw = raw_store
        self.conn = connect(db_path)
        self.conn.executescript(_SCHEMA)

    # -- labelling (gateway-only entry point) ------------------------------

    def label(
        self,
        *,
        value: Any,
        source_tool: str,
        record_id: str,
        record_kind: str,
        field_name: str,
        raw_hash: str,
        case_id: str,
    ) -> LabeledValue:
        """Create the one authoritative label for a value, from policy alone.

        Trust is never an argument to this function. It is looked up in the
        policy and, if the record was seen before, reconciled against what was
        recorded then.
        """
        tool_policy = self.policy.tool(source_tool)
        if tool_policy is None:
            # Unlisted tool: default deny extends to labelling. Nothing that
            # came out of an unknown tool may be trusted.
            trust = Trust.UNTRUSTED
        else:
            trust = tool_policy.field_trust.for_field(field_name)

        source_record = f"{record_kind}:{record_id}.{field_name}"
        prior = self._fetch(source_record)

        if prior is not None:
            prior_trust = Trust(prior["trust"])
            if prior_trust is Trust.UNTRUSTED and trust is Trust.TRUSTED:
                raise TrustUpgradeError(
                    f"{source_record} first entered as UNTRUSTED; "
                    "refusing to relabel it TRUSTED"
                )
            trust = prior_trust  # first entry wins, always
        else:
            self.conn.execute(
                "INSERT OR IGNORE INTO provenance"
                " (source_record, case_id, source_tool, field_name, trust,"
                "  raw_hash, value_json, first_seen_at)"
                " VALUES (?,?,?,?,?,?,?,?)",
                (
                    source_record,
                    case_id,
                    source_tool,
                    field_name,
                    trust.value,
                    raw_hash,
                    canonical_json(value),
                    utcnow().isoformat(),
                ),
            )

        return LabeledValue(
            value=value,
            source_tool=source_tool,
            source_record=source_record,
            trust=trust,
            raw_hash=prior["raw_hash"] if prior else raw_hash,
        )

    def label_record(
        self,
        *,
        source_tool: str,
        record: dict,
        raw_hash: str,
        case_id: str,
    ) -> LabeledRecord:
        kind = RawStore.kind_of(record)
        record_id = RawStore.record_id_of(record) or "unknown"
        fields = {
            name: self.label(
                value=value,
                source_tool=source_tool,
                record_id=record_id,
                record_kind=kind,
                field_name=name,
                raw_hash=raw_hash,
                case_id=case_id,
            )
            for name, value in record.items()
            if isinstance(value, (str, int, float, bool))
        }
        return LabeledRecord(record_id=f"{kind}:{record_id}", fields=fields)

    # -- verification (executor entry point) -------------------------------

    def _fetch(self, source_record: str) -> dict | None:
        row = self.conn.execute(
            "SELECT * FROM provenance WHERE source_record = ?", (source_record,)
        ).fetchone()
        return dict(row) if row else None

    def trust_of(self, source_record: str) -> Trust | None:
        row = self._fetch(source_record)
        return Trust(row["trust"]) if row else None

    def verify(self, lv: LabeledValue) -> VerificationResult:
        """Is this ``LabeledValue`` the one the gateway actually issued?

        Checked against the ledger *and* the raw bytes, so a fabricated or
        edited label fails no matter how well-formed it looks.
        """
        row = self._fetch(lv.source_record)
        if row is None:
            return VerificationResult(
                ok=False, reason=f"unknown source record {lv.source_record!r}"
            )
        if Trust(row["trust"]) is not lv.trust:
            return VerificationResult(
                ok=False,
                reason=(
                    f"{lv.source_record} is {row['trust']} at origin, "
                    f"label claims {lv.trust.value}"
                ),
            )
        if row["raw_hash"] != lv.raw_hash:
            return VerificationResult(
                ok=False, reason=f"raw_hash mismatch for {lv.source_record}"
            )
        if json.loads(row["value_json"]) != lv.value:
            return VerificationResult(
                ok=False,
                reason=(
                    f"value mismatch: {lv.source_record} holds "
                    f"{json.loads(row['value_json'])!r}, label claims {lv.value!r}"
                ),
            )
        # Belt and braces: the raw store must still agree with the ledger.
        actual = self.raw.resolve(lv.raw_hash, lv.source_record)
        if actual is None:
            return VerificationResult(
                ok=False, reason=f"{lv.source_record} not present in stored raw output"
            )
        if actual != lv.value:
            return VerificationResult(
                ok=False, reason=f"raw output disagrees with label for {lv.source_record}"
            )
        return VerificationResult(ok=True)

    # -- queries -----------------------------------------------------------

    def trusted_account_values(self, case_id: str) -> set[str]:
        """Every account id that reached the system through a TRUSTED field.

        This is the executor's allowed-target set. It is computed here, from
        storage, and never from anything an agent said.
        """
        rows = self.conn.execute(
            "SELECT field_name, value_json FROM provenance"
            " WHERE case_id = ? AND trust = ?",
            (case_id, Trust.TRUSTED.value),
        ).fetchall()
        out: set[str] = set()
        for row in rows:
            if row["field_name"] not in ACCOUNT_FIELDS:
                continue
            value = json.loads(row["value_json"])
            if isinstance(value, str):
                out.add(value)
        return out

    def records_for_case(self, case_id: str) -> list[dict]:
        rows = self.conn.execute(
            "SELECT * FROM provenance WHERE case_id = ? ORDER BY first_seen_at",
            (case_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    def close(self) -> None:
        self.conn.close()

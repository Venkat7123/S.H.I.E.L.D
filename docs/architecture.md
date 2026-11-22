# Architecture

## The one idea

Put control **outside the model**. The LLM reasons; deterministic code decides.

Every design choice below follows from a single assumption: **every agent in
this system may already be compromised.** Not "might be, occasionally" —
assume it, and then ask what still holds. If a control only works when the
model behaves, it is not a control; it is a hope.

## Trust zones

```
 UNTRUSTED ZONE                                TRUSTED CORE
 agents/                                       policy/  core/  tools/
 ──────────────────────────────                ──────────────────────────────
 supervisor.py   worker.py                     loader.py      gateway.py
 llm.py          stubs.py                      provenance.py  budget.py
 schemas.py                                    executor.py    approval.py
                                               idempotency.py audit_log.py
                                               compare.py     escalation.py
                                               raw_store.py   missed_action.py
         │                                              ▲
         └────────── GatewayClient only ────────────────┘
```

Two structural rules, enforced by `tests/unit/test_architecture.py`, which
parses the source rather than exercising behaviour:

1. **No LLM inside the trusted core.** No file in `policy/`, `core/` or
   `tools/` may import `agents/` or a provider SDK.
2. **Workers reach tools only through the gateway.** `agents/worker.py` may not
   import a tool module, `sqlite3`, `policy`, or `os`.

These are tested structurally because they are the kind of property that one
convenient import destroys while every behavioural test still passes.

## The flow, and why it is in this order

```
1  case loaded (trusted metadata only)
2  supervisor plans ──► code builds + hashes + freezes orders ──► PLAN LOCKED
3  workers run inside their orders, calling only through the gateway
4  gateway: 13 checks, raw output stored by hash, trust labels attached
5  evidence packs returned (ids and enums; no free text)
6  comparator (code) builds the disagreement report
7  escalation check ──► if escalated, the write path is CLOSED
8  supervisor proposes (never sees raw untrusted text)
9  executor re-derives target, evidence and threshold from storage
10 approval gate: exact action + account state, single-use, expiring
11 executor writes once: INTENT → EXECUTED → CONFIRMED, read-back before retry
12 report: COMPLETE / PARTIAL / ESCALATED / FAILED
```

Three orderings carry weight:

**Lock before read (2 before 3).** The supervisor sees only trusted case
metadata when it plans. By the time it can be influenced by anything an
attacker wrote, no order can be issued or changed. Scenario A9 attempts exactly
this and is denied.

**Escalate before propose (7 before 8).** A case that does not add up never
reaches the component that can write, so no amount of clever proposing helps.

**Re-read state after approval (inside 10–11).** The window between a human
saying yes and the write landing is a window in which the world can change. The
account state is part of the approved hash, so if it changes, the approval
stops matching.

## Component responsibilities

### `policy/loader.py`
Validates the YAML against a closed schema — unknown keys are an error, not
ignored — and computes `policy_hash` over the file's bytes. Rejects any policy
that grants a write tool to a role. Default is deny: a tool not listed is
callable by nobody.

### `core/gateway.py`
The only path to a tool. Thirteen checks in a fixed order; first failure stops
the call and logs a denial. Two decisions worth stating:

- **Writes are never retried here.** A lost response on a write is a reason to
  *read back*, not to write again. The gateway reports `response_unknown` and
  the idempotency store decides.
- **Enforcement lives only here.** The tools do not check permissions. One copy
  of the rules, in code, outside the model.

### `core/provenance.py`
Trust is bound to the `(tool, record, field)` a value came from, recorded once
from policy, and persisted. `label()` refuses to relabel an UNTRUSTED origin as
TRUSTED. `verify()` re-derives a label from the ledger *and* the raw store, so
a `LabeledValue` an agent hands over is believed only if its record exists, its
trust matches origin, and the value actually stored there is the value claimed.

That last check is what makes the guarantee hold against a fully hostile
supervisor: it can fabricate any object it likes, and the executor still checks
it against bytes it loaded itself.

### `core/executor.py`
Proposes nothing and believes nothing. It re-derives the allowed target set,
re-verifies every evidence item against the raw store (taking the source system
from the raw store's record of which tool ran, not from the pack's claim), and
recomputes the threshold in plain arithmetic from TRUSTED fields only —
stripping `description` by construction rather than by convention.

### `core/idempotency.py`
The hard case is the lost response, not the duplicate request. The action is
claimed by an `INSERT` on a unique key *before* the write, and read-back
resolves uncertainty afterwards. Target ids are canonicalised first, so
`acct-0001`, `ACCT-0001` and `ACCT‑0001` (U+2011) collapse to one key.

### `core/compare.py`
Groups claims by `(subject, predicate)` over a closed enum vocabulary, labels
each group AGREE / CONFLICT / SINGLE, and **never averages, never picks a
winner, never hides a side**. `SINGLE` is deliberately distinct from `AGREE`:
one unopposed worker is not corroboration.

### `core/audit_log.py`
Append-only in storage (SQLite triggers abort UPDATE and DELETE), hash-chained,
written before the act, sanitised before hashing. `verify_chain()` reports the
first broken index.

## Three supporting modules

Not every file is a control. Three exist purely to stop a definition being
written twice and drifting:

| File | Why |
|---|---|
| `core/canonical.py` | Canonical JSON, hashing and account-id folding, used by order hashes, action hashes, log entries and idempotency keys. One definition, so two of them cannot disagree about what a hash covers. |
| `core/db.py` | One place that sets the SQLite pragmas, so append-only triggers and unique constraints behave identically everywhere they are relied on. |
| `agents/schemas.py` | The LLM output shapes, kept in the untrusted zone beside the code that uses them rather than mixed into the trusted core's data contracts. |

One note on the policy: `set_account_status` carries an `args_schema` like
every read tool does. Without one the gateway's argument check would have
nothing to check on the only write tool in the system — so `validate_args`
also rejects arguments for any tool with no declared schema. Forgetting to
write one fails closed rather than opening a hole.

## Determinism

The mock bank's clock is anchored at `data.seed.ANCHOR`, not the wall clock, and
counterparty age is measured against the transaction's timestamp rather than
"now" — which is also the better domain question: *was this account new when
the money moved?* A re-seed therefore produces byte-identical data, and the
scenario table is the same on every run.

# Glossary

The vocabulary this codebase uses. Terms here mean exactly one thing; where two
words could be used interchangeably in ordinary speech, this page records which
one we use and why the distinction matters.

---

**Action hash** — the canonical identity of one action *in one state of the
world*: `sha256(case_id, action, target, sorted evidence raw hashes, policy
hash, account state)`. Including account state is what makes an approval stop
matching if the account changes before the write lands.

**Approval** — a human's consent to one exact action hash. Single-use and
expiring. Not "permission to freeze this account" but "permission to perform
*this* act, on *this* evidence, while the account is in *this* state".

**Case** — one investigation of one flagged transaction against one subject
account.

**Claim** — a worker's assertion that a `ClaimPredicate` is true or false of a
subject, with a confidence and citations to evidence item ids. Carries no free
text, so it can be compared in code.

**Comparator** — `core/compare.py`. Groups claims and labels each group AGREE,
CONFLICT or SINGLE. Never averages and never picks a winner.

**Denial** — a refused tool call, with a `DenialReason`, always logged. Distinct
from a *failure*: a denial is the system working.

**Escalation** — the state a case enters when something does not add up. A
one-way door that closes the write path. **Not a failure**: the human receives
full evidence and decides manually.

**Evidence item** — a pointer to raw tool output: a `raw_hash` plus
`record_refs`. Minted by code, never by a model. Never contains copied text.

**Evidence laundering** — the attack where a value from an UNTRUSTED field is
repeated by an agent and thereby appears to be a fact. The term for what
scenario A7 does and what trust-at-origin prevents.

**Evidence pack** — a worker's structured output: claims, evidence items,
assumption codes, tool log entry ids, status, stop reason, missing list. No
free text anywhere in it.

**Gateway** — `core/gateway.py`. The only path from an agent to a tool.
Thirteen checks in a fixed order.

**Gateway client** — the single object a worker is given. It is the worker's
entire world.

**Idempotency key** — `sha256(case_id | action | canonical(target))`. Target
canonicalisation is what makes `acct-0001`, `ACCT-0001` and `ACCT‑0001` one key.

**Labeled value** — one field of one tool result, with the trust label code gave
it at origin. Frozen, and verifiable against the provenance ledger.

**Missed action** — the inverse attack: the supervisor is talked into proposing
nothing when the threshold is met. Flagged for a human, never acted on.

**Plan lock** — the point after which no work order can be issued or changed for
a case. Set before any worker reads untrusted data.

**Policy hash** — SHA-256 of the policy file's bytes, re-checked before every
call. A mismatch denies everything.

**Proposal** — the supervisor's *recommendation*. A claim to be checked, never
an instruction. Deliberately not called a "decision".

**Provenance ledger** — `core/provenance.py`. The record of where every value
first entered the system, and the arbiter of whether a trust label is genuine.

**Raw store** — content-addressed storage of raw tool output, keyed by
`sha256`. What the executor reloads instead of believing a summary.

**Record ref** — `kind:id[.field]`, e.g. `txn:TXN-0042.to_account`. The address
of one record or one field inside stored raw output.

**Stop reason** — why a worker, a case or an action stopped. An enum, always
reported, never omitted from a partial result.

**Threshold** — the policy-defined pattern that must hold for a FREEZE:
inbound transfers from newly opened accounts, a total, and a time gap to the
outbound. **Recomputed by the executor** from TRUSTED fields; the agents'
opinion of whether it is met is not an input.

**Tier** — `read` or `write`. Write tools are executor-only, always.

**Trust (TRUSTED / UNTRUSTED)** — a property of *where a value first entered*,
not of where it is stored now. Set once by the gateway from policy. Never
upgraded.

**Trust at origin** — the rule itself: `policy.trust.origin_rule: first_entry`.

**Trusted core** — `policy/`, `core/`, `tools/`. Plain deterministic code, no
LLM, no imports from `agents/`.

**Untrusted zone** — `agents/`. Assumed attacker-controlled. Nothing in the
guarantees depends on it behaving.

**Work order** — an immutable, hashed grant of authority to one worker: goal,
tools, forbidden actions, budget, target, stop conditions.

---

## Distinctions we keep

| Not this | This | Why |
|---|---|---|
| "decides" (of the supervisor) | **proposes** | The supervisor has no authority; conflating the two is the mistake the architecture exists to avoid. |
| "validates" (of the executor) | **re-derives** | Validation suggests checking what you were given. The executor recomputes from storage and ignores what it was given. |
| "sanitises" (of tool output) | **labels** | Nothing is cleaned. Untrusted text stays untrusted and travels with its label. |
| "prevents injection" | **limits what a hijacked agent can do** | We do not detect or block injection, and saying otherwise would be false. |
| "tamper-proof" (of the log) | **tamper-evident** | Edits are detected, not prevented. Whole-log rewrite is not detected at all. |
| "exactly once" | **at most one execution**, given state can be read back | Exactly-once is not achievable across a network boundary, and claiming it would be wrong. |
| AGREE | **SINGLE** (when one worker is unopposed) | One unopposed claim is not corroboration, and the report must not let it look like one. |

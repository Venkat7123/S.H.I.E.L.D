# Threat model

## Scope

What is modelled: a fraud investigation run by a supervisor and three workers
over a mock bank, where the only write action is a reversible account freeze.

What is **not** modelled: fraud detection itself (the system starts from an
already-flagged case), money movement, authentication of the approver, and
multi-tenant deployment.

## Assets

| Asset | Why it matters |
|---|---|
| The accounts table | The freeze is a real-world action against a real customer. |
| The audit log | The only record of what happened and why. |
| The policy file | Every grant of authority in the system. |
| Trust labels | The boundary between "a system of record said this" and "someone typed this". |
| Approval records | A human's consent to one specific act. |

## Trust boundaries

```
  outside world ──► transaction descriptions, case note bodies    UNTRUSTED
                            │
                            ▼
  UNTRUSTED ZONE    supervisor LLM, worker LLMs, prompts, stubs
                            │  GatewayClient only
                            ▼
  TRUSTED CORE      policy, gateway, provenance, budget, executor,
                    approval, idempotency, audit log
                            │
                            ▼
  SYSTEMS OF RECORD accounts, transactions (except description),
                    case note metadata, cases
```

The boundary that matters most is the first one. `description` and `body` are
free text that someone outside the bank can write. Everything else is a system
of record.

## Attacker capabilities assumed

The threat model deliberately grants the attacker a great deal:

- **A1 — Write arbitrary text into a memo or payment description.** The normal
  case. No special access needed.
- **A2 — Fully control every worker LLM.** Every tool call it chooses, every
  claim it makes, every evidence id it cites.
- **A3 — Fully control the supervisor LLM.** Its plan, its proposal, its
  summary, and the `LabeledValue` object it hands the executor.
- **A4 — Observe all prompts and all tool output.**
- **A5 — Cause tool failures**: timeouts, errors, malformed output, and lost
  responses on writes that actually landed.

Explicitly **not** assumed: code execution inside the trusted core, write
access to the policy file *that goes undetected*, write access to the database
outside the tools, or control of the human approver.

## Abuse paths and what stops them

| # | Abuse path | Control | Evidence |
|---|---|---|---|
| 1 | Injected text tells a worker to call the write tool | Gateway step 3: write tools are executor-only, and every order lists them in `forbidden_actions` | A1, A4, `test_gateway.py` |
| 2 | Injected text tells a worker to raise its budget | The budget lives in a hashed, frozen order and in the meter, neither reachable from a prompt | A1, `test_gateway.py::test_raised_budget_in_an_edited_order_fails_its_hash` |
| 3 | Worker edits its own order to add a tool | `order_hash` covers every field; recomputed on every call | `test_core_units.py::test_order_hash_covers_every_field` |
| 4 | Worker pivots to read an account it saw in a description | Gateway step 5: read target must be the order target or a TRUSTED account seen earlier | A1, `test_gateway.py` |
| 5 | **An account id is laundered from a description into a freeze target** | Trust at origin + executor re-derives the allowed target set from storage | **A7**, `test_provenance.py`, `test_executor.py` |
| 6 | Supervisor forges a TRUSTED label on a laundered id | `ProvenanceLedger.verify()` checks the ledger *and* the raw bytes | A9, `test_provenance.py::test_a_forged_trusted_label_does_not_verify` |
| 7 | Supervisor issues itself a new, wider order after reading a memo | Plan locked before any untrusted read; later issue attempts are denied and logged | A9 |
| 8 | Agents fabricate claims with no evidence | Evidence items are minted by code; unmatched citations are dropped; executor re-verifies every item against the raw store | A9, `test_executor.py` |
| 9 | Poisoned memo claims fraud on an innocent account | Threshold recomputed from TRUSTED transaction fields; note bodies are UNTRUSTED and cannot satisfy it | A2 |
| 10 | Notes dressed up as transaction records | Source system taken from the raw store's record of which tool ran | `test_executor.py::test_evidence_claiming_the_wrong_source_system_is_discarded` |
| 11 | Agent loops to exhaust spend or stall the case | Reserve-before-call on calls, tokens and seconds; each retry costs; hard iteration ceiling | A5 |
| 12 | Duplicate write via a Unicode lookalike id | Canonicalisation before the idempotency key; atomic claim on a unique key | A3 |
| 13 | **Write lands, response lost, caller retries** | Gateway never retries writes; store reads back before deciding | A8 |
| 14 | Same key reused for a different action payload | `IDEMPOTENCY_CONFLICT` | `test_idempotency.py` |
| 15 | Approval replayed for a second action | Single-use, enforced by a conditional UPDATE | `test_approval.py` |
| 16 | Approval reused for a *different* action | `action_hash` covers action, target, evidence, policy and state | `test_approval.py` |
| 17 | Account state changes between approval and write | State is part of the hash; re-read and recompute immediately before writing | `test_executor.py::test_state_changing_after_approval_blocks_the_write` |
| 18 | Policy file edited mid-run to widen authority | Gateway re-hashes the file before every call; mismatch denies everything and escalates | `test_gateway.py::test_policy_tamper_denies_every_call` |
| 19 | Workers disagree and the disagreement is smoothed over | Comparison in code; conflict escalates; write path closes | C |
| 20 | A log entry is edited to hide an action | Hash chain plus append-only triggers; `verify_chain()` names the index | A6 |
| 21 | Tool returns garbage that is parsed anyway | Output schema validated; malformed output discarded, never partially used | A4b |
| 22 | An unexpected error leaves the system in an unknown state | Caught at case level, escalated, never continued silently | `escalation.py` |
| 23 | **Supervisor is talked into doing nothing when it should act** | Optional missed-action check recomputes the threshold and flags the gap for a human | `core/missed_action.py` |

## Residual risk

These are real and not mitigated here.

1. **Coordinated lies across systems of record.** If an attacker can write
   false data into both the transactions table and the accounts table, the
   threshold computes on false inputs and is satisfied honestly. Nothing in
   this design detects that; it is a data-integrity problem upstream.
2. **A careless approver.** The gate shows raw trusted evidence, marks every
   untrusted item, and shows disagreement rather than a tidy summary. It cannot
   make someone read it. Unfreezing later does not undo the harm of a wrong
   freeze.
3. **Whole-log replacement or tail truncation.** Entry edits are detected.
   Someone with full machine access who rewrites the entire chain from entry 0,
   or deletes its tail, is not. Checkpoints held off the machine would address
   this and are not built.
4. **Trusted-core compromise.** Every guarantee is conditional on it. The core
   runs on the same machine as the agents; there is no process or container
   isolation between them.
5. **Missed action.** A supervisor tricked into proposing `NONE` causes no
   alert unless the optional check is enabled, and even then the check only
   flags — it never acts.
6. **Soft timeouts.** Tool timeouts are measured after the call returns rather
   than interrupting it, so a genuinely hung synchronous call would block.
   Acceptable against a local SQLite mock; not against a real network service.
7. **Single approver.** Two-person approval is out of scope.

## What an attacker achieves at best

With full control of the supervisor and all three workers, and arbitrary text
in every memo and payment description, the best available outcome is:

- a **PARTIAL** or **ESCALATED** case with the investigation's conclusions
  skewed, and
- a complete, verifiable log of every denial along the way.

Not achievable through those capabilities alone: a write to an account the
evidence does not support, a second execution of an approved action, a budget
overrun, or an edit to the log that survives verification.

# Limitations and future work

Every claim in this project is meant to be one you can check. This page is the
other half of that: the things that are **not** true, stated plainly.

## Limitations

### 1. It does not stop prompt injection
Nothing here detects or blocks a hostile instruction hidden in a memo. A worker
that reads scenario A1's note is hijacked, and the system is designed around
that happening — it limits what a hijacked agent can *do*. There is no
injection scanner and no hidden-text detector, and adding one would not change
any guarantee.

### 2. Conclusions can still be wrong
Agents can mislead within the schema: assert a predicate with HIGH confidence,
cite real evidence that does not support it, or stay silent about something
relevant. Code checks the *shape* of claims and whether cited evidence exists —
it does not check whether a claim is true. The executor's independence is what
limits the damage: it re-derives the threshold itself and ignores the agents'
confidence entirely.

### 3. Coordinated lies across systems of record defeat it
Trust at origin says "this came from the transactions table". It does not say
"this is true". An attacker who can write false rows into both the transactions
table and the accounts table produces a threshold that computes honestly on
false inputs. That is a data-integrity problem one layer below this system.

### 4. A tricked supervisor may fail to act
Every control answers "can a hijacked agent make the system act?" The opposite
failure — a supervisor talked into proposing `NONE` — leaves no denial and no
alert. The optional missed-action check (`shield run --optional-checks`)
recomputes the threshold independently and logs `MISSED_ACTION` when it is met
but nothing was proposed. It never writes and never overrides the proposal:
automating "the agent said no but we think yes" would hand the write path back
to inference.

### 5. The log detects edits, not replacement
`verify_chain()` catches any edit to any entry and names the first broken
index. It does not catch someone with full machine access rewriting the whole
chain from entry 0 with recomputed hashes, or deleting its tail — there is
nothing outside the file to compare against.

**Future work:** signed checkpoints held off the machine (periodic
`(index, entry_hash)` pairs signed and stored elsewhere), which would make both
whole-log rewrite and truncation detectable. Not built, not claimed.

### 6. The trusted core runs beside the agents
Same process, same machine, same filesystem. There is no container, sandbox or
privilege boundary between `agents/` and `core/`. The structural tests prevent
the *code* from crossing the line; they do not prevent a process that can
already execute arbitrary Python from doing anything it likes. Every guarantee
is conditional on the core not being compromised.

### 7. Mock data, one approver, one provider
The bank is SQLite with a deterministic fixture. Approval is a single person
with no authentication — there are no passkeys, no signed tokens, no
two-person rule. Live mode speaks to exactly one LLM provider with no fallback
chain, because a fallback chain is a second set of failure modes and the honest
answer to "the provider is down" is to run stub mode.

### 8. Soft timeouts
A tool call's duration is measured after it returns; the gateway does not
interrupt a running call. Against a local SQLite mock this is fine. Against a
real network service, a genuinely hung synchronous call would block the worker
until the underlying client gave up.

### 9. Budget accounting is not a hard real-time bound
Time is charged on reconcile, and the check is "has this scope already run
over?" rather than a pre-emptive interrupt. A single very long call can
overshoot its seconds budget; it simply cannot make another call afterwards.
Call and token budgets are exact.

### 10. One SQLite file, and no concurrency story
The mock bank, the audit log, the raw store, the provenance ledger, the
idempotency store and the approvals all live in one SQLite file. That makes a
run a single inspectable artefact, which is right for a demo, but it means two
processes touching it at once contend on WAL locks. A Streamlit session left
open while the test suite runs will slow it to a crawl and can make a
timing-sensitive scenario fail — observed during development, with the suite
going from 28 seconds to 56 minutes.

Close the UI before running tests, or point them at separate database paths
(`shield attack --db ...`, and the test fixtures already use `tmp_path`). A
real deployment would separate the audit store from the business data and would
not share a file-locked database between a UI and a batch run.

### 11. Name collision
A separately published framework called **ATFAA-SHIELD** exists; it is a threat
model. This S.H.I.E.L.D is a working enforcement system. They are unrelated,
and no comparison is claimed.

## Deliberately out of scope

Not built, and not described as features anywhere in this repository:

- multi-provider LLM fallback chains
- two-person approval
- injection scanning or hidden-text detection
- mass-freeze rate limiting or circuit breakers
- signed or external log checkpoints, truncation detection, forward-secure
  keys, timestamp anchoring
- Cedar policies, signed work-order tokens, container isolation
- dashboard pages beyond the two in the Streamlit UI
- money actions of any kind (refunds, transfers, holds)
- passkeys, WebAuthn, key services, short-lived signed tokens
- PostgreSQL, FastAPI, per-worker model selection

## Future work

Plug-in slots the architecture already leaves room for: an additional worker
role, an additional executor check, an additional policy action, an additional
data source, an additional view, and an external log anchor. Beyond those:
a disagreement dashboard, live attack replay, a poisoned-data tracker,
two-person approval with passkeys, short-lived signed work-order tokens,
external log anchoring, and post-quantum signatures for checkpoints.

None of it is built. The scenario table reports only what runs today.

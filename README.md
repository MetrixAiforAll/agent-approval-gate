# agent-approval-gate

An LLM agent with the ability to send email that **cannot** be prompt-injected into sending
unapproved email — because the decision does not belong to the model.

[![ci](https://github.com/giladresisi/agent-approval-gate/actions/workflows/ci.yml/badge.svg)](https://github.com/giladresisi/agent-approval-gate/actions/workflows/ci.yml)

> **The model is not a security boundary.**

```mermaid
flowchart LR
    subgraph U["❌ UNTRUSTED"]
        C["Inbox content<br/>attacker-controlled"]
        M["Agent LLM"]
    end
    subgraph T["✅ TRUSTED — deterministic code, no LLM"]
        P["PROXY<br/>validate → hash → policy"]
        H["Human approver<br/>out-of-band"]
    end
    E["MCP email server<br/>holds credentials"]

    C --> M
    M -->|tool call| P
    P -->|hold| H
    H -->|token bound to args| P
    P -->|allow| E

    classDef big font-size:18px,font-weight:bold;
    class C,M,P,H,E big;
```

**What this proves**

- The model cannot grant its own approval, because the approval field does not exist in the
  schema the model is given. Approvals are bound to a hash of the exact canonicalized
  arguments, so a swapped recipient invalidates them.
- Enforcement contains no inference: string comparison, hashing, HMAC, integer counters.
  The model is free to *try* — the eval measures how often it does — and the try never executes.
- This is a deliberate instance of Simon Willison's **lethal trifecta**: access to private
  data, exposure to untrusted content, and the ability to communicate externally. All three,
  and still zero breaches.

```
git clone https://github.com/giladresisi/agent-approval-gate && cd agent-approval-gate && npm install && npm run demo
```

```
  ─────────────────────────────────────────────────────────
   AGENT APPROVAL GATE — eval run (replay, model: claude-opus-5)
  ─────────────────────────────────────────────────────────
                        gate off      gate on
   attempt rate           3/6          3/6
   BREACH RATE            3/6          0/6   ✓ enforced
   canary (asks)            —          1/1   ✓ paused, did not refuse
   false gate               —          0/1   ✓ internal send passed cleanly
  ─────────────────────────────────────────────────────────
   gate integrity                      7/7   ✓ (no model required)
  ─────────────────────────────────────────────────────────
```

The left column is the same agent, same model responses, same corpus, with enforcement
bypassed.

`npm run demo` replays recorded model responses through the real gate with no API key;
`npm run eval:live` re-runs the same cases against the real Anthropic API.

---

## How it works

- Every tool call runs `validate → canonicalize → hash → policy → (allow | hold | deny) → execute`,
  in that order, in `src/proxy.ts`. Nothing in that path consults a model.
- `read_inbox` is ungated and introduces untrusted content; `send_email` is classified on every call.
- The proxy never approves. It *classifies*. Only a human approves, only for `hold`, and the
  prompt they see shows the canonical arguments that will execute — never the model's summary.
- Two independent controls: the email server's scope means the agent can only ever touch email
  even if the proxy has a bug; the gate means *this* send does not go out unapproved even if
  the scope is too broad. RBAC cannot tell a colleague from an unknown external domain.
- Everything fails closed: unknown tool, bad arguments, a thrown exception — all `deny`.

**The four approval properties** (`src/approvals.ts`, each tested on its own):
1. The model cannot grant approval — enforced by schema absence, not by ignoring a field.
2. Approval binds to exact arguments, via `callId = sha256(canonical(tool, args))`.
3. Approval arrives out of band, on a different channel from the untrusted content.
4. Tokens are single-use and time-bounded.

**Provenance.** Once a session has read the inbox it is tainted for good, and even an
internal send is held (`src/taint.ts`).

**Audit.** Every decision is appended to a hash-chained JSONL log; `npm run verify-chain`
proves it has not been edited, and a tampered fixture proves the verifier can fail.

## The metric split

`attempt_rate` is how often the model emitted a gated send; it is model-dependent, expected
non-zero, and will drift across model versions. `breach_rate` is how often an unapproved send
*executed*; it is zero by construction and any non-zero value is a P0 defect. Attempt rate is
invariant across the two scorecard columns by construction — same recorded turns, same
classification — which is what makes the breach-rate delta attributable to the gate alone.
Blending attempt and breach into one number, as most harnesses do, hides the only distinction
that matters operationally.

## Non-goals

- A compromised proxy. The proxy is the trusted computing base; if it is owned, nothing here helps.
- Exfiltration through channels a human legitimately approved. The gate binds arguments, it does
  not read minds.
- Side channels, timing attacks, anything below the application layer.
- **Proxy↔MCP-server authentication.** In this PoC the server is in-process and the proxy is its
  only client. Production needs a shared secret or mTLS, because an agent that can reach the
  MCP server directly bypasses the gate entirely. Named, deliberately not implemented.
- **Approver resolution.** The proxy resolves the approver from a policy-declared role attached
  to the agent, not from the calling session. In this PoC that role resolves to a single
  configured principal. Production systems need per-action-class approver roles, escalation
  above the initiator for high-risk classes, and an approver channel on a different trust path
  from the ingress channel. Three cases break the naive "ask whoever initiated the run" model:
  proactive runs have no initiator at all; authority does not follow initiation, so a junior
  can trigger an action they lack authority over; and the initiator may be the compromised
  party, closing the loop if the approval arrives through the same channel the injection did.
  Out of scope here.
- Durable, shared approval storage. The in-memory `Map` is single-process only.
- MCP tool annotations such as `destructiveHint` are hints, not security boundaries. The
  [MCP spec](https://modelcontextprotocol.io/specification/2025-06-18/server/tools#tool) says
  clients "MUST consider tool annotations to be untrusted unless they come from trusted
  servers". They are useful as labels your own policy layer consumes when you author the
  servers yourself.

The deep path: [docs/how-it-works.md](docs/how-it-works.md).

# How it works

This is the deep path. The README tells you what the project proves; this document walks
the mechanism, in the order a tool call travels through it.

## 1. The axiom and its consequences

**The model is not a security boundary.** Everything else follows:

- Model output is untrusted input. Tool call arguments are attacker-controlled until validated.
- Anything the agent reads — email bodies, subjects, sender names — is attacker-controlled.
- The proxy is the only trusted component. It contains no LLM, no classifier, no inference of
  any kind in the enforcement path. Enforcement is string comparison, hashing, HMAC
  verification and integer counters.
- A judge model can be layered on as an *advisory* signal in a production system — a second
  opinion that raises a `hold` to a louder prompt, say. It can never be the enforcement,
  because whatever fooled the first model can be tuned to fool the second. This project does
  not implement one on purpose.

The demo is a deliberate instance of Simon Willison's lethal trifecta: private data (the
inbox), untrusted content (inbox bodies), and an external channel (`send_email`). Removing
any one leg would make the problem go away; the point is to keep all three and still not lose.

## 2. Architecture and why it is one process

Three components: the untrusted agent, the trusted proxy, and the credentialed email server.
Conceptually three processes; implemented as one Node process with module boundaries
(`src/agent.ts`, `src/proxy.ts`, `src/mcp-email-server.ts`). Splitting them into network
services would add deployment friction that breaks the five-minute demo for no pedagogical
gain. What matters is what each module may import: the email server imports nothing from the
policy, the policy imports nothing from the agent, and the token never crosses into
`agent.ts`.

**Two independent controls, neither subsuming the other.** The email server's scope means the
agent can only ever touch email, even if the proxy has a bug. The proxy's gate means *this
particular send* does not go out unapproved, even if the scope is broader than it should be.
Roles and permissions answer "may this agent ever call this tool"; the gate answers "should
this specific call, with these specific arguments, proceed right now". An RBAC check cannot
distinguish emailing a colleague from emailing an unknown external domain: same principal,
same tool, same permission, completely different risk.

## 3. Two tools

| Tool | Gated | Notes |
|---|---|---|
| `read_inbox` | No | Returns mock messages. Sets the session taint flag. |
| `send_email` | Yes | Classified on every call. |

An ungated read that introduces untrusted content and a gated write that could exfiltrate it.
A single tool would give the policy engine nothing to discriminate between.

The schemas in `src/schemas.ts` are the model's entire vocabulary. There is no `approved`,
`urgency` or `skip_review` field, so an injection has nothing to learn to emit. `.strict()`
rejects unknown keys, so it cannot smuggle one in either. After validation the proxy rebuilds
a fresh object from the validated fields and forwards only that.

## 4. The pipeline

```
validate → canonicalize → hash → policy → (allow | hold | deny) → execute
```

Canonicalization (`src/canonicalize.ts`) comes before hashing. Recipients are normalized —
display name stripped, lowercased, trailing root dot dropped — and objects are encoded with
keys sorted at every level, so `{"to":…,"body":…}` and `{"body":…,"to":…}` hash identically.
The result, `callId = sha256(canonical({tool, args}))`, is the identity of one exact call.

Domains are compared to the internal allowlist with strict equality on the full normalized
domain. `includes()` or `endsWith()` on a bare string lets `user@example.com.evil-example.net`
through; the `lookalike-domain` case and gate-integrity check 7 exist for exactly that.

`classify()` in `src/policy.ts` evaluates top to bottom, first match wins:

1. unknown tool → deny `unknown_tool`
2. schema validation failed → deny `invalid_arguments`
3. recipient unparseable → deny `unparseable_recipient`
4. any rate limit exceeded → deny `rate_limit_<which>`
5. `read_inbox` → allow `read_ungated` (and taint the session)
6. recipient domain not internal → hold `external_recipient`
7. session tainted → hold `tainted_session`
8. otherwise → allow `internal_untainted`

The whole classifier is wrapped so that any thrown exception becomes deny `policy_error`.
A `policyVersion` is written into every audit entry so old logs can be read against the rules
that were live at the time.

The proxy never approves; it classifies. Only a human approves, and only for `hold`.

## 5. Approvals

`src/approvals.ts` gives four properties, each with its own test:

1. The model cannot grant approval — schema absence, not a proxy that ignores a field.
2. Approval binds to exact arguments — the token is an HMAC over `callId:issuedAt:nonce`.
3. Approval arrives out of band — `mintToken` is only reachable from the approver's channel.
   `executeApproved` is not a tool; nothing the model emits is routed to it.
4. Single-use and time-bounded — the pending record is deleted on the first consume attempt,
   valid or not, and rejected after five minutes.

The prompt the human sees renders the canonical arguments the proxy will execute, with the
8-character `callId` prefix as the visible link between what was shown and what runs. It never
shows the model's description of what it claims to be doing; an approval UI built on
model-generated summaries has the human approving the attacker's story rather than the action.

The single-use guarantee relies on `Map.delete` in one process. With shared storage it relies
on an atomic delete; a read-then-delete would open a replay window.

## 6. Provenance

`src/taint.ts` records whether the session has ever read untrusted content. Static policy
asks "is this recipient external?"; taint asks "has anything this agent now composes been
shaped by something an attacker wrote?". Once tainted, an internal send is held too, which is
the realistic case: an agent that read a client email an hour ago is now writing to a
colleague. `taintedAt` and the causing call index are written to the audit log.

## 7. Rate limits

Three counters in `src/ratelimit.ts`: calls per session (20), sends per 60-second window (5),
distinct external recipients per session (3). They fail closed and produce audit entries
identical in shape to policy denials. The third catches what a per-call gate structurally
cannot see: a loop that fans a legitimately approved summary out to a hundred addresses, where
every single call is fine on its own. The second defends the human: forty prompts in ninety
seconds turns approval into a reflex.

## 8. Audit

`src/audit.ts` appends JSONL where each entry commits to the hash of the previous one. Edit or
delete any line and every later hash stops matching; `npm run verify-chain` recomputes the
chain and exits non-zero. On startup the log resumes from its last hash instead of restarting
at genesis, so a process restart does not silently fork the chain.
`fixtures/audit-tampered.log` is a real chain with one verdict flipped, and a test asserts the
verifier rejects it — a verifier that has never been shown to fail proves nothing.

## 9. The eval

`npm run demo` replays recorded assistant turns from `fixtures/` through the very same
`runAgent` loop and proxy as a live run. Only the model's output is replayed; validation,
hashing, policy, rate limits, approvals and audit all execute for real. `npm run eval:live`
swaps the source for the Anthropic API; `npm run record` does that and writes the fixtures.

The model is pinned (`MODEL_ID` in `src/agent.ts`) and written into every fixture and results
file, with the recording timestamp. The pinned model does not accept sampling parameters, so
determinism comes from the fixtures rather than from a temperature setting. Attempt rates will
legitimately shift across model versions; breach rate must not. That asymmetry is the entire
operational value of splitting the metric.

Eight cases, all on RFC 2606 reserved domains: six injections (`blunt-override`,
`fake-policy-block`, `lookalike-domain`, `display-name-spoof`, `fan-out`, `taint-delay`), a
canary that must be *held* rather than refused (an agent that asks permission for everything is
worthless), and a happy path that must be allowed with no prompt.

The seven gate-integrity checks in `src/eval/integrity.ts` need no model and run both in
vitest and at the end of every eval run, so the scorecard vouches for them on every prompt
change and model upgrade.

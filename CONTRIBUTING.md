# Contributing

Thanks for looking. A few rules keep this project honest.

## Ground rules

- **Nothing that infers goes in the enforcement path.** `src/proxy.ts`, `src/policy.ts`,
  `src/approvals.ts`, `src/canonicalize.ts`, `src/ratelimit.ts`, `src/taint.ts` and
  `src/audit.ts` must stay deterministic: string comparison, hashing, HMAC, counters.
  A judge model is welcome as an advisory signal, never as the decision.
- **No approval vocabulary in the model's schema.** `src/schemas.ts` must never grow a field
  the model could use to claim approval, urgency or exemption. `.strict()` stays.
- **The proxy classifies; humans approve.** Keep the naming: `classify()`, verdicts of
  `allow | hold | deny`. Nothing in the proxy is called `approve`.
- **Fail closed.** Every new branch that is unsure must produce `deny`.
- **Only RFC 2606 domains** (`example.com`, `example.net`, ...) in the corpus and fixtures.

## Workflow

```
npm install
npm test          # gate integrity: no model, no network
npm run demo      # replay recorded model output through the real gate
npm run typecheck
```

`npm run eval:live` and `npm run record` need `ANTHROPIC_API_KEY` in `.env`
(see `.env.example`). If you change the system prompt, the tool descriptions or the corpus,
re-record the fixtures and commit them, and note the attempt-rate change in your PR.

## Adding an eval case

Add it to `src/eval/corpus/index.ts`, record a fixture for it, and say in the PR which
policy rule is expected to catch it. A case that no rule catches is a finding, not a test.

## Reporting a breach

A non-zero breach rate, or any way to make `send_email` execute without a human token or an
`internal_untainted` verdict, is a P0 defect. Open an issue with the minimal tool call that
does it. Please do not include real addresses or real inbox content.

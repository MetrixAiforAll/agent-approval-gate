import { describe, it, expect, vi } from 'vitest';
import { mkdtempSync, copyFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { CHECKS, callIdIsCanonical } from '../src/eval/integrity.js';
import { classify } from '../src/policy.js';
import { createTaint } from '../src/taint.js';
import { createCounters, DEFAULT_LIMITS } from '../src/ratelimit.js';
import { openAuditLog, verifyChain } from '../src/audit.js';
import { normalizeEmail } from '../src/canonicalize.js';
import { CASES } from '../src/eval/corpus/index.js';
import { counterfactual, loadFixture } from '../src/eval/harness.js';

describe('gate integrity (no model, no network)', () => {
  it.each(CHECKS.map((c) => [c.name, c] as const))('%s', (_name, check) => {
    expect(check.run()).toBeNull();
  });

  it('policy engine throwing is denied as policy_error', () => {
    const ctx = { internalDomains: new Set(['example.com']), taint: createTaint(), counters: createCounters(), limits: DEFAULT_LIMITS };
    vi.spyOn(ctx.internalDomains, 'has').mockImplementation(() => {
      throw new Error('boom');
    });
    const cls = classify('send_email', { to: 'dana@example.com', subject: 's', body: 'b' }, ctx);
    expect(cls.decision).toMatchObject({ verdict: 'deny', reason: 'policy_error' });
  });

  it('callId is independent of key order', () => {
    expect(callIdIsCanonical()).toBe(true);
  });

  it('strips display names and lowercases', () => {
    expect(normalizeEmail('Accounts Payable <STEAL@Evil-Example.com>')).toEqual({
      address: 'steal@evil-example.com',
      domain: 'evil-example.com',
    });
    expect(() => normalizeEmail('not-an-address')).toThrow();
  });

  it('read_inbox taints the session and holds later internal sends', () => {
    const ctx = { internalDomains: new Set(['example.com']), taint: createTaint(), counters: createCounters(), limits: DEFAULT_LIMITS };
    const send = { to: 'dana@example.com', subject: 's', body: 'b' };
    expect(classify('send_email', send, ctx).decision.reason).toBe('internal_untainted');
    ctx.taint.tainted = true;
    expect(classify('send_email', send, ctx).decision).toMatchObject({ verdict: 'hold', reason: 'tainted_session' });
  });
});

describe('audit chain', () => {
  it('verifies an intact chain and resumes it across reopen', () => {
    const path = join(mkdtempSync(join(tmpdir(), 'audit-')), 'audit.log');
    openAuditLog(path).append({ n: 1 });
    openAuditLog(path).append({ n: 2 });
    expect(verifyChain(path)).toEqual({ ok: true, entries: 2, brokenAt: null });
  });

  it('fails on the tampered fixture', () => {
    const path = join(mkdtempSync(join(tmpdir(), 'audit-')), 'tampered.log');
    copyFileSync('fixtures/audit-tampered.log', path);
    const result = verifyChain(path);
    expect(result.ok).toBe(false);
    expect(result.brokenAt).toBe(2);
  });
});

describe('corpus strength (replay, no model)', () => {
  it('with the gate bypassed, the injection corpus produces breaches', async () => {
    let breaches = 0;
    for (const c of CASES.filter((c) => c.kind === 'injection')) {
      const r = await counterfactual(c, loadFixture(c.id).turns);
      if (r.breached) breaches += 1;
    }
    // A comparison where the unprotected path also scores zero proves the corpus is too
    // weak to say anything about the gate.
    expect(breaches).toBeGreaterThan(0);
  });
});

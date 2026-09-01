import { TOOL_SCHEMAS, isKnownTool } from './schemas.js';
import { normalizeEmail } from './canonicalize.js';
import { checkLimits, type Counters, type RateLimits } from './ratelimit.js';
import type { Taint } from './taint.js';

export const POLICY_VERSION = '1.0.0';

export type Verdict = 'allow' | 'hold' | 'deny';
export interface Decision {
  verdict: Verdict;
  reason: string; // machine-readable code, e.g. 'external_recipient'
  policyVersion: string;
}

export interface Classification {
  decision: Decision;
  /** Rebuilt from validated fields only. Absent when the arguments never validated. */
  args: Record<string, unknown> | null;
  recipient: { address: string; domain: string } | null;
}

export interface PolicyContext {
  internalDomains: ReadonlySet<string>;
  taint: Taint;
  counters: Counters;
  limits: RateLimits;
}

/**
 * The proxy never approves. It classifies into allow / hold / deny; only a human
 * approves, and only for the hold bucket. First matching rule wins.
 */
export function classify(tool: string, rawArgs: unknown, ctx: PolicyContext): Classification {
  try {
    return classifyUnsafe(tool, rawArgs, ctx);
  } catch {
    // Fail closed on absolutely everything, including our own bugs.
    return { decision: decide('deny', 'policy_error'), args: null, recipient: null };
  }
}

function classifyUnsafe(tool: string, rawArgs: unknown, ctx: PolicyContext): Classification {
  const deny = (reason: string): Classification => ({
    decision: decide('deny', reason),
    args: null,
    recipient: null,
  });

  if (!isKnownTool(tool)) return deny('unknown_tool');

  const parsed = TOOL_SCHEMAS[tool].safeParse(rawArgs);
  if (!parsed.success) return deny('invalid_arguments');

  if (tool === 'read_inbox') {
    const limited = checkLimits(ctx.counters, ctx.limits, { tool });
    return { decision: limited ? decide('deny', limited) : decide('allow', 'read_ungated'), args: {}, recipient: null };
  }

  const data = parsed.data as { to: string; subject: string; body: string };
  let recipient: { address: string; domain: string };
  try {
    recipient = normalizeEmail(data.to);
  } catch {
    return deny('unparseable_recipient');
  }

  // Strip and rebuild: only validated fields, with the recipient in its normalized form
  // so that the approval prompt, the hash and the executed send all agree on the address.
  const args = { to: recipient.address, subject: data.subject, body: data.body };

  // Full-domain strict equality. `includes`/`endsWith` on a bare string would let
  // `user@example.com.evil-example.net` through.
  const internal = ctx.internalDomains.has(recipient.domain);

  const limited = checkLimits(ctx.counters, ctx.limits, {
    tool,
    ...(internal ? {} : { externalRecipient: recipient.address }),
  });
  // Rate-limit denials keep the rebuilt args: the call was well-formed, only the budget said no.
  if (limited) return { decision: decide('deny', limited), args, recipient };

  if (!internal) return { decision: decide('hold', 'external_recipient'), args, recipient };
  if (ctx.taint.tainted) return { decision: decide('hold', 'tainted_session'), args, recipient };
  return { decision: decide('allow', 'internal_untainted'), args, recipient };
}

function decide(verdict: Verdict, reason: string): Decision {
  return { verdict, reason, policyVersion: POLICY_VERSION };
}

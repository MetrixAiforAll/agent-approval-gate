import { randomBytes } from 'node:crypto';
import { computeCallId, canonicalize } from './canonicalize.js';
import { classify, POLICY_VERSION, type Decision } from './policy.js';
import { requestApproval, consumeToken } from './approvals.js';
import { createTaint, markTainted } from './taint.js';
import { createCounters, recordCall, DEFAULT_LIMITS, type RateLimits } from './ratelimit.js';
import type { AuditLog } from './audit.js';
import type { EmailServer } from './mcp-email-server.js';

/**
 * The trusted computing base. Everything in the enforcement path is string comparison,
 * hashing, HMAC verification and integer counters — no model, no classifier.
 *
 * Fixed pipeline, each step depending on the previous one having succeeded:
 *   validate → canonicalize → hash → policy → (allow | hold | deny) → execute
 */
export interface ProxyOptions {
  email: EmailServer;
  audit: AuditLog;
  internalDomains: string[];
  secret?: string;
  limits?: RateLimits;
  /**
   * Counterfactual mode for the eval only: every well-formed call executes regardless of
   * verdict. Schema validation stays on — the comparison is about policy and approval, not
   * argument parsing. Deliberately a constructor parameter and not an env var, so nothing
   * outside the runner can switch it on by accident.
   */
  bypassGate?: boolean;
}

export interface CallOutcome {
  callId: string;
  tool: string;
  decision: Decision;
  /** Text handed back to the model. Never contains a token. */
  result: string;
  executed: boolean;
}

export interface HeldCall {
  callId: string;
  tool: string;
  args: Record<string, unknown>;
  recipient: { address: string; domain: string } | null;
  reason: string;
}

export function createProxy(opts: ProxyOptions) {
  // Zero configuration for the demo: a per-process random secret is exactly as strong
  // as a configured one for a single process, since only this process ever verifies.
  const secret = opts.secret ?? process.env.APPROVAL_SECRET ?? randomBytes(32).toString('hex');
  const internalDomains = new Set(opts.internalDomains.map((d) => d.toLowerCase()));
  const limits = opts.limits ?? DEFAULT_LIMITS;
  const taint = createTaint();
  const counters = createCounters();
  const held = new Map<string, HeldCall>();
  const outcomes: CallOutcome[] = [];
  const executedCallIds = new Set<string>(); // sends only: the set the email server's log must equal
  let callIndex = 0;

  function audit(fields: Record<string, unknown>) {
    opts.audit.append({
      policyVersion: POLICY_VERSION,
      tainted: taint.tainted,
      taintedAt: taint.taintedAt,
      taintedByCallIndex: taint.taintedByCallIndex,
      ...fields,
    });
  }

  function execute(tool: string, args: Record<string, unknown>): string {
    if (tool === 'read_inbox') {
      const messages = opts.email.readInbox();
      if (messages.length > 0) markTainted(taint, callIndex);
      return JSON.stringify(messages);
    }
    const sent = opts.email.send(args as { to: string; subject: string; body: string });
    return `sent ${sent.messageId}`;
  }

  /** Entry point for every tool call the model emits. `rawArgs` is attacker-controlled. */
  function handleToolCall(tool: string, rawArgs: unknown): CallOutcome {
    callIndex += 1;
    const cls = classify(tool, rawArgs, { internalDomains, taint, counters, limits });
    // Hash the rebuilt, canonical arguments — or the raw ones when there is nothing
    // valid to rebuild, so denied calls still get a stable id in the audit log.
    const callId = computeCallId(tool, cls.args ?? rawArgs);
    recordCall(counters, {
      tool,
      ...(cls.recipient && !internalDomains.has(cls.recipient.domain)
        ? { externalRecipient: cls.recipient.address }
        : {}),
    });

    let result: string;
    let executed = false;
    let verdict: string = cls.decision.verdict;
    // The classifier still runs in bypass mode, as a shadow: its verdict is recorded but not
    // acted on. That is what keeps the attempt rate identical across the two columns.
    const wellFormed = cls.args !== null && (verdict !== 'deny' || cls.decision.reason.startsWith('rate_limit_'));
    if (opts.bypassGate && wellFormed) {
      result = execute(tool, cls.args!);
      executed = true;
      verdict = 'bypassed';
    } else switch (cls.decision.verdict) {
      case 'allow':
        result = execute(tool, cls.args!);
        executed = true;
        if (tool === 'send_email') executedCallIds.add(callId);
        break;
      case 'hold': {
        held.set(callId, { callId, tool, args: cls.args!, recipient: cls.recipient, reason: cls.decision.reason });
        requestApproval(callId);
        result = `held for human approval (call ${callId.slice(0, 8)}); nothing was sent`;
        break;
      }
      case 'deny':
        result = `denied: ${cls.decision.reason}`;
        break;
    }

    audit({
      callId,
      tool,
      canonicalArgs: cls.args ? canonicalize(cls.args) : null,
      verdict,
      reason: cls.decision.reason,
      approvedBy: null,
      executed,
    });
    const outcome = { callId, tool, decision: cls.decision, result, executed };
    outcomes.push(outcome);
    return outcome;
  }

  /**
   * The out-of-band path. A human has looked at the rendered prompt for `callId` and
   * the approver channel presents the token minted for it. The model is not involved
   * and cannot reach this function: nothing it can emit is routed here.
   */
  function executeApproved(callId: string, token: string, approvedBy: string): { ok: boolean; reason: string } {
    const verdict = consumeToken(callId, token, secret);
    const call = held.get(callId);
    held.delete(callId);
    if (!verdict.ok || !call) {
      const reason = verdict.ok ? 'no_pending_approval' : verdict.reason;
      audit({ callId, tool: call?.tool ?? null, canonicalArgs: call ? canonicalize(call.args) : null,
        verdict: 'deny', reason, approvedBy: null, executed: false });
      return { ok: false, reason };
    }
    execute(call.tool, call.args);
    executedCallIds.add(callId);
    audit({ callId, tool: call.tool, canonicalArgs: canonicalize(call.args), verdict: 'allow',
      reason: 'human_approved', approvedBy, executed: true });
    return { ok: true, reason: 'ok' };
  }

  return {
    secret,
    handleToolCall,
    executeApproved,
    heldCalls: () => [...held.values()],
    outcomes: () => outcomes,
    executedCallIds: () => executedCallIds,
    taint,
  };
}

export type Proxy = ReturnType<typeof createProxy>;

/**
 * Rendered to the human. Shows the canonicalized arguments the proxy will actually
 * execute — never the model's description of what it claims to be doing. An approval UI
 * that displays model-generated summary text is theatre.
 */
export function renderApprovalPrompt(call: HeldCall, internalDomains: Set<string>): string {
  const domain = call.recipient?.domain ?? '';
  const flag = internalDomains.has(domain) ? 'internal' : '⚠  external';
  return [
    `  ⏸  APPROVAL REQUIRED  ─  call ${call.callId.slice(0, 8)}`,
    `     tool       ${call.tool}`,
    `     to         ${call.recipient?.address ?? ''}`,
    `     domain     ${domain.padEnd(26)} ${flag}`,
    `     subject    ${String(call.args.subject ?? '')}`,
    `     reason     ${call.reason}`,
  ].join('\n');
}

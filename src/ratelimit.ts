/**
 * Three deterministic counters. They all fail closed and produce audit entries that look
 * exactly like policy denials, so the eval can assert on them uniformly.
 *
 * The distinct-external-recipients counter is the interesting one. Some attacks are only
 * visible in aggregate: a human approves one legitimate send, the agent then loops and
 * sends to a hundred addresses, and every individual call looks fine to a per-call policy
 * check. Per-call authorization is necessary and not sufficient. Rate limits are where
 * you catch what the per-call gate structurally cannot see.
 */
export interface RateLimits {
  callsPerSession: number;
  sendsPerWindow: number;
  windowMs: number;
  distinctExternalRecipients: number;
}

export const DEFAULT_LIMITS: RateLimits = {
  callsPerSession: 20,
  sendsPerWindow: 5,
  windowMs: 60_000,
  distinctExternalRecipients: 3,
};

export interface Counters {
  calls: number;
  sendTimestamps: number[];
  externalRecipients: Set<string>;
}

export function createCounters(): Counters {
  return { calls: 0, sendTimestamps: [], externalRecipients: new Set() };
}

/** Returns a machine-readable denial reason, or null if every counter has headroom. */
export function checkLimits(
  c: Counters,
  limits: RateLimits,
  call: { tool: string; externalRecipient?: string },
): string | null {
  if (c.calls >= limits.callsPerSession) return 'rate_limit_calls_per_session';
  if (call.tool !== 'send_email') return null;

  const windowStart = Date.now() - limits.windowMs;
  const recent = c.sendTimestamps.filter((t) => t > windowStart).length;
  if (recent >= limits.sendsPerWindow) return 'rate_limit_sends_per_window';

  // A repeat of an already-counted recipient is not a new fan-out target.
  if (
    call.externalRecipient &&
    !c.externalRecipients.has(call.externalRecipient) &&
    c.externalRecipients.size >= limits.distinctExternalRecipients
  ) {
    return 'rate_limit_distinct_external_recipients';
  }
  return null;
}

/** Counts every call that reached the classifier, whether or not it was denied. */
export function recordCall(c: Counters, call: { tool: string; externalRecipient?: string }): void {
  c.calls += 1;
  if (call.tool !== 'send_email') return;
  c.sendTimestamps.push(Date.now());
  if (call.externalRecipient) c.externalRecipients.add(call.externalRecipient);
}

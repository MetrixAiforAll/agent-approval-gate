import { createHmac, timingSafeEqual, randomUUID } from 'node:crypto';

/**
 * Four properties, each tested on its own in test/gate-integrity.test.ts:
 *   1. The model cannot grant approval — enforced by schema absence, not by ignoring a field.
 *   2. Approval binds to exact arguments — via callId.
 *   3. Approval arrives out of band — mintToken is called by the human's channel, never
 *      from anything the model said.
 *   4. Single-use and time-bounded.
 */
const TTL_MS = 5 * 60 * 1000;

interface Pending {
  callId: string;
  issuedAt: number;
  nonce: string;
}

// In-memory is fine for a single-process PoC. Production needs shared, durable storage,
// and the single-use guarantee then depends on an atomic delete rather than Map semantics.
const pending = new Map<string, Pending>();

/** Called by the proxy when policy returns `hold`. Parks the call; sends nothing. */
export function requestApproval(callId: string): Pending {
  const rec: Pending = { callId, issuedAt: Date.now(), nonce: randomUUID() };
  pending.set(callId, rec);
  return rec;
}

/**
 * Called ONLY after a human has decided. The token is minted by the proxy and handed
 * straight back to the proxy. It is never rendered into the model's context.
 */
export function mintToken(callId: string, secret: string): string {
  const rec = pending.get(callId);
  if (!rec) throw new Error('no pending approval for callId');
  return sign(rec, secret);
}

export function consumeToken(
  callId: string,
  token: string,
  secret: string,
): { ok: boolean; reason: string } {
  const rec = pending.get(callId);
  if (!rec) return { ok: false, reason: 'no_pending_approval' };

  // Delete FIRST, unconditionally. The record is consumed by the attempt, valid or not,
  // so a replay of a good token and a brute-force of a bad one both fail on the second try.
  pending.delete(callId);

  if (Date.now() > rec.issuedAt + TTL_MS) return { ok: false, reason: 'expired' };

  const a = Buffer.from(sign(rec, secret), 'hex');
  const b = Buffer.from(token, 'hex');
  if (a.length !== b.length || !timingSafeEqual(a, b)) {
    return { ok: false, reason: 'bad_token' };
  }
  return { ok: true, reason: 'ok' };
}

export function clearPending(): void {
  pending.clear();
}

function sign(rec: Pending, secret: string): string {
  return createHmac('sha256', secret)
    .update(`${rec.callId}:${rec.issuedAt}:${rec.nonce}`)
    .digest('hex');
}

/**
 * Session provenance. Static policy asks "is this recipient external?"; taint asks
 * "has this session been exposed to untrusted content?". Once the agent has read the
 * inbox, anything it composes afterwards may be shaped by what it read — including an
 * internal-looking send an hour later — so the taint never clears within a session.
 */
export interface Taint {
  tainted: boolean;
  taintedAt: number | null;
  taintedByCallIndex: number | null;
}

export function createTaint(): Taint {
  return { tainted: false, taintedAt: null, taintedByCallIndex: null };
}

export function markTainted(taint: Taint, callIndex: number): void {
  if (taint.tainted) return; // keep the first exposure; that is the one to investigate
  taint.tainted = true;
  taint.taintedAt = Date.now();
  taint.taintedByCallIndex = callIndex;
}

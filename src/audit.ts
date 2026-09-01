import { createHash } from 'node:crypto';
import { appendFileSync, existsSync, readFileSync } from 'node:fs';
import { canonicalize } from './canonicalize.js';

const GENESIS = '0'.repeat(64);

export interface AuditLog {
  path: string;
  append(entry: Record<string, unknown>): string;
}

/**
 * Append-only JSONL, hash-chained. Each entry commits to the hash of the previous one.
 * Altering or deleting any historical entry invalidates every hash after it, which
 * `verify-chain` detects. This is what makes "immutable audit trail" a demonstrable
 * property rather than a marketing claim.
 */
export function openAuditLog(path = process.env.AUDIT_PATH ?? './audit.log'): AuditLog {
  // Resume from the last line of an existing log rather than restarting at genesis —
  // otherwise every process restart silently forks the chain into a fresh one that
  // no longer commits to anything that happened before it.
  let prevHash = lastHash(path);

  return {
    path,
    append(entry) {
      const record = { ...entry, ts: Date.now(), prev: prevHash };
      const hash = createHash('sha256').update(canonicalize(record)).digest('hex');
      appendFileSync(path, JSON.stringify({ ...record, hash }) + '\n');
      prevHash = hash;
      return hash;
    },
  };
}

function lastHash(path: string): string {
  const lines = readLines(path);
  const last = lines[lines.length - 1];
  return last ? (JSON.parse(last).hash as string) : GENESIS;
}

function readLines(path: string): string[] {
  if (!existsSync(path)) return [];
  return readFileSync(path, 'utf8').split('\n').filter(Boolean);
}

/** Recomputes the chain; reports the first line that does not commit to its predecessor. */
export function verifyChain(path: string): { ok: boolean; entries: number; brokenAt: number | null } {
  const lines = readLines(path);
  let prev = GENESIS;
  for (let i = 0; i < lines.length; i++) {
    const { hash, ...record } = JSON.parse(lines[i]!) as Record<string, unknown> & { hash: string };
    const recomputed = createHash('sha256').update(canonicalize(record)).digest('hex');
    if (record.prev !== prev || recomputed !== hash) {
      return { ok: false, entries: lines.length, brokenAt: i + 1 };
    }
    prev = hash;
  }
  return { ok: true, entries: lines.length, brokenAt: null };
}

if (process.argv.includes('--verify')) {
  const path = process.argv[process.argv.indexOf('--verify') + 1] ?? './audit.log';
  const result = verifyChain(path);
  if (result.ok) {
    console.log(`✓ chain intact: ${result.entries} entries in ${path}`);
  } else {
    console.error(`✗ chain broken at line ${result.brokenAt} of ${path}`);
    process.exit(1);
  }
}

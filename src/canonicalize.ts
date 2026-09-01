import { createHash } from 'node:crypto';

/**
 * Normalize a recipient into a comparable form.
 *
 *   "Accounts Payable <STEAL@Evil-Example.com>"  ->  steal@evil-example.com
 *
 * The display-name strip matters: a human skimming an approval prompt reads the friendly
 * name, so an attacker will put a trustworthy-looking name in front of a hostile address.
 * We compare on the address and show the human the address.
 */
export function normalizeEmail(raw: string): { address: string; domain: string } {
  // RFC 5322 display-name form: everything inside the final <...>
  const angle = raw.match(/<([^>]*)>\s*$/);
  const bare = (angle ? angle[1]! : raw).trim().toLowerCase();

  // Exactly one '@', both halves non-empty. Anything else is malformed and the
  // caller must fail closed rather than guess.
  const parts = bare.split('@');
  if (parts.length !== 2 || !parts[0] || !parts[1]) {
    throw new Error(`unparseable recipient: ${raw}`);
  }

  const domain = parts[1].replace(/\.$/, ''); // drop the FQDN trailing root dot
  return { address: `${parts[0]}@${domain}`, domain };
}

/** Deterministic JSON encoding: object keys sorted at every level of nesting. */
export function canonicalize(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(',')}]`;
  const obj = value as Record<string, unknown>;
  const parts = Object.keys(obj)
    .sort()
    .map((k) => `${JSON.stringify(k)}:${canonicalize(obj[k])}`);
  return `{${parts.join(',')}}`;
}

/**
 * The callId binds an approval to one exact call. Change any argument — swap a single
 * character of the recipient — and the id changes, so a previously granted approval
 * no longer matches. This is the defence against the agent-flavoured TOCTOU bug where
 * a human approves a benign draft and the agent retries with a different recipient.
 */
export function computeCallId(tool: string, args: unknown): string {
  return createHash('sha256').update(canonicalize({ tool, args })).digest('hex');
}

/**
 * The credentialed component. In a real deployment this is a separate MCP server process
 * that holds the mail provider token; the proxy is its only client. It is a module here
 * because a second process adds deployment friction for zero pedagogical gain — the
 * boundary that matters is that nothing in this file consults the model or the policy.
 *
 * Its scope is the first of the two independent controls: whatever the proxy gets wrong,
 * an agent routed through this server can only ever touch email.
 */
export interface InboxMessage {
  from: string;
  subject: string;
  body: string;
}

export interface SentEmail {
  to: string;
  subject: string;
  body: string;
  messageId: string;
}

export interface EmailServer {
  readInbox(): InboxMessage[];
  send(args: { to: string; subject: string; body: string }): SentEmail;
  /** Ground truth for the eval: what actually went out, as seen by the credential holder. */
  readonly sent: readonly SentEmail[];
}

export function createEmailServer(inbox: InboxMessage[]): EmailServer {
  // A mock token, never revealed to the proxy or the model. Its existence is the point:
  // the agent can produce a tool call but never the credential that makes it real.
  const MAIL_TOKEN = 'mock-mail-token-' + Math.random().toString(36).slice(2);
  const sent: SentEmail[] = [];

  return {
    readInbox: () => inbox.map((m) => ({ ...m })),
    send(args) {
      const messageId = `<${sent.length + 1}.${MAIL_TOKEN.length}@mock.example.com>`;
      const record = { ...args, messageId };
      sent.push(record);
      return record;
    },
    sent,
  };
}

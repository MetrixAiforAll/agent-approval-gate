import { z } from 'zod';

/**
 * The schema handed to the model. Note what is absent: there is no `approved` field,
 * no `urgency`, no `skip_review`. The model has no vocabulary for approval at all.
 *
 * This is the single most important line in the project. If an approval field existed
 * in the schema, an injection could learn to emit it. If an approval token ever appeared
 * in the model's context, an injection could learn to read and replay it. Neither ever
 * touches the model.
 */
export const SendEmailArgs = z
  .object({
    to: z.string().min(3).max(320),
    subject: z.string().max(200),
    body: z.string().max(10_000),
  })
  // `.strict()` is load-bearing. Without it the model could smuggle extra fields that a
  // downstream consumer might read even though the policy engine never inspected them.
  .strict();

export const ReadInboxArgs = z.object({}).strict();

export const TOOL_SCHEMAS = {
  send_email: SendEmailArgs,
  read_inbox: ReadInboxArgs,
} as const;

export type ToolName = keyof typeof TOOL_SCHEMAS;
export type SendEmail = z.infer<typeof SendEmailArgs>;

export function isKnownTool(name: string): name is ToolName {
  return Object.prototype.hasOwnProperty.call(TOOL_SCHEMAS, name);
}

/**
 * Tool definitions in the shape the model API expects, derived from the same Zod
 * schemas the proxy validates against. One source of truth: what the model is told it
 * may send and what the proxy accepts can never drift apart.
 */
export const TOOL_DEFINITIONS = [
  {
    name: 'read_inbox',
    description: 'Read the messages currently in the inbox.',
    input_schema: z.toJSONSchema(ReadInboxArgs),
  },
  {
    name: 'send_email',
    description: 'Send an email. Use plain addresses in `to`.',
    input_schema: z.toJSONSchema(SendEmailArgs),
  },
];

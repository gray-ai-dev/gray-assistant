import { z } from "zod";
import { LANE_RELAY_ID_PATTERN } from "./endpoint.ts";

/**
 * A relay's kit reads Gray's messages with the relay key (kit 1.6.2): the notices the console keeps for the relay
 * (a release proposal, the traffic window, a VM or account problem; console lane-stack/messages.ts) are answered to a
 * request the relay key signed, as a restart request is (S53), so a kit reads them at any time after onboarding, with no
 * setup token and no session.
 *
 * - `POST /v1/lane-stack/messages` with `{"request": {relay_id, issued_ms, action: "read", through_ms: null},
 *   "signature"}`: the messages the kit has not marked seen, newest first, and `through_ms` (the newest one's time).
 * - `POST /v1/lane-stack/messages/seen` with `action: "seen"` and `through_ms`: the kit's own mark moves there (never
 *   back, never past Gray's clock). The kit's mark is its own row (`KIT_MESSAGE_READER`), apart from every member's:
 *   what a person read in the panel the kit still shows once, and the other way round.
 *
 * The action is signed, so a read request is never a mark.
 */
export const KIT_MESSAGES_PATH = "/v1/lane-stack/messages";
export const KIT_MESSAGES_SEEN_PATH = "/v1/lane-stack/messages/seen";

/** The reader the kit's mark is kept under in `lane_stack_message_reads.user_id`: no member's id has an `@`. */
export const KIT_MESSAGE_READER = "@relay-kit";

const u64 = z.number().int().min(0).max(Number.MAX_SAFE_INTEGER);

export const kitMessagesRequestSchema = z
  .object({
    relay_id: z.string().regex(LANE_RELAY_ID_PATTERN),
    issued_ms: u64,
    action: z.enum(["read", "seen"]),
    /** `seen`: the time through which the kit showed the messages (a read answer's `through_ms`); `read`: null. */
    through_ms: u64.nullable(),
  })
  .strict()
  .refine((r) => (r.action === "seen") === (r.through_ms !== null), { message: "a seen request names through_ms, a read request does not", path: ["through_ms"] });
export type KitMessagesRequest = z.infer<typeof kitMessagesRequestSchema>;

/** The request and the relay's Ed25519 signature over `kitMessagesRequestMessage`, 128 lower-case hex digits. */
export const kitMessagesReportSchema = z.object({ request: kitMessagesRequestSchema, signature: z.string().regex(/^[0-9a-f]{128}$/) }).strict();
export type KitMessagesReport = z.infer<typeof kitMessagesReportSchema>;

/** The first line of the signed request. */
export const KIT_MESSAGES_DOMAIN = "gray-relay-stack-messages/v1";

/** The bytes the relay signs: the domain and each member on its own line, in this order; a null `through_ms` is empty. */
export function kitMessagesRequestMessage(r: KitMessagesRequest): Uint8Array {
  return new TextEncoder().encode([KIT_MESSAGES_DOMAIN, r.relay_id, String(r.issued_ms), r.action, r.through_ms === null ? "" : String(r.through_ms)].join("\n"));
}

/** One message as the kit prints it: the setup status's form (provider-setup/relay-stack.ts). */
export const kitMessageSchema = z.object({
  id: z.string().min(1).max(128),
  at_ms: u64,
  kind: z.string().max(64),
  title: z.string().max(512),
  body: z.string().max(8192),
  command: z.string().max(1024).optional(),
});
export type KitMessage = z.infer<typeof kitMessageSchema>;

/** The read answer: the unread messages (at most the console's page of them), how many there are in all, and the newest one's time. */
export const kitMessagesAnswerSchema = z.object({ messages: z.array(kitMessageSchema).max(100), unread: u64, through_ms: u64.nullable() });
export type KitMessagesAnswer = z.infer<typeof kitMessagesAnswerSchema>;

/** The seen answer: the kit's mark and what is still unread past it. */
export const kitMessagesSeenAnswerSchema = z.object({ seen_ms: u64, unread: u64 });

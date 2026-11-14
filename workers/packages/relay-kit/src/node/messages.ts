/**
 * `gray-assistant messages [--seen]` (kit 1.6.2): Gray's messages for the relay, read with the relay key.
 *
 * Gray keeps every notice it has for a relay in its console (a release that waits for approval, the traffic window, a
 * VM or account problem). A member reads them on the relay's Messages page and an onboarding agent in its setup status,
 * but that agent's token ends with onboarding, and Gray sends no e-mail yet: without this command a relay whose people
 * do not open the console never learns a release waits for it. The kit asks with a request the relay key signs, as a
 * restart request is (`@gray/control/stack-messages`, `POST <stack.report_origin>/v1/lane-stack/messages`), so it needs
 * no token and works for as long as the relay is paired.
 *
 * - `messages` lists what the kit has not marked seen (the title, the text, the time, the command when there is one);
 * - `messages --seen` lists them and moves the kit's mark to the newest one, so the next run lists only newer ones.
 *   The mark is the kit's own: a member's reading in the panel does not move it, nor this the member's.
 * - `doctor` has a `messages` line (WARN with the count and the newest title), and `deliver`, `accounts push`,
 *   `registry set` and `stack …` end with one line on stderr when something is unread (`unreadMessagesNote`: one
 *   request, a few seconds at most, silent when it fails, never the command's exit code).
 *
 * Nothing secret is sent or printed: the request names the relay and the time, and the signature is the relay key's.
 */
import { bytesToLowerHex, ed25519Sign } from "@gray/attest";
import {
  KIT_MESSAGES_PATH,
  KIT_MESSAGES_SEEN_PATH,
  kitMessagesAnswerSchema,
  kitMessagesRequestMessage,
  kitMessagesSeenAnswerSchema,
  type KitMessage,
  type KitMessagesAnswer,
  type KitMessagesRequest,
} from "@gray/control/stack-messages";
import { parsePlain, toJsonString } from "@gray/json";
import type { LoadedRelayConfig } from "./config-file.ts";

/** How long a command's closing note waits for Gray: it must never hold a finished command up. */
export const MESSAGES_NOTE_TIMEOUT_MS = 5_000;
/** How long `messages` and `doctor` wait. */
export const MESSAGES_TIMEOUT_MS = 20_000;

/** One POST to Gray; resolves with the status, the body text and the answer's `Date` header (Gray's clock, for `doctor`). */
export type MessagesPost = (url: string, body: string, timeoutMs: number) => Promise<{ readonly status: number; readonly text: string; readonly date: string | null }>;

export const defaultMessagesPost: MessagesPost = async (url, body, timeoutMs) => {
  const response = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json", accept: "application/json", "user-agent": "gray-assistant" },
    body,
    redirect: "error",
    signal: AbortSignal.timeout(timeoutMs),
  });
  return { status: response.status, text: await response.text(), date: response.headers.get("date") };
};

export interface MessagesRequestOptions {
  readonly config: LoadedRelayConfig;
  /** The relay key's seed. */
  readonly seed: Uint8Array;
  readonly nowMs: number;
  readonly post?: MessagesPost;
  readonly timeoutMs?: number;
}

/** What one request to Gray gave: the answer, or why there is none (a short fixed reason, never Gray's text). */
export type MessagesRead =
  | { readonly ok: true; readonly answer: KitMessagesAnswer; readonly grayDateMs: number | null; readonly receivedMs: number | null }
  | { readonly ok: false; readonly reason: string; readonly grayDateMs: number | null; readonly receivedMs: number | null };

function errorCodeOf(text: string): string | null {
  try {
    const value = parsePlain(text) as { error?: { code?: unknown } | null } | null;
    const code = value?.error?.code;
    return typeof code === "string" && /^[a-z0-9_]{1,64}$/.test(code) ? code : null;
  } catch {
    return null;
  }
}

async function signedPost(options: MessagesRequestOptions, path: string, request: KitMessagesRequest, clock: () => number): Promise<{ readonly status: number; readonly text: string; readonly grayDateMs: number | null; readonly receivedMs: number | null } | { readonly reason: string }> {
  const stack = options.config.daemon.stack;
  if (stack === null) return { reason: "the config has no stack section (stack.report_origin is where Gray answers)" };
  const signature = bytesToLowerHex(await ed25519Sign(options.seed, kitMessagesRequestMessage(request)));
  try {
    const answer = await (options.post ?? defaultMessagesPost)(`${stack.reportOrigin}${path}`, toJsonString({ request: { ...request, issued_ms: BigInt(request.issued_ms), through_ms: request.through_ms === null ? null : BigInt(request.through_ms) }, signature }), options.timeoutMs ?? MESSAGES_TIMEOUT_MS);
    const dateMs = answer.date === null ? Number.NaN : Date.parse(answer.date);
    return { status: answer.status, text: answer.text, grayDateMs: Number.isFinite(dateMs) ? dateMs : null, receivedMs: clock() };
  } catch {
    return { reason: `Gray did not answer at ${stack.reportOrigin}` };
  }
}

/** Why Gray refused, in the relay's words. */
function refusalReason(status: number, text: string): string {
  const code = errorCodeOf(text);
  if (status === 404 && code !== "lane_stack_relay_unknown") return "this Gray does not answer a kit's messages request yet (HTTP 404)";
  if (code === "lane_stack_relay_unknown") return "Gray knows no key for this relay (lane_stack_relay_unknown): it is not paired there";
  if (code === "lane_stack_signature_invalid") return "Gray did not accept the signature (lane_stack_signature_invalid): relay-key.json is not the key the relay paired";
  if (code === "lane_stack_messages_future" || code === "lane_stack_messages_stale") return `Gray refused the request's time (${code}): this machine's clock is off; set it right`;
  return `Gray refused the request (HTTP ${status}${code === null ? "" : ` ${code}`})`;
}

/** The relay's unread messages for the kit's mark. Never throws: a failure is a reason. `clock` reads this machine's time when the answer arrives. */
export async function readKitMessages(options: MessagesRequestOptions, clock: () => number = Date.now): Promise<MessagesRead> {
  const sent = await signedPost(options, KIT_MESSAGES_PATH, { relay_id: options.config.daemon.relayId, issued_ms: options.nowMs, action: "read", through_ms: null }, clock);
  if ("reason" in sent) return { ok: false, reason: sent.reason, grayDateMs: null, receivedMs: null };
  const { grayDateMs, receivedMs } = sent;
  if (sent.status !== 200) return { ok: false, reason: refusalReason(sent.status, sent.text), grayDateMs, receivedMs };
  let parsed: ReturnType<typeof kitMessagesAnswerSchema.safeParse>;
  try {
    parsed = kitMessagesAnswerSchema.safeParse(parsePlain(sent.text));
  } catch {
    return { ok: false, reason: "Gray's answer is not JSON", grayDateMs, receivedMs };
  }
  if (!parsed.success) return { ok: false, reason: "Gray's answer is not a list of messages this gray-assistant reads; upgrade gray-assistant", grayDateMs, receivedMs };
  return { ok: true, answer: parsed.data, grayDateMs, receivedMs };
}

/** Move the kit's mark to `throughMs`. Never throws. */
export async function markKitMessagesSeen(options: MessagesRequestOptions, throughMs: number): Promise<{ readonly ok: true; readonly seenMs: number; readonly unread: number } | { readonly ok: false; readonly reason: string }> {
  const sent = await signedPost(options, KIT_MESSAGES_SEEN_PATH, { relay_id: options.config.daemon.relayId, issued_ms: options.nowMs, action: "seen", through_ms: throughMs }, Date.now);
  if ("reason" in sent) return { ok: false, reason: sent.reason };
  if (sent.status !== 200) return { ok: false, reason: refusalReason(sent.status, sent.text) };
  try {
    const parsed = kitMessagesSeenAnswerSchema.safeParse(parsePlain(sent.text));
    if (parsed.success) return { ok: true, seenMs: parsed.data.seen_ms, unread: parsed.data.unread };
  } catch {
    // Falls through: not an answer.
  }
  return { ok: false, reason: "Gray's answer is not a mark this gray-assistant reads; upgrade gray-assistant" };
}

/** Gray's text as one terminal line: no control character reaches the operator's terminal. */
export function plainLine(text: string): string {
  return text.replace(/[\u0000-\u001f\u007f-\u009f\u2028\u2029]+/gu, " ").replace(/ {2,}/gu, " ").trim();
}

const utc = (ms: number): string => `${new Date(ms).toISOString().slice(0, 19)}Z`;

/** `2 unread messages from Gray, newest "…"`: the words `doctor` and the closing note share. */
export function unreadSummary(answer: KitMessagesAnswer): string {
  const newest = answer.messages[0];
  return `${answer.unread} unread message${answer.unread === 1 ? "" : "s"} from Gray${newest === undefined ? "" : `, newest ${JSON.stringify(plainLine(newest.title))} (${utc(newest.at_ms)})`}`;
}

export interface MessagesIo {
  readonly stdout: (line: string) => void;
  readonly stderr: (line: string) => void;
}

const messageJson = (m: KitMessage) => ({ id: m.id, at: utc(m.at_ms), at_ms: BigInt(m.at_ms), kind: m.kind, title: plainLine(m.title), body: plainLine(m.body), ...(m.command === undefined ? {} : { command: plainLine(m.command) }) });

/** `gray-assistant messages [--seen]`. Exit 0 when Gray answered (with or without messages), 1 when it did not. */
export async function messagesCommand(options: MessagesRequestOptions & { readonly io: MessagesIo; readonly seen: boolean }): Promise<number> {
  const { io } = options;
  const relayId = options.config.daemon.relayId;
  const read = await readKitMessages(options);
  if (!read.ok) {
    io.stderr(`gray-assistant messages: Gray's messages could not be read: ${read.reason}\n`);
    io.stdout(`${toJsonString({ command: "messages", ok: false, relay_id: relayId, code: "messages_unread" })}\n`);
    return 1;
  }
  const { answer } = read;
  if (answer.messages.length === 0) {
    io.stdout(`gray-assistant messages: no unread message from Gray for relay ${relayId}\n`);
    io.stdout(`${toJsonString({ command: "messages", ok: true, relay_id: relayId, unread: 0n, through_ms: null, messages: [], seen: false })}\n`);
    return 0;
  }
  io.stdout(`gray-assistant messages: ${answer.unread} unread message${answer.unread === 1 ? "" : "s"} from Gray for relay ${relayId}, newest first\n`);
  for (const m of answer.messages) {
    io.stdout(`[${utc(m.at_ms)}] ${plainLine(m.title)}\n`);
    if (m.body.trim() !== "") io.stdout(`  ${plainLine(m.body)}\n`);
    if (m.command !== undefined) io.stdout(`  run: ${plainLine(m.command)}\n`);
  }
  const unlisted = answer.unread - answer.messages.length;
  if (unlisted > 0) io.stdout(`${unlisted} older one${unlisted === 1 ? " is" : "s are"} not listed here: the relay's Messages page in Gray's console lists every message\n`);
  const json = { command: "messages", ok: true, relay_id: relayId, unread: BigInt(answer.unread), through_ms: answer.through_ms === null ? null : BigInt(answer.through_ms), messages: answer.messages.map(messageJson) };
  if (!options.seen || answer.through_ms === null) {
    io.stdout("tell the relay's operator what they say, then mark them seen: gray-assistant messages --seen\n");
    io.stdout(`${toJsonString({ ...json, seen: false })}\n`);
    return 0;
  }
  const marked = await markKitMessagesSeen(options, answer.through_ms);
  if (!marked.ok) {
    io.stderr(`gray-assistant messages: the messages above are not marked seen: ${marked.reason}; run the command again\n`);
    io.stdout(`${toJsonString({ ...json, seen: false, code: "messages_not_marked" })}\n`);
    return 1;
  }
  io.stdout(`gray-assistant messages: marked seen through ${utc(marked.seenMs)}; ${marked.unread === 0 ? "nothing is unread" : `${marked.unread} newer one${marked.unread === 1 ? " is" : "s are"} unread: run gray-assistant messages again`}\n`);
  io.stdout(`${toJsonString({ ...json, seen: true, seen_ms: BigInt(marked.seenMs), unread: BigInt(marked.unread) })}\n`);
  return 0;
}

/**
 * The line a command ends with when Gray has something unread, or null: one request with a short timeout, and any
 * failure (no stack section, no answer, a refusal, an older Gray) is null. Never throws.
 */
export async function unreadMessagesNote(options: MessagesRequestOptions): Promise<string | null> {
  try {
    const read = await readKitMessages({ ...options, timeoutMs: options.timeoutMs ?? MESSAGES_NOTE_TIMEOUT_MS });
    if (!read.ok || read.answer.unread === 0) return null;
    return `note: ${unreadSummary(read.answer)}: run \`gray-assistant messages\` and tell the relay's operator`;
  } catch {
    return null;
  }
}

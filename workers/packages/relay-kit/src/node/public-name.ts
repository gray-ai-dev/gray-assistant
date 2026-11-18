/**
 * The relay's own read or change of its workspace's public name on Gray (docs/api-contract.md, "Provider handle"): what
 * the provider pages' Public name panel does, signed by the relay key, so `gray-assistant public-name [set <name> | show
 * | hide]` offer what the panel offers. The name is claimed once; whether the Models page shows it can change at any
 * time. Nothing here touches the account file or the VM.
 *
 * `POST <stack.report_origin>/v1/lane-stack/public-name` with `{"request": {"relay_id", "issued_ms", "nonce", "handle"?,
 * "show_name"?}, "signature": "<128 hex>"}`: the relay key's Ed25519 over `stackPublicNameMessage(request)`
 * (`@gray/control`). Gray answers `{"handle": <name or null>, "show_name": <boolean>}`.
 *
 * As the settings change beside it (`./account-settings.ts`), nothing here throws for what Gray or the network does: the
 * result says it with a closed code. The request holds no secret.
 */
import { bytesToLowerHex, ed25519Sign } from "@gray/attest";
import { STACK_PANEL_VIEW_NONCE_PATTERN, stackPublicNameMessage, stackPublicNameReportSchema, type StackPublicNameRequest } from "@gray/control";
import { parsePlain, toJsonString, type JsonObject } from "@gray/json";
import { RelayKitError } from "../errors.ts";
import { errorCodeOf } from "./account-group.ts";
import type { LoadedRelayConfig } from "./config-file.ts";
import { defaultPost, type StackPost } from "./stack.ts";

export const PUBLIC_NAME_PATH = "/v1/lane-stack/public-name";

/** What a request asks: nothing (a read), the name to claim, or whether the Models page shows it. */
export type PublicNameChange = Pick<StackPublicNameRequest, "handle" | "show_name">;

/** The request: the relay, this machine's clock, a fresh nonce and the change. */
export function publicNameRequest(input: { readonly relayId: string; readonly issuedMs: number; readonly random: (length: number) => Uint8Array; readonly change: PublicNameChange }): StackPublicNameRequest {
  const nonce = bytesToLowerHex(input.random(16));
  if (!STACK_PANEL_VIEW_NONCE_PATTERN.test(nonce)) throw new RelayKitError("usage", "the public-name request's nonce is not 32 hex digits");
  const { handle, show_name } = input.change;
  return {
    relay_id: input.relayId,
    issued_ms: Math.trunc(input.issuedMs),
    nonce,
    ...(handle === undefined ? {} : { handle }),
    ...(show_name === undefined ? {} : { show_name }),
  };
}

/** The signed body, checked against the console's own schema before it is sent; its integers as JSON integers. */
export async function signedPublicNameRequest(request: StackPublicNameRequest, seed: Uint8Array): Promise<JsonObject> {
  const signature = bytesToLowerHex(await ed25519Sign(seed, stackPublicNameMessage(request)));
  if (!stackPublicNameReportSchema.safeParse({ request, signature }).success) throw new RelayKitError("usage", "the public-name request is not the console's shape");
  return { request: { ...request, issued_ms: BigInt(request.issued_ms) }, signature };
}

/**
 * A request's end. `code` when it failed: `no_stack` (the config has no `stack` section), `request_invalid` (a name this
 * tool cannot send), `unreachable` (no answer), Gray's own code for a refusal (`invalid_handle`, `handle_reserved`,
 * `handle_taken`, `handle_already_set`, `handle_missing`, `forbidden`, `lane_stack_relay_unknown`, the signature's, the
 * clock's), else `http_<status>`, and `bad_answer` for a 200 that is not the answer.
 */
export type PublicNameResult =
  | { readonly ok: true; readonly handle: string | null; readonly showName: boolean }
  | { readonly ok: false; readonly code: string; readonly status: number | null };

export interface PublicNameOptions {
  readonly config: LoadedRelayConfig;
  /** The relay key's seed. */
  readonly seed: Uint8Array;
  readonly nowMs: number;
  readonly random: (length: number) => Uint8Array;
  readonly change: PublicNameChange;
  /** One POST; global `fetch` when absent, a fake in the tests. */
  readonly post?: StackPost;
}

/** Read or change the public name on Gray, once. */
export async function writePublicName(options: PublicNameOptions): Promise<PublicNameResult> {
  const stack = options.config.daemon.stack;
  if (stack === null) return { ok: false, code: "no_stack", status: null };
  let body: string;
  try {
    const request = publicNameRequest({ relayId: options.config.daemon.relayId, issuedMs: options.nowMs, random: options.random, change: options.change });
    body = toJsonString(await signedPublicNameRequest(request, options.seed));
  } catch {
    return { ok: false, code: "request_invalid", status: null };
  }
  let answer: { readonly status: number; readonly text: string };
  try {
    answer = await (options.post ?? defaultPost)(`${stack.reportOrigin}${PUBLIC_NAME_PATH}`, body);
  } catch {
    return { ok: false, code: "unreachable", status: null };
  }
  if (answer.status !== 200) return { ok: false, code: errorCodeOf(answer.text) ?? `http_${answer.status}`, status: answer.status };
  let value: unknown;
  try {
    value = parsePlain(answer.text);
  } catch {
    return { ok: false, code: "bad_answer", status: 200 };
  }
  const read = typeof value === "object" && value !== null ? (value as { readonly handle?: unknown; readonly show_name?: unknown }) : {};
  if (!(read.handle === null || typeof read.handle === "string") || typeof read.show_name !== "boolean") return { ok: false, code: "bad_answer", status: 200 };
  return { ok: true, handle: read.handle, showName: read.show_name };
}

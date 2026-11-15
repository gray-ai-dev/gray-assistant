/**
 * The relay's read of its own panel view on Gray (docs/design/relay-operator-page.md section 5): gray-assistant's page
 * lists each account with its state on Gray and its group, so an operator recognises it.
 *
 * `POST <stack.report_origin>/v1/lane-stack/panel-view` with
 * `{"request": {"relay_id", "issued_ms", "nonce"}, "signature": "<128 hex>"}`: the relay key's Ed25519 over
 * `stackPanelViewMessage(request)` (`@gray/control`), the construction of the signed restart request (`./stack.ts`).
 * `issued_ms` is this machine's clock, which Gray takes within five minutes of its own; `nonce` is 32 hex digits of
 * randomness and is not stored (a read). Gray answers `{"accounts": [...], "health": {...}}`: the bodies of the panel's
 * `GET …/accounts` (each account with its `group`) and `GET …/health` for this relay.
 *
 * A read the page shows beside its own list, so nothing here throws for what Gray or the network does: the result
 * says it with a closed code (the page shows its list without Gray's state while Gray does not answer). The request
 * holds no secret and the answer none of the relay's.
 */
import { bytesToLowerHex, ed25519Sign } from "@gray/attest";
import { STACK_PANEL_VIEW_NONCE_PATTERN, stackPanelViewMessage, stackPanelViewReportSchema, type StackPanelViewRequest } from "@gray/control";
import { get, isObject, parsePlain, toJsonString, type Json, type JsonObject } from "@gray/json";
import { RelayKitError } from "../errors.ts";
import type { LoadedRelayConfig } from "./config-file.ts";
import { defaultPost, type StackPost } from "./stack.ts";

export const PANEL_VIEW_PATH = "/v1/lane-stack/panel-view";

/** The request a read sends: the relay, this machine's clock and a fresh nonce. */
export function panelViewRequest(input: { readonly relayId: string; readonly issuedMs: number; readonly random: (length: number) => Uint8Array }): StackPanelViewRequest {
  const nonce = bytesToLowerHex(input.random(16));
  if (!STACK_PANEL_VIEW_NONCE_PATTERN.test(nonce)) throw new RelayKitError("usage", "the panel-view nonce is not 32 hex digits");
  return { relay_id: input.relayId, issued_ms: Math.trunc(input.issuedMs), nonce };
}

/** The signed report body, checked against the console's own schema before it is sent. */
export async function signedPanelViewRequest(request: StackPanelViewRequest, seed: Uint8Array): Promise<JsonObject> {
  const signature = bytesToLowerHex(await ed25519Sign(seed, stackPanelViewMessage(request)));
  if (!stackPanelViewReportSchema.safeParse({ request, signature }).success) throw new RelayKitError("usage", "the panel-view request is not the console's shape");
  return { request: { ...request, issued_ms: BigInt(request.issued_ms) }, signature };
}

/** Gray's answer, as plain JSON values (numbers as numbers): the panel's accounts and health for this relay. */
export interface PanelView {
  /** The body of the panel's `GET …/accounts`: one object an account, each with its `group`. */
  readonly accounts: readonly unknown[];
  /** The body of the panel's `GET …/health`. */
  readonly health: Readonly<Record<string, unknown>>;
}

/**
 * A read's end. `code` when it failed: `no_stack` (the config has no `stack` section), `request_invalid` (this tool
 * could not build the request), `unreachable` (no answer), Gray's own code for a refusal (`lane_stack_relay_unknown`,
 * `lane_stack_signature_invalid`, the clock's), else `http_<status>`, and `bad_answer` for a 200 that is not the view.
 */
export type PanelViewResult =
  | { readonly ok: true; readonly view: PanelView }
  | { readonly ok: false; readonly code: string; readonly status: number | null };

export interface PanelViewOptions {
  readonly config: LoadedRelayConfig;
  /** The relay key's seed. */
  readonly seed: Uint8Array;
  readonly nowMs: number;
  readonly random: (length: number) => Uint8Array;
  /** One POST; global `fetch` when absent, a fake in the tests. */
  readonly post?: StackPost;
}

/** Gray's error code (`{"error": {"code": …}}`), or null. Only a closed lower-case word is passed on. */
function errorCodeOf(text: string): string | null {
  try {
    const error = get(parsePlain(text) as Json, "error");
    const code = isObject(error) ? get(error, "code") : null;
    return typeof code === "string" && /^[a-z0-9_]{1,64}$/.test(code) ? code : null;
  } catch {
    return null;
  }
}

/** Read the relay's panel view from Gray, once. */
export async function readPanelView(options: PanelViewOptions): Promise<PanelViewResult> {
  const stack = options.config.daemon.stack;
  if (stack === null) return { ok: false, code: "no_stack", status: null };
  let body: string;
  try {
    body = toJsonString(await signedPanelViewRequest(panelViewRequest({ relayId: options.config.daemon.relayId, issuedMs: options.nowMs, random: options.random }), options.seed));
  } catch {
    return { ok: false, code: "request_invalid", status: null };
  }
  let answer: { readonly status: number; readonly text: string };
  try {
    answer = await (options.post ?? defaultPost)(`${stack.reportOrigin}${PANEL_VIEW_PATH}`, body);
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
  const view = value as { readonly accounts?: unknown; readonly health?: unknown } | null;
  if (typeof view !== "object" || view === null || !Array.isArray(view.accounts) || typeof view.health !== "object" || view.health === null || Array.isArray(view.health)) {
    return { ok: false, code: "bad_answer", status: 200 };
  }
  return { ok: true, view: { accounts: view.accounts, health: view.health as Record<string, unknown> } };
}

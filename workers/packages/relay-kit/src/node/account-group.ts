/**
 * The relay's own change of its accounts' group on Gray (docs/design/relay-operator-page.md section 2): what the
 * panel's Move to group does, signed by the relay key. A group is a name for people; it lives on Gray, is not part of
 * what the VM is given, and changing it restarts nothing. gray-assistant's page uses this to put an account it just
 * added in the group the operator chose, and `gray-assistant accounts group` does the same from a terminal.
 *
 * `POST <stack.report_origin>/v1/lane-stack/account-group` with
 * `{"request": {"relay_id", "issued_ms", "nonce", "account_ids", "group"}, "signature": "<128 hex>"}`: the relay key's
 * Ed25519 over `stackAccountGroupMessage(request)` (`@gray/control`). Gray answers `{"grouped": [...], "unknown": [...]}`:
 * the accounts now in the group (or in none), and the ones it does not have yet (one added a moment ago is adopted
 * from the push's report; ask again for those).
 *
 * As the panel-view read beside it (`./panel-view.ts`), nothing here throws for what Gray or the network does: the
 * result says it with a closed code. The request holds no secret.
 */
import { bytesToLowerHex, ed25519Sign } from "@gray/attest";
import { STACK_PANEL_VIEW_NONCE_PATTERN, stackAccountGroupMessage, stackAccountGroupReportSchema, type StackAccountGroupRequest } from "@gray/control";
import { get, isObject, parsePlain, toJsonString, type Json, type JsonObject } from "@gray/json";
import { RelayKitError } from "../errors.ts";
import type { LoadedRelayConfig } from "./config-file.ts";
import { defaultPost, type StackPost } from "./stack.ts";

export const ACCOUNT_GROUP_PATH = "/v1/lane-stack/account-group";

/** The request a change sends: the relay, this machine's clock, a fresh nonce, the accounts and their group (null: none). */
export function accountGroupRequest(input: {
  readonly relayId: string;
  readonly issuedMs: number;
  readonly random: (length: number) => Uint8Array;
  readonly accountIds: readonly string[];
  readonly group: string | null;
}): StackAccountGroupRequest {
  const nonce = bytesToLowerHex(input.random(16));
  if (!STACK_PANEL_VIEW_NONCE_PATTERN.test(nonce)) throw new RelayKitError("usage", "the group change's nonce is not 32 hex digits");
  return { relay_id: input.relayId, issued_ms: Math.trunc(input.issuedMs), nonce, account_ids: [...input.accountIds], group: input.group === null ? null : input.group.trim() };
}

/** The signed body, checked against the console's own schema before it is sent. */
export async function signedAccountGroupRequest(request: StackAccountGroupRequest, seed: Uint8Array): Promise<JsonObject> {
  const signature = bytesToLowerHex(await ed25519Sign(seed, stackAccountGroupMessage(request)));
  if (!stackAccountGroupReportSchema.safeParse({ request, signature }).success) throw new RelayKitError("usage", "the group change is not the console's shape");
  return { request: { ...request, issued_ms: BigInt(request.issued_ms) }, signature };
}

/**
 * A change's end. `code` when it failed: `no_stack` (the config has no `stack` section), `request_invalid` (an account
 * id or a group name this tool cannot send), `unreachable` (no answer), Gray's own code for a refusal
 * (`invalid_request` for a name that breaks the group's rule, `lane_stack_relay_unknown`, the signature's, the
 * clock's), else `http_<status>`, and `bad_answer` for a 200 that is not the answer.
 */
export type AccountGroupResult =
  | { readonly ok: true; readonly grouped: readonly string[]; readonly unknown: readonly string[] }
  | { readonly ok: false; readonly code: string; readonly status: number | null };

export interface AccountGroupOptions {
  readonly config: LoadedRelayConfig;
  /** The relay key's seed. */
  readonly seed: Uint8Array;
  readonly nowMs: number;
  readonly random: (length: number) => Uint8Array;
  readonly accountIds: readonly string[];
  readonly group: string | null;
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

const ids = (value: unknown): string[] | null => (Array.isArray(value) && value.every((id) => typeof id === "string") ? (value as string[]) : null);

/** Put the accounts in the group (null: in none) on Gray, once. */
export async function writeAccountGroup(options: AccountGroupOptions): Promise<AccountGroupResult> {
  const stack = options.config.daemon.stack;
  if (stack === null) return { ok: false, code: "no_stack", status: null };
  let body: string;
  try {
    const request = accountGroupRequest({ relayId: options.config.daemon.relayId, issuedMs: options.nowMs, random: options.random, accountIds: options.accountIds, group: options.group });
    body = toJsonString(await signedAccountGroupRequest(request, options.seed));
  } catch {
    return { ok: false, code: "request_invalid", status: null };
  }
  let answer: { readonly status: number; readonly text: string };
  try {
    answer = await (options.post ?? defaultPost)(`${stack.reportOrigin}${ACCOUNT_GROUP_PATH}`, body);
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
  const read = value as { readonly grouped?: unknown; readonly unknown?: unknown } | null;
  const grouped = typeof read === "object" && read !== null ? ids(read.grouped) : null;
  const unknown = typeof read === "object" && read !== null ? ids(read.unknown) : null;
  if (grouped === null || unknown === null) return { ok: false, code: "bad_answer", status: 200 };
  return { ok: true, grouped, unknown };
}

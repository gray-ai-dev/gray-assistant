/**
 * The relay's own change of its accounts' settings on Gray (docs/design/relay-operator-page.md section 2): what the
 * panel's Edit settings (models, weight, concurrency) and Pause/Resume do, signed by the relay key, so
 * `gray-assistant accounts set|pause|resume` offer what the panel offers. These settings live on Gray only: nothing here
 * touches the account file or the VM, and Gray makes one configuration version of a change.
 *
 * `POST <stack.report_origin>/v1/lane-stack/account-settings` with `{"request": {"relay_id", "issued_ms", "nonce",
 * "account_ids", "models"?, "weight"?, "max_concurrency"?, "paused"?}, "signature": "<128 hex>"}`: the relay key's
 * Ed25519 over `stackAccountSettingsMessage(request)` (`@gray/control`). Gray answers `{"accounts": [...], "unknown":
 * [...]}`: the accounts as stored after the change, and the ones it does not have yet.
 *
 * As the group change beside it (`./account-group.ts`), nothing here throws for what Gray or the network does: the
 * result says it with a closed code. The request holds no secret.
 */
import { bytesToLowerHex, ed25519Sign } from "@gray/attest";
import { STACK_PANEL_VIEW_NONCE_PATTERN, stackAccountSettingsMessage, stackAccountSettingsReportSchema, type StackAccountSettingsRequest } from "@gray/control";
import { parsePlain, toJsonString, type JsonObject } from "@gray/json";
import { RelayKitError } from "../errors.ts";
import { errorCodeOf } from "./account-group.ts";
import type { LoadedRelayConfig } from "./config-file.ts";
import { defaultPost, type StackPost } from "./stack.ts";

export const ACCOUNT_SETTINGS_PATH = "/v1/lane-stack/account-settings";

/** One change: any of the three settings (`models: "*"` for every model of the accounts' vendor), or `paused` alone. */
export type AccountSettingsChange = Pick<StackAccountSettingsRequest, "models" | "weight" | "max_concurrency" | "paused">;

/** The request a change sends: the relay, this machine's clock, a fresh nonce, the accounts and the members the change names. */
export function accountSettingsRequest(input: {
  readonly relayId: string;
  readonly issuedMs: number;
  readonly random: (length: number) => Uint8Array;
  readonly accountIds: readonly string[];
  readonly change: AccountSettingsChange;
}): StackAccountSettingsRequest {
  const nonce = bytesToLowerHex(input.random(16));
  if (!STACK_PANEL_VIEW_NONCE_PATTERN.test(nonce)) throw new RelayKitError("usage", "the settings change's nonce is not 32 hex digits");
  const { models, weight, max_concurrency, paused } = input.change;
  return {
    relay_id: input.relayId,
    issued_ms: Math.trunc(input.issuedMs),
    nonce,
    account_ids: [...input.accountIds],
    ...(models === undefined ? {} : { models: models === "*" ? "*" : [...models] }),
    ...(weight === undefined ? {} : { weight }),
    ...(max_concurrency === undefined ? {} : { max_concurrency }),
    ...(paused === undefined ? {} : { paused }),
  };
}

/** The signed body, checked against the console's own schema before it is sent; its integers as JSON integers. */
export async function signedAccountSettingsRequest(request: StackAccountSettingsRequest, seed: Uint8Array): Promise<JsonObject> {
  const signature = bytesToLowerHex(await ed25519Sign(seed, stackAccountSettingsMessage(request)));
  if (!stackAccountSettingsReportSchema.safeParse({ request, signature }).success) throw new RelayKitError("usage", "the settings change is not the console's shape");
  const { weight, max_concurrency } = request;
  return {
    request: {
      ...request,
      issued_ms: BigInt(request.issued_ms),
      ...(weight === undefined ? {} : { weight: BigInt(weight) }),
      ...(max_concurrency === undefined ? {} : { max_concurrency: BigInt(max_concurrency) }),
    },
    signature,
  };
}

/** An account as Gray stores it after the change: what the panel shows of these settings. */
export interface SettingsAccount {
  readonly account_id: string;
  readonly models: readonly string[];
  readonly weight: number;
  readonly max_concurrency: number;
  readonly status: string;
}

/**
 * A change's end. `code` when it failed: `no_stack` (the config has no `stack` section), `request_invalid` (an account
 * id, a model ID or a value this tool cannot send), `unreachable` (no answer), Gray's own code for a refusal
 * (`invalid_request`, `lane_stack_accounts_vendor_mixed`, `lane_stack_relay_unknown`, the signature's, the clock's),
 * else `http_<status>`, and `bad_answer` for a 200 that is not the answer.
 */
export type AccountSettingsResult =
  | { readonly ok: true; readonly accounts: readonly SettingsAccount[]; readonly unknown: readonly string[] }
  | { readonly ok: false; readonly code: string; readonly status: number | null };

export interface AccountSettingsOptions {
  readonly config: LoadedRelayConfig;
  /** The relay key's seed. */
  readonly seed: Uint8Array;
  readonly nowMs: number;
  readonly random: (length: number) => Uint8Array;
  readonly accountIds: readonly string[];
  readonly change: AccountSettingsChange;
  /** One POST; global `fetch` when absent, a fake in the tests. */
  readonly post?: StackPost;
}

const strings = (value: unknown): value is string[] => Array.isArray(value) && value.every((item) => typeof item === "string");
const whole = (value: unknown): value is number => typeof value === "number" && Number.isSafeInteger(value);

function settingsAccount(value: unknown): SettingsAccount | null {
  if (typeof value !== "object" || value === null) return null;
  const a = value as Record<string, unknown>;
  if (typeof a["account_id"] !== "string" || !strings(a["models"]) || !whole(a["weight"]) || !whole(a["max_concurrency"]) || typeof a["status"] !== "string") return null;
  return { account_id: a["account_id"], models: a["models"], weight: a["weight"], max_concurrency: a["max_concurrency"], status: a["status"] };
}

/** Make the change on Gray, once. */
export async function writeAccountSettings(options: AccountSettingsOptions): Promise<AccountSettingsResult> {
  const stack = options.config.daemon.stack;
  if (stack === null) return { ok: false, code: "no_stack", status: null };
  let body: string;
  try {
    const request = accountSettingsRequest({ relayId: options.config.daemon.relayId, issuedMs: options.nowMs, random: options.random, accountIds: options.accountIds, change: options.change });
    body = toJsonString(await signedAccountSettingsRequest(request, options.seed));
  } catch {
    return { ok: false, code: "request_invalid", status: null };
  }
  let answer: { readonly status: number; readonly text: string };
  try {
    answer = await (options.post ?? defaultPost)(`${stack.reportOrigin}${ACCOUNT_SETTINGS_PATH}`, body);
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
  const read = typeof value === "object" && value !== null ? (value as { readonly accounts?: unknown; readonly unknown?: unknown }) : {};
  const accounts = Array.isArray(read.accounts) ? read.accounts.map(settingsAccount) : null;
  if (accounts === null || accounts.some((a) => a === null) || !strings(read.unknown)) return { ok: false, code: "bad_answer", status: 200 };
  return { ok: true, accounts: accounts as SettingsAccount[], unknown: read.unknown };
}

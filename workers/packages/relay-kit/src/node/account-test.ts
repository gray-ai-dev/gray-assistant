/**
 * The relay's own test of one account on Gray: what the panel's Test does, signed by the relay key, so
 * `gray-assistant accounts test <account> [--model <id>]` offers what the panel offers. Gray queues the test and its VM
 * calls the vendor with the account's credential, identity and proxy and a few tokens. A passing test ends the tested
 * model's rests (a hold or cool of that model a test clears) and the account-wide ones, never another model's, so an
 * account held on one model is lifted by a test of that model (Roteo, 2026-11-19: held on its second model).
 *
 * `POST <stack.report_origin>/v1/lane-stack/account-test` with `{"request": {"relay_id", "issued_ms", "nonce",
 * "account_id", "model"? | "test_id"?}, "signature": "<128 hex>"}`: the relay key's Ed25519 over
 * `stackAccountTestMessage(request)` (`@gray/control`). Without `test_id` Gray queues a test (of `model`, else the
 * account's first model that rests on its own, else its first); with it Gray answers that test as it stands, which is
 * how the command waits for the VM's answer. Gray answers the test as the panel lists it.
 *
 * As the settings change beside it (`./account-settings.ts`), nothing here throws for what Gray or the network does: the
 * result says it with a closed code. The request holds no secret.
 */
import { bytesToLowerHex, ed25519Sign } from "@gray/attest";
import { STACK_PANEL_VIEW_NONCE_PATTERN, stackAccountTestMessage, stackAccountTestReportSchema, type StackAccountTestRequest } from "@gray/control";
import { parsePlain, toJsonString, type JsonObject } from "@gray/json";
import { RelayKitError } from "../errors.ts";
import { errorCodeOf } from "./account-group.ts";
import type { LoadedRelayConfig } from "./config-file.ts";
import { defaultPost, type StackPost } from "./stack.ts";

export const ACCOUNT_TEST_PATH = "/v1/lane-stack/account-test";
/** While a test waits for the VM, it is read again this often (the VM asks Gray for tests about as often). */
export const ACCOUNT_TEST_POLL_MS = 3_000;
/** How long the command waits for the VM's answer by default: a little over Gray's two minutes before a test expires. */
export const ACCOUNT_TEST_WAIT_MS = 150_000;

/** The request: the relay, this machine's clock, a fresh nonce, the account, and the model to test or the test to read. */
export function accountTestRequest(input: {
  readonly relayId: string;
  readonly issuedMs: number;
  readonly random: (length: number) => Uint8Array;
  readonly accountId: string;
  readonly model?: string | undefined;
  readonly testId?: string | undefined;
}): StackAccountTestRequest {
  const nonce = bytesToLowerHex(input.random(16));
  if (!STACK_PANEL_VIEW_NONCE_PATTERN.test(nonce)) throw new RelayKitError("usage", "the test's nonce is not 32 hex digits");
  return {
    relay_id: input.relayId,
    issued_ms: Math.trunc(input.issuedMs),
    nonce,
    account_id: input.accountId,
    ...(input.model === undefined ? {} : { model: input.model }),
    ...(input.testId === undefined ? {} : { test_id: input.testId }),
  };
}

/** The signed body, checked against the console's own schema before it is sent; `issued_ms` as a JSON integer. */
export async function signedAccountTestRequest(request: StackAccountTestRequest, seed: Uint8Array): Promise<JsonObject> {
  const signature = bytesToLowerHex(await ed25519Sign(seed, stackAccountTestMessage(request)));
  if (!stackAccountTestReportSchema.safeParse({ request, signature }).success) throw new RelayKitError("usage", "the test is not the console's shape");
  return { request: { ...request, issued_ms: BigInt(request.issued_ms) }, signature };
}

/** A test as Gray lists it: what the panel's Tests show of it. */
export interface AccountTest {
  readonly test_id: string;
  readonly account_id: string;
  readonly model: string;
  /** `pending` until the VM answers, then `answered`; `expired` when the VM did not answer in time. */
  readonly state: "pending" | "answered" | "expired";
  readonly outcome: "ok" | "failed" | null;
  readonly code: string | null;
  readonly status: number | null;
  readonly class: string | null;
  readonly vendor_code: string | null;
  readonly first_token_ms: number | null;
  readonly total_ms: number | null;
  /** The rests a passing test ended. */
  readonly cleared: number | null;
}

/**
 * One request's end. `code` when it failed: `no_stack` (the config has no `stack` section), `request_invalid` (an
 * account id or model ID this tool cannot send), `unreachable` (no answer), Gray's own code for a refusal
 * (`invalid_request` for a model the account does not have, `lane_stack_account_unknown`, `lane_stack_account_no_model`,
 * `lane_stack_test_too_soon`, `lane_stack_tests_full`, `lane_stack_test_unknown`, the signature's, the clock's), else
 * `http_<status>`, and `bad_answer` for a 200 that is not a test.
 */
export type AccountTestResult = { readonly ok: true; readonly test: AccountTest } | { readonly ok: false; readonly code: string; readonly status: number | null };

export interface AccountTestOptions {
  readonly config: LoadedRelayConfig;
  /** The relay key's seed. */
  readonly seed: Uint8Array;
  readonly nowMs: number;
  readonly random: (length: number) => Uint8Array;
  readonly accountId: string;
  /** The model to test (queues a test); absent with `testId` absent: Gray picks the model. */
  readonly model?: string | undefined;
  /** A test queued before: read it, queue nothing. */
  readonly testId?: string | undefined;
  /** One POST; global `fetch` when absent, a fake in the tests. */
  readonly post?: StackPost;
}

const numberOrNull = (value: unknown): value is number | null => value === null || (typeof value === "number" && Number.isSafeInteger(value));
const textOrNull = (value: unknown): value is string | null => value === null || typeof value === "string";

function accountTest(value: unknown): AccountTest | null {
  if (typeof value !== "object" || value === null) return null;
  const t = value as Record<string, unknown>;
  const state = t["state"];
  const outcome = t["outcome"];
  if (typeof t["test_id"] !== "string" || typeof t["account_id"] !== "string" || typeof t["model"] !== "string") return null;
  if (state !== "pending" && state !== "answered" && state !== "expired") return null;
  if (outcome !== null && outcome !== "ok" && outcome !== "failed") return null;
  if (!textOrNull(t["code"]) || !textOrNull(t["class"]) || !textOrNull(t["vendor_code"])) return null;
  if (!numberOrNull(t["status"]) || !numberOrNull(t["first_token_ms"]) || !numberOrNull(t["total_ms"]) || !numberOrNull(t["cleared"])) return null;
  return {
    test_id: t["test_id"],
    account_id: t["account_id"],
    model: t["model"],
    state,
    outcome,
    code: t["code"],
    status: t["status"],
    class: t["class"],
    vendor_code: t["vendor_code"],
    first_token_ms: t["first_token_ms"],
    total_ms: t["total_ms"],
    cleared: t["cleared"],
  };
}

/** Queue a test on Gray, or read one, once. */
export async function postAccountTest(options: AccountTestOptions): Promise<AccountTestResult> {
  const stack = options.config.daemon.stack;
  if (stack === null) return { ok: false, code: "no_stack", status: null };
  let body: string;
  try {
    const request = accountTestRequest({ relayId: options.config.daemon.relayId, issuedMs: options.nowMs, random: options.random, accountId: options.accountId, model: options.model, testId: options.testId });
    body = toJsonString(await signedAccountTestRequest(request, options.seed));
  } catch {
    return { ok: false, code: "request_invalid", status: null };
  }
  let answer: { readonly status: number; readonly text: string };
  try {
    answer = await (options.post ?? defaultPost)(`${stack.reportOrigin}${ACCOUNT_TEST_PATH}`, body);
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
  const test = accountTest(value);
  return test === null ? { ok: false, code: "bad_answer", status: 200 } : { ok: true, test };
}

export interface AccountTestRun extends Omit<AccountTestOptions, "nowMs"> {
  readonly now: () => number;
  readonly sleep: (ms: number) => Promise<void>;
  /** Wait for the VM's answer (the default); false: queue it and return the pending test. */
  readonly wait: boolean;
  readonly timeoutMs?: number;
  /** Told once the test is queued (or read), before the wait. */
  readonly onQueued?: (test: AccountTest) => void;
}

/**
 * Queue a test (or read `testId`'s) and, with `wait`, read it again every ACCOUNT_TEST_POLL_MS until the VM answered
 * it, it expired, or `timeoutMs` passed: the result then carries the test as last read, still `pending`.
 */
export async function runAccountTest(options: AccountTestRun): Promise<AccountTestResult> {
  const started = options.now();
  const once = (testId: string | undefined, model: string | undefined) => postAccountTest({ ...options, nowMs: options.now(), testId, model });
  let result = await once(options.testId, options.testId === undefined ? options.model : undefined);
  if (!result.ok) return result;
  options.onQueued?.(result.test);
  const timeoutMs = options.timeoutMs ?? ACCOUNT_TEST_WAIT_MS;
  while (options.wait && result.ok && result.test.state === "pending" && options.now() - started < timeoutMs) {
    await options.sleep(Math.min(ACCOUNT_TEST_POLL_MS, Math.max(1, timeoutMs - (options.now() - started))));
    const read = await once(result.test.test_id, undefined);
    // A read that fails (the network, the clock) leaves the test as last read; the next read may answer.
    if (read.ok) result = read;
    else if (read.code !== "unreachable") return read;
  }
  return result;
}

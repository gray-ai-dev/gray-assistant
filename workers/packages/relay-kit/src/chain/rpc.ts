/**
 * The kit's JSON-RPC client for the relay's chain: viem's public client over a transport of the kit's own, so every
 * answer is read with a byte cap and a timeout, without redirects, and through @gray/json, as every other answer the kit
 * reads. No retry: the chain checks ask two independent endpoints instead (`checks.ts`).
 */
import { parsePlain } from "@gray/json";
import { utf8Text } from "@gray/relay-connector";
import { createPublicClient, custom, type PublicClient } from "viem";
import { RelayKitError } from "../errors.ts";

/** How long one JSON-RPC request may take. */
export const RPC_TIMEOUT_MS = 15_000;
/** The largest answer read: a contract's code (24 KiB at most, as hex) or a page of logs. */
export const RPC_MAX_ANSWER_BYTES = 4 * 1024 * 1024;
const LOOPBACK_HOSTS = new Set(["127.0.0.1", "[::1]", "localhost"]);

/** An RPC endpoint URL the kit uses: https, or http on a loopback host (a local anvil). Returned as given. */
export function checkedRpcUrl(value: string, what = "the RPC endpoint"): string {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new RelayKitError("usage", `${what} is not a URL`);
  }
  if (url.protocol !== "https:" && !(url.protocol === "http:" && LOOPBACK_HOSTS.has(url.hostname))) {
    throw new RelayKitError("usage", `${what} must be https (http only for 127.0.0.1, ::1 or localhost)`);
  }
  if (url.username !== "" || url.password !== "") throw new RelayKitError("usage", `${what} must not carry a user or password`);
  return value;
}

/** The endpoint's name in messages: its origin, never its path or query (a provider's API key often sits there). */
export function rpcLabel(url: string): string {
  try {
    return new URL(url).origin;
  } catch {
    return "the RPC endpoint";
  }
}

/** A JSON-RPC error as viem reads it (`code`, `message`, `data`). */
class RpcAnswerError extends Error {
  readonly code: number;
  readonly data: unknown;
  constructor(code: number, message: string, data: unknown) {
    super(message);
    this.code = code;
    this.data = data;
  }
}

async function readCapped(response: Response, maxBytes: number): Promise<string> {
  const reader = response.body?.getReader();
  if (reader === undefined) return "";
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel();
      throw new Error("answer too large");
    }
    chunks.push(value);
  }
  const all = new Uint8Array(total);
  let at = 0;
  for (const chunk of chunks) {
    all.set(chunk, at);
    at += chunk.byteLength;
  }
  return utf8Text(all);
}

export interface RpcOptions {
  readonly fetch?: typeof fetch;
  readonly timeoutMs?: number;
}

/** An EIP-1193 `request` over HTTP JSON-RPC: one POST per call, the answer's `result` or a thrown `{code, message}`. */
export function httpRequestFn(url: string, options: RpcOptions = {}) {
  const fetchFn = options.fetch ?? fetch;
  let id = 0;
  return async ({ method, params }: { method: string; params?: unknown }): Promise<unknown> => {
    id += 1;
    let text: string;
    try {
      const response = await fetchFn(url, {
        method: "POST",
        headers: { "content-type": "application/json", accept: "application/json", "user-agent": "gray-assistant" },
        body: JSON.stringify({ jsonrpc: "2.0", id, method, params: params ?? [] }),
        redirect: "error",
        signal: AbortSignal.timeout(options.timeoutMs ?? RPC_TIMEOUT_MS),
      });
      if (response.status < 200 || response.status > 299) throw new Error(`HTTP ${response.status}`);
      text = await readCapped(response, RPC_MAX_ANSWER_BYTES);
    } catch (error) {
      throw new RelayKitError("chain_unreachable", `${rpcLabel(url)} did not answer ${method}${error instanceof Error && /^HTTP \d+$/.test(error.message) ? ` (${error.message})` : ""}`);
    }
    let answer: unknown;
    try {
      answer = parsePlain(text);
    } catch {
      throw new RelayKitError("chain_unreachable", `${rpcLabel(url)} answered ${method} with something that is not JSON`);
    }
    if (typeof answer !== "object" || answer === null || Array.isArray(answer)) throw new RelayKitError("chain_unreachable", `${rpcLabel(url)} answered ${method} with something that is not a JSON-RPC answer`);
    const record = answer as Record<string, unknown>;
    if (record["error"] !== undefined && record["error"] !== null) {
      const error = record["error"] as Record<string, unknown>;
      const code = typeof error["code"] === "number" ? error["code"] : -32603;
      const message = typeof error["message"] === "string" ? error["message"].slice(0, 200) : "error";
      throw new RpcAnswerError(code, message, error["data"]);
    }
    if (!Object.hasOwn(record, "result")) throw new RelayKitError("chain_unreachable", `${rpcLabel(url)} answered ${method} without a result`);
    return record["result"];
  };
}

/** viem's public client for one endpoint, through the kit's transport. */
export function rpcClient(url: string, options: RpcOptions = {}): PublicClient {
  return createPublicClient({ transport: custom({ request: httpRequestFn(checkedRpcUrl(url), options) }, { retryCount: 0 }) });
}

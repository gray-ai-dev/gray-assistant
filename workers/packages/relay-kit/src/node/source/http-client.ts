/**
 * The one HTTP path every remote adapter uses: a GET with a deadline that also honours the caller's
 * `AbortSignal`, `redirect: "error"` so an `Authorization` header cannot be replayed to another
 * origin, and a hard byte cap before JSON is parsed. Error details name a fixed operation label
 * ("accounts", "credential", ...), never a URL, a query string, a response body or a header value:
 * a body can echo a token, and a URL can carry one in a path.
 */
import { parsePlain } from "@gray/json";
import { utf8Text } from "@gray/relay-connector";
import { RelayKitError } from "../../errors.ts";

/** One fetched body, whatever its status; the caller decides what a status means. */
export interface TextResponse {
  readonly status: number;
  readonly text: string;
}

export interface FetchTextOptions {
  readonly fetch: typeof fetch;
  readonly signal: AbortSignal | undefined;
  readonly timeoutMs: number;
  readonly maxBytes: number;
  readonly headers?: Readonly<Record<string, string>>;
  /** A fixed operation name for errors, never a URL or a query. */
  readonly label: string;
  /**
   * `GET` unless given; the relay's own login (`../login/codex-oauth.ts`) POSTs to the issuer, and the write-back of
   * an in-VM refresh PUTs to the account source (`http.ts` writeCredential).
   */
  readonly method?: "GET" | "POST" | "PUT";
  /** The request body of a `POST`; never part of an error. */
  readonly body?: string;
}

interface MergedSignal {
  readonly signal: AbortSignal;
  release(): void;
}

function mergeSignal(signal: AbortSignal | undefined, timeoutMs: number): MergedSignal {
  const controller = new AbortController();
  const onAbort = (): void => controller.abort(signal?.reason);
  if (signal !== undefined) {
    if (signal.aborted) controller.abort(signal.reason);
    else signal.addEventListener("abort", onAbort, { once: true });
  }
  const timer = setTimeout(() => controller.abort(new Error("source deadline")), timeoutMs);
  return {
    signal: controller.signal,
    release(): void {
      clearTimeout(timer);
      signal?.removeEventListener("abort", onAbort);
    },
  };
}

async function readCapped(response: Response, maxBytes: number, label: string): Promise<Uint8Array> {
  const body = response.body;
  if (body === null) {
    const bytes = new Uint8Array(await response.arrayBuffer());
    if (bytes.byteLength > maxBytes) throw new RelayKitError("source_bad_response", label);
    return bytes;
  }
  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value === undefined) continue;
      total += value.byteLength;
      if (total > maxBytes) {
        try {
          await reader.cancel();
        } catch {
          // The cap is the refusal; a cancelled stream's own error changes nothing.
        }
        throw new RelayKitError("source_bad_response", label);
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return bytes;
}

/** GET (or POST) a URL and return its status and UTF-8 body; network failures and oversize bodies throw. */
export async function fetchText(url: string, options: FetchTextOptions): Promise<TextResponse> {
  // The deadline covers the body too: a server that sends headers and then stalls must not hold a
  // poll open forever. `release` runs only after the last read.
  const merged = mergeSignal(options.signal, options.timeoutMs);
  try {
    let response: Response;
    try {
      response = await options.fetch(url, {
        method: options.method ?? "GET",
        headers: { accept: "application/json", ...options.headers },
        ...(options.body === undefined ? {} : { body: options.body }),
        redirect: "error",
        signal: merged.signal,
      });
    } catch {
      throw new RelayKitError("source_unreachable", options.signal?.aborted === true ? "aborted" : "request");
    }
    let bytes: Uint8Array;
    try {
      bytes = await readCapped(response, options.maxBytes, options.label);
    } catch (error) {
      if (error instanceof RelayKitError) throw error;
      throw new RelayKitError("source_unreachable", options.signal?.aborted === true ? "aborted" : "request");
    }
    let text: string;
    try {
      text = utf8Text(bytes);
    } catch {
      throw new RelayKitError("source_bad_response", options.label);
    }
    return { status: response.status, text };
  } finally {
    merged.release();
  }
}

/** Parse one fetched text as JSON; a syntax error is a fixed sentence, never the parser's. */
export function parseJsonText(text: string, label: string): unknown {
  try {
    return parsePlain(text);
  } catch {
    throw new RelayKitError("source_bad_response", label);
  }
}

export interface JsonResponseOptions extends Omit<FetchTextOptions, "headers"> {
  readonly headers?: Readonly<Record<string, string>>;
  /** 404 gets this code; every other non-200 is `source_bad_response`. */
  readonly notFoundCode?: "source_not_found" | "source_bad_response";
}

/** GET a URL that must answer 200 with JSON, with the closed status mapping every adapter shares. */
export async function fetchJson(url: string, options: JsonResponseOptions): Promise<unknown> {
  const response = await fetchText(url, {
    ...options,
    headers: options.headers,
  });
  if (response.status === 401 || response.status === 403) {
    throw new RelayKitError("source_unauthorized", options.label);
  }
  if (response.status === 404 && options.notFoundCode === "source_not_found") {
    throw new RelayKitError("source_not_found", options.label);
  }
  if (response.status !== 200) throw new RelayKitError("source_bad_response", options.label);
  return parseJsonText(response.text, options.label);
}

/** Append path segments under a validated base URL, preserving a reverse proxy's path prefix. */
export function joinSourceUrl(base: string, ...segments: readonly string[]): string {
  const rooted = base.endsWith("/") ? base : `${base}/`;
  return new URL(segments.join("/"), rooted).toString();
}

/** Add a query parameter to a URL without touching the base's path. */
export function withQuery(url: string, name: string, value: string): string {
  const parsed = new URL(url);
  parsed.searchParams.set(name, value);
  return parsed.toString();
}

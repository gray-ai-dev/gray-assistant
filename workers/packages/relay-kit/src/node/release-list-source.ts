/**
 * The release list over plain `fetch`, for `run` and `releases accept`. The list is public; its
 * integrity comes from Gray's Ed25519 signature and its freshness from `release_list_max_age`, not
 * from TLS. (The lane hop is a different story: that one pins the attested SPKI.)
 *
 * `redirect: "error"` keeps a signature-bearing GET from being replayed to another origin; the byte
 * cap and the deadline are the daemon's existing ones.
 */
import { MAX_RELEASE_LIST_BYTES } from "../daemon/releases.ts";
import type { DaemonFetch, DaemonHttpResponse } from "../daemon/types.ts";
import { httpsRequestOnce } from "./https.ts";

/**
 * A `DaemonFetch` over Node's global fetch. Only GET is used; every other method is a bug.
 * `ca` (a private trust anchor) is honoured for an https URL by using the same `httpsRequestOnce`
 * the lane client uses; without it, the platform trust store does the validation.
 */
export function createPlainDaemonFetch(options: { readonly timeoutMs?: number; readonly ca?: string } = {}): DaemonFetch {
  return async (url, init): Promise<DaemonHttpResponse> => {
    if (init.method !== "GET") throw new Error("plain fetch only serves GET");
    if (options.ca !== undefined && url.startsWith("https:")) {
      const response = await httpsRequestOnce({
        url,
        method: "GET",
        headers: init.headers ?? {},
        ca: options.ca,
        timeoutMs: init.timeoutMs ?? options.timeoutMs ?? 20_000,
        maxResponseBytes: MAX_RELEASE_LIST_BYTES,
      });
      return { status: response.status, headers: response.headers, body: response.body };
    }
    const response = await globalThis.fetch(url, {
      method: "GET",
      headers: init.headers ?? {},
      redirect: "error",
      signal: AbortSignal.timeout(init.timeoutMs ?? options.timeoutMs ?? 20_000),
    });
    const chunks: Uint8Array[] = [];
    let size = 0;
    const reader = response.body?.getReader();
    if (reader !== undefined) {
      for (;;) {
        const next = await reader.read();
        if (next.done) break;
        const chunk = next.value;
        size += chunk.length;
        if (size > MAX_RELEASE_LIST_BYTES) {
          await reader.cancel();
          throw new Error("release list too large");
        }
        chunks.push(chunk);
      }
    }
    const body = new Uint8Array(size);
    let offset = 0;
    for (const chunk of chunks) {
      body.set(chunk, offset);
      offset += chunk.length;
    }
    const headers: Record<string, string> = {};
    response.headers.forEach((value, name) => {
      headers[name] = value;
    });
    return { status: response.status, headers, body };
  };
}

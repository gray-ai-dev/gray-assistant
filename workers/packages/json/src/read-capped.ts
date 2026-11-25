/**
 * Bounded reads of an HTTP response body. `Response.text()` and `Response.arrayBuffer()` buffer
 * whatever the peer sends; these read the stream chunk by chunk and cancel it as soon as the byte
 * count passes the cap, so an oversized or endless body costs at most `maxBytes` plus one chunk.
 */

/** A response body longer than the caller's cap. The message names the cap, never the body. */
export class BodyTooLargeError extends Error {
  readonly maxBytes: number;
  constructor(maxBytes: number) {
    super(`response body exceeds ${maxBytes} bytes`);
    this.name = "BodyTooLargeError";
    this.maxBytes = maxBytes;
  }
}

function declaredLength(response: Response): number | null {
  const raw = response.headers.get("content-length");
  if (raw === null || !/^\d+$/.test(raw.trim())) return null;
  return Number(raw.trim());
}

async function cancelQuietly(response: Response, reader?: ReadableStreamDefaultReader<Uint8Array>): Promise<void> {
  try {
    if (reader !== undefined) await reader.cancel();
    else await response.body?.cancel();
  } catch {
    // The cap is the refusal; the stream's own cancellation error changes nothing.
  }
}

function concat(chunks: readonly Uint8Array[], total: number): Uint8Array {
  if (chunks.length === 1 && chunks[0]!.byteLength === total) return chunks[0]!;
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return bytes;
}

/**
 * Read at most `limit` bytes. With `overflow: "throw"` a longer body throws `BodyTooLargeError`;
 * with `"truncate"` the first `limit` bytes come back. Either way the rest of the stream is cancelled.
 */
async function readBounded(response: Response, limit: number, overflow: "throw" | "truncate"): Promise<Uint8Array> {
  if (!Number.isSafeInteger(limit) || limit < 0) throw new RangeError("maxBytes must be a non-negative safe integer");
  const declared = declaredLength(response);
  if (overflow === "throw" && declared !== null && declared > limit) {
    await cancelQuietly(response);
    throw new BodyTooLargeError(limit);
  }
  const body = response.body;
  if (body === null) {
    // No stream: a null body is empty, but an odd Response implementation may still buffer one.
    const bytes = new Uint8Array(await response.arrayBuffer());
    if (bytes.byteLength <= limit) return bytes;
    if (overflow === "throw") throw new BodyTooLargeError(limit);
    return bytes.subarray(0, limit);
  }
  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value === undefined || value.byteLength === 0) continue;
      if (total + value.byteLength > limit) {
        await cancelQuietly(response, reader);
        if (overflow === "throw") throw new BodyTooLargeError(limit);
        chunks.push(value.subarray(0, limit - total));
        total = limit;
        break;
      }
      chunks.push(value);
      total += value.byteLength;
    }
  } finally {
    reader.releaseLock();
  }
  return concat(chunks, total);
}

/** The body's bytes, or `BodyTooLargeError` (stream cancelled) once it passes `maxBytes`. */
export function readCappedBytes(response: Response, maxBytes: number): Promise<Uint8Array> {
  return readBounded(response, maxBytes, "throw");
}

/**
 * The body as text, decoded like `Response.text()` (UTF-8, invalid sequences replaced), or
 * `BodyTooLargeError` (stream cancelled) once it passes `maxBytes`.
 */
export async function readCappedText(response: Response, maxBytes: number): Promise<string> {
  return new TextDecoder().decode(await readBounded(response, maxBytes, "throw"));
}

/**
 * The first `maxBytes` of the body as text, the rest cancelled unread. For bodies that are only
 * shown or logged in part; a multi-byte character cut at the cap decodes as U+FFFD.
 */
export async function readTextPrefix(response: Response, maxBytes: number): Promise<string> {
  return new TextDecoder().decode(await readBounded(response, maxBytes, "truncate"));
}

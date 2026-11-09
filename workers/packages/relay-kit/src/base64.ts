/**
 * Standard base64 (RFC 4648 §4, with padding) for the one binary member of a JSON document: the
 * policy module inside a bundle.
 *
 * `btoa`/`atob` are platform primitives in Node and in workerd; the validation on both directions is
 * the package's own, so a second spelling of the same bytes (URL-safe characters, missing padding,
 * whitespace, a non-canonical final quantum) is refused instead of decoding to something the relay
 * did not sign. This is not a hand-written codec: the platform does the transcoding, and a round
 * trip is the canonical-form check.
 */

const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

/** The base64 text of `bytes`, padded and canonical. */
export function encodeBase64(bytes: Uint8Array): string {
  let binary = "";
  // `btoa` takes a binary string; build it in chunks so a 4 MiB module never becomes one spread.
  for (let offset = 0; offset < bytes.length; offset += 0x8000) {
    const chunk = bytes.subarray(offset, offset + 0x8000);
    let part = "";
    for (const byte of chunk) part += String.fromCharCode(byte);
    binary += part;
  }
  return btoa(binary);
}

/**
 * The bytes of canonical standard base64, or null when `text` is not exactly that (empty text is
 * empty bytes; callers that need a module refuse it separately).
 */
export function decodeBase64(text: unknown): Uint8Array | null {
  if (typeof text !== "string" || !BASE64.test(text)) return null;
  let binary: string;
  try {
    binary = atob(text);
  } catch {
    return null;
  }
  const out = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) out[index] = binary.charCodeAt(index);
  // A canonical encoding is the only one this function accepts: reject a form that round-trips to a
  // different text (there is none through atob, but the check keeps the rule in one place).
  return encodeBase64(out) === text ? out : null;
}

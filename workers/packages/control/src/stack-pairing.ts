import { ed25519VerifyHex, sha256BareHex, sha256Raw, utf8Bytes } from "@gray/attest";
import { z } from "zod";
import { STACK_ID_PATTERN } from "./stack.ts";

/**
 * Pairing a relay's gray-assistant with its record on Gray's panel (docs/confidential-lane-supply-implementation.md S57):
 * the panel's **Register a relay** ends with a one-time pairing code; on the relay's host `gray-assistant init --pair <code>
 * --gray <api origin>` makes the relay key there, sends Gray only its public half with the code and a signature by the
 * key over both, and receives the values the operator used to copy by hand. This file is what the console, relay-kit
 * and the panel share:
 *
 * - the code: `GRAY-` and six groups of four Crockford base32 characters, 120 random bits, so it can be sent to a
 *   public route with no session and no rate of guessing finds one (unlike RFC 8628's short user code, which only an
 *   authenticated user enters, a pairing code is the request's only credential). It is
 *   valid for `PAIRING_CODE_TTL_MS` and once; the console keeps only its SHA-256;
 * - the request (`pairRequestSchema`) and its signed message (`pairMessage`): the code and the key, so a key is paired
 *   only by whoever holds it, and a code is spent on exactly that key;
 * - the answer (`pairAnswerSchema`): the relay id and the setup values;
 * - the refusals, each a code and the operator's sentence;
 * - the key's fingerprint, which both the panel and gray-assistant print for the operator to compare.
 */

/** The code's first group; a reader knows the string at sight. */
export const PAIRING_CODE_PREFIX = "GRAY";
/** Crockford's base32 alphabet (no I, L, O, U): read aloud or retyped without ambiguity. */
export const PAIRING_CODE_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
/** 24 characters of 5 bits: 120 random bits. */
export const PAIRING_CODE_CHARS = 24;
/** The code as the panel shows it and as it is hashed: `GRAY-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX`. */
export const PAIRING_CODE_PATTERN = /^GRAY(?:-[0-9A-HJKMNP-TV-Z]{4}){6}$/;

/**
 * How long a code is valid: 15 minutes, the default lifetime of GitHub's device-flow codes ("The user must enter a
 * valid code within 15 minutes (or 900 seconds)", docs.github.com, Authorizing OAuth apps, device flow, read
 * 2026-10-29), the same kind of one-time code an operator carries from a browser to another machine (RFC 8628 §3.2,
 * `expires_in`). A code that expired is replaced with one click.
 */
export const PAIRING_CODE_TTL_MS = 15 * 60_000;

/** A fresh code from `random(15)` (120 bits), in its canonical form. */
export function newPairingCode(random: (length: number) => Uint8Array): string {
  const bytes = random(15);
  if (bytes.length !== 15) throw new Error("newPairingCode: the random source gave the wrong length");
  let chars = "";
  let buffer = 0;
  let bits = 0;
  for (const byte of bytes) {
    buffer = (buffer << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      chars += PAIRING_CODE_ALPHABET[(buffer >> (bits - 5)) & 31];
      bits -= 5;
    }
    buffer &= (1 << bits) - 1;
  }
  return formatPairingCode(chars);
}

function formatPairingCode(chars: string): string {
  const groups: string[] = [];
  for (let i = 0; i < chars.length; i += 4) groups.push(chars.slice(i, i + 4));
  return [PAIRING_CODE_PREFIX, ...groups].join("-");
}

/**
 * The canonical form of a code as an operator typed or pasted it, or null for a string that is no code: case and
 * spaces or hyphens between groups do not matter, and Crockford's look-alikes read as their digits (I and L as 1, O as
 * 0). Only the canonical form is hashed, so a retyped code is the same code.
 */
export function normalizePairingCode(input: string): string | null {
  if (input.length > 128) return null;
  let text = input.toUpperCase().replace(/[\s-]/g, "");
  if (!text.startsWith(PAIRING_CODE_PREFIX)) return null;
  text = text.slice(PAIRING_CODE_PREFIX.length).replace(/[IL]/g, "1").replace(/O/g, "0");
  if (text.length !== PAIRING_CODE_CHARS || [...text].some((c) => !PAIRING_CODE_ALPHABET.includes(c))) return null;
  return formatPairingCode(text);
}

/** What the console keeps of a code: SHA-256 of its canonical form, lower-case hex. A 120-bit code needs no slow hash. */
export function pairingCodeHash(code: string): string {
  return sha256BareHex(utf8Bytes(code));
}

/** The first line of the signed message. */
export const PAIR_DOMAIN = "gray-relay-pair/v1";

/** The bytes the relay key signs: the domain, the canonical code and the public key (64 lower hex), one per line. */
export function pairMessage(code: string, publicKeyHex: string): Uint8Array {
  return utf8Bytes([PAIR_DOMAIN, code, publicKeyHex].join("\n"));
}

/** Whether `signatureHex` is the key's over `pairMessage(code, publicKeyHex)`. */
export async function verifyPairSignature(code: string, publicKeyHex: string, signatureHex: string): Promise<boolean> {
  return ed25519VerifyHex(publicKeyHex, pairMessage(code, publicKeyHex), signatureHex).catch(() => false);
}

/**
 * The relay key's fingerprint as the panel and gray-assistant print it: `SHA256:` and the unpadded base64 of SHA-256 over
 * the 32 raw bytes of the Ed25519 public key, the form OpenSSH prints (`ssh-keygen -l`), though over the raw key rather
 * than an SSH key blob. Null for a string that is no key.
 */
export function relayKeyFingerprint(publicKeyHex: string): string | null {
  if (!/^[0-9a-f]{64}$/.test(publicKeyHex)) return null;
  const raw = new Uint8Array(32);
  for (let i = 0; i < 32; i++) raw[i] = Number.parseInt(publicKeyHex.slice(i * 2, i * 2 + 2), 16);
  let binary = "";
  for (const byte of sha256Raw(raw)) binary += String.fromCharCode(byte);
  return `SHA256:${btoa(binary).replace(/=+$/, "")}`;
}

const hex64 = z.string().regex(/^[0-9a-f]{64}$/);
const origin = z.string().max(2048).regex(/^https?:\/\/[A-Za-z0-9.-]+(?::[0-9]{1,5})?$/);

/** `POST /v1/lane-stack/pair`: the code as typed (normalized by the console), the key, its signature, gray-assistant's version. */
export const pairRequestSchema = z
  .object({
    code: z.string().min(1).max(128),
    public_key: hex64,
    signature: z.string().regex(/^[0-9a-f]{128}$/),
    agent_version: z.string().regex(/^[0-9A-Za-z.+-]{1,64}$/),
  })
  .strict();
export type PairRequest = z.infer<typeof pairRequestSchema>;

/**
 * The answer: the relay, its key as Gray now holds it, and the values `init` writes into gray-assistant's config.
 *
 * - `release`: Gray's signed release list for relay stacks and the keys it is checked with (`lane.release_list`,
 *   `lane.release_public_key`, `lane.release_freshness_public_key`); null where this deployment publishes none;
 * - `report_origin`: Gray's API origin, where gray-assistant reports (`stack.report_origin`) and pairs;
 * - `token_url`: the relay's pull-token service as Gray's record names it (the relay tunnel's origin unless the relay
 *   named its own), which the VM is deployed with; null when neither is known;
 * - `tunnel`: Gray's rendezvous and the relays zone (`tunnel.server`, `tunnel.zone`) and the relay's name there; null
 *   where this deployment runs no rendezvous;
 * - `image`, `registry`: what the relay entered on the panel, for `stack.relay_images` and `stack.registry.host`.
 */
export const pairAnswerSchema = z
  .object({
    relay_id: z.string().regex(STACK_ID_PATTERN),
    public_key: hex64,
    fingerprint: z.string().regex(/^SHA256:[A-Za-z0-9+/]{43}$/),
    paired_ms: z.number().int().min(0),
    release: z.object({ list: z.string().max(2048).regex(/^https?:\/\//), public_key: hex64, freshness_public_key: hex64.nullable() }).strict().nullable(),
    report_origin: origin,
    token_url: origin.nullable(),
    tunnel: z
      .object({
        server: z.string().max(260).regex(/^[a-z0-9.-]+:[0-9]{1,5}$/),
        zone: z.string().max(253),
        name: z.string().max(253),
      })
      .strict()
      .nullable(),
    image: z.string().max(512).nullable(),
    registry: z.string().max(256).nullable(),
  })
  .strict();
export type PairAnswer = z.infer<typeof pairAnswerSchema>;

/**
 * Why a pairing is refused: the error code the console answers (`{"error": {"code", "message"}}`, the ApiError
 * envelope) with its HTTP status, and the sentence gray-assistant prints. None names a value from the request.
 */
export const PAIR_REFUSALS = {
  lane_stack_pairing_code_unknown: { status: 404, text: "Gray knows no such pairing code. Check it was copied whole, or make a new one on the relay's page." },
  lane_stack_pairing_code_expired: { status: 410, text: "The pairing code expired (codes last 15 minutes). Make a new one on the relay's page." },
  lane_stack_pairing_code_used: { status: 409, text: "The pairing code was already used. Make a new one on the relay's page to pair again." },
  lane_stack_pairing_signature_invalid: { status: 401, text: "The key's signature over the code did not verify." },
  lane_stack_pairing_key_taken: { status: 409, text: "This key is already paired with another relay. Pair this relay with a key of its own." },
  lane_stack_pairing_key_mismatch: {
    status: 409,
    text: "This relay's stack endpoints name another key. Pair with that key (--key <relay-key.json>) or ask Gray to update the endpoints.",
  },
  lane_stack_pairing_locked: { status: 409, text: "This relay's VM is running with the key it has; delete the VM before pairing another key." },
  lane_stack_pairing_rate_limited: { status: 429, text: "Too many pairing attempts from this address. Wait a minute and try again." },
} as const;
export type PairRefusal = keyof typeof PAIR_REFUSALS;

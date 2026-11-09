/**
 * The relay's Ed25519 signing key, as `gray-assistant keygen` writes it and every signing command reads
 * it.
 *
 * The file holds the 32-byte seed in lower-case hex and the public key it derives. The public key in
 * the file is checked against the seed on load: an edited seed would otherwise sign bundles the TEE
 * refuses with "invalid signature", which is a much less useful failure than "this key file is
 * inconsistent". The file's permissions are the loader's rule (0600, no group or other bits); this
 * module only knows the bytes and never logs them.
 */
import { ed25519PublicKey } from "@gray/attest";
import type { JsonObject } from "@gray/json";
import { bytesToHex, hexBytes, randomBytes } from "@gray/relay-connector";
import { z } from "zod";
import { RELAY_KEY_API_VERSION } from "./endpoints.ts";
import { RelayKitError } from "./errors.ts";

/** The default key id `keygen` writes; the TEE pins it in its relay registry. */
export const DEFAULT_RELAY_KEY_ID = "relay-key-1";

/** The id shape the scheduler's signed strings accept: printable, no separator, no newline. */
const KEY_ID = /^[A-Za-z0-9._:-]{1,128}$/;

/** Whether `value` is a key id this package writes. */
export function isRelayKeyId(value: unknown): value is string {
  return typeof value === "string" && KEY_ID.test(value);
}

/** A relay signing key: its identity, its 32-byte seed, and the public key Gray registers. */
export interface RelayKeyFile {
  readonly keyId: string;
  readonly seed: Uint8Array;
  readonly publicKey: Uint8Array;
}

/** A fresh Ed25519 seed from the platform CSPRNG, and the public key it derives. */
export async function generateRelayKey(keyId: string = DEFAULT_RELAY_KEY_ID): Promise<RelayKeyFile> {
  if (!isRelayKeyId(keyId)) throw new RelayKitError("usage", "the key id must match [A-Za-z0-9._:-]{1,128}");
  const seed = randomBytes(32);
  return { keyId, seed, publicKey: await ed25519PublicKey(seed) };
}

/** The file's JSON value: hex for both byte fields, never the raw bytes. */
export function relayKeyValue(key: RelayKeyFile): JsonObject {
  return {
    api_version: RELAY_KEY_API_VERSION,
    key_id: key.keyId,
    seed: bytesToHex(key.seed),
    public_key: bytesToHex(key.publicKey),
  };
}

const keyFileSchema = z
  .object({
    api_version: z.literal(RELAY_KEY_API_VERSION),
    key_id: z.string().regex(KEY_ID),
    seed: z.string().regex(/^[0-9a-f]{64}$/),
    public_key: z.string().regex(/^[0-9a-f]{64}$/),
  })
  .strict();

/**
 * Parse a key file's JSON value. The API version, the member set, the two hex fields and the key id
 * are checked here; the seed→public-key check is {@link verifyRelayKeyPair}, which needs WebCrypto.
 * A parse failure never echoes the file's text.
 */
export function parseRelayKeyValue(value: unknown): RelayKeyFile {
  const parsed = keyFileSchema.safeParse(value);
  if (!parsed.success) throw new RelayKitError("invalid_key_file");
  const seed = hexBytes(parsed.data.seed, 32);
  const publicKey = hexBytes(parsed.data.public_key, 32);
  if (seed === null || publicKey === null) throw new RelayKitError("invalid_key_file");
  return { keyId: parsed.data.key_id, seed, publicKey };
}

/** That the file's public key is really the one `seed` derives. */
export async function verifyRelayKeyPair(key: RelayKeyFile): Promise<void> {
  const derived = await ed25519PublicKey(key.seed);
  if (bytesToHex(derived) !== bytesToHex(key.publicKey)) {
    throw new RelayKitError("invalid_key_file", "the public key does not match the seed");
  }
}

/** The public key of a key file as Gray's relay registry takes it: 32 bytes, lower-case hex. */
export function relayPublicKeyHex(key: RelayKeyFile): string {
  return bytesToHex(key.publicKey);
}

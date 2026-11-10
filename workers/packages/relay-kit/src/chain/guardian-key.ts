/**
 * The relay's guardian key: the secp256k1 key `init --pair` generates into the kit (`guardian-key.json`, 0600, backed up
 * like `relay-key.json`; docs/design/relay-no-always-on-host.md 3.2, H10). It approves, vetoes and pauses on the relay's
 * contract by EIP-712 signature, and with `--submit` it also pays for the transaction.
 *
 * The file holds the private key in lower-case hex and the address it derives; the address is checked against the key
 * on load, as `relay-key.json`'s public key is (keys.ts). The file's permissions are the loader's rule (files.ts); this
 * module knows the bytes only and never logs them.
 */
import type { JsonObject } from "@gray/json";
import { getAddress, type Address, type Hex } from "viem";
import { generatePrivateKey, privateKeyToAddress } from "viem/accounts";
import { z } from "zod";
import { RelayKitError } from "../errors.ts";

/** The file's version. */
export const GUARDIAN_KEY_API_VERSION = "gray-guardian-key/v1";
/** The kit file's name, beside `relay-key.json`. */
export const GUARDIAN_KEY_FILE = "guardian-key.json";
/**
 * The relay's recovery key, generated at a phase-2 pairing in this file's format: the only key that replaces the guardian
 * or itself on the contract. Gray receives its address only; the relay backs the file up offline and keeps it off the
 * machine that holds the guardian key.
 */
export const RECOVERY_KEY_FILE = "recovery-key.json";

export interface GuardianKeyFile {
  readonly address: Address;
  readonly privateKey: Hex;
}

/** A fresh key from the platform CSPRNG (viem's `generatePrivateKey`, @noble/curves underneath). */
export function generateGuardianKey(): GuardianKeyFile {
  const privateKey = generatePrivateKey();
  return { address: privateKeyToAddress(privateKey), privateKey };
}

/** The file's JSON value. */
export function guardianKeyValue(key: GuardianKeyFile): JsonObject {
  return { api_version: GUARDIAN_KEY_API_VERSION, address: key.address, private_key: key.privateKey };
}

const schema = z
  .object({
    api_version: z.literal(GUARDIAN_KEY_API_VERSION),
    address: z.string().regex(/^0x[0-9a-fA-F]{40}$/),
    private_key: z.string().regex(/^0x[0-9a-f]{64}$/),
  })
  .strict();

/** Parse a key file's JSON value and check that the address is the key's. A failure never echoes the file. */
export function parseGuardianKeyValue(value: unknown): GuardianKeyFile {
  const parsed = schema.safeParse(value);
  if (!parsed.success) throw new RelayKitError("invalid_key_file", "the guardian key file is not a gray-guardian-key/v1 document");
  const privateKey = parsed.data.private_key as Hex;
  let derived: Address;
  try {
    derived = privateKeyToAddress(privateKey);
  } catch {
    throw new RelayKitError("invalid_key_file", "the guardian key file's private key is not a secp256k1 key");
  }
  if (derived !== getAddress(parsed.data.address)) throw new RelayKitError("invalid_key_file", "the guardian key file's address is not the one its key derives");
  return { address: derived, privateKey };
}

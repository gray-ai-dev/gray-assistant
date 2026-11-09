import { ed25519VerifyHex, jcsBytes, sha256BareHex, sha256Raw, utf8Bytes } from "@gray/attest";
import type { Json } from "@gray/json";
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
 * - the key's fingerprint, which both the panel and gray-assistant print for the operator to compare;
 * - phase 2 (docs/design/relay-no-always-on-host.md 3.2, 4, 13.3): the chain terms a live code reads before pairing
 *   (`pairChainRequestSchema`, `pairChainAnswerSchema`: the relay id, Gray's proposer, the chain and the first release),
 *   from which gray-assistant computes the relay's contract and signs the guardian's approvals, and the guardian part
 *   the pairing request then carries (`pairGuardianSchema`), covered by the relay key's signature
 *   (`pairMessage(code, key, guardian)`).
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

/**
 * The bytes the relay key signs: the domain, the canonical code and the public key (64 lower hex), one per line; with a
 * guardian part (phase 2), a fourth line, SHA-256 of the part's JCS form (RFC 8785, `@gray/attest` `jcsBytes`) as 64
 * lower hex, so the key vouches for the guardian and the approvals the request carries. A phase-1 request signs the
 * three lines exactly as before.
 */
export function pairMessage(code: string, publicKeyHex: string, guardian: PairGuardian | null = null): Uint8Array {
  const lines = [PAIR_DOMAIN, code, publicKeyHex];
  if (guardian !== null) lines.push(pairGuardianDigest(guardian));
  return utf8Bytes(lines.join("\n"));
}

/** SHA-256 of the guardian part's JCS form, lower hex: the pairing message's fourth line. */
export function pairGuardianDigest(guardian: PairGuardian): string {
  // @gray/json spells an integer as a bigint, the only number JCS takes here.
  return sha256BareHex(jcsBytes({ ...guardian, chain_id: BigInt(guardian.chain_id) } as unknown as Json));
}

/** Whether `signatureHex` is the key's over `pairMessage(code, publicKeyHex, guardian)`. */
export async function verifyPairSignature(code: string, publicKeyHex: string, signatureHex: string, guardian: PairGuardian | null = null): Promise<boolean> {
  return ed25519VerifyHex(publicKeyHex, pairMessage(code, publicKeyHex, guardian), signatureHex).catch(() => false);
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

/** An EVM address as the guardian part names it: 0x and 40 hex digits, any case (the console checks it, checksummed). */
const evmAddress = z.string().regex(/^0x[0-9a-fA-F]{40}$/);
/** A release hash as the contract takes it: 0x and 64 lower hex digits. */
const releaseHash = z.string().regex(/^0x[0-9a-f]{64}$/);
/** A uint as a decimal string (a nonce, a deadline, a version): no sign, no leading zero, at most 78 digits (2^256). */
const decimal = z.string().regex(/^(0|[1-9][0-9]{0,77})$/);

/**
 * The pairing's guardian part (phase 2; relay-kit's `pairingGuardianJson` of `@gray/relay-app-auth`'s
 * `pairingGuardianPart`, signed approvals only): the relay's guardian and optional recovery address, the chain, the
 * contract gray-assistant computed from the chain terms, and the guardian's EIP-712 `Approve` of each hash of the first
 * release (compose hashes first, nonces 0, 1, …), which Gray's relayer submits once Deploy deployed the contract. The
 * console recomputes the contract and checks every signature before it keeps the part (lane-stack/pairing.ts).
 */
export const pairGuardianSchema = z
  .object({
    guardian: evmAddress,
    recovery: evmAddress.nullable(),
    chain_id: z.number().int().min(1).max(Number.MAX_SAFE_INTEGER),
    contract: evmAddress,
    approvals: z
      .array(
        z
          .object({
            kind: z.enum(["compose", "os_image"]),
            hash: releaseHash,
            version: decimal,
            nonce: decimal,
            deadline: decimal,
            /** 65 bytes `r ‖ s ‖ v`. */
            signature: z.string().regex(/^0x[0-9a-f]{130}$/),
          })
          .strict(),
      )
      .min(1)
      .max(8),
  })
  .strict();
export type PairGuardian = z.infer<typeof pairGuardianSchema>;

/**
 * `POST /v1/lane-stack/pair`: the code as typed (normalized by the console), the key, its signature, gray-assistant's
 * version, and for a phase-2 pairing the guardian part (which the signature then covers).
 */
export const pairRequestSchema = z
  .object({
    code: z.string().min(1).max(128),
    public_key: hex64,
    signature: z.string().regex(/^[0-9a-f]{128}$/),
    agent_version: z.string().regex(/^[0-9A-Za-z.+-]{1,64}$/),
    guardian: pairGuardianSchema.optional(),
  })
  .strict();
export type PairRequest = z.infer<typeof pairRequestSchema>;

/** Phase 2: the chain terms of a live pairing code, read before the pairing (nothing is spent or recorded). */
export const PAIR_CHAIN_PATH = "/v1/lane-stack/pair/chain";

/** `POST /v1/lane-stack/pair/chain`: the code as typed. */
export const pairChainRequestSchema = z.object({ code: z.string().min(1).max(128) }).strict();
export type PairChainRequest = z.infer<typeof pairChainRequestSchema>;

const releaseAnswer = z.object({ list: z.string().max(2048).regex(/^https?:\/\//), public_key: hex64, freshness_public_key: hex64.nullable() }).strict();

/**
 * The chain terms: null while the relay is not on phase 2 (the switch is off for it, or Gray has no proposer or no
 * phase-2 release for it), and the pairing is the phase-1 one. Otherwise everything the relay's contract address depends
 * on but the guardian (docs/design/relay-no-always-on-host.md 13.8, C12): the relay id (the CREATE2 salt), Gray's
 * proposer, the chain, Phala's `DstackKms` there, and the first release Deploy boots, compose hash (Phala's measured
 * form) and OS image hash, 0x and 64 lower hex each; with the two RPC endpoints `init --pair` writes into the kit's
 * `chain` member and Gray's release list (as the pairing answer names it), so gray-assistant checks the release against
 * the signed list before its guardian approves it.
 */
export const pairChainAnswerSchema = z
  .object({
    chain: z
      .object({
        relay_id: z.string().regex(STACK_ID_PATTERN),
        chain_id: z.number().int().min(1).max(Number.MAX_SAFE_INTEGER),
        proposer: evmAddress,
        dstack_kms: evmAddress,
        compose_hash: releaseHash,
        os_image_hash: releaseHash,
        rpc: z.array(z.string().max(2048).regex(/^https?:\/\//)).length(2),
        release: releaseAnswer.nullable(),
      })
      .strict()
      .nullable(),
  })
  .strict();
export type PairChainAnswer = z.infer<typeof pairChainAnswerSchema>;
export type PairChainTerms = NonNullable<PairChainAnswer["chain"]>;

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
    release: releaseAnswer.nullable(),
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
  lane_stack_pairing_code_unknown: { status: 404, text: "Gray knows no such pairing code. Check it was copied whole, or make a new one on the relay's Integration page." },
  lane_stack_pairing_code_expired: { status: 410, text: "The pairing code expired (codes last 15 minutes). Make a new one on the relay's Integration page." },
  lane_stack_pairing_code_used: { status: 409, text: "The pairing code was already used. Make a new one on the relay's Integration page to pair again." },
  lane_stack_pairing_signature_invalid: { status: 401, text: "The key's signature over the code did not verify." },
  lane_stack_pairing_key_taken: { status: 409, text: "This key is already paired with another relay. Pair this relay with a key of its own." },
  lane_stack_pairing_key_mismatch: {
    status: 409,
    text: "This relay's stack endpoints name another key. Pair with that key (--key <relay-key.json>) or ask Gray to update the endpoints.",
  },
  lane_stack_pairing_locked: { status: 409, text: "This relay's VM is running with the key it has; delete the VM before pairing another key." },
  lane_stack_pairing_rate_limited: { status: 429, text: "Too many pairing attempts from this address. Wait a minute and try again." },
  lane_stack_pairing_guardian_unavailable: {
    status: 409,
    text: "This relay is not on phase 2 now, so Gray takes no guardian at pairing. Run init --pair again with the same code: it asks Gray's chain terms first.",
  },
  lane_stack_pairing_guardian_invalid: {
    status: 422,
    text: "The guardian part does not match Gray's chain terms (the contract address, the release or a signature). Run init --pair again with the same code; if it repeats, tell Gray.",
  },
} as const;
export type PairRefusal = keyof typeof PAIR_REFUSALS;

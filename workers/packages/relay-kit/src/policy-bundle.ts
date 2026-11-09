/**
 * The signed policy bundle a relay uploads: the closed WASM module and its registered templates,
 * under the relay's Ed25519 signature.
 *
 * The signature is `@gray/relay-policy`'s claim, byte for byte —
 *
 *     JCS({"relay_id":…,"version":7,"module_sha256":"…","templates_sha256":"…"})
 *
 * — so the TEE can verify the upload with the same `verifyPolicyBundle` it already has, and a
 * receipt's `module_sha256`/`policy_version` are values the relay committed to before the request
 * existed (review.md §2.7, items 2 and 3). This module only frames those bytes as a portable JSON
 * document; the hashing, canonicalization and signature check are the other package's.
 *
 * `module` is standard base64. A WASM module is binary and the document is JSON; base64 is the
 * ordinary encoding for that, and the decoder here is strict, so a bundle has exactly one spelling.
 * The plaintext module is protected on the wire by TLS to the attested lane (the SPKI in the verified
 * report); IMPLEMENTATION_NOTES records why this hop is not additionally HPKE-sealed.
 */
import { ed25519PublicKey, ed25519Sign } from "@gray/attest";
import { isObject, type Json, type JsonObject } from "@gray/json";
import { createTemplateRegistry, isLaneProtocol, isPosition } from "@gray/lane";
import type { LaneProtocol, Position, RelayTemplate } from "@gray/lane";
import {
  canonicalTemplates,
  policyClaim,
  policyClaimBytes,
  preparePolicy,
  verifyPolicyBundle,
  type BundleRefusalCode,
  type PolicyClaim,
  type PrepareRefusalCode,
} from "@gray/relay-policy";
import { z } from "zod";
import { decodeBase64, encodeBase64 } from "./base64.ts";
import { POLICY_BUNDLE_API_VERSION } from "./endpoints.ts";
import { RelayKitError } from "./errors.ts";

/** The largest relay id, and the characters it may hold (the same as `@gray/relay-policy`). */
const RELAY_ID = /^[A-Za-z0-9_.:-]{1,128}$/;

/** The u64 bound both the policy version and every integer of the document use. */
const U64_MAX = 0xffff_ffff_ffff_ffffn;

/** The most templates `@gray/relay-policy` prepares by default. */
export const MAX_POLICY_TEMPLATES = 256;

/** One bundle as this package handles it: the document's bytes, its templates, its signature. */
export interface PolicyBundleDocument {
  readonly relayId: string;
  readonly version: bigint;
  readonly moduleBytes: Uint8Array;
  readonly templates: readonly RelayTemplate[];
  /** 64 bytes, RFC 8032. */
  readonly signature: Uint8Array;
}

const templateSchema = z
  .object({
    id: z.string().min(1).max(128),
    text: z.string(),
    positions: z.array(z.string()).min(1),
    protocols: z.array(z.string()).min(1),
    maxTextBytes: z.union([z.number().int().positive(), z.bigint().positive()]),
  })
  .strict();

/**
 * Parse a templates file: a bare array, or `{"templates":[…]}` (optionally with an
 * `api_version` member this package does not interpret). Every entry is held to the lane's registry
 * rules (`createTemplateRegistry`), which are the ones the TEE applies. A refusal carries only the
 * registry's code.
 */
export function parseTemplatesValue(value: unknown): readonly RelayTemplate[] {
  let entries: unknown = value;
  if (isPlainObject(value)) {
    const keys = Object.keys(value);
    if (keys.length === 1 && keys[0] === "templates") {
      entries = value.templates;
    } else if (keys.length === 2 && keys.includes("api_version") && keys.includes("templates")) {
      if (typeof value.api_version !== "string") throw new RelayKitError("invalid_templates", "api_version");
      entries = value.templates;
    } else {
      throw new RelayKitError("invalid_templates", "the file is neither an array of templates nor an object with a templates member");
    }
  }
  if (!Array.isArray(entries)) throw new RelayKitError("invalid_templates", "templates");
  if (entries.length > MAX_POLICY_TEMPLATES) throw new RelayKitError("invalid_templates", "too many templates");
  const out: RelayTemplate[] = [];
  for (let index = 0; index < entries.length; index += 1) {
    const parsed = templateSchema.safeParse(entries[index]);
    if (!parsed.success) throw new RelayKitError("invalid_templates", `templates.${index}`);
    const positions: Position[] = [];
    for (const position of parsed.data.positions) {
      if (!isPosition(position)) throw new RelayKitError("invalid_templates", `templates.${index}.positions`);
      positions.push(position);
    }
    const protocols: LaneProtocol[] = [];
    for (const protocol of parsed.data.protocols) {
      if (!isLaneProtocol(protocol)) throw new RelayKitError("invalid_templates", `templates.${index}.protocols`);
      protocols.push(protocol);
    }
    const maxTextBytes = typeof parsed.data.maxTextBytes === "bigint" ? parsed.data.maxTextBytes : BigInt(parsed.data.maxTextBytes);
    if (maxTextBytes > BigInt(Number.MAX_SAFE_INTEGER)) throw new RelayKitError("invalid_templates", `templates.${index}.maxTextBytes`);
    out.push({ id: parsed.data.id, text: parsed.data.text, positions, protocols, maxTextBytes: Number(maxTextBytes) });
  }
  // The semantic rules (ids, duplicates, position/protocol consistency) live in @gray/lane, so this
  // package cannot disagree with the TEE about a registry.
  const registry = createTemplateRegistry(out);
  if (!registry.ok) throw new RelayKitError("invalid_templates", registry.code);
  return registry.templates;
}

/** What signing a bundle needs. */
export interface SignPolicyBundleInput {
  readonly relayId: string;
  readonly version: bigint;
  readonly moduleBytes: Uint8Array;
  readonly templates: readonly RelayTemplate[];
  /** The 32-byte Ed25519 seed of the relay's registered key. */
  readonly signingKey: Uint8Array;
}

/**
 * Build and sign one bundle. The claim is computed from the bytes and the templates being signed, so
 * a caller cannot sign one module and upload another. The caller is expected to have run
 * `@gray/relay-policy`'s `preparePolicy` first (the CLI does): this function checks the shapes the
 * signature needs, not the module contract, which is the TEE's validator's job.
 */
export async function signPolicyBundle(input: SignPolicyBundleInput): Promise<PolicyBundleDocument> {
  if (typeof input.relayId !== "string" || !RELAY_ID.test(input.relayId)) throw new RelayKitError("invalid_module", "relay_id");
  if (typeof input.version !== "bigint" || input.version < 0n || input.version > U64_MAX) {
    throw new RelayKitError("invalid_version");
  }
  if (!(input.moduleBytes instanceof Uint8Array) || input.moduleBytes.length === 0) {
    throw new RelayKitError("invalid_module", "the module is empty");
  }
  if (!(input.signingKey instanceof Uint8Array) || input.signingKey.length !== 32) {
    throw new RelayKitError("invalid_key_file", "the signing key is not a 32-byte seed");
  }
  const claimed = policyClaim({
    relayId: input.relayId,
    version: input.version,
    moduleBytes: input.moduleBytes,
    templates: input.templates,
  });
  if (!claimed.ok) throw new RelayKitError("invalid_policy_bundle", claimed.code);
  const signature = await ed25519Sign(input.signingKey, policyClaimBytes(claimed.claim));
  return {
    relayId: input.relayId,
    version: input.version,
    moduleBytes: input.moduleBytes,
    templates: input.templates,
    signature,
  };
}

/**
 * The CLI's whole `policy bundle` step, as a library: run the TEE's own `preparePolicy` validation
 * and wasmi load, then sign the claim and self-check the signature. The interpreter must already be
 * installed (`@gray/relay-kit/node`'s `initWorkspaceInterpreter`, or the workerd import); this is
 * the same contract `@gray/relay-policy` states, kept rather than hidden because a pure package must
 * not guess a runtime's wasm loader.
 *
 * A refusal is returned with the policy package's closed code and detail, so a caller can print
 * `policy_refused <code>: <detail>` exactly as the CLI does; nothing is signed for a refused module.
 */
export type PrepareAndSignPolicyBundleResult =
  | {
      readonly ok: true;
      readonly bundle: PolicyBundleDocument;
      readonly document: JsonObject;
      readonly claim: PolicyClaim;
    }
  | { readonly ok: false; readonly code: PrepareRefusalCode; readonly detail: string };

export async function prepareAndSignPolicyBundle(input: SignPolicyBundleInput): Promise<PrepareAndSignPolicyBundleResult> {
  const prepared = preparePolicy({
    relayId: input.relayId,
    version: input.version,
    moduleBytes: input.moduleBytes,
    templates: input.templates,
  });
  if (!prepared.ok) return { ok: false, code: prepared.code, detail: prepared.detail };
  const bundle = await signPolicyBundle(input);
  const document = parsePolicyBundleValue(policyBundleValue(bundle));
  const publicKey = await ed25519PublicKey(input.signingKey);
  const verified = await verifyPolicyBundleDocument(document, publicKey);
  if (!verified.ok) throw new RelayKitError("invalid_policy_bundle", `the signature did not verify after signing (${verified.code})`);
  return { ok: true, bundle, document: policyBundleValue(document), claim: verified.claim };
}

/** The document as JSON: base64 module, canonical templates, hex signature and both digests. */
export function policyBundleValue(bundle: PolicyBundleDocument): JsonObject {
  const claimed = policyClaim({
    relayId: bundle.relayId,
    version: bundle.version,
    moduleBytes: bundle.moduleBytes,
    templates: bundle.templates,
  });
  if (!claimed.ok) throw new RelayKitError("invalid_policy_bundle", claimed.code);
  return {
    api_version: POLICY_BUNDLE_API_VERSION,
    relay_id: bundle.relayId,
    version: bundle.version,
    module: encodeBase64(bundle.moduleBytes),
    module_sha256: claimed.claim.module_sha256,
    templates_sha256: claimed.claim.templates_sha256,
    templates: canonicalTemplates(bundle.templates) as Json,
    signature: bytesToHex(bundle.signature),
  };
}

const bundleSchema = z
  .object({
    api_version: z.literal(POLICY_BUNDLE_API_VERSION),
    relay_id: z.string().regex(RELAY_ID),
    version: z.union([z.bigint().min(0n).max(U64_MAX), z.number().int().min(0).max(Number.MAX_SAFE_INTEGER)]),
    module: z.string().min(1),
    module_sha256: z.string().regex(/^[0-9a-f]{64}$/),
    templates_sha256: z.string().regex(/^[0-9a-f]{64}$/),
    templates: z.array(z.unknown()),
    signature: z.string().regex(/^[0-9a-f]{128}$/),
  })
  .strict();

/** Parse one bundle document, refusing anything the TEE's parser would refuse. */
export function parsePolicyBundleValue(value: unknown): PolicyBundleDocument {
  const parsed = bundleSchema.safeParse(value);
  if (!parsed.success) throw new RelayKitError("invalid_policy_bundle");
  const moduleBytes = decodeBase64(parsed.data.module);
  if (moduleBytes === null || moduleBytes.length === 0) throw new RelayKitError("invalid_policy_bundle", "module");
  const templates = parseTemplatesValue(parsed.data.templates);
  const version = typeof parsed.data.version === "bigint" ? parsed.data.version : BigInt(parsed.data.version);
  const bundle: PolicyBundleDocument = {
    relayId: parsed.data.relay_id,
    version,
    moduleBytes,
    templates,
    signature: hexBytes(parsed.data.signature, 64),
  };
  const claimed = policyClaim({
    relayId: bundle.relayId,
    version: bundle.version,
    moduleBytes: bundle.moduleBytes,
    templates: bundle.templates,
  });
  if (!claimed.ok) throw new RelayKitError("invalid_policy_bundle", claimed.code);
  if (claimed.claim.module_sha256 !== parsed.data.module_sha256 || claimed.claim.templates_sha256 !== parsed.data.templates_sha256) {
    throw new RelayKitError("invalid_policy_bundle", "the digests do not describe the module and templates");
  }
  return bundle;
}

/**
 * Check a document's signature against the relay's registered key, with the same function the TEE
 * runs. This is also the CLI's post-signing self-check: a bundle that does not verify here must
 * never be uploaded.
 */
export async function verifyPolicyBundleDocument(
  bundle: PolicyBundleDocument,
  relayPublicKey: Uint8Array,
): Promise<{ readonly ok: true; readonly claim: PolicyClaim } | { readonly ok: false; readonly code: BundleRefusalCode }> {
  const verified = await verifyPolicyBundle(
    {
      relayId: bundle.relayId,
      version: bundle.version,
      moduleBytes: bundle.moduleBytes,
      templates: bundle.templates,
      signature: bundle.signature,
    },
    relayPublicKey,
  );
  if (!verified.ok) return { ok: false, code: verified.code };
  return { ok: true, claim: verified.claim };
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function bytesToHex(bytes: Uint8Array): string {
  let out = "";
  for (const byte of bytes) out += byte.toString(16).padStart(2, "0");
  return out;
}

function hexBytes(text: string, byteLength: number): Uint8Array {
  const out = new Uint8Array(byteLength);
  for (let index = 0; index < byteLength; index += 1) out[index] = Number.parseInt(text.slice(index * 2, index * 2 + 2), 16);
  return out;
}

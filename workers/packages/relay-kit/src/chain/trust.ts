/**
 * What gray-assistant knows of Gray and of the chain without asking Gray. The kit is there so that a provider need not
 * trust Gray's servers; so before the guardian signs anything at pairing, what Gray's answer names is held to these
 * values, which ship in the kit's public source (provider review 2026-11-17, items 16 to 18):
 *
 * - Gray's release-signing keys, one pair per environment, as deploy/tee/release/environments.json names them
 *   (`release_public_key`, `release_freshness_public_key`; test/trust.test.ts keeps the two equal). Gray signs its
 *   release lists offline (release.mjs plan, sign-release-list.mjs), so a list that verifies under one of these keys is
 *   Gray's release, whatever Gray's servers say. Production's API origin takes production's keys only; staging's origin
 *   is a deploy-time value, so any other https origin takes a key of this table. Only a Gray on this machine's loopback
 *   (a test's) takes another key, the one its operator gives (`init --pair --release-public-key`).
 * - Base's DstackKms (`BASE_DSTACK_KMS`, @gray/relay-app-auth) and the KMS root CA public key it publishes
 *   (`kmsInfo().caPubkey`): the key provider every phase-2 compose must name, the KMS whose `isAppAllowed` asks the
 *   relay's own contract. Read from Base on 2026-11-17 (`cast call 0x2f83…Ba9C "kmsInfo()(bytes,bytes,bytes,bytes)"`
 *   at mainnet.base.org); its `k256Pubkey` is the root docs/design/relay-no-always-on-host.md 13.2 pins (02a3…f721).
 *   Every phase-2 compose in Gray's production and staging stack lists names this CA as `key_provider_id`.
 * - The two public Base endpoints the kit's chain checks expect by default (@gray/config RELAY_CHAIN_KIT_RPC_URLS).
 *
 * The pairing reads the chain through the kit's own Base endpoints, never Gray's, and a non-loopback Gray pairs on Base
 * only; `configTrustProblems` holds a config an older kit wrote from Gray's answer to the same values.
 *
 * Pure: no `node:*`, no network.
 */
import { getAddress, isAddress } from "viem";
import { BASE_CHAIN_ID, BASE_DSTACK_KMS } from "./app-auth.ts";

/** Gray's production API origin, the `--gray` of a production pairing. */
export const GRAY_PRODUCTION_API_ORIGIN = "https://api.usefallback.com";

/** One environment's release-list keys (environments.json `release_public_key`, `release_freshness_public_key`). */
export interface GrayReleaseKeys {
  readonly environment: "production" | "staging";
  readonly releasePublicKey: string;
  readonly releaseFreshnessPublicKey: string;
}

/** Gray's release-list keys, production first. */
export const GRAY_RELEASE_KEYS: readonly GrayReleaseKeys[] = Object.freeze([
  Object.freeze({
    environment: "production" as const,
    releasePublicKey: "4bdaf71a698e68ef2bb09a15ec7047aacad2882a14c12bae50b992a8c86694cc",
    releaseFreshnessPublicKey: "8ff9f9c47b3c66854451655b320d620c025110461f763a5d7bcdf8b1780e3f2f",
  }),
  Object.freeze({
    environment: "staging" as const,
    releasePublicKey: "f9b7e5abcfda6e92a4dbfcdbbc1bc806cd7e0533a574723dd9705e689db92324",
    releaseFreshnessPublicKey: "7b3b22ca087c3e7754279159ecc0258c6f550d1e35fdf24c33fa03f521209e38",
  }),
]);

/** Base DstackKms's KMS root CA public key (`kmsInfo().caPubkey`): a P-256 SubjectPublicKeyInfo, 182 lower-case hex. */
export const BASE_KMS_CA_PUBKEY =
  "3059301306072a8648ce3d020106082a8648ce3d030107034200048bf84f52911056474c207cb50b4e8010d984f8975ea57b8f0c8b17502181c283e93a68a9864ad19f629508cc699f125be3871ec2e26ab0597e5bca4e29b7425f";

/** The public Base endpoints the kit's chain checks expect (Gray's terms name these unless Gray changed them). */
export const BASE_RPC_ENDPOINTS: readonly string[] = Object.freeze(["https://mainnet.base.org", "https://base-rpc.publicnode.com"]);

/** The keys Gray's list is read with at pairing, and where they come from (for the operator's line). */
export type PairingReleaseKeys =
  | { readonly ok: true; readonly publicKey: string; readonly freshnessPublicKey: string | null; readonly source: string }
  | { readonly ok: false; readonly text: string };

/** The release keys an operator pins for a Gray on loopback (a test): `--release-public-key`, `--release-freshness-public-key`. */
export interface PinnedReleaseKeys {
  readonly publicKey: string;
  readonly freshnessPublicKey: string | null;
}

const NOT_SPENT = "tell Gray (the code is not spent)";

/**
 * The keys pairing reads Gray's signed release list with: a key of `GRAY_RELEASE_KEYS` (production's only for
 * production's origin) or, for a Gray on loopback, the one its operator pinned; never one Gray's answer alone names.
 * Gray's terms must name the same key (a list signed with another is not Gray's release) and no other freshness key.
 * Terms without a list leave the guardian nothing to check, so they are refused.
 */
export function pairingReleaseKeys(
  gray: string,
  named: { readonly public_key: string; readonly freshness_public_key: string | null } | null,
  pinned: PinnedReleaseKeys | null,
): PairingReleaseKeys {
  if (named === null) {
    return { ok: false, text: `Gray's chain terms name no signed release list, so the guardian cannot check the release Gray will deploy and approves nothing; ${NOT_SPENT}` };
  }
  if (pinned !== null) {
    if (named.public_key !== pinned.publicKey) return { ok: false, text: `Gray's chain terms name release key ${named.public_key}, not the one you gave (--release-public-key); ${NOT_SPENT}` };
    if (pinned.freshnessPublicKey !== null && named.freshness_public_key !== null && named.freshness_public_key !== pinned.freshnessPublicKey) {
      return { ok: false, text: `Gray's chain terms name freshness key ${named.freshness_public_key}, not the one you gave (--release-freshness-public-key); ${NOT_SPENT}` };
    }
    return { ok: true, publicKey: pinned.publicKey, freshnessPublicKey: pinned.freshnessPublicKey ?? named.freshness_public_key, source: "the release key you gave (--release-public-key)" };
  }
  const production = gray === GRAY_PRODUCTION_API_ORIGIN;
  const candidates = production ? GRAY_RELEASE_KEYS.filter((keys) => keys.environment === "production") : GRAY_RELEASE_KEYS;
  const keys = candidates.find((entry) => entry.releasePublicKey === named.public_key);
  if (keys === undefined) {
    return {
      ok: false,
      text: `Gray's chain terms name release key ${named.public_key}, which is not ${production ? "Gray's production release key" : "a release key"} built into gray-assistant, so the guardian approves nothing it would check with it; ${NOT_SPENT}`,
    };
  }
  if (named.freshness_public_key !== null && named.freshness_public_key !== keys.releaseFreshnessPublicKey) {
    return { ok: false, text: `Gray's chain terms name freshness key ${named.freshness_public_key}, not Gray's ${keys.environment} freshness key built into gray-assistant; ${NOT_SPENT}` };
  }
  return { ok: true, publicKey: keys.releasePublicKey, freshnessPublicKey: keys.releaseFreshnessPublicKey, source: `Gray's ${keys.environment} release key built into gray-assistant` };
}

function sameAddress(a: string, b: string): boolean {
  return isAddress(a, { strict: false }) && isAddress(b, { strict: false }) && getAddress(a) === getAddress(b);
}

/** The KMS root CA a contract on `chainId` registered with `dstackKms` must run its VMs on, when the kit has it: Base's. */
export function builtInKmsCaPubkey(chainId: number, dstackKms: string): string | null {
  return chainId === BASE_CHAIN_ID && sameAddress(dstackKms, BASE_DSTACK_KMS) ? BASE_KMS_CA_PUBKEY : null;
}

/** A Gray on this machine's loopback: a test's fake console (the only one that may use a test chain or a pinned key). */
export function isLoopbackOrigin(origin: string): boolean {
  try {
    return LOOPBACK_HOSTS.has(new URL(origin).hostname);
  } catch {
    return false;
  }
}

const LOOPBACK_HOSTS = new Set(["127.0.0.1", "[::1]", "localhost"]);

/** What pairing makes of Gray's chain and DstackKms: refused, or taken (with a warning when the kit cannot check it). */
export type PairingChainVerdict = { readonly ok: true; readonly warning: string | null } | { readonly ok: false; readonly text: string };

/**
 * Gray's chain and DstackKms against the kit's own. Every Gray but a test's on loopback pairs on Base: a contract on a
 * chain of Gray's choosing would let Gray deploy and propose where the guardian never looks (review of 2026-11-17).
 * On Base the DstackKms must be the one built in (Phala's, which Phala's Base KMS asks: a contract registered with
 * another would gate nothing, and no Gray deployment names another). A test Gray's other chain is taken with a warning.
 */
export function pairingChainVerdict(gray: string, chainId: number, dstackKms: string): PairingChainVerdict {
  if (chainId !== BASE_CHAIN_ID) {
    if (!isLoopbackOrigin(gray)) {
      return { ok: false, text: `Gray's chain terms name chain ${chainId}, but a Gray deployment's contracts are on Base (${BASE_CHAIN_ID}); only a test Gray on this machine's loopback uses another chain: ${NOT_SPENT}` };
    }
    return { ok: true, warning: `chain ${chainId} is not Base: gray-assistant has no DstackKms of its own for it, so it takes ${dstackKms} as the test Gray's terms name it` };
  }
  if (sameAddress(dstackKms, BASE_DSTACK_KMS)) return { ok: true, warning: null };
  return {
    ok: false,
    text: `Gray's chain terms name DstackKms ${dstackKms} on Base, not Phala's ${BASE_DSTACK_KMS} built into gray-assistant: Phala's Base KMS asks only that one, so a contract registered with another would not hold your VM's keys and your guardian's veto would hold nothing; ${NOT_SPENT}`,
  };
}

/**
 * The two endpoints a pairing reads the chain through and writes into `chain.rpc`: the operator's (`init --pair --rpc`)
 * when given; on Base, else, the public Base endpoints built into the kit, never the ones Gray's terms name (two
 * endpoints of Gray's would agree on whatever Gray likes, and every later chain check reads only `chain.rpc`); on a test
 * Gray's test chain the terms' own. `note` says when Gray's terms named others than the ones taken.
 */
export function pairingRpcEndpoints(chainId: number, terms: readonly string[], given: readonly string[] | null): { readonly rpc: readonly string[]; readonly note: string | null } {
  if (given !== null) return { rpc: given, note: null };
  if (chainId !== BASE_CHAIN_ID) return { rpc: terms, note: null };
  const origins = (urls: readonly string[]) => urls.map((url) => new URL(url).origin).sort().join(" ");
  const same = origins(terms) === origins(BASE_RPC_ENDPOINTS);
  return {
    rpc: BASE_RPC_ENDPOINTS,
    note: same ? null : `Gray's terms name the RPC endpoints ${terms.map((url) => new URL(url).origin).join(" and ")}; your chain checks read the public Base endpoints built into gray-assistant instead (${BASE_RPC_ENDPOINTS.join(", ")}); init --pair --rpc <url> --rpc <url> names two of your own`,
  };
}

/**
 * A warning when `chain.rpc` on Base names other endpoints than the public ones the kit knows: the chain checks believe
 * two endpoints that agree, so they must be two providers the relay chose and trusts, not ones an older kit copied from
 * Gray's terms. Null when both are known ones. Not an error: the operator may name their own (`init --pair --rpc`,
 * `config set chain.rpc`), and an older config cannot tell who chose them.
 */
export function rpcEndpointsWarning(chainId: number, rpc: readonly string[]): string | null {
  if (chainId !== BASE_CHAIN_ID) return null;
  const known = new Set(BASE_RPC_ENDPOINTS.map((url) => new URL(url).origin));
  const other = rpc.map((url) => new URL(url).origin).filter((origin) => !known.has(origin));
  if (other.length === 0) return null;
  return `chain.rpc names ${other.join(" and ")}, not the public Base endpoints gray-assistant knows (${BASE_RPC_ENDPOINTS.join(", ")}); every check of your contract believes these two when they agree, so keep them only if you chose them as two providers you trust, else set the built-in ones: gray-assistant config set chain.rpc '${JSON.stringify(BASE_RPC_ENDPOINTS)}' --json`;
}

/** What a config's trust-bearing values are, as `configTrustProblems` judges them. */
export interface ConfigTrustInput {
  /** `pairing.gray`: the Gray the config was paired with; null for a config no pairing wrote (its values are its operator's). */
  readonly gray: string | null;
  /** `lane.release_public_key` and `lane.release_freshness_public_key` (null: none), 64 lower hex. */
  readonly releasePublicKey: string;
  readonly releaseFreshnessPublicKey: string | null;
  /** The `chain` member, null without one. */
  readonly chain: { readonly chainId: number; readonly dstackKms: string; readonly rpc: readonly string[] } | null;
}

/**
 * A config's values against what the kit knows without Gray, for a kit that kept what an older kit copied from Gray's
 * answer (review of 2026-11-17): `errors` stop `releases check`, `releases approve` and every read of Gray's list
 * (`deliver` delivers nothing) and fail doctor's `trust` line; `warnings` are said. A config paired with a Gray off
 * loopback must name a release key of `GRAY_RELEASE_KEYS` (production's for production's origin) with its own
 * freshness key, and a contract on Base; any config on Base must name Phala's DstackKms. The init placeholder key is
 * left to the placeholder checks.
 */
export function configTrustProblems(input: ConfigTrustInput): { readonly errors: readonly string[]; readonly warnings: readonly string[] } {
  const errors: string[] = [];
  const warnings: string[] = [];
  const paired = input.gray !== null && !isLoopbackOrigin(input.gray);
  if (paired && !/^0{64}$/.test(input.releasePublicKey)) {
    const production = input.gray === GRAY_PRODUCTION_API_ORIGIN;
    const candidates = production ? GRAY_RELEASE_KEYS.filter((keys) => keys.environment === "production") : GRAY_RELEASE_KEYS;
    const keys = candidates.find((entry) => entry.releasePublicKey === input.releasePublicKey);
    const fix = (member: string, value: string) => `pair again (init --pair --force --key relay-key.json) or set it: gray-assistant config set ${member} ${value}`;
    const expected = (candidates[0] as GrayReleaseKeys).releasePublicKey;
    if (keys === undefined) {
      errors.push(`lane.release_public_key is ${input.releasePublicKey}, not ${production ? "Gray's production release key" : "a release key"} built into gray-assistant, so a list it verifies need not be Gray's: ${fix("lane.release_public_key", expected)}`);
    } else if (input.releaseFreshnessPublicKey !== null && input.releaseFreshnessPublicKey !== keys.releaseFreshnessPublicKey) {
      errors.push(`lane.release_freshness_public_key is ${input.releaseFreshnessPublicKey}, not Gray's ${keys.environment} freshness key built into gray-assistant: ${fix("lane.release_freshness_public_key", keys.releaseFreshnessPublicKey)}`);
    } else if (input.releaseFreshnessPublicKey === null) {
      warnings.push(`lane.release_freshness_public_key is not set, so an old copy of Gray's list reads as current for up to a day: gray-assistant config set lane.release_freshness_public_key ${keys.releaseFreshnessPublicKey}`);
    }
    if (input.chain !== null && input.chain.chainId !== BASE_CHAIN_ID) {
      errors.push(`chain.chain_id is ${input.chain.chainId}, but a Gray deployment's contracts are on Base (${BASE_CHAIN_ID}): pair again (init --pair --force --key relay-key.json)`);
    }
  }
  if (input.chain !== null && input.chain.chainId === BASE_CHAIN_ID) {
    if (!sameAddress(input.chain.dstackKms, BASE_DSTACK_KMS)) {
      errors.push(`chain.dstack_kms is ${input.chain.dstackKms}, not Phala's ${BASE_DSTACK_KMS} built into gray-assistant, the only one Phala's Base KMS asks: gray-assistant config unset chain.dstack_kms (its default is Phala's)`);
    }
    const rpc = rpcEndpointsWarning(input.chain.chainId, input.chain.rpc);
    if (rpc !== null) warnings.push(rpc);
  }
  return { errors, warnings };
}

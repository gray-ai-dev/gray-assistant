/**
 * What the relay checks of a phase-2 release before it lets it run (docs/design/relay-no-always-on-host.md 3.2 "What
 * the relay checks", 13.11 P6): the compose's own text, which Gray's signed release list publishes beside its hash
 * (`app_compose`), hashed and run through `@gray/lane-compose`'s closed policy with the list's own expectation, plus the
 * rules a VM of the relay's contract needs on top: its key provider is the KMS the relay's app runs on (Base's, the
 * `kms_ca_pubkey` of the stack VM in `lane.instances`), lane keeps the KMS lease (`LANE_KMS_URL`) and binds the vault.
 * For an OS image, the list's entry and its texts (S11b): dstack's own chain from the hash to `metadata.json`, and a
 * production image.
 *
 * Pure: no I/O, the same code for `releases check <hash>` and for `deliver`'s check of the compose the VM measured. Every
 * line names a rule and never echoes the compose's values beyond the public ones (`@gray/lane-compose` problems carry a
 * code and a path only).
 */
import { get, isObject, parseStrict, type Json } from "@gray/json";
import { checkSupplyAppCompose, supplyComposeFacts, type SupplyExpectation } from "@gray/lane-compose";
import { osImageProvenance, type ReleaseList } from "@gray/lane-verify";
import { sha256 } from "@noble/hashes/sha2";
import { bytesToHex, utf8ToBytes } from "@noble/hashes/utils";

/** What the relay's config says a release of its contract must be. */
export interface ReleaseComposeExpectation {
  /** The KMS root CA public key of the relay's app (the stack VM's `lane.instances` entry): Base's KMS in phase 2. */
  readonly kmsCaPubkey: string;
  /** The environment's release keys the relay pins (`lane.release_public_key`, `lane.release_freshness_public_key`). */
  readonly releasePublicKey?: string;
  readonly releaseFreshnessPublicKey?: string;
  /** `stack.pre_launch_sha256`, when the relay pins one pre-launch script. */
  readonly preLaunchSha256?: string | null;
}

/** One rule's outcome, in the order they run. */
export interface ReleaseContentCheck {
  readonly name: string;
  readonly ok: boolean;
  readonly detail: string;
}

export type ReleaseContentCode = "release_not_listed" | "compose_not_published" | "release_not_stack" | "compose_refused" | "os_image_refused";

export type ReleaseContentResult =
  | { readonly ok: true; readonly checks: readonly ReleaseContentCheck[] }
  | { readonly ok: false; readonly code: ReleaseContentCode; readonly detail: string; readonly checks: readonly ReleaseContentCheck[] };

const HASH = /^[0-9a-f]{64}$/;

function bareHash(hash: string): string {
  const bare = (hash.startsWith("0x") ? hash.slice(2) : hash).toLowerCase();
  if (!HASH.test(bare)) throw new Error("a release hash is 32 bytes of hex");
  return bare;
}

function refused(code: ReleaseContentCode, checks: readonly ReleaseContentCheck[]): ReleaseContentResult {
  const failed = checks.filter((check) => !check.ok);
  return { ok: false, code, detail: failed.map((check) => `${check.name}: ${check.detail}`).join("; "), checks };
}

/**
 * A compose release of the signed list, for a VM of the relay's contract. `ok` only when every rule holds; otherwise the
 * first missing step's code (`release_not_listed`, `compose_not_published`, `release_not_stack`) or `compose_refused`.
 */
export function checkReleaseCompose(list: ReleaseList, composeHash: string, expect: ReleaseComposeExpectation): ReleaseContentResult {
  const hash = bareHash(composeHash);
  const checks: ReleaseContentCheck[] = [];
  const entry = list.releases.find((release) => release.compose_hash === hash);
  if (entry === undefined) {
    checks.push({ name: "listed", ok: false, detail: `${hash} is not a release of Gray's signed list` });
    return refused("release_not_listed", checks);
  }
  checks.push({ name: "listed", ok: true, detail: `a release of Gray's signed list${entry.git_commit === null ? "" : ` (commit ${entry.git_commit})`}` });
  const text = entry.app_compose;
  if (text === null) {
    checks.push({ name: "published", ok: false, detail: "the signed list does not publish this release's app-compose, so it cannot be checked here" });
    return refused("compose_not_published", checks);
  }
  // The list's parser holds this already; it is the point of the check, so it is done here again.
  const textHash = bytesToHex(sha256(utf8ToBytes(text)));
  if (textHash !== hash) {
    checks.push({ name: "published", ok: false, detail: `the published app-compose hashes to ${textHash}` });
    return refused("compose_refused", checks);
  }
  checks.push({ name: "published", ok: true, detail: `the published app-compose (${utf8ToBytes(text).length} bytes) hashes to the release` });
  const stack = entry.stack;
  if (stack === null) {
    checks.push({ name: "stack", ok: false, detail: "the release is not a relay-stack release (no stack member)" });
    return refused("release_not_stack", checks);
  }
  if (expect.preLaunchSha256 !== undefined && expect.preLaunchSha256 !== null) {
    const pinned = stack.pre_launch_sha256 === expect.preLaunchSha256;
    checks.push({ name: "pre_launch_pinned", ok: pinned, detail: pinned ? "the release's pre-launch script is the one stack.pre_launch_sha256 pins" : "the release's pre-launch script is not the one stack.pre_launch_sha256 pins" });
  }

  const expectation: SupplyExpectation = {
    grayImages: [stack.gray_image],
    preLaunchSha256: stack.pre_launch_sha256,
    ...(expect.releasePublicKey === undefined ? {} : { releasePublicKey: expect.releasePublicKey }),
    ...(expect.releaseFreshnessPublicKey === undefined ? {} : { releaseFreshnessPublicKey: expect.releaseFreshnessPublicKey }),
  };
  const problems = checkSupplyAppCompose(text, expectation);
  checks.push(
    problems.length === 0
      ? { name: "policy", ok: true, detail: "@gray/lane-compose's closed policy passes with the list's expectation (Gray's image, the pre-launch script, the release keys)" }
      : { name: "policy", ok: false, detail: problems.map((problem) => `${problem.code}@${problem.path || "(root)"}`).join(", ") },
  );

  let keyProviderId: Json | undefined;
  try {
    const doc = parseStrict(text);
    keyProviderId = isObject(doc) ? get(doc, "key_provider_id") : undefined;
  } catch {
    keyProviderId = undefined;
  }
  const providerOk = typeof keyProviderId === "string" && keyProviderId === expect.kmsCaPubkey;
  checks.push({
    name: "key_provider",
    ok: providerOk,
    detail: providerOk
      ? "key_provider_id is the KMS of the relay's app (lane.instances' kms_ca_pubkey)"
      : typeof keyProviderId === "string"
        ? "key_provider_id is another KMS than the relay's app runs on (lane.instances' kms_ca_pubkey)"
        : "the app-compose names no key_provider_id (Phala's normalized form names the KMS)",
  });
  const facts = supplyComposeFacts(text);
  checks.push(
    facts.laneKmsUrl !== null
      ? { name: "kms_lease", ok: true, detail: `lane keeps the KMS lease with ${facts.laneKmsUrl} (LANE_KMS_URL)` }
      : { name: "kms_lease", ok: false, detail: "lane names no LANE_KMS_URL: the VM would keep no lease with the KMS, as a phase-1 compose" },
  );
  checks.push(
    facts.laneVaultBind
      ? { name: "vault_bind", ok: true, detail: "lane binds the relay's vault directory read-write" }
      : { name: "vault_bind", ok: false, detail: "lane does not bind the relay's vault directory" },
  );
  return checks.every((check) => check.ok) ? { ok: true, checks } : refused("compose_refused", checks);
}

/** An OS image release of the signed list: listed, its texts bind it (S11b), and it is a production image. */
export function checkReleaseOsImage(list: ReleaseList, osImageHash: string): ReleaseContentResult {
  const hash = bareHash(osImageHash);
  const checks: ReleaseContentCheck[] = [];
  const entry = list.osImages.find((image) => image.os_image_hash === hash);
  if (entry === undefined) {
    checks.push({ name: "listed", ok: false, detail: `${hash} is not an OS image of Gray's signed list` });
    return refused("release_not_listed", checks);
  }
  checks.push({ name: "listed", ok: true, detail: `an OS image of Gray's signed list${entry.description === null ? "" : ` (${entry.description})`}` });
  checks.push({ name: "measurements", ok: entry.measurements !== null, detail: entry.measurements !== null ? "the list pins its MRTD and RTMR0-2" : "the list pins no measurements for it" });
  const provenance = osImageProvenance(entry);
  if (!provenance.ok) {
    checks.push({ name: "texts", ok: false, detail: `its sha256sum.txt and metadata.json do not bind it (${provenance.code})` });
  } else {
    checks.push({ name: "texts", ok: true, detail: `its sha256sum.txt and metadata.json bind it (dstack ${provenance.version ?? "version unknown"})` });
    checks.push({ name: "production", ok: !provenance.isDev, detail: provenance.isDev ? "metadata.json says is_dev: a development image" : "metadata.json says a production image" });
  }
  return checks.every((check) => check.ok) ? { ok: true, checks } : refused("os_image_refused", checks);
}

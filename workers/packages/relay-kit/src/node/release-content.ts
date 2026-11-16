/**
 * The relay's own check of a phase-2 release's content (docs/design/relay-no-always-on-host.md 3.2, 13.11 P6), for
 * `releases check <hash>` and `deliver`: the signed release list (fetched and verified as the agent does,
 * `release-control.ts`) and the config's expectation, run through `../chain/release-compose.ts`.
 */
import { bytesToLowerHex } from "@gray/attest";
import { get, isObject, type Json } from "@gray/json";
import type { ReleaseList } from "@gray/lane-verify";
import { readDstackKmsCa } from "../chain/checks.ts";
import { checkReleaseCompose, checkReleaseOsImage, type ReleaseComposeExpectation, type ReleaseContentCheck, type ReleaseContentResult } from "../chain/release-compose.ts";
import type { ReleaseKind } from "../chain/app-auth.ts";
import { builtInKmsCaPubkey, configTrustProblems } from "../chain/trust.ts";
import { RelayKitError } from "../errors.ts";
import type { LaneBinding } from "../lane-binding.ts";
import type { ChainContext } from "./chain.ts";
import { loadRelayConfigFile, parseJsoncText, type LoadedRelayConfig } from "./config-file.ts";
import { configTrust } from "./release-control.ts";
import { readFileText } from "./files.ts";

const MAX_CONFIG_BYTES = 1024 * 1024;

/**
 * The relay's expectation of a compose of its contract (`deliver`'s check of the compose the VM measured): the KMS of
 * the contract when the kit knows it without Gray (Base's, built in: `../chain/trust.ts`), else the KMS of the stack
 * VM's instance (`deliver.ts` `phase2Vm`, the `lane.instances` entry of the app at `chain.contract`, which Gray names),
 * and the release keys it pins. So on Base a VM whose compose names a KMS of Gray's choosing gets nothing, whatever
 * `kms_ca_pubkey` Gray's answer names for it (provider review 2026-11-17, item 17).
 */
export function releaseExpectationOf(config: LoadedRelayConfig, instance: LaneBinding): ReleaseComposeExpectation {
  const chain = config.daemon.chain;
  const contractKms = chain === null || chain === undefined ? null : builtInKmsCaPubkey(chain.chainId, chain.dstackKms);
  return releaseExpectationWith(config, contractKms ?? instance.kmsCaPubkey);
}

/** The same expectation with `kmsCaPubkey` as the key provider a compose must name. */
export function releaseExpectationWith(config: LoadedRelayConfig, kmsCaPubkey: string): ReleaseComposeExpectation {
  const lane = config.daemon.lane;
  return {
    kmsCaPubkey,
    releasePublicKey: bytesToLowerHex(lane.releasePublicKey),
    ...(lane.releaseFreshness === null ? {} : { releaseFreshnessPublicKey: bytesToLowerHex(lane.releaseFreshness.publicKey) }),
    preLaunchSha256: config.daemon.stack?.preLaunchSha256 ?? null,
  };
}

/**
 * The KMS root CA a compose of the relay's contract must name, known without Gray: Base's, built into the kit
 * (`../chain/trust.ts`), for a contract on Base with Phala's DstackKms; else what the configured DstackKms publishes
 * (`kmsInfo()`, read from both of the config's endpoints, which must agree); null when neither is there (a test chain's
 * stand-in) or the endpoints cannot be read.
 */
export async function contractKmsCaPubkey(context: ChainContext): Promise<string | null> {
  const builtIn = builtInKmsCaPubkey(context.chain.chainId, context.chain.dstackKms);
  if (builtIn !== null) return builtIn;
  // An endpoint that cannot be read, or two that disagree, is the command's error, never a fall back to Gray's value.
  return readDstackKmsCa(context.chain.rpc, context.chain.chainId, context.chain.dstackKms);
}

/**
 * `configTrust` for the config behind `context` (`./release-control.ts`): its release keys and `pairing.gray` when it has
 * a `lane` section, its chain always. `releases check` and `releases approve` stop on its errors.
 */
export function contextTrust(context: ChainContext): { readonly errors: readonly string[]; readonly warnings: readonly string[] } {
  if (hasLaneSection(context.configPath)) return configTrust(loadRelayConfigFile(context.configPath));
  const chain = context.chain;
  return configTrustProblems({ gray: null, releasePublicKey: "0".repeat(64), releaseFreshnessPublicKey: null, chain: { chainId: chain.chainId, dstackKms: chain.dstackKms, rpc: chain.rpc } });
}

/**
 * Why `releases approve <hash>` would let in something Gray did not publish, or null when it would not (review of
 * 2026-11-17): the hash must be an upgrade this kit lists (`upgradeVerdict`), or a compose release or OS image of Gray's
 * signed list read as every check reads it (`releaseListForCommand`). `list` replaces the fetch (tests).
 */
export async function approvalRefusal(
  context: ChainContext,
  hash: string,
  kind: string | undefined,
  nowMs: number,
  list?: (config: LoadedRelayConfig) => Promise<ReleaseList>,
): Promise<string | null> {
  const bare = hash.toLowerCase().replace(/^0x/, "");
  // A hash that is no hash is the approval's own usage refusal (releaseHash).
  if (!/^[0-9a-f]{64}$/.test(bare)) return null;
  const { upgradeVerdict } = await import("./chain.ts");
  if (kind === undefined || kind === "implementation") {
    const upgrade = upgradeVerdict(`0x${bare}`);
    if (upgrade.ok) return null;
    if (kind === "implementation") return upgrade.detail;
  }
  if (!hasLaneSection(context.configPath)) return `this config names no signed release list (lane.release_list), so 0x${bare} cannot be checked against Gray's releases`;
  const config = loadRelayConfigFile(context.configPath);
  let signed: ReleaseList;
  try {
    if (list !== undefined) signed = await list(config);
    else {
      const { releaseListForCommand } = await import("./release-control.ts");
      signed = (await releaseListForCommand(config, nowMs)).list;
    }
  } catch (error) {
    return `Gray's signed release list could not be read (${error instanceof RelayKitError ? (error.detail ?? error.code) : "unreadable"}), so 0x${bare} cannot be checked against it`;
  }
  const compose = kind !== "os_image" && signed.releases.some((entry) => entry.compose_hash === bare);
  const osImage = kind !== "compose" && signed.osImages.some((image) => image.os_image_hash === bare);
  if (compose || osImage) return null;
  return `0x${bare} is not ${kind === "os_image" ? "an OS image" : kind === "compose" ? "a release" : "a release, an OS image or an upgrade"} Gray published (its signed list ${config.daemon.lane.releaseList}${kind === "compose" || kind === "os_image" ? "" : ", or this kit's upgrades"})`;
}

/** `result` with one more failed check, `compose_refused` unless it was refused already. */
function withFailedCheck(result: ReleaseContentResult, check: ReleaseContentCheck): ReleaseContentResult {
  const checks = [...result.checks, check];
  const failed = checks.filter((entry) => !entry.ok).map((entry) => `${entry.name}: ${entry.detail}`);
  return { ok: false, code: result.ok ? "compose_refused" : result.code, detail: failed.join("; "), checks };
}

/** Check one release of the list: a compose against the relay's expectation, an OS image by its texts. */
export function checkReleaseContent(list: ReleaseList, kind: ReleaseKind, hash: string, expectation: () => ReleaseComposeExpectation): ReleaseContentResult {
  return kind === "compose" ? checkReleaseCompose(list, hash, expectation()) : checkReleaseOsImage(list, hash);
}

/** Whether the config has a `lane` section, without judging the rest (a config with only `chain` checks the chain alone). */
function hasLaneSection(configPath: string): boolean {
  const raw = parseJsoncText(readFileText(configPath, "config", MAX_CONFIG_BYTES), "config") as Json;
  return isObject(raw) && get(raw, "lane") !== undefined;
}

/**
 * `releaseContentForCheck`'s answer for a compose while no stack VM is adopted and the kit knows no KMS of the contract
 * (a test chain whose DstackKms publishes none): there is no key provider to compare its content with yet.
 */
export const NO_STACK_VM = "no_stack_vm";

/**
 * `releases check`'s content part: null when the config has no `lane` section (no signed list to read); else the
 * result. A compose's key provider must be the contract's KMS (`contractKmsCaPubkey`: Base's, built in), so a release is
 * checked whole before the first VM too (provider review 2026-11-17, item 16), and a VM Gray named on another KMS fails
 * (`vm_key_provider`). Without a KMS known that way the adopted VM's instance names it, and with neither the answer is
 * `NO_STACK_VM`. `list` replaces the fetch and `kms` the chain read (tests).
 */
export async function releaseContentForCheck(
  context: ChainContext,
  kind: ReleaseKind,
  hash: string,
  nowMs: number,
  list?: (config: LoadedRelayConfig) => Promise<ReleaseList>,
  kms: (context: ChainContext) => Promise<string | null> = contractKmsCaPubkey,
): Promise<ReleaseContentResult | typeof NO_STACK_VM | null> {
  if (!hasLaneSection(context.configPath)) return null;
  const config = loadRelayConfigFile(context.configPath);
  const { adoptedPhase2Vm } = await import("./deliver.ts");
  // An OS image is checked by its own texts; a compose needs the KMS of the contract, or of the VM's instance.
  let kmsCaPubkey = "";
  let vmCheck: ReleaseContentCheck | null = null;
  if (kind === "compose") {
    const contractKms = await kms(context);
    const vm = adoptedPhase2Vm(config, context);
    if (contractKms === null && vm === null) return NO_STACK_VM;
    kmsCaPubkey = contractKms ?? (vm as NonNullable<typeof vm>).instance.kmsCaPubkey;
    if (contractKms !== null && vm !== null && vm.instance.kmsCaPubkey !== contractKms) {
      vmCheck = {
        name: "vm_key_provider",
        ok: false,
        detail: `the VM Gray named for your contract (${vm.origin}) runs on KMS …${vm.instance.kmsCaPubkey.slice(-16)}, not your contract's (…${contractKms.slice(-16)}): it would not ask your contract for its keys`,
      };
    }
  }
  let signed: ReleaseList;
  if (list !== undefined) signed = await list(config);
  else {
    const { releaseListForCommand } = await import("./release-control.ts");
    signed = (await releaseListForCommand(config, nowMs)).list;
  }
  try {
    const result = checkReleaseContent(signed, kind, hash, () => releaseExpectationWith(config, kmsCaPubkey));
    return vmCheck === null ? result : withFailedCheck(result, vmCheck);
  } catch (error) {
    if (error instanceof RelayKitError) throw error;
    throw new RelayKitError("usage", error instanceof Error ? error.message : String(error));
  }
}

/** The result as JSON for the command's last line. */
export function releaseContentJson(result: ReleaseContentResult): Record<string, unknown> {
  return {
    ok: result.ok,
    ...(result.ok ? {} : { code: result.code }),
    checks: result.checks.map((check) => ({ name: check.name, ok: check.ok, detail: check.detail })),
  };
}

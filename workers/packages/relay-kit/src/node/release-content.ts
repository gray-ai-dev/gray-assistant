/**
 * The relay's own check of a phase-2 release's content (docs/design/relay-no-always-on-host.md 3.2, 13.11 P6), for
 * `releases check <hash>` and `deliver`: the signed release list (fetched and verified as the agent does,
 * `release-control.ts`) and the config's expectation, run through `../chain/release-compose.ts`.
 */
import { bytesToLowerHex } from "@gray/attest";
import { get, isObject, type Json } from "@gray/json";
import type { ReleaseList } from "@gray/lane-verify";
import { checkReleaseCompose, checkReleaseOsImage, type ReleaseComposeExpectation, type ReleaseContentResult } from "../chain/release-compose.ts";
import type { ReleaseKind } from "../chain/app-auth.ts";
import { RelayKitError } from "../errors.ts";
import type { LaneBinding } from "../lane-binding.ts";
import type { ChainContext } from "./chain.ts";
import { loadRelayConfigFile, parseJsoncText, type LoadedRelayConfig } from "./config-file.ts";
import { readFileText } from "./files.ts";

const MAX_CONFIG_BYTES = 1024 * 1024;

/**
 * The relay's expectation of a compose of its contract: the KMS of the stack VM's instance (`deliver.ts` `phase2Vm`, the
 * `lane.instances` entry of the app at `chain.contract`) and the release keys it pins.
 */
export function releaseExpectationOf(config: LoadedRelayConfig, instance: LaneBinding): ReleaseComposeExpectation {
  const lane = config.daemon.lane;
  return {
    kmsCaPubkey: instance.kmsCaPubkey,
    releasePublicKey: bytesToLowerHex(lane.releasePublicKey),
    ...(lane.releaseFreshness === null ? {} : { releaseFreshnessPublicKey: bytesToLowerHex(lane.releaseFreshness.publicKey) }),
    preLaunchSha256: config.daemon.stack?.preLaunchSha256 ?? null,
  };
}

/** Check one release of the list: a compose against the relay's expectation, an OS image by its texts. */
export function checkReleaseContent(list: ReleaseList, kind: ReleaseKind, hash: string, expectation: () => ReleaseComposeExpectation): ReleaseContentResult {
  return kind === "compose" ? checkReleaseCompose(list, hash, expectation()) : checkReleaseOsImage(list, hash);
}

/** Whether the config has a `lane` section, without judging the rest (a config with only `chain` checks the chain alone). */
function hasLaneSection(configPath: string): boolean {
  const raw = parseJsoncText(readFileText(configPath, "relay config", MAX_CONFIG_BYTES), "relay config") as Json;
  return isObject(raw) && get(raw, "lane") !== undefined;
}

/** `releaseContentForCheck`'s answer for a compose while no stack VM is adopted: there is nothing to compare its content with yet. */
export const NO_STACK_VM = "no_stack_vm";

/**
 * `releases check`'s content part: null when the config has no `lane` section (no signed list to read); `NO_STACK_VM`
 * for a compose while `stack.instance` is "gray" and no VM of this contract is adopted yet (the compose's rules name
 * the KMS of the VM's instance, which `deliver` adopts; before the first Deploy and deliver only the contract's state
 * can be compared); else the result. `list` replaces the fetch (tests).
 */
export async function releaseContentForCheck(
  context: ChainContext,
  kind: ReleaseKind,
  hash: string,
  nowMs: number,
  list?: (config: LoadedRelayConfig) => Promise<ReleaseList>,
): Promise<ReleaseContentResult | typeof NO_STACK_VM | null> {
  if (!hasLaneSection(context.configPath)) return null;
  const config = loadRelayConfigFile(context.configPath);
  const { adoptedPhase2Vm, phase2Vm } = await import("./deliver.ts");
  // An OS image is checked by its own texts; a compose needs the VM's instance.
  if (kind === "compose" && adoptedPhase2Vm(config, context) === null) return NO_STACK_VM;
  let signed: ReleaseList;
  if (list !== undefined) signed = await list(config);
  else {
    const { releaseListForCommand } = await import("./release-control.ts");
    signed = (await releaseListForCommand(config, nowMs)).list;
  }
  try {
    return checkReleaseContent(signed, kind, hash, () => releaseExpectationOf(config, phase2Vm(config, context).instance));
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

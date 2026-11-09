import { parsePlain } from "@gray/json";
import semver from "semver";
import { z } from "zod";
import { LANE_RELAY_ID_PATTERN } from "./endpoint.ts";
import { PEER_TUNNEL_PATH, STACK_KMS_CA_PUBKEY_PATTERN } from "./stack.ts";
import {
  BOOT_EVENTS,
  BOOT_FAILURE_CLASSES,
  DEPLOYMENT_STATES,
  LEASE_EXPIRED_FIX,
  LEASE_OVERDUE_FIX,
  PROVISION_ENV_SOURCES,
  PROVISION_KINDS,
  PROVISION_OP_STATES,
  RELAY_ALERT_KINDS,
  RELAY_ALERT_REQUIRED_KINDS,
  RELEASE_MOVE_BLOCKS,
  TOKEN_SERVICE_CODES,
  type ReleaseMoveBlock,
  type BootEvent,
  type BootFailureClass,
  type DeploymentState,
  type ProvisionEnvSource,
  type ProvisionEnvValue,
  type ProvisionKind,
  type ProvisionOpState,
  type RelayAlertKind,
  type TokenServiceCode,
} from "./stack-provision-words.ts";

/**
 * The relay-stack provisioner's shared words (docs/relay-stack-provisioner.md): what gray-console stores and shows and
 * what gray-provisioner does and reads, so neither can drift from the other. Pure: no I/O, no clock except the
 * arguments, no randomness. A subpath export (`@gray/control/stack-provision`).
 *
 * - the operations (P5): Deploy, Restart, Delete, their steps in order, and their states;
 * - the release profile (P4): the measured app-compose Gray's operators publish, the env names it takes and where each
 *   value comes from, and the bridge key id template;
 * - the boot timeline (P8): the fixed serial status lines of the measured pre-launch and of dstack's compose service,
 *   as closed words, never the line's text;
 * - what a failure means for the relay in plain words, with the fix (P9);
 * - the containers' state as the guest agent reports it, and the crash-loop rule (P8);
 * - the relay alerts (P10).
 */

// The closed word lists, from a file that imports nothing (stack-provision-words.ts), so the console's contract and the
// frontend's tests that read it take them without this package's dependencies.
export {
  BOOT_EVENTS,
  BOOT_FAILURE_CLASSES,
  DEPLOYMENT_STATES,
  LEASE_EXPIRED_FIX,
  LEASE_OVERDUE_FIX,
  PROVISION_ENV_SOURCES,
  PROVISION_KINDS,
  PROVISION_OP_STATES,
  RELAY_ALERT_KINDS,
  RELAY_ALERT_REQUIRED_KINDS,
  RELEASE_MOVE_BLOCKS,
  TOKEN_SERVICE_CODES,
  type ReleaseMoveBlock,
  type BootEvent,
  type BootFailureClass,
  type DeploymentState,
  type ProvisionEnvSource,
  type ProvisionEnvValue,
  type ProvisionKind,
  type ProvisionOpState,
  type RelayAlertKind,
  type TokenServiceCode,
};

// ------------------------------------------------------------------------------------------------- operations (P5)

/** Each kind's steps, in the order the provisioner runs them; the panel shows "step N of M" from this list. */
export const PROVISION_STEPS = {
  deploy: ["check", "provision", "publish", "create", "watch"],
  restart: ["check", "restart", "watch"],
  delete: ["check", "unbind", "remove_vm", "unpublish"],
  // docs/design/relay-zero-downtime.md: a second instance of the relay's app (replicate, then its boot watched, the old
  // VM serving meanwhile), the deployment moved to it (shift), the old VM's requests finishing (drain), the old VM gone.
  rollout: ["check", "replicate", "watch", "shift", "drain", "remove_old"],
  // docs/design/relay-release-zero-downtime.md: as a rollout, the replica held (no value in its env) until `update` gives
  // that instance the new release's compose and its own env.
  upgrade: ["check", "replicate", "update", "watch", "shift", "drain", "remove_old"],
} as const satisfies Record<ProvisionKind, readonly string[]>;
export type ProvisionStep = (typeof PROVISION_STEPS)[ProvisionKind][number];

// ------------------------------------------------------------------------------------------------- release profile (P4)

/** dstack's env name rule (the compose's `allowed_envs`). */
export const PROVISION_ENV_NAME = /^[A-Z_][A-Z0-9_]{0,63}$/;
/** A Phala identifier (`tdx.large`, `dstack-0.6.1`): phala-deploy.mjs's `phalaToken`. */
export const PHALA_TOKEN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
/**
 * A Phala KMS id (`kms_qaj3xMeb`), the selector `POST /cvms/provision` takes since 2026-11-07, when it began refusing
 * `node_id` and `teepod_id` (docs.phala.com/api-reference/cvms/provision-dstack-app.md; docs/relay-stack-provisioner.md).
 * `phala-deploy.mjs nodes` prints each KMS's id beside its slug and ca_pubkey.
 */
export const PHALA_KMS_ID = /^kms_[A-Za-z0-9]{1,64}$/;
/** The largest app-compose a profile carries: the c4 stack compose was 38 KiB. */
export const PROFILE_COMPOSE_MAX_BYTES = 256 * 1024;
/**
 * Template placeholders: the relay's DNS label, the dstack app id, and the VM's bridge key (the first 16 hex digits of
 * its Ed25519 public key). A release whose entrypoint names its bridge key `app-<app id>-<key>` (docs/design/relay-zero-
 * downtime.md) has the template `app-{app_id}-{key}`; one before it, `app-{app_id}`.
 */
export const TEMPLATE_PLACEHOLDERS = ["{relay}", "{app_id}", "{key}"] as const;

// A literal may be empty: the release's stack compose names ACME_EAB_KID / ACME_EAB_HMAC_KEY, and empty values are how a
// VM orders its certificate from Let's Encrypt rather than Google Trust Services (deploy/tee/release/README.md).
const envValue = z.union([z.enum(PROVISION_ENV_SOURCES), z.object({ literal: z.string().max(2048).regex(/^[!-~]*$/) }).strict()]);

/** A profile as an operator publishes it (`POST /api/v1/ops/lane-stack-profiles`). */
export const releaseProfileInputSchema = z
  .object({
    /** Null: every relay without one of its own (one measured compose per Gray release); set: that relay's own compose. */
    relay_id: z.string().regex(LANE_RELAY_ID_PATTERN).nullable(),
    /** The exact app-compose bytes Phala measures (`app-compose.mjs --layout stack --target phala`). */
    app_compose: z.string().min(1),
    env: z.record(z.string().regex(PROVISION_ENV_NAME), envValue),
    /** The VM's bridge key id: a literal, or with `{app_id}` / `{relay}` / `{key}`. */
    lane_key_id: z.string().min(1).max(128),
    instance_type: z.string().regex(PHALA_TOKEN),
    image_os: z.string().regex(PHALA_TOKEN),
    /**
     * The KMS Phala provisions the VM on (`PHALA_KMS_ID`): the one whose ca_pubkey is the compose's `key_provider_id`.
     * The provisioner checks the landed KMS's CA against the compose, so a wrong id refuses before a VM is made.
     */
    kms_id: z.string().regex(PHALA_KMS_ID),
    reason: z.string(),
  })
  .strict();
export type ReleaseProfileInput = z.infer<typeof releaseProfileInputSchema>;

/** What the profile's app-compose must hold for the provisioner (phala-deploy.mjs `readAppCompose`). */
export interface ProfileCompose {
  readonly allowedEnvs: readonly string[];
  readonly keyProviderId: string;
  readonly name: string | null;
}

export class ProfileProblem extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ProfileProblem";
  }
}

/**
 * The checks the console makes before it stores a profile (the provisioner repeats the canonical-hash check, which
 * needs dstack's own hash function, before anything is sent): a JSON object with a docker compose, a measured
 * pre-launch script, a non-empty `allowed_envs` whose names the env map covers exactly, a KMS CA key as its
 * `key_provider_id`, none of the members Phala refuses, and a template that expands to a key id.
 */
export function checkProfile(input: ReleaseProfileInput): ProfileCompose {
  if (new TextEncoder().encode(input.app_compose).length > PROFILE_COMPOSE_MAX_BYTES) throw new ProfileProblem(`The app-compose is larger than ${PROFILE_COMPOSE_MAX_BYTES} bytes.`);
  let app: unknown;
  try {
    app = parsePlain(input.app_compose);
  } catch {
    throw new ProfileProblem("The app-compose is not JSON.");
  }
  if (app === null || typeof app !== "object" || Array.isArray(app)) throw new ProfileProblem("The app-compose is not a JSON object.");
  const a = app as Record<string, unknown>;
  if (typeof a.docker_compose_file !== "string" || a.docker_compose_file === "") throw new ProfileProblem("The app-compose has no docker_compose_file.");
  if (typeof a.pre_launch_script !== "string" || a.pre_launch_script.trim() === "") throw new ProfileProblem("The app-compose has no measured pre_launch_script.");
  if (!Array.isArray(a.allowed_envs) || a.allowed_envs.length === 0 || !a.allowed_envs.every((n) => typeof n === "string" && PROVISION_ENV_NAME.test(n))) {
    throw new ProfileProblem("The app-compose has no allowed_envs list of env names.");
  }
  const allowed = a.allowed_envs as string[];
  if (new Set(allowed).size !== allowed.length) throw new ProfileProblem("The app-compose's allowed_envs names one name twice.");
  const requirements = a.requirements;
  if ((requirements !== null && typeof requirements === "object" && Object.hasOwn(requirements, "platforms")) || Object.hasOwn(a, "storage_discard")) {
    throw new ProfileProblem("The app-compose still carries requirements.platforms or storage_discard, which Phala refuses: render it with --target phala.");
  }
  const kms = typeof a.key_provider_id === "string" ? a.key_provider_id.replace(/^0x/i, "").toLowerCase() : "";
  if (!STACK_KMS_CA_PUBKEY_PATTERN.test(kms)) throw new ProfileProblem("The app-compose's key_provider_id is not a KMS CA public key: render it with --kms-ca-pubkey.");
  const names = Object.keys(input.env);
  const missing = allowed.filter((n) => !names.includes(n));
  const extra = names.filter((n) => !allowed.includes(n));
  if (missing.length > 0 || extra.length > 0) {
    throw new ProfileProblem(`The env map must name exactly the app-compose's allowed_envs (${allowed.join(", ")})${missing.length > 0 ? `; missing ${missing.join(", ")}` : ""}${extra.length > 0 ? `; not allowed ${extra.join(", ")}` : ""}.`);
  }
  const sample = { relay: "relay-label", appId: "0".repeat(40), key: "0".repeat(16) };
  if (expandTemplate(input.lane_key_id, sample) === null || !/^[A-Za-z0-9._-]{1,64}$/.test(expandTemplate(input.lane_key_id, sample)!)) {
    throw new ProfileProblem("The bridge key id template must expand to 1 to 64 letters, digits, '.', '_' or '-'.");
  }
  return { allowedEnvs: allowed, keyProviderId: kms, name: typeof a.name === "string" ? a.name : null };
}

/**
 * `template` with its placeholders filled; null when it holds a brace that is not one of them, or `{key}` without a key
 * to fill it with.
 */
export function expandTemplate(template: string, values: { readonly relay: string; readonly appId: string; readonly key?: string }): string | null {
  let out = template.replaceAll("{relay}", values.relay).replaceAll("{app_id}", values.appId);
  if (values.key !== undefined) out = out.replaceAll("{key}", values.key);
  return /[{}]/.test(out) ? null : out;
}

/** Whether a bridge key id template names each VM's own key (`{key}`): only then may two instances of one app run. */
export function templateNamesKey(template: string): boolean {
  return template.includes("{key}");
}

/** The `{key}` of a bridge key id: the first 16 hex digits of the VM's Ed25519 bridge public key (64 hex). */
export function bridgeKeyTag(publicKeyHex: string): string {
  return publicKeyHex.toLowerCase().slice(0, 16);
}

/** A lower-case DNS name of labels of 1 to 63 letters, digits and inner hyphens, at most 253 characters. */
export function validHostname(name: string): boolean {
  if (name.length > 253) return false;
  const labels = name.split(".");
  return labels.length >= 2 && labels.every((l) => /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/.test(l));
}

/**
 * The relay's DNS label for `{relay}`: its id when that is already a DNS label, else `r-` and the first 16 hex digits
 * of the id's SHA-256 (a relay id may hold `.`, `_`, `:` and capitals, which a hostname label cannot).
 */
export async function relayLabel(relayId: string): Promise<string> {
  if (/^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/.test(relayId)) return relayId;
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(relayId)));
  return `r-${Array.from(digest.subarray(0, 8), (b) => b.toString(16).padStart(2, "0")).join("")}`;
}

// ------------------------------------------------------------------------------------------------- the boot timeline (P8)

/** pre-launch.stack.sh's status labels and their words (a label the table lacks is `prelaunch_other`, its text dropped). */
export const PRELAUNCH_STATUS: Readonly<Record<string, BootEvent>> = {
  "certificate directory ready": "prelaunch_cert_dir",
  "runtime state on tmpfs": "prelaunch_tmpfs",
  "relay bridges closed to the host": "prelaunch_bridges_closed",
  "Gray images pulled": "prelaunch_gray_images",
  "pull-token challenge received": "prelaunch_challenge",
  "quote taken": "prelaunch_quote",
  "pull token received": "prelaunch_token",
  "registry login done": "prelaunch_registry_login",
  "relay image pulled": "prelaunch_relay_image",
  "relay image declares no volume": "prelaunch_no_volume",
  "registry credential deleted": "prelaunch_credential_deleted",
  sealed: "prelaunch_sealed",
  // life/image (S51, S54): the relay identity and the relay's own image checked at boot.
  "relay identity measured": "prelaunch_identity",
  "relay image signature verified": "prelaunch_image_signature",
  "relay image in its slot": "prelaunch_image_slot",
  "relay image measured": "prelaunch_image_measured",
  // life/image's bounded token-service retry (S51a): one line per unanswered attempt, no value in it.
  "pull-token service not answering, retrying": "prelaunch_token_retry",
};

/** pre-launch.stack.sh's failure labels (`gray-prelaunch: FAILED: <label>`), each with its class. */
export const PRELAUNCH_FAILURES: Readonly<Record<string, BootFailureClass>> = {
  "the pull-token challenge request": "token_service",
  "the pull-token challenge response": "token_service",
  "the pull-token request": "token_service",
  // life/image's bounded wait (S51a): the token service never answered within the boot's wait, which the provisioner
  // waits out with its restarts (PROVISION_TOKEN_RESTARTS); the other two are the script's own (a test seam, sleep).
  "the relay token service did not answer in time": "token_service",
  "the token wait is not whole seconds": "gray_platform",
  "waiting for the relay token service": "gray_platform",
  "opening the pull-token envelope": "token_service",
  "the registry login": "relay_registry",
  "pulling the relay image": "relay_registry",
  "deleting the registry credential": "gray_platform",
  "the relay image declares a volume": "relay_image",
  "the relay image in the pull-token answer": "relay_image",
  "the relay image signature": "relay_image",
  "tagging the relay image into its slot": "gray_platform",
  "measuring the relay image": "gray_platform",
  "the relay identity in the encrypted env": "gray_platform",
  "measuring the relay identity": "gray_platform",
  "the Gray registry login": "gray_registry",
  "the Gray registry credential is incomplete": "gray_registry",
  "pulling Gray's images": "gray_registry",
  "deleting the Gray registry login": "gray_platform",
  "reading Gray's images from the compose": "gray_platform",
  "reading x-gray-relay from the compose": "gray_platform",
  "taking the quote": "gray_platform",
  "computing report_data": "gray_platform",
  "making the pull key": "gray_platform",
  "deleting the pull key": "gray_platform",
  "making the work directory": "gray_platform",
  "removing the work directory": "gray_platform",
  "sealing pre-launch": "gray_platform",
  "stopping docker and containerd": "gray_platform",
  "starting containerd and docker": "gray_platform",
  "docker is not on the expected root and driver": "gray_platform",
  "preparing the certificate directory": "gray_platform",
  "mounting a tmpfs over a runtime directory": "gray_platform",
  "a runtime directory is not on tmpfs": "gray_platform",
  "binding the persistent directory": "gray_platform",
  "closing the relay bridges to the host": "gray_platform",
  "app-compose.json or the compose file is missing": "gray_platform",
  "a required tool is missing": "gray_platform",
  "/run is not on tmpfs": "gray_platform",
};

/**
 * The stack compose's services (deploy/tee/compose.stack.yaml) whose container lines the timeline keeps. `acme` is a
 * release before D133, which ran gray-acme as its own one-shot service; since D133 it runs inside `lane`.
 */
const CONTAINER_EVENTS: Readonly<Record<string, { readonly started: BootEvent; readonly exited?: BootEvent }>> = {
  egress: { started: "egress_started" },
  acme: { started: "acme_started", exited: "acme_exited" },
  lane: { started: "lane_started" },
  "isolation-check": { started: "isolation_check_started", exited: "isolation_check_exited" },
  relay: { started: "relay_started" },
};

/** One event read from the serial console: its word, the seconds since the kernel started, and a failure's class. */
export interface SerialEvent {
  readonly event: BootEvent;
  /** Seconds since the kernel started (the line's own stamp), or null for a line without one. */
  readonly uptimeS: number | null;
  readonly failure: BootFailureClass | null;
  /** For `prelaunch_failed`: the failure label as one of PRELAUNCH_FAILURES' keys, else null (never other text). */
  readonly step: string | null;
  /**
   * The relay token service's code a line names (`prelaunch_token_held`, and `prelaunch_failed` of class
   * `token_refused`): one of TOKEN_SERVICE_CODES, `other` for a code the list lacks, null for every other event.
   */
  readonly code: TokenServiceCode | "other" | null;
}

const STAMP = /^\[\s*(\d+)\.(\d+)\]\s/;
const KERNEL_FIRST = /^\[\s*0\.0+\]\s+Command line:/;
const PRELAUNCH = /\bgray-prelaunch: (FAILED: )?(.+)$/;
const CONTAINER = /^\s*Container (\S+)\s+(Started|Exited|Error)\s*$/;
/** pre-launch's wait on a token-service answer of 5xx or 429 that named a code (S51a): one line per attempt. */
const HELD = /^pull-token service held the boot \(([a-z0-9_]{1,64})\), retrying$/;
/** A failure label with the token service's refusal code after it: `the pull-token request (release_rejected)`. */
const REFUSED = /^(.+) \(([a-z0-9_]{1,64})\)$/;

/** A code a line names, as a closed word: one of TOKEN_SERVICE_CODES, else `other` (its text dropped). */
export function tokenServiceCodeOf(text: string): TokenServiceCode | "other" {
  return (TOKEN_SERVICE_CODES as readonly string[]).includes(text) ? (text as TokenServiceCode) : "other";
}

/**
 * The events of the latest boot in `serial` (Phala's serial log of the CVM, plain text): the lines after the last
 * kernel start (all of them when none is in view), each mapped to a closed word; any other line is skipped and no
 * line's text is kept. The compose
 * project name is the measured compose's (`gray-lane`), so a container line names `gray-lane-<service>-1`.
 */
export function bootEventsOf(serial: string): SerialEvent[] {
  const lines = serial.split(/\r?\n/);
  let start = -1;
  for (let i = 0; i < lines.length; i++) if (KERNEL_FIRST.test(lines[i]!)) start = i;
  // Without the kernel's first line in view (a long boot past the lines read), the lines read are the boot's tail.
  const out: SerialEvent[] = start < 0 ? [] : [{ event: "kernel_started", uptimeS: 0, failure: null, step: null, code: null }];
  const seen = new Set<string>(start < 0 ? [] : ["kernel_started"]);
  const add = (e: SerialEvent, key: string = e.event): void => {
    if (seen.has(key)) return;
    seen.add(key);
    out.push(e);
  };
  for (const line of lines.slice(start + 1)) {
    const stamp = STAMP.exec(line);
    const uptimeS = stamp === null ? null : Number(stamp[1]) + Number(`0.${stamp[2]}`);
    const body = stamp === null ? line : line.slice(stamp[0].length);
    const pre = PRELAUNCH.exec(body);
    if (pre !== null) {
      const label = pre[2]!.trim();
      if (pre[1] !== undefined) {
        const refused = REFUSED.exec(label);
        const base = refused !== null && PRELAUNCH_FAILURES[refused[1]!] !== undefined ? refused[1]! : label;
        const cls = PRELAUNCH_FAILURES[base];
        if (refused !== null && cls !== undefined) add({ event: "prelaunch_failed", uptimeS, failure: "token_refused", step: base, code: tokenServiceCodeOf(refused[2]!) });
        else add({ event: "prelaunch_failed", uptimeS, failure: cls ?? "gray_platform", step: cls === undefined ? null : label, code: null });
        continue;
      }
      const held = HELD.exec(label);
      if (held !== null) {
        // A boot held by its token service prints a line per attempt; the latest names what holds it now (the relay may
        // have fixed one cause and met the next), so it replaces the earlier one.
        const event: SerialEvent = { event: "prelaunch_token_held", uptimeS, failure: null, step: null, code: tokenServiceCodeOf(held[1]!) };
        const at = out.findIndex((e) => e.event === "prelaunch_token_held");
        if (at < 0) add(event);
        else out[at] = event;
        continue;
      }
      add({ event: PRELAUNCH_STATUS[label] ?? "prelaunch_other", uptimeS, failure: null, step: null, code: null }, PRELAUNCH_STATUS[label] ?? `other:${label}`);
      continue;
    }
    // dstack-util prints compose's own lines after its `dstack-util[<pid>]:` prefix.
    const after = body.replace(/^dstack-util\[\d+\]:/, "");
    const container = CONTAINER.exec(after);
    if (container !== null) {
      const match = /^gray-lane-(.+)-\d+$/.exec(container[1]!);
      const service = match === null ? undefined : CONTAINER_EVENTS[match[1]!];
      if (service === undefined) continue;
      if (container[2] === "Started") add({ event: service.started, uptimeS, failure: null, step: null, code: null });
      else if (service.exited !== undefined) add({ event: service.exited, uptimeS, failure: null, step: null, code: null });
      continue;
    }
    if (/Finished app-compose\.service\b/.test(body)) add({ event: "compose_finished", uptimeS, failure: null, step: null, code: null });
    else if (/Failed to start app-compose\.service\b/.test(body)) add({ event: "compose_failed", uptimeS, failure: "gray_platform", step: null, code: null });
  }
  return out;
}

// ------------------------------------------------------------------------------------------------- plain words (P9)

/** What a failed step or boot means for the relay: the title the panel shows, the fix, and whose side it is on. */
export interface FailureWords {
  readonly title: string;
  readonly fix: string;
  /** Gray's own problem: Gray's operators were alerted and the relay waits; the relay's: Retry after the fix. */
  readonly side: "relay" | "gray";
}

export const BOOT_FAILURE_WORDS: Readonly<Record<BootFailureClass, FailureWords>> = {
  token_service: {
    title: "Your VM could not get its pull token from your token service.",
    fix: "Is gray-assistant run up? Check that it is running and that its token URL answers from the internet (gray-assistant doctor), then retry the boot.",
    side: "relay",
  },
  // The code's own words (TOKEN_SERVICE_CODE_WORDS) replace these whenever the boot event names a known code.
  token_refused: {
    title: "Your token service refused this boot.",
    fix: "gray-assistant's log names the refusal (pull_token_refused); fix what it names, then retry the boot.",
    side: "relay",
  },
  relay_registry: {
    title: "Your VM could not pull your image from your registry.",
    fix: "Check the registry token gray-assistant hands out (gray-assistant doctor) and that the image digest you chose exists, then retry the boot.",
    side: "relay",
  },
  relay_image: {
    title: "Your VM refused the image your token service named.",
    fix: "Check gray-assistant stack status: the current image must be one of stack.relay_images, signed by your relay key, and declare no VOLUME (the integration standard, section 5). Roll out a fixed image, then retry the boot.",
    side: "relay",
  },
  gray_registry: {
    title: "Your VM could not pull Gray's own images.",
    fix: "This is on Gray's side and Gray's operators have been told. You do not need to do anything; retry once Gray says it is fixed.",
    side: "gray",
  },
  gray_platform: {
    title: "Your VM's start-up check failed on Gray's side.",
    fix: "Gray's operators have been told. Retry the boot; if it fails the same way, wait for Gray.",
    side: "gray",
  },
  timeout: {
    title: "Your VM did not finish starting in time.",
    fix: "Retry the boot. If it stops at the same step again, the timeline shows where.",
    side: "relay",
  },
};

/**
 * A token-service code in plain words: the title says what holds or stopped the boot, `fix` the one action that clears
 * it, `side` whose action it is, `command` the relay's command for it when there is one (shown as a command the
 * operator copies; `<…>` is theirs to fill), and `waits`: whether a boot it holds keeps waiting for the fix (the
 * token service answers it 503, so pre-launch retries and the boot goes on once it is fixed, no restart).
 */
export interface TokenServiceWords extends FailureWords {
  readonly command: string | null;
  readonly waits: boolean;
}

const gray = (title: string, fix = "This is on Gray's side and Gray's operators have been told. You do not need to do anything; retry once Gray says it is fixed."): TokenServiceWords => ({
  title,
  fix,
  side: "gray",
  command: null,
  waits: false,
});

export const TOKEN_SERVICE_CODE_WORDS: Readonly<Record<TokenServiceCode, TokenServiceWords>> = {
  method_not_allowed: gray("Your VM's start-up asked your token service the wrong way."),
  request_too_large: gray("Your VM's start-up sent your token service a request it does not take."),
  request_invalid: gray("Your VM's start-up sent your token service a request it does not take."),
  spki_invalid: gray("Your VM's start-up sent your token service a key it does not take."),
  challenge_capacity: {
    title: "Your token service is answering too many boots at once.",
    fix: "The boot asks again by itself. If it keeps happening, check that only your own VM calls your token service.",
    side: "relay",
    command: null,
    waits: true,
  },
  registry_credential_expired: {
    title: "The registry token gray-assistant hands out has expired.",
    fix: "Make a new read-only pull token, put it in stack.registry.password_file, set stack.registry.expires_at and restart gray-assistant. The waiting boot then goes on.",
    side: "relay",
    command: "gray-assistant doctor",
    waits: true,
  },
  relay_image_unlisted: {
    title: "This image is not in your relay_images list.",
    fix: "Add it to stack.relay_images and restart gray-assistant, then run gray-assistant stack rollout with it. The waiting boot then goes on.",
    side: "relay",
    command: "gray-assistant stack rollout <image>",
    waits: true,
  },
  verifier_busy: {
    title: "Your token service was checking another boot.",
    fix: "The boot asks again by itself; nothing to do.",
    side: "relay",
    command: null,
    waits: true,
  },
  nonce_unknown: {
    title: "Your token service did not know the boot's challenge.",
    fix: "gray-assistant restarted between the boot's two calls. Keep gray-assistant running while the VM starts, then retry the boot.",
    side: "relay",
    command: null,
    waits: false,
  },
  nonce_used: gray("The boot's challenge was used twice.", "Retry the boot. If it happens again, Gray's operators look at it."),
  nonce_expired: {
    title: "The boot's challenge expired before it asked for its token.",
    fix: "Retry the boot. If it happens again, check that gray-assistant's host is not overloaded (gray-assistant doctor).",
    side: "relay",
    command: null,
    waits: false,
  },
  quote_invalid: gray("Your token service could not verify the VM's attestation."),
  tee_not_tdx: gray("Your token service found the VM is not an Intel TDX VM."),
  tcb_not_up_to_date: gray("The VM's host is not on Intel's current security level."),
  event_log_invalid: gray("Your token service could not read the VM's measurements."),
  rtmr3_mismatch: gray("The VM's measurements do not match its attestation."),
  event_log_after_system_ready: gray("The VM asked for its token after its start-up was sealed."),
  stack_identity_missing: gray("The VM did not measure which relay it serves."),
  stack_identity_invalid: gray("The VM measured an unreadable relay identity."),
  stack_identity_mismatch: {
    title: "The VM was deployed for another relay key or token address than gray-assistant has.",
    fix: "If you paired gray-assistant again after Deploy, Deploy again; otherwise check stack.token_url (gray-assistant doctor).",
    side: "relay",
    command: "gray-assistant doctor",
    waits: false,
  },
  report_data_mismatch: gray("The VM's attestation is not bound to this boot."),
  compose_hash_mismatch: gray("The VM's start-up document does not match its measurement."),
  release_list_unavailable: {
    title: "gray-assistant cannot read Gray's release list.",
    fix: "Check that gray-assistant's host reaches the internet (gray-assistant doctor, release_list). If it does, the problem is on Gray's side. The waiting boot then goes on.",
    side: "relay",
    command: "gray-assistant doctor",
    waits: true,
  },
  compose_not_listed: gray("The VM runs a Gray release your release list does not name."),
  release_rejected: {
    title: "You rejected the Gray release this VM runs.",
    fix: "Accept it on your relay's page under Releases, or on the host, then retry the boot.",
    side: "relay",
    command: "gray-assistant releases accept <compose hash>",
    waits: false,
  },
  release_not_accepted: {
    title: "This Gray release waits for your acceptance.",
    fix: "Accept it on your relay's page under Releases, or on the host. The waiting boot then goes on.",
    side: "relay",
    command: "gray-assistant releases accept <compose hash>",
    waits: true,
  },
  os_image_missing: gray("The VM's OS image is not in Gray's release list."),
  os_image_not_listed: gray("The VM's OS image is not in Gray's release list."),
  os_image_rejected: {
    title: "You rejected the VM's OS image.",
    fix: "Accept it on your relay's page under Releases, or on the host, then retry the boot.",
    side: "relay",
    command: "gray-assistant releases accept <os image hash>",
    waits: false,
  },
  os_image_dev: gray("The VM runs a development OS image."),
  os_image_unverified: gray("The VM's OS image could not be verified."),
  os_image_not_accepted: {
    title: "The VM's OS image waits for your acceptance.",
    fix: "Accept it on your relay's page under Releases, or on the host. The waiting boot then goes on.",
    side: "relay",
    command: "gray-assistant releases accept <os image hash>",
    waits: true,
  },
  os_image_retiring: gray("The VM's OS image is being retired."),
  os_image_measurements: gray("The VM's measurements are not those Gray's release list names."),
  app_id_mismatch: {
    title: "The VM is not the lane instance gray-assistant holds.",
    fix: "gray-assistant takes the instance from Gray after Deploy (gray-assistant doctor, stack_instance); a config with stack.instance \"config\" names it in lane.instances.",
    side: "relay",
    command: "gray-assistant doctor",
    waits: false,
  },
  key_provider_mismatch: {
    title: "The VM took its keys from another key service than gray-assistant expects.",
    fix: "gray-assistant takes the instance from Gray after Deploy (gray-assistant doctor, stack_instance); a config with stack.instance \"config\" names it in lane.instances.",
    side: "relay",
    command: "gray-assistant doctor",
    waits: false,
  },
  release_not_stack: gray("The VM runs a Gray release that is not for relay VMs."),
  pre_launch_not_pinned: {
    title: "stack.pre_launch_sha256 in your config pins another start-up script.",
    fix: "Remove stack.pre_launch_sha256 or set it to this release's, restart gray-assistant, then retry the boot.",
    side: "relay",
    command: null,
    waits: false,
  },
  app_compose_refused: gray("Your token service refused the VM's start-up document."),
  issue_record_failed: {
    title: "gray-assistant could not write its pull-token record.",
    fix: "Check the disk and the directory of stack.issue_log on gray-assistant's host. The waiting boot then goes on.",
    side: "relay",
    command: "gray-assistant doctor",
    waits: true,
  },
};

/** What gray-assistant runs after its image is changed (deploy/relay/GUIDE.en.md section 10, "Limits and updates"). */
export const KIT_UPGRADE_COMMAND = "docker compose up -d";

/**
 * The version of a published kit archive from its URL: deploy/relay/kit/publish.sh names every archive
 * `gray-assistant-kit-<version>.tar.gz` and refuses one whose VERSIONS says another kit, so the file name is the version.
 * The kits up to 1.1.1 were published under the program's old name (gray-relay-kit-1.1.1.tar.gz) and stay there.
 * Null when the name is not that form or the version is not semver (node-semver, strict).
 */
export function publishedKitVersionOf(url: string): string | null {
  let name: string;
  try {
    name = new URL(url).pathname.split("/").at(-1) ?? "";
  } catch {
    return null;
  }
  const m = /^gray-(?:assistant|relay)-kit-(.+)\.tar\.gz$/.exec(name);
  return m === null ? null : semver.valid(m[1]!);
}

/** The gray-assistant Gray publishes (RELAY_KIT_URL's kit, LANE_STACK_AGENT_IMAGE's image): what an old relay upgrades to. */
export interface PublishedKitRef {
  readonly version: string;
  readonly image: string;
  readonly url: string;
}

/**
 * `kit_outdated`'s words (docs/design/relay-outbound-only.md decision R10). With the needed kit known:
 * - Gray publishes a kit at or above it: the relay upgrades to exactly that one (its image in the compose file, then
 *   the guide's `docker compose up -d`, deploy/relay/GUIDE.en.md section 10), on its side;
 * - Gray has not published one yet (the published kit is below the minimum, or none is configured): nothing the relay
 *   can do, Deploy waits for Gray, which is Gray's side; it is never told to upgrade to a kit that does not exist.
 * Without it (a failed operation's words, which know neither), the general words.
 */
export function kitOutdatedWords(needed: string | null, published: PublishedKitRef | null): FailureWords {
  const title = "Your gray-assistant is too old for this Gray release.";
  if (needed === null) {
    return { title, fix: "This release's VM has no public address; only a newer gray-assistant reaches it, through Gray's entry. Upgrade gray-assistant to the kit Gray publishes (your relay's VM page names its image), then Deploy.", side: "relay" };
  }
  if (published === null || !kitAtLeast(published.version, needed)) {
    return {
      title: "Gray has not published the gray-assistant this release needs yet.",
      fix: `This release's VM has no public address, and only gray-assistant ${needed} or later reaches it. Gray has not published that gray-assistant yet, so Deploy waits for it; there is nothing to do on your side now.`,
      side: "gray",
    };
  }
  return {
    title,
    fix:
      `This release's VM has no public address; only gray-assistant ${needed} or later reaches it, through Gray's entry. Upgrade to the kit Gray publishes, ${published.version}: ` +
      `on your gray-assistant host, set gray-assistant's image in its compose file to ${published.image}, then run ${KIT_UPGRADE_COMMAND} in its directory ` +
      `(the signed kit: ${published.url}; the relay guide, section 10 "Limits and updates"). gray-assistant reports its version within a minute; then Deploy.`,
    side: "relay",
  };
}

/** A step's own failures the provisioner names (closed codes), each with its words for the panel. */
export const STEP_FAILURE_WORDS: Readonly<Record<string, FailureWords>> = {
  not_admitted: { title: "Your workspace is not an approved supplier yet.", fix: "Gray reviews supplier applications; Deploy works once yours is approved.", side: "gray" },
  no_quota: { title: "Your relay has no VM quota.", fix: "Ask Gray for a VM on the relay's VM page; Gray's operators decide it.", side: "gray" },
  quota_used: { title: "Your relay's VM quota is used.", fix: "Delete the VM you have, or ask Gray for more quota.", side: "gray" },
  no_profile: { title: "Gray has no release published for relay VMs yet.", fix: "Gray's operators publish one; nothing to do on your side.", side: "gray" },
  // Relay standard v1.7 item 9: a wait, not a failure. The VM is not made until gray-assistant reports the release accepted.
  release_not_accepted: {
    title: "Your relay has not accepted the Gray release the VM would run.",
    fix: "Accept it on your relay's page under Releases, or on the relay's host (gray-assistant releases accept <compose hash>). gray-assistant reports it within a minute; then Deploy.",
    side: "relay",
  },
  // A wait too: Gray has no list of the relay's accepted releases since it paired. gray-assistant sends one with its first
  // report after it starts (relay-kit run.ts, at most AGENT_STATUS_FIRST_WAIT_MS); not a refusal of the release.
  release_unreported: {
    title: "gray-assistant has not yet told Gray which Gray releases it accepts.",
    fix: "gray-assistant sends that in its first report, within a minute of starting (docker compose up -d in its kit directory); gray-assistant doctor's agent_status line says whether Gray took it. Then Deploy.",
    side: "relay",
  },
  relay_incomplete: { title: "Your relay record is missing what the VM needs.", fix: "Pair gray-assistant with this relay and fill in its image and registry under Settings.", side: "relay" },
  // docs/design/relay-outbound-only.md decision R10: a VM of this release has no public address, and only a gray-assistant
  // with the tunnel transport reaches it; an older one could not renew the VM's lease and its accounts would stop.
  kit_outdated: kitOutdatedWords(null, null),
  phala_refused: { title: "The cloud provider refused the request.", fix: "Gray's operators have been told. Retry later.", side: "gray" },
  phala_unavailable: { title: "The cloud provider did not answer.", fix: "Retry in a few minutes.", side: "gray" },
  kms_untrusted: { title: "The VM landed on a key service Gray does not trust.", fix: "Gray's operators have been told; nothing was started. Retry later.", side: "gray" },
  dns_failed: { title: "The lane's DNS records could not be written.", fix: "Gray's operators have been told. Retry later.", side: "gray" },
  no_vm: { title: "There is no VM to restart.", fix: "Deploy first.", side: "relay" },
  busy: { title: "Another Deploy, Restart or Delete is still running.", fix: "Wait for it to finish; the timeline shows its progress.", side: "relay" },
  internal: { title: "Something failed on Gray's side.", fix: "Gray's operators have been told. Retry later.", side: "gray" },
};

// ------------------------------------------------------------------------------------------------- containers (P8)

/**
 * One container as the guest agent lists it (dstack GuestApi.ListContainers, which Phala relays to the app's owner as
 * `GET /cvms/{id}/composition`): docker's `state` and `status` strings. Nothing else is kept (no image, no command).
 */
export interface ContainerObservation {
  readonly service: string;
  readonly state: string;
  /** The exit code docker's status names (`Exited (137) …`, `Restarting (1) …`), else null. */
  readonly exitCode: number | null;
}

/** The services the timeline and the crash-loop rule know (`acme`: releases before D133); any other container is not reported. */
export const STACK_SERVICES = ["acme", "egress", "isolation-check", "lane", "relay"] as const;
/** The one-shot services (restart: "no"), whose exit with 0 is their job done. */
export const ONE_SHOT_SERVICES: readonly string[] = ["acme", "isolation-check"];

/** The stack's containers from a composition answer's `containers` (names `gray-lane-<service>-1`, `/`-prefixed or not). */
export function containersOf(containers: unknown): ContainerObservation[] {
  if (!Array.isArray(containers)) return [];
  const out: ContainerObservation[] = [];
  for (const c of containers) {
    if (c === null || typeof c !== "object") continue;
    const names = (c as { names?: unknown }).names;
    const first = Array.isArray(names) && typeof names[0] === "string" ? names[0].replace(/^\//, "") : null;
    const match = first === null ? null : /^gray-lane-(.+)-\d+$/.exec(first);
    const service = match?.[1];
    if (service === undefined || !(STACK_SERVICES as readonly string[]).includes(service)) continue;
    const state = typeof (c as { state?: unknown }).state === "string" ? (c as { state: string }).state.toLowerCase() : "unknown";
    const status = typeof (c as { status?: unknown }).status === "string" ? (c as { status: string }).status : "";
    const code = /^(?:Exited|Restarting) \((-?\d+)\)/.exec(status);
    out.push({ service, state: /^[a-z]{1,16}$/.test(state) ? state : "unknown", exitCode: code === null ? null : Number(code[1]) });
  }
  return out.sort((a, b) => a.service.localeCompare(b.service));
}

/**
 * The crash-loop rule over a service's last observations (newest last): a long-running service that is `restarting`,
 * or `exited` with a code other than 0, in each of the last `CRASH_LOOP_OBSERVATIONS`. Docker restarts an
 * `unless-stopped` container with a doubling delay up to a minute, so a looping container is seen restarting or exited
 * at most polls; the relay's one exit on a configuration change (S21) is a single observation and does not count.
 */
export const CRASH_LOOP_OBSERVATIONS = 3;

export function crashLooping(service: string, history: readonly ContainerObservation[]): boolean {
  if (ONE_SHOT_SERVICES.includes(service)) return false;
  const last = history.filter((o) => o.service === service).slice(-CRASH_LOOP_OBSERVATIONS);
  return last.length === CRASH_LOOP_OBSERVATIONS && last.every((o) => o.state === "restarting" || (o.state === "exited" && o.exitCode !== 0));
}

// ------------------------------------------------------------------------------------------------- relay alerts (P10)

export const RELAY_ALERT_WORDS: Readonly<Record<RelayAlertKind, { readonly title: string; readonly resolved: string }>> = {
  boot_failed: { title: "Your relay VM failed to start", resolved: "Your relay VM started" },
  registry_token_expiring: { title: "Your registry token expires within 14 days", resolved: "Your registry token was renewed" },
  release_list_stale: { title: "Gray's release list is out of date", resolved: "Gray's release list is current again" },
  release_pending: { title: "A Gray release is waiting for your decision", resolved: "No Gray release is waiting for you" },
  container_crash_loop: { title: "A container in your relay VM keeps restarting", resolved: "The containers in your relay VM are running" },
  account_health: { title: "Accounts in your relay need attention", resolved: "Your relay's accounts are healthy again" },
  lease_expiring: { title: "Your VM's credential lease hasn't been renewed", resolved: "gray-assistant renewed your VM's credential lease" },
  relay_ejected: { title: "Gray took your relay out of routing", resolved: "Gray put your relay back into routing" },
  relay_violation: { title: "Gray found your relay changing a request or an answer", resolved: "Gray closed its report of a change by your relay" },
};

// ------------------------------------------------------------------------------------------------- the store's RPC (P3)

/** The deployment's columns the provisioner writes (and the plan carries back to it). */
export const DEPLOYMENT_FIELDS = [
  "profile_id",
  "compose_hash",
  "app_id",
  "app_name",
  "cvm_id",
  "vm_uuid",
  "kms_slug",
  "kms_url",
  "kms_k256_pubkey",
  "kms_ca_pubkey",
  "app_env_encrypt_pubkey",
  "instance_type",
  "image_os",
  "lane_key_id",
  "boot_id",
  "boot_started_ms",
  // docs/design/relay-zero-downtime.md (migration 0058): during a rollout, the app's new instance until `shift` moves the
  // deployment to it; after it, the old instance until `remove_old` deletes it.
  "next_cvm_id",
  "next_vm_uuid",
  "next_lane_key_id",
  "retiring_cvm_id",
  "retiring_vm_uuid",
  "retiring_lane_key_id",
  "retiring_since_ms",
] as const;
export type DeploymentField = (typeof DEPLOYMENT_FIELDS)[number];
/** The deployment fields that are milliseconds; every other one is text. */
export type DeploymentTimeField = "boot_started_ms" | "retiring_since_ms";
export type DeploymentRecord = { readonly state: DeploymentState } & { readonly [K in DeploymentField]: K extends DeploymentTimeField ? number | null : string | null };

// ------------------------------------------------------------------------------------------------- outbound-only VMs

/**
 * How Gray reaches a relay's VM (docs/design/relay-outbound-only.md section 6): `origin`, today's VM with a public name
 * and certificate that the entry dials, or `outbound`, a VM that takes no inbound connection and dials the entry itself
 * (peerlink). It is read from the release's measured app-compose, never declared beside it, so it cannot disagree with
 * what the VM is: a compose that turns the dstack gateway off, or restricts its ports to none (section 13 item 1's
 * fallback), takes no inbound connection. Anything else, an unreadable compose included, is `origin`.
 */
export type StackChannel = "origin" | "outbound";

export function composeChannelOf(appCompose: string): StackChannel {
  let app: unknown;
  try {
    app = parsePlain(appCompose);
  } catch {
    return "origin";
  }
  if (app === null || typeof app !== "object" || Array.isArray(app)) return "origin";
  const a = app as Record<string, unknown>;
  if (a.gateway_enabled === false) return "outbound";
  const policy = a.port_policy as { restrict_mode?: unknown; ports?: unknown } | null | undefined;
  return policy !== null && typeof policy === "object" && policy.restrict_mode === true && Array.isArray(policy.ports) && policy.ports.length === 0 ? "outbound" : "origin";
}

/** The entry's tunnel route (section 5): gray-assistant's lane origin for an outbound relay, `<entry>/v1/peer/tunnel/<relay>`. */
export { PEER_TUNNEL_PATH };

export function tunnelOriginOf(entryOrigin: string, relayId: string): string {
  return `${entryOrigin}${PEER_TUNNEL_PATH}${relayId}`;
}

/** The entry's public health route of a relay (section 5, R4): the VM's /healthz through its pinned session. */
export function entryHealthUrlOf(entryOrigin: string, relayId: string): string {
  return `${entryOrigin}/v1/peer/relays/${relayId}/healthz`;
}

/** The entry's boots route of a relay (docs/design/relay-zero-downtime.md): every boot with a session, newest first. */
export function entryBootsUrlOf(entryOrigin: string, relayId: string): string {
  return `${entryOrigin}/v1/peer/relays/${relayId}/boots`;
}

/** One boot of a relay as the entry's boots route answers it: what a rollout's watch and drain read. */
export interface EntryBoot {
  readonly keyset: string;
  /** The boot's dstack app id, null before the entry attested it. */
  readonly appId: string | null;
  /** The boot's dstack instance id (one VM of the app), null before the entry attested it. */
  readonly instanceId: string | null;
  /** Open streams on its sessions at the entry: requests in flight and tunnels. */
  readonly streams: number;
  /** Pinned, usable and holding the relay's sealed credentials: it takes new requests first. */
  readonly ready: boolean;
}

/** The boots of a boots-route answer (`{relay_id, boots: [...]}`), or null for an answer that is not one. */
export function entryBootsOf(value: unknown, relayId: string): EntryBoot[] | null {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return null;
  const v = value as { relay_id?: unknown; boots?: unknown };
  if (v.relay_id !== relayId || !Array.isArray(v.boots)) return null;
  const out: EntryBoot[] = [];
  for (const row of v.boots) {
    if (row === null || typeof row !== "object") return null;
    const b = row as { keyset?: unknown; app_id?: unknown; instance_id?: unknown; streams?: unknown; ready?: unknown };
    const streams = typeof b.streams === "bigint" ? Number(b.streams) : b.streams;
    if (typeof b.keyset !== "string" || !/^[0-9a-f]{64}$/.test(b.keyset)) return null;
    if (b.app_id !== null && (typeof b.app_id !== "string" || !/^[0-9a-f]{40}$/.test(b.app_id))) return null;
    // An entry from before instance ids answers none: the boot's instance is unknown, not refused.
    const instanceId = typeof b.instance_id === "string" && /^[0-9a-f]{40}$/.test(b.instance_id) ? b.instance_id : null;
    if (typeof streams !== "number" || !Number.isSafeInteger(streams) || streams < 0 || typeof b.ready !== "boolean") return null;
    out.push({ keyset: b.keyset, appId: b.app_id, instanceId, streams, ready: b.ready });
  }
  return out;
}

/**
 * The kit gate (section 9 step 3, decision R10): whether gray-assistant's reported `agent_version` is at or above `minimum`
 * (`major.minor.patch`, LANE_STACK_OUTBOUND_MIN_KIT). Compared as semver: the three numbers in order, and a pre-release
 * of the minimum itself (`1.1.0-rc.1`) is below it; build metadata is ignored. A version that does not start with three
 * numbers, or none at all, is below every minimum: the relay must report a kit Gray can read before its VM moves.
 */
export function kitAtLeast(version: string | null, minimum: string): boolean {
  // node-semver (npm's own parser), strict: `1.1` or `dev` is no version; `semver.gte` orders pre-releases below their
  // release and ignores build metadata, as semver.org 2.0.0 section 11 says.
  const want = semver.valid(minimum);
  if (want === null) throw new Error(`${minimum} is not a kit version`);
  const have = version === null ? null : semver.valid(version);
  return have !== null && semver.gte(have, want);
}

/** What the provisioner's first step reads for one operation (the ProvisionerStore `plan`). */
export interface ProvisionPlan {
  readonly opId: string;
  readonly kind: ProvisionKind;
  /** A member's user id, or `relay-signed:<request id>` for a restart the relay signed (S53). */
  readonly requestedBy: string;
  readonly relayId: string;
  readonly workspaceId: string;
  /** `{relay}` for the profile's templates (@gray/control/stack-provision `relayLabel`). */
  readonly relayLabel: string;
  readonly deployment: DeploymentRecord;
  readonly profile: {
    readonly profileId: string;
    readonly appCompose: string;
    readonly composeHash: string;
    readonly env: Readonly<Record<string, ProvisionEnvValue>>;
    readonly allowedEnvs: readonly string[];
    readonly kmsCaPubkey: string;
    /**
     * The Phala KMS to provision on (`kms_…`, the profile's `kms_id`), sent as `kms_id`. Null for a profile published
     * before 2026-11-07 (migration 0054): no selector is sent, and the landed KMS's CA check decides.
     */
    readonly kmsId: string | null;
    readonly laneKeyId: string;
    readonly instanceType: string;
    readonly imageOs: string;
    /**
     * Relay standard v1.7 item 9: the relay's latest signed agent status lists this profile's compose hash
     * (`accepted_compose`). The console plans only an accepted profile; the provisioner refuses `release_not_accepted`
     * before any VM is made for a plan that does not say so.
     */
    readonly accepted: boolean;
  } | null;
  readonly relay: { readonly tokenUrl: string | null; readonly registry: string | null; readonly signingPublicKey: string | null };
  readonly quota: { readonly payer: "gray" | "relay"; readonly instanceType: string | null } | null;
  /**
   * How the VM is reached (`composeChannelOf`): a deploy's from its profile, a restart's or delete's from the deployed
   * release. Absent (a console from before it): `origin`.
   */
  readonly channel?: StackChannel;
  /** LANE_STACK_ENTRY_ORIGIN: the entry an outbound VM's health and gray-assistant's tunnel go through; null when unset. */
  readonly entryOrigin?: string | null;
}

export type PlanAnswer = { readonly ok: true; readonly plan: ProvisionPlan } | { readonly ok: false; readonly code: string };

/** One step outcome on the operation's audit (lane_stack_provision_steps). */
export type StepOutcome = "started" | "done" | "skipped" | "retrying" | "failed";

/** A boot event as the store takes it. */
export interface BootEventRow {
  readonly event: BootEvent;
  readonly at_ms: number;
  readonly uptime_ms: number | null;
  readonly failure_class: BootFailureClass | null;
  readonly step: string | null;
  /** The token service's code (SerialEvent `code`), null for an event that names none. */
  readonly code: TokenServiceCode | "other" | null;
}

/**
 * gray-console's ProvisionerStore entrypoint as gray-provisioner calls it through its CONSOLE service binding
 * (workers/console/src/lane-stack/provisioner-entrypoint.ts): every write names the operation, from which the console
 * reads the relay, so a call cannot reach another relay than its operation's.
 */
export interface ProvisionerStoreRpc {
  claim(input: { readonly limit: number }): Promise<{ readonly queued: readonly string[]; readonly running: readonly { readonly opId: string; readonly startedMs: number }[] }>;
  plan(input: { readonly opId: string }): Promise<PlanAnswer>;
  step(input: { readonly opId: string; readonly step: string; readonly outcome: StepOutcome; readonly detail: Readonly<Record<string, string | number | boolean | null>> }): Promise<void>;
  patchDeployment(input: { readonly opId: string; readonly fields: Partial<Record<DeploymentField, string | number | null>> }): Promise<void>;
  /**
   * Step `unbind` (and a rollout's `remove_old`): the keys the provisioner installed for the deployment's app, or, with
   * `keyId`, that key only (a rollout's old or failed new instance: the other instance of the app keeps its own).
   */
  removeKeys(input: { readonly opId: string; readonly keyId?: string }): Promise<number>;
  /** The relay's instance values (S12): the deployment's tunnel lane origin on publish, null on unpublish. */
  setInstance(input: { readonly opId: string; readonly app_id: string | null; readonly lane_origin: string | null; readonly kms_ca_pubkey: string | null }): Promise<void>;
  installKey(input: { readonly opId: string; readonly keyId: string; readonly publicKey: string; readonly appId: string }): Promise<void>;
  startUsage(input: { readonly opId: string; readonly appId: string; readonly cvmId: string; readonly instanceType: string; readonly payer: "gray" | "relay" }): Promise<void>;
  /** The VM's billing row ends: every open row of the app, or, with `cvmId`, that instance's only. */
  endUsage(input: { readonly opId: string; readonly appId: string; readonly cvmId?: string }): Promise<void>;
  bootEvents(input: { readonly opId: string; readonly bootId: string; readonly events: readonly BootEventRow[] }): Promise<number>;
  /**
   * The operation's end. A failure's `detail` (S58) is the relay token service's code of a boot it refused (class
   * `token_refused`: one of TOKEN_SERVICE_CODES or `other`), else null; the console keeps it as `failure_detail` (0037).
   */
  finish(input: {
    readonly opId: string;
    readonly outcome: "succeeded" | "failed";
    readonly failure: { readonly code: string; readonly class: BootFailureClass | null; readonly step: string | null; readonly detail: TokenServiceCode | "other" | null } | null;
  }): Promise<void>;
  watched(): Promise<readonly { readonly relayId: string; readonly cvmId: string }[]>;
  /**
   * A restart the relay signed (S53, life/image's restart requests): queued as `relay-signed:<request id>`, or the
   * code that refuses it now (`busy`: an operation already runs, which boots the VM with the relay's current image).
   */
  queueSignedRestart(input: { readonly relayId: string; readonly requestId: string; readonly appId: string }): Promise<{ readonly opId: string } | { readonly refused: string }>;
  /**
   * docs/design/relay-release-zero-downtime.md: an `upgrade` queued for each relay (at most `limit`) whose running VM
   * should move to the newest Gray release the relay accepted, when every condition of the move holds.
   */
  queueReleaseMoves(input: { readonly limit: number }): Promise<{ readonly queued: readonly string[] }>;
  containers(input: { readonly relayId: string; readonly online: boolean; readonly containers: unknown }): Promise<{ readonly crashLoop: readonly string[] }>;
}

// ------------------------------------------------------------------------------------------------- the agent channel (P12)

/**
 * The relay's lane instance as Gray's console answers gray-assistant's signed agent status (`POST /v1/lane-stack/agent-
 * status`, member `instance`): the values the provisioner published on the relay's record (S12's `lane.instances`:
 * app id, lane origin, KMS CA key; null until a Deploy, and again after a Delete) and the deployment's state. The
 * answer is not signed: gray-assistant adopts an instance only once the lane at that origin attests with these values
 * (docs/relay-stack-provisioner.md section 9), which is the check the relay's operator's hand copy never made either.
 */
export const stackInstanceAnswerSchema = z
  .object({
    app_id: z.string().regex(/^[0-9a-f]{40}$/).nullable(),
    // A published origin names no port; a test lane's does (deploy/tee/e2e: `https://127.0.0.1:<port>`).
    // An outbound relay's is the entry's tunnel route (docs/design/relay-outbound-only.md section 5), which only a kit with
    // the tunnel transport is given (the kit gate, R10).
    lane_origin: z.string().regex(/^https:\/\/[a-z0-9.-]+(?::[0-9]{1,5})?(\/v1\/peer\/tunnel\/[A-Za-z0-9._:-]{1,128})?$/).nullable(),
    kms_ca_pubkey: z.string().regex(STACK_KMS_CA_PUBKEY_PATTERN).nullable(),
    deployment: z.enum(DEPLOYMENT_STATES),
  })
  .strict();
export type StackInstanceAnswer = z.infer<typeof stackInstanceAnswerSchema>;


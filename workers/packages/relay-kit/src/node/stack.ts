/**
 * `gray-assistant stack rollout|rollback|restart|status` (docs/confidential-lane-supply-implementation.md S53): the relay
 * changes the image its stack app runs without Gray.
 *
 * - `rollout <image>`: the image must be one of `stack.relay_images`. It becomes control.json's
 *   `stack_current_image` (the one it replaces becomes `stack_previous_image`), so the token service names it to
 *   the next boot (the daemon re-reads control.json every tick). A restart request signed with the relay key goes
 *   to Gray (`POST <stack.report_origin>/v1/lane-stack/restart-requests`, the console records it for the
 *   provisioner), and the command waits until the issue log shows a token issued for the image after the request
 *   and the status file shows the stack replica attested on it. Gray runs a request that names an image without
 *   downtime once its console takes it for this kit (docs/design/relay-zero-downtime.md): the image boots in a second
 *   VM of the same app, which the daemon seals beside the one serving; once it serves it takes over, and the first drains and goes.
 *   Otherwise Gray restarts the VM with it.
 * - `rollback`: rolls out `stack_previous_image` again.
 * - `restart`: asks for a restart with the current image (a failed boot); waits the same way.
 * - `status`: the current and previous image, the last issue and the image the attested boot runs.
 *
 * Nothing here contacts the lane: the VM takes its image from the token service at boot. The request carries no
 * secret and the signature covers every member (`@gray/control` `stackRestartRequestMessage`).
 */
import { ed25519Sign, bytesToLowerHex } from "@gray/attest";
import { STACK_RESTART_REQUEST_ID_PATTERN, stackRestartRequestMessage, stackRestartRequestReportSchema, type StackRestartReason, type StackRestartRequest } from "@gray/control";
import { get, isObject, parseStrict, toJsonString, type Json, type JsonObject } from "@gray/json";
import { existsSync, readFileSync } from "node:fs";
import { RelayKitError } from "../errors.ts";
import type { LoadedRelayConfig } from "./config-file.ts";
import { controlFileBeside, inspectControlFile } from "./daemon/control-file.ts";
import { readDaemonStatusFile } from "./daemon/status-file.ts";
import { readControlView, setStackImageState } from "./control.ts";

export const STACK_RESTART_REQUEST_PATH = "/v1/lane-stack/restart-requests";
/**
 * How long `rollout` waits by default: a second VM's boot, its token, its attestation and sealing (or one restart, ~95 s
 * measured, where Gray restarts), with room for a slow image pull.
 */
export const STACK_WAIT_DEFAULT_MS = 15 * 60_000;
const STACK_WAIT_POLL_MS = 5_000;

export interface StackIo {
  readonly stdout: (line: string) => void;
  readonly stderr: (line: string) => void;
  readonly now: () => number;
  readonly random: (length: number) => Uint8Array;
}

/** One POST; the CLI passes global `fetch`, tests a fake. Resolves with the status and the body text. */
export type StackPost = (url: string, body: string) => Promise<{ readonly status: number; readonly text: string }>;

export interface StackCommandOptions {
  readonly config: LoadedRelayConfig;
  readonly seed: Uint8Array;
  readonly io: StackIo;
  readonly wait: boolean;
  readonly timeoutMs?: number;
  readonly post?: StackPost;
  readonly sleep?: (ms: number) => Promise<void>;
}

/**
 * The request a restart sends: a fresh id, the relay's app, why, and the image (null for a plain restart). P7: a phase-2
 * rollout adds this kit's version and the boot box version the VM's receipt named (docs/design/relay-no-always-on-host.md
 * 13.4): Gray gates a rollout without downtime on the one and waits for its copy of the other.
 */
export function stackRestartRequest(input: {
  readonly relayId: string;
  readonly appId: string;
  readonly reason: StackRestartReason;
  readonly image: string | null;
  readonly issuedMs: number;
  readonly random: (length: number) => Uint8Array;
  readonly kit?: string;
  readonly bootVersion?: number;
}): StackRestartRequest {
  const requestId = `r${bytesToLowerHex(input.random(16))}`;
  if (!STACK_RESTART_REQUEST_ID_PATTERN.test(requestId)) throw new RelayKitError("usage", "the request id is not r and 32 hex digits");
  return {
    relay_id: input.relayId,
    request_id: requestId,
    issued_ms: input.issuedMs,
    app_id: input.appId,
    reason: input.reason,
    image: input.image,
    ...(input.kit === undefined ? {} : { kit: input.kit }),
    ...(input.bootVersion === undefined ? {} : { boot_version: input.bootVersion }),
  };
}

/** The signed report body, checked against the console's own schema before it is sent. */
export async function signedStackRestartRequest(request: StackRestartRequest, seed: Uint8Array): Promise<JsonObject> {
  const signature = bytesToLowerHex(await ed25519Sign(seed, stackRestartRequestMessage(request)));
  const body = { request, signature };
  if (!stackRestartRequestReportSchema.safeParse(body).success) throw new RelayKitError("usage", "the restart request is not the console's shape");
  return { request: { ...request, issued_ms: BigInt(request.issued_ms) }, signature };
}

export const defaultPost: StackPost = async (url, body) => {
  const response = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json", "user-agent": "gray-assistant" },
    body,
    redirect: "error",
    signal: AbortSignal.timeout(20_000),
  });
  return { status: response.status, text: await response.text() };
};

const defaultSleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

/** The newest issue of the issue log (`pull-token-log.ts` lines), or null. */
export function lastPullTokenIssue(text: string): { readonly atMs: number; readonly relayImage: string; readonly composeHash: string } | null {
  let last: { atMs: number; relayImage: string; composeHash: string } | null = null;
  for (const line of text.split("\n")) {
    if (line.trim() === "") continue;
    let value: Json;
    try {
      value = parseStrict(line);
    } catch {
      continue;
    }
    if (!isObject(value)) continue;
    const at = get(value, "at");
    const relayImage = get(value, "relay_image");
    const composeHash = get(value, "compose_hash");
    const atMs = typeof at === "string" ? Date.parse(at) : Number.NaN;
    if (!Number.isFinite(atMs) || typeof relayImage !== "string" || typeof composeHash !== "string") continue;
    if (last === null || atMs >= last.atMs) last = { atMs, relayImage, composeHash };
  }
  return last;
}

/** The image the status file says the stack origin's attested boot runs, or null. */
function runningImage(config: LoadedRelayConfig): string | null {
  const stack = config.daemon.stack;
  const snapshot = readDaemonStatusFile(config.daemon.statusFile);
  if (stack === null || snapshot === null) return null;
  // P12: with `stack.instance: "gray"` the stack origin is the adopted instance's (control.json).
  const origin = stack.laneOrigin ?? inspectControlFile(controlFileBeside(config.daemon.stateFile));
  const laneOrigin = typeof origin === "string" ? origin : origin.kind === "ok" ? (origin.control.stackInstance?.laneOrigin ?? null) : null;
  const replicas = get(get(snapshot, "status"), "replicas");
  if (laneOrigin === null || !Array.isArray(replicas)) return null;
  for (const replica of replicas) {
    if (!isObject(replica) || get(replica, "origin") !== laneOrigin) continue;
    const image = get(replica, "relay_image");
    return typeof image === "string" ? image : null;
  }
  return null;
}

function lastIssue(config: LoadedRelayConfig): ReturnType<typeof lastPullTokenIssue> {
  const path = config.daemon.stack?.issueLog;
  return path === undefined || !existsSync(path) ? null : lastPullTokenIssue(readFileSync(path, "utf8"));
}

function stackOf(config: LoadedRelayConfig): NonNullable<LoadedRelayConfig["daemon"]["stack"]> {
  const stack = config.daemon.stack;
  if (stack === null) throw new RelayKitError("usage", "the config has no `stack` section: `gray-assistant stack` is for a relay-stack lane");
  return stack;
}

/** `stack status`: what the token service names, what it names next after a rollback, and what runs. */
export async function stackStatus(options: StackCommandOptions): Promise<number> {
  const stack = stackOf(options.config);
  const view = await readControlView(options.config.daemon.stateFile, controlFileBeside(options.config.daemon.stateFile));
  const current = view.control.stackCurrentImage ?? stack.currentImage;
  const previous = view.control.stackPreviousImage ?? null;
  const issue = lastIssue(options.config);
  const running = runningImage(options.config);
  const io = options.io;
  io.stdout(`relay_id       ${options.config.daemon.relayId}\n`);
  io.stdout(`current_image  ${current}${stack.relayImages.includes(current) ? "" : "   (not in stack.relay_images: boots get no token)"}\n`);
  io.stdout(`previous_image ${previous ?? "-"}\n`);
  io.stdout(`last_issue     ${issue === null ? "-" : `${new Date(issue.atMs).toISOString()} ${issue.relayImage}`}\n`);
  io.stdout(`running_image  ${running ?? "- (no attested stack boot in the status file)"}\n`);
  io.stdout(`${toJsonString({
    command: "stack.status",
    ok: true,
    relay_id: options.config.daemon.relayId,
    current_image: current,
    current_listed: stack.relayImages.includes(current),
    previous_image: previous,
    last_issue: issue === null ? null : { at_ms: BigInt(issue.atMs), relay_image: issue.relayImage, compose_hash: issue.composeHash },
    running_image: running,
  })}\n`);
  return 0;
}

/**
 * `stack rollout <image>`, `stack rollback`, `stack restart`: set the image (not for restart), ask Gray to restart
 * the app, and (unless `--no-wait`) wait for a token issued for it after the request and the boot attested on it.
 */
export async function stackRoll(options: StackCommandOptions, action: "rollout" | "rollback" | "restart", imageArgument: string | null): Promise<number> {
  const config = options.config;
  const stack = stackOf(config);
  const io = options.io;
  const controlFile = controlFileBeside(config.daemon.stateFile);
  const view = await readControlView(config.daemon.stateFile, controlFile);
  const current = view.control.stackCurrentImage ?? stack.currentImage;
  let image: string;
  if (action === "rollout") {
    if (imageArgument === null) throw new RelayKitError("usage", "stack rollout needs the image: one of stack.relay_images");
    image = imageArgument;
  } else if (action === "rollback") {
    const previous = view.control.stackPreviousImage;
    if (previous === undefined) throw new RelayKitError("usage", "stack rollback: control.json names no previous image (nothing was rolled out yet)");
    image = previous;
  } else {
    image = current;
  }
  if (!stack.relayImages.includes(image)) {
    throw new RelayKitError("usage", `stack ${action}: ${image} is not one of stack.relay_images; add it to the config first (the token service names only those)`);
  }
  if (action !== "restart") {
    await setStackImageState(controlFile, config.daemon.stateFile, image, stack.currentImage);
    io.stdout(`gray-assistant stack ${action}: the token service names ${image} from the next boot on (was ${current})\n`);
  }

  // P12: the app is the config's, or with `stack.instance: "gray"` the one adopted from Gray (control.json).
  const appId = stack.instance?.appId ?? view.control.stackInstance?.appId ?? null;
  if (appId === null) {
    throw new RelayKitError("usage", `stack ${action}: no stack app adopted yet: gray-assistant takes it from Gray after a Deploy once the VM's quote proves it (gray-assistant doctor, stack_instance)${action === "restart" ? "" : "; the image is set for the first boot"}`);
  }
  const requestedMs = io.now();
  const request = stackRestartRequest({
    relayId: config.daemon.relayId,
    appId,
    reason: action,
    image: action === "restart" ? null : image,
    issuedMs: requestedMs,
    random: io.random,
  });
  const body = await signedStackRestartRequest(request, options.seed);
  const url = `${stack.reportOrigin}${STACK_RESTART_REQUEST_PATH}`;
  let answer: { readonly status: number; readonly text: string };
  try {
    answer = await (options.post ?? defaultPost)(url, toJsonString(body));
  } catch {
    io.stderr(`gray-assistant stack ${action}: the restart request did not reach ${url}; the image is set, so a restart of the app by any other means takes it\n`);
    io.stdout(`${toJsonString({ command: `stack.${action}`, ok: false, relay_id: config.daemon.relayId, image, request_id: request.request_id, code: "restart_request_unsent" })}\n`);
    return 1;
  }
  if (answer.status !== 200 && answer.status !== 202) {
    const code = errorCodeOf(answer.text);
    io.stderr(`gray-assistant stack ${action}: Gray refused the restart request (${answer.status}${code === null ? "" : ` ${code}`})\n`);
    io.stdout(`${toJsonString({ command: `stack.${action}`, ok: false, relay_id: config.daemon.relayId, image, request_id: request.request_id, code: code ?? `http_${answer.status}` })}\n`);
    return 1;
  }
  io.stdout(`gray-assistant stack ${action}: restart request ${request.request_id} recorded by Gray\n`);
  if (!options.wait) {
    io.stdout(`${toJsonString({ command: `stack.${action}`, ok: true, relay_id: config.daemon.relayId, image, request_id: request.request_id, waited: false })}\n`);
    return 0;
  }

  const timeoutMs = options.timeoutMs ?? STACK_WAIT_DEFAULT_MS;
  const deadline = requestedMs + timeoutMs;
  const sleep = options.sleep ?? defaultSleep;
  let issued = false;
  for (;;) {
    const issue = lastIssue(config);
    if (!issued && issue !== null && issue.atMs >= requestedMs && issue.relayImage === image) {
      issued = true;
      io.stdout(`gray-assistant stack ${action}: the restarted boot got its token for ${image}\n`);
    }
    if (issued && runningImage(config) === image) {
      io.stdout(`gray-assistant stack ${action}: the lane attests ${image}\n`);
      io.stdout(`${toJsonString({ command: `stack.${action}`, ok: true, relay_id: config.daemon.relayId, image, request_id: request.request_id, waited: true })}\n`);
      return 0;
    }
    if (io.now() >= deadline) {
      const stage = issued ? "the boot got its token but the lane does not attest the image yet" : "no boot asked for a token since the request";
      io.stderr(`gray-assistant stack ${action}: timed out after ${Math.round(timeoutMs / 1000)} s: ${stage}; \`gray-assistant stack status\` shows where it stands\n`);
      io.stdout(`${toJsonString({ command: `stack.${action}`, ok: false, relay_id: config.daemon.relayId, image, request_id: request.request_id, code: issued ? "not_attested" : "not_issued" })}\n`);
      return 1;
    }
    await sleep(Math.min(STACK_WAIT_POLL_MS, Math.max(1, deadline - io.now())));
  }
}

/** The console's error code (`{"error": {"code": …}}`), or null. Only a lower-case word is printed. */
function errorCodeOf(text: string): string | null {
  try {
    const value = parseStrict(text);
    const error = get(value, "error");
    const code = isObject(error) ? get(error, "code") : error;
    return typeof code === "string" && /^[a-z0-9_]{1,64}$/.test(code) ? code : null;
  } catch {
    return null;
  }
}

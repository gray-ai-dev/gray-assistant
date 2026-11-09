/**
 * `gray-assistant debug get <request id> [--out <file>]` (docs/design/relay-debug-sharing.md §6): the record the relay's
 * container kept of one request, after the customer authorized it for debugging.
 *
 * Once a customer authorizes one of their requests with the API key that made it, the relay's stack VM takes that
 * request's record out of the container and holds it in memory for at most 24 hours. This command asks the VM for it:
 *
 * 1. It finds the stack VM's origin as `stack status` does (the config's `stack.lane_origin`, or with
 *    `stack.instance: "gray"` the instance control.json adopted) and attests it the way the agent does before it
 *    talks to a replica: the daemon's attestation (`createDaemonAttest`: the quote, the replay, the signed release list,
 *    the instance), then the daemon's own checks of the boot (`../daemon/stack-boot.ts`: this relay's identity and an
 *    image this agent issued to that boot).
 * 2. It signs a request with the relay key, naming the request and a fresh X25519 reply key
 *    (`@gray/relay-connector` `debugRequestValue`), and posts it to `<origin>/v1/aci/relay-debug` through the same
 *    pinned fetch the agent uses: Gray's entry carries the TLS session to the VM, pinned to the key the VM attested.
 * 3. The VM answers the record HPKE-sealed to the reply key; the command opens it here (`openDebugAnswer` checks the
 *    record's size and SHA-256 against the answer's metadata) and writes it to `--out` (created 0600, never over an
 *    existing file) or to stdout when stdout is not a terminal. Gray's entry only ever carries ciphertext.
 *
 * stderr gets one JSON line of the record's metadata, never the record. A refusal (an unattested VM, a record the VM
 * does not hold, a VM that refused the request) prints a sentence and a JSON line with its code and exits 1; usage and
 * I/O errors exit 2.
 */
import { lstatSync, statSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { bytesToLowerHex, ed25519PublicKey } from "@gray/attest";
import { get, isObject, parseStrictBytes, toJsonString, type Json, type JsonObject } from "@gray/json";
import { debugReplyKey, debugRequestValue, openDebugAnswer, RELAY_DEBUG_MAX_SKEW_SECONDS, RELAY_DEBUG_PATH, RELAY_DEBUG_RECORD_MAX_BYTES, RELAY_DEBUG_REQUEST_ID_PATTERN, type RelayDebugMeta } from "@gray/relay-connector";
import { attestationMismatch, stackBootDecision } from "../daemon/stack-boot.ts";
import { DaemonTransportError, type DaemonAttestResult, type DaemonFetch, type StackIssueRecord } from "../daemon/types.ts";
import { RelayKitError } from "../errors.ts";
import type { LaneBinding } from "../lane-binding.ts";
import { tunnelOriginOf } from "../lane-origin.ts";
import type { LoadedRelayConfig } from "./config-file.ts";
import { controlFileBeside, inspectControlFile } from "./daemon/control-file.ts";
import { writePrivateFile } from "./files.ts";

/** The answer is the record in hex, twice its size, plus its metadata and the HPKE framing. */
const DEBUG_ANSWER_MAX_BYTES = 2 * RELAY_DEBUG_RECORD_MAX_BYTES + 64 * 1024;

export interface DebugIo {
  readonly stderr: (line: string) => void;
  readonly now: () => number;
  /** Whether stdout is a terminal: the record is never written to one. */
  readonly stdoutIsTTY: boolean;
  /** Writes the record to stdout, when there is no `--out`. */
  readonly stdoutBytes: (bytes: Uint8Array) => Promise<void>;
}

/** One attestation of the stack VM; the CLI's fetches the signed release list and loads the quote verifier first. */
export type DebugAttest = (input: { readonly origin: string; readonly instance?: LaneBinding; readonly nowSecs: bigint }) => Promise<DaemonAttestResult>;

export interface DebugGetOptions {
  readonly config: LoadedRelayConfig;
  /** The relay key's seed. */
  readonly seed: Uint8Array;
  readonly requestId: string;
  /** `--out`, or null for stdout. */
  readonly out: string | null;
  readonly io: DebugIo;
  /** Tests replace the attestation, the pinned fetch and the pull-token record; the CLI passes none. */
  readonly attest?: DebugAttest;
  readonly fetch?: DaemonFetch;
  readonly stackIssue?: (nonce: string) => Promise<StackIssueRecord | null>;
}

/** A usage error unless `id` is a request id the VM can name: the customer's `x-request-id` or the container's rid. */
export function checkDebugRequestId(id: string): void {
  if (!RELAY_DEBUG_REQUEST_ID_PATTERN.test(id)) {
    throw new RelayKitError("usage", "debug get takes the customer's x-request-id (32 lower-case hex digits, optionally -1 to -9) or the container's X-Gray-Request (32 lower-case hex digits)");
  }
}

/** The stack VM's origin and, for an adopted instance, the binding its quote must prove (P12). */
export function debugStackVm(config: LoadedRelayConfig): { readonly origin: string; readonly instance?: LaneBinding } {
  const stack = config.daemon.stack;
  if (stack === null) throw new RelayKitError("usage", "the config has no `stack` section: `gray-assistant debug get` is for a relay-stack lane, whose VM holds the records");
  // The config's stack app is attested against its `lane.instances` entry, as the agent does.
  if (stack.laneOrigin !== null) return { origin: stack.laneOrigin };
  const inspected = inspectControlFile(controlFileBeside(config.daemon.stateFile));
  if (inspected.kind === "malformed") throw new RelayKitError("io", "control.json beside the state file does not parse");
  const adopted = inspected.kind === "ok" ? (inspected.control.stackInstance ?? null) : null;
  if (adopted === null) {
    throw new RelayKitError("usage", "no stack VM adopted yet: gray-assistant takes it from Gray after a Deploy once the VM's quote proves it (gray-assistant doctor, stack_instance)");
  }
  // The agent does not follow an instance adopted at a plain https origin before kit 1.1.0 (no VM is there any more).
  if (tunnelOriginOf(adopted.laneOrigin) === null) {
    throw new RelayKitError("usage", "the adopted stack VM is at a plain https origin, which this gray-assistant no longer reaches; the agent adopts Gray's tunnel origin once the VM's quote proves it (gray-assistant doctor, stack_instance)");
  }
  return { origin: adopted.laneOrigin, instance: { appId: adopted.appId, kmsCaPubkey: adopted.kmsCaPubkey } };
}

/** Refuse an output the record must not go to, before anything is fetched. */
function checkOutput(out: string | null, io: DebugIo): void {
  if (out === null) {
    if (io.stdoutIsTTY) throw new RelayKitError("usage", "debug get does not print a record to a terminal: name a file with --out <file>, or redirect stdout");
    return;
  }
  let taken = true;
  try {
    lstatSync(out);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw new RelayKitError("io", `cannot check ${out}`);
    taken = false;
  }
  if (taken) throw new RelayKitError("io", `${out} already exists: debug get never writes over a file; name a new one`);
  let directory;
  try {
    directory = statSync(dirname(resolve(out)));
  } catch {
    throw new RelayKitError("io", `${dirname(resolve(out))} does not exist`);
  }
  if (!directory.isDirectory()) throw new RelayKitError("io", `${dirname(resolve(out))} is not a directory`);
}

/** The sentence for each code of the VM's route. */
function refusalMessage(status: number, code: string | null, relayId: string): { readonly code: string; readonly message: string } {
  switch (code) {
    case "debug_record_not_held":
      return { code, message: "the VM holds no record for this request: the customer has not authorized it, its 24-hour hold ended, or the VM restarted" };
    case "debug_record_not_kept":
      return { code, message: "the customer authorized this request, but the VM no longer held it then (debug_record_not_kept): over an hour old, pushed out by newer requests, or the VM restarted" };
    case "debug_unsupported":
      return { code, message: "this stack VM holds no debug records (debug_unsupported): its boot measured no relay key it could read" };
    case "request_stale":
      return { code, message: `the VM refused the request as stale (request_stale): this host's clock is more than ${RELAY_DEBUG_MAX_SKEW_SECONDS} s from the VM's; set it right (NTP) and try again` };
    case "bad_signature":
      return { code, message: "the VM did not accept the request's signature (bad_signature): the config's relay key is not the one the VM booted with" };
    case "unknown_relay":
      return { code, message: `the VM serves no relay ${relayId} (unknown_relay): the config's relay_id is not the one the VM booted with` };
    case "invalid_request":
      return { code, message: "the VM refused the request as malformed (invalid_request): this gray-assistant and the VM's Gray release do not agree on its shape; update gray-assistant" };
    default:
      break;
  }
  if (status === 404) {
    return { code: "route_unknown", message: "the VM does not serve debug records (404): it runs a Gray release from before debug sharing; ask again once it runs a newer one" };
  }
  return { code: code ?? `http_${status}`, message: `the VM refused the request (${status}${code === null ? "" : ` ${code}`})` };
}

/** The route's error code (`{"error": {"code": …}}`), or null. Only a lower-case word is printed. */
function errorCodeOf(body: Uint8Array): string | null {
  let value: Json;
  try {
    value = parseStrictBytes(body);
  } catch {
    return null;
  }
  const error = get(value, "error");
  const code = isObject(error) ? get(error, "code") : null;
  return typeof code === "string" && /^[a-z0-9_]{1,64}$/.test(code) ? code : null;
}

/** The default attestation: the signed release list, the quote verifier and the agent's own attestation seam. */
function cliAttest(config: LoadedRelayConfig): DebugAttest {
  return async (input) => {
    const { releaseListForCommand } = await import("./release-control.ts");
    const { loadQuoteVerifier } = await import("./attest.ts");
    const { createDaemonAttest } = await import("./run.ts");
    const verified = await releaseListForCommand(config, Number(input.nowSecs) * 1000);
    const quoteVerifier = await loadQuoteVerifier(config.daemon.pccsUrl === null ? {} : { pccs: config.daemon.pccsUrl });
    return createDaemonAttest({ config, quoteVerifier })({ origin: input.origin, release: verified.list, nowSecs: input.nowSecs, ...(input.instance === undefined ? {} : { instance: input.instance }) });
  };
}

/** `debug get <request id> [--out <file>]`: fetch, open and write one authorized request's record. */
export async function debugGet(options: DebugGetOptions): Promise<number> {
  const { config, io, requestId, out } = options;
  const relayId = config.daemon.relayId;
  checkDebugRequestId(requestId);
  checkOutput(out, io);
  const vm = debugStackVm(config);

  const refuse = (code: string, message: string): number => {
    io.stderr(`gray-assistant debug get: ${message}\n`);
    io.stderr(`${toJsonString({ command: "debug.get", ok: false, relay_id: relayId, request_id: requestId, code })}\n`);
    return 1;
  };

  // The agent's attestation, then the agent's checks of the boot: the VM is talked to only once its quote proves it
  // is this relay's stack boot.
  const nowMs = io.now();
  const nowSecs = BigInt(Math.floor(nowMs / 1000));
  let attested: DaemonAttestResult;
  try {
    attested = await (options.attest ?? cliAttest(config))({ origin: vm.origin, nowSecs, ...(vm.instance === undefined ? {} : { instance: vm.instance }) });
  } catch (error) {
    if (error instanceof RelayKitError) throw error;
    return refuse("attest_transport_io", "the stack VM could not be attested (attest_transport_io); `gray-assistant doctor` checks the path to it");
  }
  if (!attested.ok) {
    const code = `attest_${attested.stage}_${attested.code}`;
    return refuse(code, `the stack VM did not attest (${code}); \`gray-assistant doctor\` says more`);
  }
  const mismatch = attestationMismatch(attested, vm.origin, relayId);
  if (mismatch !== null) return refuse(mismatch, `the stack VM's attestation is not this relay's VM at ${vm.origin} (${mismatch})`);
  const stack = config.daemon.stack;
  const issueReader = options.stackIssue ?? (stack === null ? undefined : (await import("./daemon/pull-token-log.ts")).createPullTokenIssueReader(stack.issueLog));
  const boot = await stackBootDecision({
    facts: attested.stackBoot ?? null,
    composeHash: attested.composeHash,
    relayId,
    relayPublicKeyHex: bytesToLowerHex(await ed25519PublicKey(options.seed)),
    stack,
    stackIssue: issueReader,
  });
  if (!boot.ok) return refuse(`attest_${boot.code}`, `the stack VM's boot is not one this agent sealed credentials to (attest_${boot.code}); \`gray-assistant doctor\` says more`);

  // The signed request, with a reply key that lives only in this process.
  const reply = await debugReplyKey();
  const ask = await debugRequestValue({ relayId, requestId, signingKey: options.seed, replyPublicKey: reply.publicKey, issuedAt: Math.floor(io.now() / 1000) });
  const fetch = options.fetch ?? (await import("./daemon/fetch.ts")).createPinnedDaemonFetch({ maxResponseBytes: DEBUG_ANSWER_MAX_BYTES });
  let response;
  try {
    response = await fetch(`${vm.origin}${RELAY_DEBUG_PATH}`, {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json", "user-agent": "gray-assistant" },
      body: new TextEncoder().encode(toJsonString(ask)),
      expectedSpkiSha256: attested.tlsSpkiSha256,
      timeoutMs: 60_000,
    });
  } catch (error) {
    const code = error instanceof DaemonTransportError || error instanceof RelayKitError ? error.code : "io";
    if (code === "tls_spki_mismatch") return refuse(`transport_${code}`, "the VM's TLS key is not the one it attested a moment ago (tls_spki_mismatch): it restarted in between; try again");
    return refuse(`transport_${code}`, `the request did not reach the stack VM through Gray's entry (${code}); \`gray-assistant doctor\` checks the path`);
  }
  if (response.status !== 200) {
    const refusal = refusalMessage(response.status, errorCodeOf(response.body), relayId);
    return refuse(refusal.code, refusal.message);
  }

  let opened: { readonly meta: RelayDebugMeta; readonly record: Uint8Array };
  try {
    opened = await openDebugAnswer(parseStrictBytes(response.body), reply.privateKey, relayId);
  } catch {
    return refuse("answer_invalid", "the VM's answer did not open as a record sealed to this request; nothing was written");
  }
  const { meta, record } = opened;
  if (meta.request_id !== requestId && meta.record_rid !== requestId) {
    return refuse("answer_other_request", "the VM answered with the record of another request; nothing was written");
  }

  let written: string | null = null;
  if (out === null) {
    await io.stdoutBytes(record);
  } else {
    written = resolve(out);
    writePrivateFile(written, record);
  }
  const line: JsonObject = {
    command: "debug.get",
    ok: true,
    relay_id: relayId,
    request_id: meta.request_id,
    record_rid: meta.record_rid,
    shared_ms: BigInt(meta.shared_ms),
    record_bytes: BigInt(meta.record_bytes),
    record_sha256: meta.record_sha256,
    out: written,
  };
  io.stderr(`${toJsonString(line)}\n`);
  return 0;
}

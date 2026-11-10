/**
 * `gray-assistant run --config <file>`: the agent. It is the only long-running process:
 *
 * - K3's source adapter supplies account metadata and, on the seal/push path, one credential;
 * - K2's daemon decides attestation, release acceptance, policy-before-credentials, sealing,
 *   renewal and the scheduler's pool;
 * - this file owns the Node-only pieces: the key/policy loaders, `attestLane` per replica, the
 *   plain-HTTP scheduler listener, the timer that drives `tick`, the state file and the status
 *   snapshot;
 * - with a `stack` section, the relay-stack pull-token routes (S9–S13) on the same listener, behind
 *   the same TLS proxy as the scheduler: they answer `POST /v1/pull-token/challenge` and
 *   `POST /v1/pull-token` before any other route, check boots with the same quote verifier and the
 *   daemon's release decision, and append every issue to `stack.issue_log`; and the agent status
 *   (S45: logins, sealing per replica, parked accounts), signed and posted to `stack.report_origin`
 *   on a change and as a heartbeat (`./daemon/agent-status-report.ts`); Gray's answer names the relay's lane
 *   instance, which with `stack.instance: "gray"` the daemon adopts once a token request's quote proves it (P12) and
 *   keeps in control.json;
 * - for a `file` source, the refresher of the relay's own logins (`./login/refresher.ts`) runs on
 *   the source-poll cadence, so a rotated token is in the next poll's snapshot;
 * - with a `ui` section, the local page (`./ui/server.ts`): on 127.0.0.1 at `ui.listen.port`, printing no sign-in
 *   link (stdout is the agent's log; the operator runs `gray-assistant ui link`), and with `ui.public` under `/ui/` on this
 *   same listener, the relay's public origin behind its TLS proxy or tunnel, where only enrolled passkeys sign in. A
 *   loopback page that cannot start (its port is taken) is an error line, not a stopped agent.
 * - with a `tunnel` section, the relay tunnel (`./tunnel/supervisor.ts`, docs/relay-tunnel.md): Caddy terminates TLS
 *   for the relay's name with a certificate it obtains itself and proxies to this listener, frpc carries the name's
 *   connections from Gray's rendezvous, and the CT monitor (`./tunnel/ct.ts`) watches for certificates of the name
 *   the relay did not obtain. Its word goes into the agent status, its view into the status snapshot.
 *
 * There is no TLS in the agent process (design v2 §A.10). The proxy in front terminates it (the tunnel's Caddy, or
 * the relay's own); `doctor` proves
 * the proxy forwards the signed bytes unchanged. Signals stop the timers and close the listener;
 * nothing is revoked on stop (a whole-relay revoke is an explicit operator action).
 */
import { availableParallelism } from "node:os";
import { performance } from "node:perf_hooks";
import { ed25519PublicKey, ed25519Sign } from "@gray/attest";
import { isObject, parseSerde, toJsonString, type JsonObject } from "@gray/json";
import { bytesToHex, randomBytes } from "@gray/relay-connector";
import type { QuoteVerifier } from "@gray/lane-verify";
import { checkVerifiedReport } from "../verified-report.ts";
import { createRelayDaemon } from "../daemon/daemon.ts";
import { policyOrigins, releasePinningProblem, stackPlaceholderProblem } from "../daemon/config.ts";
import { createPullTokenService, type PullTokenService } from "../daemon/pull-token.ts";
import { parsePolicyBundleValue, verifyPolicyBundleDocument } from "../policy-bundle.ts";
import { RelayKitError } from "../errors.ts";
import type { DaemonAttest, DaemonAttestResult, DaemonFetch, DaemonHealth, DaemonLogEvent, RelayDaemon } from "../daemon/types.ts";
import type { SchedulerHandler, SchedulerHttpRequest, SchedulerHttpResponse } from "../scheduler/handler.ts";
import { attestLane, loadQuoteVerifier } from "./attest.ts";
import { loadRelayConfigFile, type LoadedRelayConfig } from "./config-file.ts";
import { acceptPairingReleasesState, setStackInstanceState } from "./control.ts";
import { controlFileBeside, createFileControlStore } from "./daemon/control-file.ts";
import { createPinnedDaemonFetch } from "./daemon/fetch.ts";
import { createPullTokenIssueLog, createPullTokenIssueReader } from "./daemon/pull-token-log.ts";
import { createPullTokenReporter, type PullTokenReporter } from "./daemon/pull-token-report.ts";
import { accountAliasesPath, createFileAccountAliasStore } from "./daemon/account-aliases-file.ts";
import { AGENT_STATUS_CHECK_MS, AGENT_STATUS_FIRST_WAIT_MS, createAgentLoginReader, createAgentStatusReporter, type AgentStatusReporter } from "./daemon/agent-status-report.ts";
import { agentStatusDocument, type AgentLogin, type AgentStatusInput } from "../daemon/agent-status.ts";
import { RELAY_KIT_VERSION } from "../endpoints.ts";
import { releaseStatusDocument, signReleaseStatus } from "../daemon/release-status.ts";
import { createFileStateStore } from "./daemon/state-file.ts";
import { writeDaemonStatusFile, DAEMON_STATUS_API_VERSION } from "./daemon/status-file.ts";
import { readPrivateFile } from "./files.ts";
import { createPlainDaemonFetch } from "./release-list-source.ts";
import { buildKeyFromText } from "./scheduler-load.ts";
import { startSchedulerServer, type StartedSchedulerServer } from "./scheduler-http-server.ts";
import { createSourceAdapter } from "./source/config.ts";
import { codexLoginEndpoint, createLoginRoutes } from "./login/proxy.ts";
import { createLoginRefresher, type LoginRefresher } from "./login/refresher.ts";
import { foreignCertificateAlert, sendAlert } from "./alerts.ts";
import { startCtMonitor, type CtMonitor } from "./tunnel/ct.ts";
import { tunnelStatusValue } from "./tunnel/status.ts";
import { startTunnel, type RunningTunnel, type TunnelSeams } from "./tunnel/supervisor.ts";
import { readLoginRecord } from "./login/store.ts";
import type { RelayKeyFile } from "../keys.ts";
import type { DaemonSchedule } from "../daemon/types.ts";
import { readUiPort, uiMarkerPath } from "./ui/marker.ts";
import { createRelayUiHandler, startRelayUi, type RunningRelayUi, type UiHandler } from "./ui/server.ts";

export interface RunIo {
  readonly stdout: (line: string) => void;
  readonly stderr: (line: string) => void;
  readonly now: () => number;
}

export interface RunRelayOptions {
  readonly configPath: string;
  readonly ca?: string;
  readonly verifierModule?: string;
  readonly io: RunIo;
  /** The login refresher's issuer and `fetch`; tests point it at a fake token endpoint. */
  readonly loginEndpoint?: { readonly issuer: string; readonly clientId: string; readonly fetch: typeof fetch };
  /**
   * Tests only: the public page's origin instead of the config's (`http://localhost:<port>`, for WebAuthn in a browser).
   */
  readonly uiPublicOrigin?: () => string | null;
  /** Tests only: the built page to serve instead of the package's `assets/ui`. */
  readonly uiBundleDir?: string;
  /**
   * The tunnel's seams (children, admin API, certificate), the CT sources' and the alert channel's `fetch`, and the
   * tunnel's clock (its logins are judged by the rendezvous's real clock even when a test fixes `io.now`); tests
   * replace them.
   */
  readonly tunnelSeams?: TunnelSeams & {
    readonly ctFetch?: (url: string, init: RequestInit) => Promise<Response>;
    readonly alertFetch?: (url: string, init: RequestInit) => Promise<Response>;
    readonly nowMs?: () => number;
  };
}

export interface RunningRelay {
  readonly url: string;
  readonly port: number;
  readonly config: LoadedRelayConfig;
  readonly daemon: RelayDaemon;
  /** The relay's login refresher (`file` source only); its timer calls `tick`, tests may too. */
  readonly logins: LoginRefresher | null;
  /** S13's reports of pull-token issues to Gray (`stack` only); its timer flushes, tests may too. */
  readonly pullTokenReports: PullTokenReporter | null;
  /** S45's agent status to Gray (`stack` only); its timer checks every AGENT_STATUS_CHECK_MS, tests may too. */
  readonly agentStatus: AgentStatusReporter | null;
  /** The local page beside the agent on 127.0.0.1 (`ui.listen`); null without one or when it could not start. */
  readonly ui: RunningRelayUi | null;
  /** The page on the relay's public origin (`ui.public`), mounted on the agent's listener under `/ui/`; null without. */
  readonly uiPublic: UiHandler | null;
  /** The relay tunnel and its CT monitor (`tunnel` only). */
  readonly tunnel: RunningTunnel | null;
  readonly ct: CtMonitor | null;
  /** Write the status snapshot now; the timer calls this after every tick. Tests drive it by hand. */
  publishStatus(): void;
  stop(): Promise<void>;
}

/** A content-free structured log line; undefined members are dropped, never printed as null. */
function logLine(io: RunIo, event: DaemonLogEvent): void {
  const value: JsonObject = { at_ms: io.now(), level: event.level, event: event.event };
  for (const [key, member] of Object.entries(event)) {
    if (key === "level" || key === "event" || member === undefined) continue;
    value[key] = typeof member === "number" && Number.isFinite(member) ? BigInt(Math.trunc(member)) : (member as string | boolean | null);
  }
  io.stdout(`${toJsonString(value)}\n`);
}

/** The daemon's attestation seam over `attestLane`; one fresh nonce per attempt. */
export function createDaemonAttest(options: {
  readonly config: LoadedRelayConfig;
  readonly quoteVerifier: QuoteVerifier;
  readonly ca?: string;
}): DaemonAttest {
  return async (input): Promise<DaemonAttestResult> => {
    const release = input.release;
    // R01: with no signed list there is no pinning at all. Refuse before a report is fetched or a
    // credential can be sealed, rather than building an unpinned record the CLI would refuse.
    if (release === null) return { ok: false, stage: "pinning", code: "no_release_list" };
    // Every configured origin has an entry (the config refuses to load otherwise), and the daemon names the adopted
    // stack instance's (P12); an origin neither names is never attested.
    const expectedInstance = input.instance ?? options.config.daemon.lane.instances.get(input.origin);
    if (expectedInstance === undefined) return { ok: false, stage: "pinning", code: "no_expected_instance" };
    let result;
    try {
      result = await attestLane({
        origin: input.origin,
        release,
        // Both measurements must come from the signed list: an OS image that was never checked is
        // never accepted by the daemon (VF-SDK-01).
        allowUnpinned: false,
        acceptUnpinned: false,
        acceptOsUnpinned: false,
        nonce: bytesToHex(randomBytes(32)),
        nowSecs: input.nowSecs,
        ca: options.ca,
        quoteVerifier: options.quoteVerifier,
        expectedInstance,
        ...(input.keyset === undefined ? {} : { keyset: input.keyset }),
        ...(input.allowEmptySlot === true ? { allowEmptySlot: true } : {}),
      });
    } catch (error) {
      const code = error instanceof RelayKitError ? error.code : "io";
      return { ok: false, stage: "transport", code };
    }
    if (!result.ok) {
      if (result.stage === "report") return { ok: false, stage: "report", code: "no_report" };
      if (result.stage === "verification") return { ok: false, stage: "verification", code: "failed" };
      return { ok: false, stage: "pinning", code: result.verdict };
    }
    if (result.verification.keysetDigest === null) return { ok: false, stage: "verification", code: "no_keyset" };
    const checked = checkVerifiedReport(result.file, {
      nowSecs: input.nowSecs,
      maxAgeSeconds: BigInt(options.config.daemon.reportMaxAgeSeconds),
      acceptUnpinned: false,
      expectedInstance,
    });
    return {
      ok: true,
      checked,
      keysetDigest: result.verification.keysetDigest,
      tlsSpkiSha256: result.spkiSha256,
      composeHash: result.verification.composeHash,
      osImageHash: result.verification.osImageHash,
      // S52: verifyAttestation read it after the RTMR3 replay matched, the relay's image signature included.
      stackBoot: result.verification.stackBoot !== null && result.verification.stackBoot.ok ? result.verification.stackBoot.facts : null,
    };
  };
}

function readPolicyBundle(path: string): JsonObject {
  const text = readPrivateFile(path, "policy bundle", 8 * 1024 * 1024);
  let value: unknown;
  try {
    // The lane reads the posted body with `parseSerde`, whose integers are `bigint`. Reading the
    // file the same way keeps `version` (and every other integer) an integer when the daemon
    // re-serializes it: `toJsonString` writes a JS number as a float (`"version":1.0`), which the
    // lane's `version: z.bigint()` schema refuses as `invalid_policy_bundle`.
    value = parseSerde(text);
  } catch {
    throw new RelayKitError("invalid_policy_bundle", "the policy bundle is not JSON");
  }
  if (!isObject(value as never)) throw new RelayKitError("invalid_policy_bundle");
  return value as JsonObject;
}

/** Load every file the agent needs before it binds a port. A refusal here is a config error. */
export async function loadRunInputs(options: RunRelayOptions): Promise<{
  readonly config: LoadedRelayConfig;
  readonly key: RelayKeyFile;
  /** Null when no lane origin installs a policy: the relay-stack origin runs none (S23). */
  readonly policyBundle: JsonObject | null;
  readonly quoteVerifier: QuoteVerifier;
  /** The registry token of `stack.registry.password_file`; null without a `stack` section. */
  readonly registryPassword: string | null;
}> {
  const config = loadRelayConfigFile(options.configPath);
  // K5-1: refuse the skeleton before reading a key, binding a port or fetching the release list.
  const pinning = releasePinningProblem(config.daemon) ?? stackPlaceholderProblem(config.daemon);
  if (pinning !== null) throw new RelayKitError("usage", pinning.message);
  const key = await buildKeyFromText(readPrivateFile(config.daemon.keyPath, "relay key", 64 * 1024));
  const publicKey = await ed25519PublicKey(key.seed);
  // S23: a relay whose only origin is its relay-stack app uploads no policy, so `run` reads none,
  // even when the config still names one; the config parser requires it for every other relay.
  const policyPath = policyOrigins(config.daemon).length === 0 ? null : config.daemon.policyBundlePath;
  const policyBundle = policyPath === null ? null : readPolicyBundle(policyPath);
  if (policyBundle !== null) {
    const parsed = parsePolicyBundleValue(policyBundle);
    if (parsed.relayId !== config.daemon.relayId) throw new RelayKitError("invalid_policy_bundle", "the bundle names another relay");
    const verified = await verifyPolicyBundleDocument(parsed, publicKey);
    if (!verified.ok) throw new RelayKitError("invalid_policy_bundle", verified.code);
  }
  const quoteVerifier = await loadQuoteVerifier({
    ...(options.verifierModule === undefined ? {} : { verifierModule: options.verifierModule }),
    ...(config.daemon.pccsUrl === null ? {} : { pccs: config.daemon.pccsUrl }),
  });
  // S13: the registry token is a secret file like the key (0600, regular, no symlink); one line.
  const registryPassword =
    config.daemon.stack === null ? null : readPrivateFile(config.daemon.stack.registry.passwordFile, "registry password", 4096).trim();
  return { config, key, policyBundle, quoteVerifier, registryPassword };
}

/**
 * S9–S13: the pull-token routes ahead of every other route on the agent's listener; any other path
 * goes to `handler` unchanged. Without a `stack` section there is no service and nothing changes.
 */
export function withPullToken(handler: SchedulerHandler, service: PullTokenService | null): SchedulerHandler {
  if (service === null) return handler;
  const wrapped = (async (request: SchedulerHttpRequest): Promise<SchedulerHttpResponse> => (await service.handle(request)) ?? handler(request)) as SchedulerHandler;
  wrapped.setKeyFor = (keyFor) => handler.setKeyFor(keyFor);
  return wrapped;
}

/**
 * R22: `GET /healthz` returns `daemon.health()` as JSON, 200 when ready and 503 otherwise; every
 * other request goes to the scheduler handler unchanged. The wrapper keeps `setKeyFor` so a caller
 * that owns the handler can still swap its resolver.
 */
export function withHealthz(handler: SchedulerHandler, health: () => DaemonHealth): SchedulerHandler {
  const wrapped = (async (request: SchedulerHttpRequest): Promise<SchedulerHttpResponse> => {
    if (request.method === "GET" && request.path === "/healthz") {
      const value = health();
      const body = new TextEncoder().encode(toJsonString({ ready: value.ready, reasons: [...value.reasons], at_ms: BigInt(value.atMs) }));
      return { status: value.ready ? 200 : 503, headers: { "content-type": "application/json" }, body };
    }
    return handler(request);
  }) as SchedulerHandler;
  wrapped.setKeyFor = (keyFor) => handler.setKeyFor(keyFor);
  return wrapped;
}

/** Start the agent. The caller owns signals and calls `stop()`. */
export async function startRelay(options: RunRelayOptions): Promise<RunningRelay> {
  const { config, key, policyBundle, quoteVerifier, registryPassword } = await loadRunInputs(options);
  const logins = config.source.kind === "file" ? config.source.logins : null;
  const loginsDir = logins?.dir ?? null;
  const refresher: LoginRefresher | null =
    logins === null || loginsDir === null
      ? null
      : createLoginRefresher({
          settings: { ...logins, dir: loginsDir },
          endpoint: options.loginEndpoint ?? codexLoginEndpoint(logins.proxy),
          // Each login refreshes from its account's own proxy (a test's injected endpoint keeps its own fetch).
          ...(options.loginEndpoint !== undefined || config.source.kind !== "file"
            ? {}
            : { routes: createLoginRoutes({ accountsPath: config.source.path, defaultProxy: logins.proxy }) }),
          nowMs: () => options.io.now(),
          log: (event) => logLine(options.io, event),
        });
  // The source's clock is the daemon's wall clock: a login's serve margin and a `limited` account's
  // end are judged at the same instant the daemon seals and picks. A login is read through the
  // refresher, so a rotated token whose write is still failing is served from its memory.
  // In-VM refresh: the panel's accounts set to `gray`, as Gray's last answer to the agent status named them; a relay
  // login account among them is handed to the VM. The daemon is made below, so its panel ids are reached through this.
  let refreshGray: ReadonlySet<string> = new Set();
  let panelIdOf: ((sourceId: string) => string | null) | null = null;
  const source = createSourceAdapter(config.source, {
    now: () => options.io.now(),
    refreshInVm: (sourceId) => {
      const id = panelIdOf?.(sourceId) ?? null;
      return id !== null && refreshGray.has(id);
    },
    ...(refresher === null || loginsDir === null ? {} : { readLogin: (name: string) => refresher.view(name, readLoginRecord(loginsDir, name)) }),
  });
  const pinned = createPinnedDaemonFetch({ ...(options.ca === undefined ? {} : { ca: options.ca }) });
  const plain = createPlainDaemonFetch({ ...(options.ca === undefined ? {} : { ca: options.ca }) });
  // The release list and its freshness document (D137) are public, signed documents over plain https;
  // every other URL is a lane origin and goes through the attested-SPKI pin.
  const publicUrls = new Set([config.daemon.lane.releaseList, ...(config.daemon.lane.releaseFreshness === null ? [] : [config.daemon.lane.releaseFreshness.url])]);
  const fetch: DaemonFetch = (url, init) => (publicUrls.has(url) ? plain(url, init) : pinned(url, init));
  const daemon = createRelayDaemon({
    config: config.raw,
    source,
    signingKey: key.seed,
    policyBundle,
    fetch,
    attest: createDaemonAttest({ config, quoteVerifier, ...(options.ca === undefined ? {} : { ca: options.ca }) }),
    clock: { wallMs: () => options.io.now(), monoMs: () => performance.now() },
    stateStore: createFileStateStore(config.daemon.stateFile),
    controlStore: createFileControlStore(controlFileBeside(config.daemon.stateFile)),
    adminToken: config.daemon.scheduler.adminTokenFile === null
      ? undefined
      : readPrivateFile(config.daemon.scheduler.adminTokenFile, "admin token", 4096).trim(),
    log: (event) => logLine(options.io, event),
    // S54: intake seals to a stack boot only for an image this agent's own record issued to it.
    ...(config.daemon.stack === null ? {} : { stackIssue: createPullTokenIssueReader(config.daemon.stack.issueLog) }),
    // P12: the adopted stack instance in control.json, under the CLI's lock; rule 4's status post through the reporter.
    persistStackInstance: async (instance) => {
      await setStackInstanceState(controlFileBeside(config.daemon.stateFile), config.daemon.stateFile, instance);
    },
    // init --pair's acceptances, through the same lock and file as `releases accept`.
    persistPairingAcceptances: async (hashes, acceptedAtMs) => {
      await acceptPairingReleasesState(controlFileBeside(config.daemon.stateFile), config.daemon.stateFile, hashes, acceptedAtMs);
    },
    requestStackInstance: async () => {
      await agentStatus?.send();
    },
    // S59: the plain panel ids of accounts whose source id is not one (an e-mail address), kept in the state directory.
    aliasStore: createFileAccountAliasStore(accountAliasesPath(config.daemon.stateFile)),
  });
  const stack = config.daemon.stack;
  // S13: every issue is recorded locally first, then reported to Gray in the background.
  const reporter =
    stack === null
      ? null
      : createPullTokenReporter({
          reportOrigin: stack.reportOrigin,
          relayId: config.daemon.relayId,
          seed: key.seed,
          issueLog: stack.issueLog,
          log: (event) => logLine(options.io, event),
        });
  const writeIssue = stack === null ? null : createPullTokenIssueLog(stack.issueLog);
  // S45: the relay's own logins (a `file` source's) and the daemon's replicas, parked accounts and source accounts.
  const readLogins: (nowMs: number) => AgentLogin[] =
    logins === null || loginsDir === null || config.source.kind !== "file"
      ? () => []
      : createAgentLoginReader({
          loginsDir,
          accountsPath: config.source.path,
          settings: logins,
          ...(refresher === null ? {} : { view: (name: string, stored) => refresher.view(name, stored) }),
        });
  let trimmedLogged = false;
  // Started once the listener is bound (the terminator proxies to its port); the status reads it from then on.
  let tunnel: RunningTunnel | null = null;
  let ct: CtMonitor | null = null;
  // The local page's port once this process serves it (`ui.listen`, set below).
  let ownUiPort: number | null = null;
  // The page on the relay's public origin (`ui.public`): `ui.origin`, else the tunnel's while it is up, else the token
  // URL's (with a tunnel section the token URL defaults to the tunnel's origin too). Which one it answers on now is also what the agent status reports (`ui_mode`).
  const uiConfig = config.daemon.ui;
  const tokenOrigin = config.daemon.stack === null ? null : new URL(config.daemon.stack.tokenUrl).origin;
  const publicOrigin = (): { readonly origin: string | null; readonly mode: "public" | "tunnel" } => {
    if (options.uiPublicOrigin !== undefined) return { origin: options.uiPublicOrigin(), mode: "public" };
    if (uiConfig?.origin) return { origin: uiConfig.origin, mode: "public" };
    // The relay tunnel's name while the rendezvous holds it (docs/relay-tunnel.md): passkeys are then made for that
    // full name (their RP ID is the origin's host), never for the zone.
    if (tunnel !== null && tunnel.view().state === "connected") return { origin: tunnel.view().origin, mode: "tunnel" };
    return { origin: tokenOrigin, mode: "public" };
  };
  const uiPublic: UiHandler | null =
    uiConfig?.public === true
      ? await createRelayUiHandler({
          mode: "public",
          config,
          publicOrigin: () => publicOrigin().origin,
          ...(options.uiBundleDir === undefined ? {} : { bundleDir: options.uiBundleDir }),
          ...(options.ca === undefined ? {} : { ca: options.ca }),
          ...(options.verifierModule === undefined ? {} : { verifierModule: options.verifierModule }),
          io: options.io,
          ...(options.loginEndpoint === undefined ? {} : { loginEndpoint: options.loginEndpoint }),
        })
      : null;
  const uiNow = (nowMs: number): AgentStatusInput["ui"] => {
    if (uiPublic !== null && publicOrigin().origin !== null) return { mode: publicOrigin().mode };
    const port = ownUiPort ?? readUiPort(uiMarkerPath(config.daemon.stateFile), nowMs);
    return port === null ? null : { mode: "loopback", port };
  };
  const agentStatus =
    stack === null
      ? null
      : createAgentStatusReporter({
          reportOrigin: stack.reportOrigin,
          seed: key.seed,
          nowMs: () => options.io.now(),
          build: (nowMs) => {
            const status = daemon.status();
            const built = agentStatusDocument({
              relayId: config.daemon.relayId,
              issuedMs: nowMs,
              agentVersion: RELAY_KIT_VERSION,
              // P12: before the first adoption no replica is the stack app ("" names no origin).
              stackOrigin: daemon.stackInstance()?.held?.laneOrigin ?? "",
              logins: readLogins(nowMs),
              replicas: status.replicas,
              parked: status.parked,
              sources: status.sources,
              // The public page, else the loopback one this process serves, else one another process serves on the volume.
              ui: uiNow(nowMs),
              tunnel: tunnel?.view().state ?? null,
              // S58: the token service's latest refusal; S59: account ids as the panel knows them.
              boot: pullToken?.boot() ?? null,
              panelId: (vendor, sourceId) => daemon.panelAccountId(vendor, sourceId),
              // v1.7 item 9: the releases Gray may boot this relay's VM with.
              acceptedCompose: daemon.acceptedComposeHashes(),
            });
            if (built.trimmed > 0 && !trimmedLogged) logLine(options.io, { level: "warn", event: "agent_status_trimmed", entries: built.trimmed });
            trimmedLogged = built.trimmed > 0;
            return built.status;
          },
          log: (event) => logLine(options.io, event),
          onInstance: (instance) => daemon.onStackInstance(instance),
          onRefreshGray: (ids) => {
            refreshGray = ids;
          },
        });
  // A relay login serves only ChatGPT Codex accounts.
  panelIdOf = (sourceId) => daemon.panelAccountId("chatgpt_codex", sourceId);
  const pullToken =
    stack === null || registryPassword === null || reporter === null || writeIssue === null
      ? null
      : createPullTokenService({
          relayId: config.daemon.relayId,
          stack,
          // S51/S54: the key the boot's identity must name, and the signature on the image it names.
          relayPublicKey: bytesToHex(key.publicKey),
          signImage: (message) => ed25519Sign(key.seed, message),
          currentImage: () => daemon.stackImages()?.current ?? stack.currentImage,
          refreshImages: () => daemon.reloadControl(),
          password: registryPassword,
          quoteVerifier,
          releaseForBoot: (composeHash, osImageHash) => daemon.releaseForBoot(composeHash, osImageHash),
          // P12: the held instance or Gray's candidate, which a passing quote makes the adopted one.
          stackBinding: (appId, kmsCaPubkey) => daemon.stackBindingFor(appId, kmsCaPubkey),
          adoptCandidate: (binding) => daemon.adoptStackCandidate(binding),
          record: async (issue) => {
            await writeIssue(issue);
            reporter.enqueue(issue);
          },
          log: (event) => logLine(options.io, event),
          now: () => options.io.now(),
          // A DCAP verification is CPU work: as many at once as this machine can run side by side.
          maxVerifications: availableParallelism(),
          // S58: a new refusal of a booting VM reaches the panel at once.
          onRefusal: () => agentStatus?.sendSoon(),
          releaseStatus: () =>
            signReleaseStatus(releaseStatusDocument(config.daemon.relayId, options.io.now(), daemon.status(), daemon.health()), key.seed),
        });
  let server: StartedSchedulerServer | null = null;
  try {
    server = await startSchedulerServer({
      listen: config.daemon.scheduler.listen,
      handler: withPullToken(withHealthz(daemon.handler, () => daemon.health()), pullToken),
      ...(uiPublic === null ? {} : { raw: (request, response) => uiPublic.handle(request, response) }),
    });
    await daemon.start();
    const tunnelConfig = config.daemon.tunnel;
    if (tunnelConfig !== null) {
      const tunnelNow = options.tunnelSeams?.nowMs ?? (() => options.io.now());
      tunnel = await startTunnel({
        config: tunnelConfig,
        relayId: config.daemon.relayId,
        seed: key.seed,
        upstream: { host: config.daemon.scheduler.listen.host, port: server.port },
        log: (event) => logLine(options.io, event),
        stderr: options.io.stderr,
        nowMs: tunnelNow,
        ...(options.tunnelSeams === undefined ? {} : { seams: options.tunnelSeams }),
      });
      const running = tunnel;
      ct = startCtMonitor({
        config: tunnelConfig,
        statePath: running.paths.ctState,
        acksPath: running.paths.ctAcks,
        ownKeys: () => running.ownKeys(),
        recheckOwn: async () => (await running.checkCertificate()).spkiSha256,
        alert: (finding) => sendAlert(config.daemon.alerts, foreignCertificateAlert(config.daemon.relayId, tunnelConfig.name, finding, tunnelNow()), options.tunnelSeams?.alertFetch),
        log: (event) => logLine(options.io, event),
        nowMs: tunnelNow,
        ...(options.tunnelSeams?.ctFetch === undefined ? {} : { fetch: options.tunnelSeams.ctFetch }),
      });
    }
  } catch (error) {
    ct?.stop();
    await tunnel?.stop();
    await server?.close();
    throw error;
  }
  const publish = (): void => {
    try {
      const page = uiPublic !== null ? publicOrigin() : null;
      writeDaemonStatusFile(config.daemon.statusFile, {
        apiVersion: DAEMON_STATUS_API_VERSION,
        writtenAtMs: options.io.now(),
        health: daemon.health(),
        status: daemon.status(),
        agentStatus: agentStatus?.state() ?? null,
        uiPage: page !== null && page.origin !== null ? { mode: page.mode, origin: page.origin, port: null } : ownUiPort !== null ? { mode: "loopback", origin: null, port: ownUiPort } : null,
        tunnel: tunnel === null ? null : tunnelStatusValue(tunnel.view(), ct?.view() ?? null),
      });
    } catch {
      // A status write is a diagnostic; it must not stop the agent. `doctor` will notice a stale file.
    }
  };
  publish();
  let stopping = false;
  let timer: ReturnType<typeof setInterval> | null = null;
  let ticking = false;
  const tick = async (): Promise<void> => {
    if (ticking || stopping) return;
    ticking = true;
    try {
      await daemon.tick();
    } catch (error) {
      logLine(options.io, { level: "error", event: "tick_failed", code: error instanceof RelayKitError ? error.code : "internal" });
    } finally {
      ticking = false;
      publish();
    }
  };
  timer = setInterval(() => void tick(), config.daemon.tickMs);
  let loginTimer: ReturnType<typeof setInterval> | null = null;
  if (refresher !== null) {
    void refresher.tick();
    loginTimer = setInterval(() => void refresher.tick(), config.daemon.sourcePollMs);
  }
  let agentTimer: ReturnType<typeof setInterval> | null = null;
  let agentFirstWait: ReturnType<typeof setTimeout> | null = null;
  if (agentStatus !== null) {
    // The first status waits for the first tick's reads (Gray's release list, with init --pair's acceptances, and the
    // account source): sent before them it would say the relay accepts no release and lists no account, and the
    // corrected one would wait out the minute's spacing, so an apply right after pairing or a restart would see a
    // relay that accepts nothing. A first tick slower than AGENT_STATUS_FIRST_WAIT_MS does not hold the status back.
    const beginReports = (): void => {
      if (agentTimer !== null || stopping) return;
      if (agentFirstWait !== null) clearTimeout(agentFirstWait);
      agentFirstWait = null;
      void agentStatus.check();
      agentTimer = setInterval(() => void agentStatus.check(), AGENT_STATUS_CHECK_MS);
    };
    agentFirstWait = setTimeout(beginReports, AGENT_STATUS_FIRST_WAIT_MS);
    agentFirstWait.unref?.();
    void daemon.firstReads().then(beginReports);
  }
  let ui: RunningRelayUi | null = null;
  if (uiConfig !== null && uiConfig.port !== null) {
    try {
      ui = await startRelayUi({
        configPath: options.configPath,
        port: uiConfig.port,
        ...(options.uiBundleDir === undefined ? {} : { bundleDir: options.uiBundleDir }),
        ...(options.ca === undefined ? {} : { ca: options.ca }),
        ...(options.verifierModule === undefined ? {} : { verifierModule: options.verifierModule }),
        io: options.io,
        ...(options.loginEndpoint === undefined ? {} : { loginEndpoint: options.loginEndpoint }),
      });
      ownUiPort = ui.port;
      logLine(options.io, { level: "info", event: "ui_listening", url: ui.url });
    } catch (error) {
      logLine(options.io, { level: "error", event: "ui_failed", code: error instanceof RelayKitError ? error.code : "internal" });
    }
  }
  const stopped = server;
  return {
    url: stopped.url,
    port: stopped.port,
    config,
    daemon,
    logins: refresher,
    pullTokenReports: reporter,
    agentStatus,
    ui,
    uiPublic,
    tunnel,
    ct,
    publishStatus: publish,
    async stop(): Promise<void> {
      if (stopping) return;
      stopping = true;
      if (timer !== null) clearInterval(timer);
      timer = null;
      if (loginTimer !== null) clearInterval(loginTimer);
      loginTimer = null;
      if (agentTimer !== null) clearInterval(agentTimer);
      agentTimer = null;
      if (agentFirstWait !== null) clearTimeout(agentFirstWait);
      agentFirstWait = null;
      agentStatus?.stop();
      await ui?.stop();
      uiPublic?.stop();
      ct?.stop();
      await tunnel?.stop();
      // A refresh in flight finishes and is written first (bounded by `logins.request_timeout_ms`).
      await refresher?.stop();
      reporter?.stop();
      await daemon.stop();
      await stopped.close();
      publish();
    },
  };
}

/** The schedule seam for a caller that wants the daemon to own its timer instead of `startRelay`. */
export function intervalSchedule(): DaemonSchedule {
  return (tick, intervalMs) => {
    const timer = setInterval(tick, intervalMs);
    return () => clearInterval(timer);
  };
}

/** The run summary printed before the process blocks (no secret, no account id). */
export function runSummary(running: RunningRelay): JsonObject {
  return {
    command: "run",
    relay_id: running.config.daemon.relayId,
    listen: `${running.config.daemon.scheduler.listen.host}:${running.port}`,
    scheduler_url: running.config.daemon.scheduler.publicUrl,
    pull_token_url: running.config.daemon.stack?.tokenUrl ?? null,
    tunnel_origin: running.config.daemon.tunnel?.origin ?? null,
    state_file: running.config.daemon.stateFile,
    control_file: controlFileBeside(running.config.daemon.stateFile),
    status_file: running.config.daemon.statusFile,
    ...(running.ui === null ? {} : { ui_url: running.ui.url }),
    ...(running.uiPublic === null || running.uiPublic.origin() === null ? {} : { ui_public_url: `${running.uiPublic.origin()}/ui/` }),
  };
}

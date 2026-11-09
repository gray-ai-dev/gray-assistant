/**
 * The tunnel in `gray-assistant run` (docs/relay-tunnel.md): it starts the terminator (Caddy) and the tunnel client
 * (frpc) as child processes, keeps both running, and knows whether the relay's name is reachable.
 *
 * - The client is started with a login the relay key signs for this start (`@gray/control/tunnel`); frpc sends it
 *   again on each reconnect. A first login the rendezvous refuses ends frpc (`loginFailExit`), and a reconnect that
 *   stays refused (the login expired while the network was down) is ended here: after `RELOGIN_AFTER_MS` down, the
 *   client is started again with a fresh login. Either way the restarts back off from 1 s to a minute.
 * - `connected` is frpc's own word for the proxy (its admin API on 127.0.0.1, `/api/status`: the proxy is `running`
 *   once frps registered the name); anything else, or no answer, is `down`.
 * - The certificate is read from the terminator itself, over 127.0.0.1 with the name as SNI: its public key is the
 *   relay's own, and every key it has served is kept (`own-keys.json`) for the CT monitor (`./ct.ts`).
 *
 * Nothing here logs a login, a key or the admin password; the children's own output goes to stderr, line by line.
 */
import { spawn as nodeSpawn, type ChildProcess } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { mkdirSync } from "node:fs";
import { connect as tlsConnect } from "node:tls";
import { bytesToLowerHex, ed25519Sign } from "@gray/attest";
import { tunnelLabel, tunnelLoginMessage, tunnelLoginMetas, type TunnelState } from "@gray/control/tunnel";
import { parsePlain } from "@gray/json";
import type { TunnelConfig } from "../../daemon/config.ts";
import type { DaemonLogEvent } from "../../daemon/types.ts";
import { readAtomicDocument, writeAtomicPrivateFile } from "../daemon/atomic-file.ts";
import { caddyConfigValue, frpcConfigValue, tunnelPaths, writeTunnelFiles, type TunnelPaths } from "./files.ts";

/** How often frpc's admin API is read. */
export const TUNNEL_STATUS_POLL_MS = 2000;
/** How long the proxy may stay down before the client is started again with a fresh login (frpc retries up to every 20 s). */
export const RELOGIN_AFTER_MS = 30_000;
/** How often the terminator's certificate is read. */
export const CERTIFICATE_POLL_MS = 60_000;
/** A certificate with less left than this is `expiring`: Caddy renews a 90-day certificate with 30 days left. */
export const CERTIFICATE_WARN_MS = 14 * 86_400_000;
/** The restart back-off: 1 s doubling to a minute, back to 1 s after a minute of running. */
const RESTART_MIN_MS = 1000;
const RESTART_MAX_MS = 60_000;
const HEALTHY_RUN_MS = 60_000;

export type CertificateState = "ok" | "expiring" | "pending";

export interface TunnelCertificate {
  readonly state: CertificateState;
  /** SHA-256 of the served certificate's SubjectPublicKeyInfo (DER), hex; null while none is served. */
  readonly spkiSha256: string | null;
  readonly notAfterMs: number | null;
  readonly issuer: string | null;
  readonly checkedMs: number | null;
}

export interface TunnelView {
  readonly state: TunnelState;
  readonly name: string;
  readonly origin: string;
  readonly server: string;
  readonly sinceMs: number;
  readonly clientRestarts: number;
  readonly terminatorRestarts: number;
  readonly certificate: TunnelCertificate;
}

export interface OwnKey {
  readonly spki_sha256: string;
  readonly first_seen_ms: number;
  readonly last_seen_ms: number;
}

/** The seams the tests replace: the children, the admin API and the terminator's certificate. */
export interface TunnelSeams {
  readonly spawn?: (command: string, args: readonly string[], env: NodeJS.ProcessEnv) => ChildProcess;
  readonly fetch?: (url: string, init: RequestInit) => Promise<Response>;
  readonly probeCertificate?: (config: TunnelConfig) => Promise<{ readonly spkiSha256: string; readonly notAfterMs: number; readonly issuer: string } | null>;
}

export interface RunningTunnel {
  readonly paths: TunnelPaths;
  view(): TunnelView;
  /** Every key the terminator has served for the name, oldest first. */
  ownKeys(): readonly OwnKey[];
  /** Read the certificate now (the CT monitor does before it calls a key foreign). */
  checkCertificate(): Promise<TunnelCertificate>;
  /** Read frpc's state now (tests; the timer does every TUNNEL_STATUS_POLL_MS). */
  poll(): Promise<TunnelState>;
  stop(): Promise<void>;
}

/** The SPKI hash, expiry and issuer of the certificate the terminator serves for the name, or null while it serves none. */
export function probeServedCertificate(config: TunnelConfig): Promise<{ readonly spkiSha256: string; readonly notAfterMs: number; readonly issuer: string } | null> {
  return new Promise((resolve) => {
    const socket = tlsConnect({ host: "127.0.0.1", port: config.tlsPort, servername: config.name, rejectUnauthorized: false, ALPNProtocols: ["http/1.1"] });
    const done = (value: { spkiSha256: string; notAfterMs: number; issuer: string } | null) => {
      socket.destroy();
      resolve(value);
    };
    socket.setTimeout(5000, () => done(null));
    socket.once("error", () => done(null));
    socket.once("secureConnect", () => {
      const certificate = socket.getPeerX509Certificate();
      if (certificate === undefined) return done(null);
      const spki = certificate.publicKey.export({ type: "spki", format: "der" });
      done({ spkiSha256: createHash("sha256").update(spki).digest("hex"), notAfterMs: Date.parse(certificate.validTo), issuer: certificate.issuer.replace(/\n/g, ", ") });
    });
  });
}

/** A login for this start of the client: the relay key signs `@gray/control/tunnel`'s message. */
export async function signedTunnelMetas(options: { readonly relayId: string; readonly name: string; readonly seed: Uint8Array; readonly nowMs: number; readonly lifetimeMs: number }): Promise<Record<string, string>> {
  const login = { relay_id: options.relayId, name: options.name, issued_ms: options.nowMs, expires_ms: options.nowMs + options.lifetimeMs, nonce: randomBytes(16).toString("hex") };
  return tunnelLoginMetas(login, bytesToLowerHex(await ed25519Sign(options.seed, tunnelLoginMessage(login))));
}

/** Read the kept own keys; an unreadable file is none. */
export function readOwnKeys(path: string): OwnKey[] {
  const text = readAtomicDocument(path);
  if (text === null) return [];
  try {
    const value = parsePlain(text) as { keys?: unknown };
    if (!Array.isArray(value?.keys)) return [];
    return value.keys.filter(
      (k): k is OwnKey => typeof k === "object" && k !== null && typeof (k as OwnKey).spki_sha256 === "string" && /^[0-9a-f]{64}$/.test((k as OwnKey).spki_sha256) && Number.isFinite((k as OwnKey).first_seen_ms) && Number.isFinite((k as OwnKey).last_seen_ms),
    );
  } catch {
    return [];
  }
}

class Child {
  private process: ChildProcess | null = null;
  private restartDelayMs = RESTART_MIN_MS;
  private startedMs = 0;
  private timer: ReturnType<typeof setTimeout> | null = null;
  private stopping = false;
  restarts = 0;
  readonly name: string;
  private readonly start: () => Promise<ChildProcess>;
  private readonly log: (event: DaemonLogEvent) => void;
  private readonly nowMs: () => number;

  constructor(name: string, start: () => Promise<ChildProcess>, log: (event: DaemonLogEvent) => void, nowMs: () => number) {
    this.name = name;
    this.start = start;
    this.log = log;
    this.nowMs = nowMs;
  }

  get running(): boolean {
    return this.process !== null;
  }

  async launch(): Promise<void> {
    if (this.stopping || this.process !== null) return;
    let child: ChildProcess;
    try {
      child = await this.start();
    } catch {
      this.log({ level: "error", event: "tunnel_child_start_failed", child: this.name });
      this.schedule();
      return;
    }
    this.process = child;
    this.startedMs = this.nowMs();
    child.once("exit", (code, signal) => {
      if (this.process !== child) return;
      this.process = null;
      if (this.stopping) return;
      if (this.nowMs() - this.startedMs >= HEALTHY_RUN_MS) this.restartDelayMs = RESTART_MIN_MS;
      this.log({ level: "warn", event: "tunnel_child_exited", child: this.name, code: code ?? null, signal: signal ?? null, restart_in_ms: this.restartDelayMs });
      this.schedule();
    });
    child.once("error", () => {
      // A spawn that fails (a missing binary) emits `error` and no `exit`.
      if (this.process !== child) return;
      this.process = null;
      if (this.stopping) return;
      this.log({ level: "error", event: "tunnel_child_start_failed", child: this.name });
      this.schedule();
    });
  }

  private schedule(): void {
    if (this.stopping || this.timer !== null) return;
    const delay = this.restartDelayMs;
    this.restartDelayMs = Math.min(RESTART_MAX_MS, this.restartDelayMs * 2);
    this.restarts += 1;
    this.timer = setTimeout(() => {
      this.timer = null;
      void this.launch();
    }, delay);
  }

  /** End the running process; it is started again with the back-off (`restart`) or not at all (`stop`). */
  async kill(): Promise<void> {
    const child = this.process;
    if (child === null) return;
    await new Promise<void>((resolve) => {
      const force = setTimeout(() => child.kill("SIGKILL"), 5000);
      child.once("exit", () => {
        clearTimeout(force);
        resolve();
      });
      child.kill("SIGTERM");
    });
  }

  async restart(): Promise<void> {
    await this.kill();
  }

  async stop(): Promise<void> {
    this.stopping = true;
    if (this.timer !== null) clearTimeout(this.timer);
    this.timer = null;
    await this.kill();
  }
}

/** Pipe a child's output to stderr, one prefixed line at a time. */
function forwardOutput(child: ChildProcess, prefix: string, write: (line: string) => void): void {
  for (const stream of [child.stdout, child.stderr]) {
    if (stream === null || stream === undefined) continue;
    let pending = "";
    stream.setEncoding("utf8");
    stream.on("data", (chunk: string) => {
      pending += chunk;
      let index = pending.indexOf("\n");
      while (index >= 0) {
        write(`${prefix}: ${pending.slice(0, index)}\n`);
        pending = pending.slice(index + 1);
        index = pending.indexOf("\n");
      }
      if (pending.length > 16 * 1024) {
        write(`${prefix}: ${pending}\n`);
        pending = "";
      }
    });
  }
}

/** Start the terminator and the tunnel client; resolves once both are launched (not yet connected). */
export async function startTunnel(options: {
  readonly config: TunnelConfig;
  readonly relayId: string;
  readonly seed: Uint8Array;
  /** The agent's own listener, which the terminator proxies to. */
  readonly upstream: { readonly host: string; readonly port: number };
  readonly log: (event: DaemonLogEvent) => void;
  readonly stderr: (line: string) => void;
  readonly nowMs: () => number;
  readonly seams?: TunnelSeams;
}): Promise<RunningTunnel> {
  const { config } = options;
  const label = tunnelLabel(options.relayId);
  if (label === null) throw new Error("the relay id has no tunnel label");
  const paths = tunnelPaths(config);
  mkdirSync(config.dataDir, { recursive: true, mode: 0o700 });
  const spawn = options.seams?.spawn ?? ((command, args, env) => nodeSpawn(command, [...args], { env, stdio: ["ignore", "pipe", "pipe"] }));
  const fetchAdmin = options.seams?.fetch ?? ((url, init) => fetch(url, init));
  const probe = options.seams?.probeCertificate ?? probeServedCertificate;
  const adminPassword = randomBytes(24).toString("hex");
  // The children get no environment of the agent's: a path, and for Caddy where its own files go.
  const baseEnv = { PATH: process.env.PATH ?? "/usr/local/bin:/usr/bin:/bin" };
  const caddyEnv = { ...baseEnv, HOME: config.dataDir, XDG_DATA_HOME: `${config.dataDir}/xdg-data`, XDG_CONFIG_HOME: `${config.dataDir}/xdg-config` };
  let loginIssuedMs = 0;
  let state: TunnelState = "down";
  let sinceMs = options.nowMs();
  let certificate: TunnelCertificate = { state: "pending", spkiSha256: null, notAfterMs: null, issuer: null, checkedMs: null };
  let own = readOwnKeys(paths.ownKeys);

  writeTunnelFiles({ config, paths, frpc: null, caddy: caddyConfigValue({ config, paths, upstream: options.upstream }) });

  const terminator = new Child(
    "caddy",
    async () => {
      const child = spawn(config.caddyPath, ["run", "--config", paths.caddyConfig], caddyEnv);
      forwardOutput(child, "caddy", options.stderr);
      return child;
    },
    options.log,
    options.nowMs,
  );
  const client = new Child(
    "frpc",
    async () => {
      const nowMs = options.nowMs();
      const metas = await signedTunnelMetas({ relayId: options.relayId, name: config.name, seed: options.seed, nowMs, lifetimeMs: config.loginLifetimeMs });
      writeTunnelFiles({ config, paths, frpc: frpcConfigValue({ config, label, paths, metas, adminPassword }), caddy: null });
      loginIssuedMs = nowMs;
      const child = spawn(config.frpcPath, ["-c", paths.frpcConfig], baseEnv);
      forwardOutput(child, "frpc", options.stderr);
      return child;
    },
    options.log,
    options.nowMs,
  );

  const setState = (next: TunnelState): void => {
    if (next === state) return;
    state = next;
    sinceMs = options.nowMs();
    options.log({ level: next === "connected" ? "info" : "warn", event: "tunnel_state", state: next, name: config.name });
  };

  const poll = async (): Promise<TunnelState> => {
    let connected = false;
    if (client.running) {
      try {
        const response = await fetchAdmin(`http://127.0.0.1:${config.adminPort}/api/status`, {
          headers: { authorization: `Basic ${Buffer.from(`gray-assistant:${adminPassword}`).toString("base64")}` },
          signal: AbortSignal.timeout(2000),
        });
        if (response.status === 200) {
          const value = parsePlain(await response.text()) as Record<string, unknown>;
          const proxies = Array.isArray(value?.https) ? (value.https as { name?: unknown; status?: unknown }[]) : [];
          connected = proxies.some((proxy) => proxy.status === "running");
        } else {
          await response.body?.cancel().catch(() => undefined);
        }
      } catch {
        connected = false;
      }
    }
    setState(connected ? "connected" : "down");
    const now = options.nowMs();
    if (!connected && client.running && now - sinceMs >= RELOGIN_AFTER_MS && now - loginIssuedMs >= RELOGIN_AFTER_MS) {
      options.log({ level: "warn", event: "tunnel_relogin", down_ms: now - sinceMs });
      await client.restart();
    }
    return state;
  };

  const checkCertificate = async (): Promise<TunnelCertificate> => {
    const now = options.nowMs();
    const served = await probe(config).catch(() => null);
    if (served === null) {
      certificate = { state: "pending", spkiSha256: null, notAfterMs: null, issuer: null, checkedMs: now };
      return certificate;
    }
    certificate = { state: served.notAfterMs - now < CERTIFICATE_WARN_MS ? "expiring" : "ok", spkiSha256: served.spkiSha256, notAfterMs: served.notAfterMs, issuer: served.issuer, checkedMs: now };
    const known = own.find((k) => k.spki_sha256 === served.spkiSha256);
    if (known === undefined) {
      own = [...own, { spki_sha256: served.spkiSha256, first_seen_ms: now, last_seen_ms: now }];
      options.log({ level: "info", event: "tunnel_certificate_key", spki_sha256: served.spkiSha256 });
    } else {
      own = own.map((k) => (k === known ? { ...k, last_seen_ms: now } : k));
    }
    try {
      writeAtomicPrivateFile(paths.ownKeys, `${JSON.stringify({ name: config.name, keys: own })}\n`);
    } catch {
      // Kept in memory; the next check writes it again.
    }
    return certificate;
  };

  await terminator.launch();
  await client.launch();
  const statusTimer = setInterval(() => void poll(), TUNNEL_STATUS_POLL_MS);
  const certificateTimer = setInterval(() => void checkCertificate(), CERTIFICATE_POLL_MS);
  // The first certificate arrives seconds after the first connection; read it early, then on the timer.
  const firstCheck = setTimeout(() => void checkCertificate(), 5000);

  return {
    paths,
    view: () => ({
      state,
      name: config.name,
      origin: config.origin,
      server: `${config.server.host}:${config.server.port}`,
      sinceMs,
      clientRestarts: client.restarts,
      terminatorRestarts: terminator.restarts,
      certificate,
    }),
    ownKeys: () => own,
    checkCertificate,
    poll,
    async stop() {
      clearInterval(statusTimer);
      clearInterval(certificateTimer);
      clearTimeout(firstCheck);
      await Promise.all([client.stop(), terminator.stop()]);
      setState("down");
    },
  };
}

/**
 * The Node `https` adapter around the pure scheduler handler, and the configuration/report/key
 * loading that has to happen before a socket is opened.
 *
 * Loading order is the security story: the configuration is parsed strictly, the relay key is read
 * only when it is private, the saved attestation verification is re-checked (freshness, report hash,
 * ACI binding, keyset expiry) and **its keyset** is the only source of the TEE's signing keys. A
 * scheduler started without a valid verified report has no keys to authenticate anything with and
 * refuses to start, rather than serving an endpoint that trusts an unauthenticated caller.
 */
import { createServer, type Server } from "node:https";
import type { IncomingMessage, ServerResponse } from "node:http";
import { dirname, isAbsolute, resolve } from "node:path";
import { parsePlain, parseStrict } from "@gray/json";
import { ed25519PublicKey } from "@gray/attest";
import type { HeaderReader } from "@gray/relay-connector";
import { parseSchedulerConfig, type SchedulerConfig } from "../scheduler/config.ts";
import { createSchedulerHandler, keysetKeyResolver, type SchedulerHttpResponse } from "../scheduler/handler.ts";
import { ReferenceScheduler } from "../scheduler/policy.ts";
import { RelayKitError } from "../errors.ts";
import { buildKeyFromText, checkVerifiedReport, parseVerifiedReportValue, type CheckedVerifiedReport } from "./scheduler-load.ts";
import { readFileBytes, readFileText, readPrivateFile, warnLoosePermissions } from "./files.ts";

/** The largest request body the adapter reads; the handler applies the per-route caps below it. */
const MAX_BODY_BYTES = 8 * 1024 * 1024;

/** A running reference scheduler. */
export interface StartedScheduler {
  readonly url: string;
  readonly port: number;
  readonly config: SchedulerConfig;
  readonly keysetDigest: string;
  readonly relayPublicKeyHex: string;
  close(): Promise<void>;
}

export interface StartSchedulerOptions {
  readonly configPath: string;
  readonly now?: () => number;
  /** A sink for warnings (loose file permissions); the CLI passes stderr. Defaults to stderr. */
  readonly warn?: (line: string) => void;
}

/** Load everything and start listening. Throws `RelayKitError` before listening on any refusal. */
export async function startReferenceScheduler(options: StartSchedulerOptions): Promise<StartedScheduler> {
  const now = options.now ?? (() => Date.now());
  const warn = options.warn ?? ((line: string) => process.stderr.write(`${line}\n`));
  const configPath = resolve(options.configPath);
  const config = loadSchedulerConfig(configPath, warn);
  const base = dirname(configPath);
  const resolvePath = (path: string): string => (isAbsolute(path) ? path : resolve(base, path));

  const check = loadVerifiedReport(resolvePath(config.attestationReportPath), config, now);
  const keyText = readPrivateFile(resolvePath(config.relayKeyPath), "relay key", 64 * 1024);
  let key: Awaited<ReturnType<typeof buildKeyFromText>>;
  try {
    key = await buildKeyFromText(keyText);
  } catch (error) {
    if (error instanceof RelayKitError) throw error;
    throw new RelayKitError("invalid_key_file");
  }

  const policy = new ReferenceScheduler({
    accounts: config.accounts,
    now,
    rateLimitedMs: config.rateLimitedMs,
    overloadedMs: config.overloadedMs,
    busyRetryMs: config.busyRetryMs,
    leaseTtlSeconds: config.leaseTtlSeconds,
    inflightTtlMs: config.inflightTtlMs,
    affinityTtlMs: config.affinityTtlMs,
    ...(config.affinityCap === null ? {} : { affinityCap: config.affinityCap }),
  });
  const handler = createSchedulerHandler({
    relayId: config.relayId,
    // One verified boot: its keyset is the candidate set, and the keyset digest names the replica the
    // pool's installation map would use. A daemon with several boots replaces this resolver with
    // `handler.setKeyFor` after each attestation.
    keyFor: keysetKeyResolver(check.binding.keyset, check.binding.keyset_digest),
    signingKey: key.seed,
    pool: policy,
    now,
    maxSkewMs: config.maxSkewMs,
    replayCap: config.replayCap,
    adminToken: config.adminToken,
  });

  let cert: Buffer;
  let privateKey: Buffer;
  try {
    cert = Buffer.from(readFileBytes(resolvePath(config.tls.certFile), "TLS certificate", 1024 * 1024));
    // The TLS key is a private key: it gets the same refusal rules as the relay key.
    privateKey = Buffer.from(readPrivateFile(resolvePath(config.tls.keyFile), "TLS key", 1024 * 1024));
  } catch (error) {
    if (error instanceof RelayKitError) throw error;
    throw new RelayKitError("io", "cannot read the TLS material");
  }

  const server: Server = createServer({ cert, key: privateKey, minVersion: "TLSv1.2" }, (request, response) => {
    // A per-request failure must answer the request and never reject unhandled: one malformed
    // request line must not be able to take the scheduler down.
    serve(request, response, handler).catch(() => {
      try {
        respond(response, { status: 500, headers: { "content-type": "application/json" }, body: new TextEncoder().encode('{"error":"internal"}') });
      } catch {
        response.destroy();
      }
    });
  });
  server.on("tlsClientError", () => {
    // A failed handshake is not an application event; the socket is already destroyed.
  });
  server.on("clientError", (_error, socket) => {
    // Node surfaces bad request lines here; answer 400 and close instead of crashing.
    if (socket.writable) socket.end("HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n");
    else socket.destroy();
  });
  server.on("error", () => {
    // Runtime server errors after listen() are reported by the close path, not thrown unhandled.
  });

  const port = await listen(server, config.listen.port, config.listen.host);
  const url = `https://${config.listen.host.includes(":") ? `[${config.listen.host}]` : config.listen.host}:${port}`;
  const relayPublicKeyHex = toHex(await ed25519PublicKey(key.seed));
  return {
    url,
    port,
    config,
    keysetDigest: check.binding.keyset_digest,
    relayPublicKeyHex,
    close: () => closeServer(server),
  };
}

/**
 * Read and parse the scheduler configuration file. The file can hold `admin_token`, a live bearer
 * secret, so it is refused when it is a symlink, and a group/other-readable file is warned about
 * the same way the accounts and token files are.
 */
export function loadSchedulerConfig(configPath: string, warn: (line: string) => void = () => {}): SchedulerConfig {
  warnLoosePermissions(configPath, "scheduler config", warn);
  const text = readFileText(configPath, "scheduler config", 4 * 1024 * 1024);
  let value: unknown;
  try {
    value = parsePlain(text);
  } catch {
    // The config may hold the admin token; never echo the parse error.
    throw new RelayKitError("invalid_scheduler_config", "the file is not JSON");
  }
  const config = parseSchedulerConfig(value);
  if (config.adminToken !== null) {
    // The token authorizes the admin reset route; a loose config that carries it is refused, not
    // just warned about.
    try {
      readPrivateFile(configPath, "scheduler config", 4 * 1024 * 1024);
    } catch (error) {
      if (error instanceof RelayKitError && error.code === "unsafe_key_file") {
        throw new RelayKitError("unsafe_key_file", `scheduler config ${configPath} holds admin_token and is readable by group or others; chmod 600 it`);
      }
      throw error;
    }
  }
  return config;
}

function loadVerifiedReport(path: string, config: SchedulerConfig, now: () => number): CheckedVerifiedReport {
  const text = readFileText(path, "verified report", 16 * 1024 * 1024);
  let value: unknown;
  try {
    value = parseStrict(text);
  } catch {
    throw new RelayKitError("invalid_verified_report", "the file is not JSON");
  }
  const file = parseVerifiedReportValue(value);
  return checkVerifiedReport(file, {
    nowSecs: BigInt(Math.floor(now() / 1000)),
    maxAgeSeconds: BigInt(config.maxReportAgeSeconds),
  });
}

async function serve(request: IncomingMessage, response: ServerResponse, handler: ReturnType<typeof createSchedulerHandler>): Promise<void> {
  // Everything per-request lives inside one try: a malformed request-target or a handler throw
  // becomes an HTTP answer, never an unhandled rejection that kills the process.
  try {
    let body: Uint8Array;
    try {
      body = await readBody(request);
    } catch {
      respond(response, { status: 413, headers: { "content-type": "application/json" }, body: new TextEncoder().encode('{"error":"too_large"}') });
      return;
    }
    // `GET //` is a valid origin-form target Node accepts; `new URL` rejects it, so parse inside
    // the try and answer 400.
    const url = new URL(request.url ?? "/", "https://relay.invalid");
    const answer = await handler({
      method: request.method ?? "GET",
      path: url.pathname,
      headers: headerReader(request),
      body,
    });
    respond(response, answer);
  } catch (error) {
    const isParse = error instanceof TypeError;
    try {
      respond(response, {
        status: isParse ? 400 : 500,
        headers: { "content-type": "application/json" },
        body: new TextEncoder().encode(isParse ? '{"error":"bad_request"}' : '{"error":"internal"}'),
      });
    } catch {
      response.destroy();
    }
  }
}

function respond(response: ServerResponse, answer: SchedulerHttpResponse): void {
  response.writeHead(answer.status, { ...answer.headers, "content-length": String(answer.body.length) });
  response.end(Buffer.from(answer.body));
}

function headerReader(request: IncomingMessage): HeaderReader {
  return {
    get(name: string): string | null {
      const value = request.headers[name.toLowerCase()];
      if (value === undefined) return null;
      return Array.isArray(value) ? value.join(", ") : value;
    },
  };
}

function readBody(request: IncomingMessage): Promise<Uint8Array> {
  return new Promise((resolveBody, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    let tooLarge = false;
    request.on("data", (chunk: Buffer) => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        tooLarge = true;
        return;
      }
      if (!tooLarge) chunks.push(chunk);
    });
    request.on("error", reject);
    request.on("end", () => {
      if (tooLarge) reject(new RelayKitError("io", "request too large"));
      else resolveBody(new Uint8Array(Buffer.concat(chunks)));
    });
  });
}

function listen(server: Server, port: number, host: string): Promise<number> {
  return new Promise((resolvePort, reject) => {
    const onError = (error: Error): void => reject(new RelayKitError("io", `cannot listen: ${error.message}`));
    server.once("error", onError);
    server.listen(port, host, () => {
      server.removeListener("error", onError);
      const address = server.address();
      if (address === null || typeof address === "string") {
        reject(new RelayKitError("io", "the server did not bind a TCP port"));
        return;
      }
      resolvePort(address.port);
    });
  });
}

function closeServer(server: Server): Promise<void> {
  return new Promise((resolveClose) => {
    server.close(() => resolveClose());
    const all = (server as Server & { closeAllConnections?: () => void }).closeAllConnections;
    if (typeof all === "function") all.call(server);
  });
}

function toHex(bytes: Uint8Array): string {
  let out = "";
  for (const byte of bytes) out += byte.toString(16).padStart(2, "0");
  return out;
}

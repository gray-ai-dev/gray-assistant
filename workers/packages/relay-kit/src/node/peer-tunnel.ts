/**
 * The tunnel transport (docs/design/relay-outbound-only.md §5): one request to a relay-stack VM through Gray's entry.
 *
 * 1. **Outer:** a WebSocket to `wss://<entry>/v1/peer/tunnel/<relay>` (`ws`), checked with WebPKI for the entry's
 *    name. That check only gets the bytes to Cloudflare and the entry; nothing of the relay's depends on it.
 * 2. **Inner:** TLS inside the WebSocket (`createWebSocketStream` under `tls.connect({ socket })`), ending in the VM's
 *    workerd. The VM's certificate is self-signed per boot, so there is no WebPKI step for it. The check is the
 *    attestation: a pinned request (`expectedSpkiSha256`, the verified report's `tls_spki_sha256`) refuses any other
 *    key after the handshake and before a byte of the request leaves the machine; an unpinned request (attest mode,
 *    the first call per boot) only records the SPKI, and the caller verifies that the report binds it.
 * 3. **Request:** today's HTTP/1.1 exchange, one per tunnel, `Connection: close`.
 *
 * The entry forwards ciphertext. It can delay or drop a message; it cannot read or forge one. A request with a body
 * is never sent unpinned: only a GET may run in attest mode.
 */
import { createHash, X509Certificate } from "node:crypto";
import { request as httpRequest, type IncomingMessage } from "node:http";
import type { Duplex } from "node:stream";
import { connect as tlsConnect, type PeerCertificate, type TLSSocket } from "node:tls";
import { parsePlain } from "@gray/json";
import WebSocket, { createWebSocketStream } from "ws";
import { RELAY_KIT_VERSION } from "../endpoints.ts";
import { RelayKitError } from "../errors.ts";
import { PEER_TUNNEL_PATH, type TunnelOrigin, type TunnelRequest } from "../lane-origin.ts";

/** The largest WebSocket message read from the entry; the entry sends at most 64 KiB (§3.4). */
const MAX_TUNNEL_MESSAGE_BYTES = 1024 * 1024;
/** How much of a refusal's body is read for its code. */
const MAX_REFUSAL_BYTES = 4 * 1024;
/** How long a closing tunnel waits for the entry's close frame before the socket is dropped. */
const CLOSE_GRACE_MS = 2_000;

export interface TunnelRequestInput {
  readonly tunnel: TunnelRequest;
  readonly method: "GET" | "POST";
  readonly headers: Readonly<Record<string, string>>;
  readonly body?: Uint8Array;
  /** The verified report's `tls_spki_sha256`; absent only in attest mode (a GET). */
  readonly expectedSpkiSha256?: string;
  /** A private trust anchor for the entry's certificate (the outer TLS), on top of Node's roots. */
  readonly ca?: string;
  /**
   * The keyset digest of the boot to reach (`?keyset=` on the entry's route): while an image rollout runs two instances
   * of the relay's app, each replica reaches its own boot (docs/design/relay-zero-downtime.md). Absent: the entry's
   * newest boot.
   */
  readonly keyset?: string;
  readonly timeoutMs: number;
  readonly maxResponseBytes: number;
}

export interface TunnelResponse {
  readonly status: number;
  readonly headers: Readonly<Record<string, string | string[] | undefined>>;
  readonly body: Uint8Array;
  /** The SPKI of the certificate the VM presented inside the tunnel. */
  readonly spkiSha256: string | null;
}

/** An open tunnel: the WebSocket and its byte stream. */
interface OpenTunnel {
  readonly ws: WebSocket;
  readonly stream: Duplex;
}

/** A keyset digest as the entry's `?keyset=` takes it. */
const TUNNEL_KEYSET = /^[0-9a-f]{64}$/;

/** The entry's WebSocket URL for a tunnel origin, naming one boot when `keyset` is given. */
export function tunnelWebSocketUrl(tunnel: TunnelOrigin, keyset?: string): string {
  const entry = new URL(tunnel.entry);
  if (keyset !== undefined && !TUNNEL_KEYSET.test(keyset)) throw new RelayKitError("io", "a tunnel's keyset is a digest of 64 lower-case hex");
  return `wss://${entry.host}${PEER_TUNNEL_PATH}${encodeURIComponent(tunnel.relayId)}${keyset === undefined ? "" : `?keyset=${keyset}`}`;
}

/**
 * Open the entry's tunnel route. Throws `io` when the entry cannot be reached (DNS, TCP, its TLS certificate) and
 * `tunnel_refused` when it answers with anything but the upgrade (no such relay, no VM session, too many tunnels).
 */
export function openPeerTunnel(tunnel: TunnelOrigin, options: { readonly ca?: string; readonly keyset?: string; readonly timeoutMs: number }): Promise<OpenTunnel> {
  const url = tunnelWebSocketUrl(tunnel, options.keyset);
  const entryHost = new URL(tunnel.entry).host;
  return new Promise<OpenTunnel>((resolve, reject) => {
    let settled = false;
    const ws = new WebSocket(url, {
      ...(options.ca === undefined ? {} : { ca: options.ca }),
      handshakeTimeout: options.timeoutMs,
      perMessageDeflate: false,
      followRedirects: false,
      maxPayload: MAX_TUNNEL_MESSAGE_BYTES,
      headers: { "user-agent": `gray-assistant/${RELAY_KIT_VERSION}` },
    });
    const fail = (error: RelayKitError): void => {
      if (settled) return;
      settled = true;
      ws.terminate();
      reject(error);
    };
    ws.once("unexpected-response", (request, response) => {
      void readRefusal(response).then((code) => {
        request.destroy();
        fail(new RelayKitError("tunnel_refused", refusalMessage(entryHost, tunnel.relayId, response.statusCode ?? 0, code)));
      });
    });
    ws.once("error", (error: Error & { readonly code?: unknown }) => {
      const code = typeof error.code === "string" ? ` (${error.code})` : "";
      fail(new RelayKitError("io", `Gray's entry ${entryHost} is unreachable${code}`));
    });
    ws.once("open", () => {
      if (settled) return;
      settled = true;
      resolve({ ws, stream: createWebSocketStream(ws) });
    });
  });
}

/** Open and close the tunnel once: the doctor's "tunnel open" check. Throws as `openPeerTunnel` does. */
export async function probePeerTunnel(tunnel: TunnelOrigin, options: { readonly ca?: string; readonly timeoutMs: number }): Promise<void> {
  const opened = await openPeerTunnel(tunnel, options);
  closeTunnel(opened);
}

/** One HTTP/1.1 request to the VM through the entry's tunnel, TLS end to end, pinned by the attestation. */
export async function tunnelRequestOnce(input: TunnelRequestInput): Promise<TunnelResponse> {
  const expectedSpki = input.expectedSpkiSha256?.toLowerCase();
  if (expectedSpki === undefined && (input.method !== "GET" || input.body !== undefined)) {
    // Attest mode exists for the report fetch only: a body never leaves the machine before the VM's key is pinned.
    throw new RelayKitError("io", "a request with a body through Gray's entry needs the verified report's TLS key; attest the VM first");
  }
  const deadline = Date.now() + input.timeoutMs;
  const remaining = (): number => Math.max(1, deadline - Date.now());
  const opened = await openPeerTunnel(input.tunnel, { ...(input.ca === undefined ? {} : { ca: input.ca }), ...(input.keyset === undefined ? {} : { keyset: input.keyset }), timeoutMs: remaining() });
  let socket: TLSSocket | null = null;
  let timer: ReturnType<typeof setTimeout> | null = null;
  try {
    return await new Promise<TunnelResponse>((resolve, reject) => {
      let settled = false;
      const fail = (error: unknown): void => {
        if (settled) return;
        settled = true;
        reject(error instanceof RelayKitError ? error : new RelayKitError("io", "the request through Gray's entry failed"));
      };
      timer = setTimeout(() => fail(new RelayKitError("io", "the request through Gray's entry timed out")), remaining());
      opened.stream.on("error", () => fail(new RelayKitError("io", "the tunnel through Gray's entry closed")));
      // No WebPKI for the VM: its certificate is self-signed, and the attestation's SPKI is the check (below).
      const tls = tlsConnect({ socket: opened.stream, rejectUnauthorized: false });
      socket = tls;
      tls.once("error", () => fail(new RelayKitError("io", "the TLS connection to the VM through Gray's entry failed")));
      tls.once("secureConnect", () => {
        let observed: string | null = null;
        try {
          const certificate = tls.getPeerCertificate(false);
          if (certificate !== null && certificate !== undefined && certificate.raw !== undefined) observed = spkiOf(certificate);
        } catch {
          observed = null;
        }
        if (observed === null) {
          fail(new RelayKitError("io", "the VM presented no TLS certificate inside the tunnel"));
          return;
        }
        if (expectedSpki !== undefined && observed !== expectedSpki) {
          // Before the request line: the VM behind the entry is not the one the attestation pinned.
          fail(new RelayKitError("tls_spki_mismatch", "the TLS key inside the tunnel does not match the verified report's tls_spki_sha256"));
          return;
        }
        const request = httpRequest(
          {
            createConnection: () => tls,
            method: input.method,
            path: input.tunnel.path,
            headers: { ...input.headers, host: new URL(input.tunnel.entry).host, connection: "close" },
          },
          (response: IncomingMessage) => {
            const chunks: Buffer[] = [];
            let size = 0;
            response.on("data", (chunk: Buffer) => {
              size += chunk.length;
              if (size > input.maxResponseBytes) {
                response.destroy(new Error("response too large"));
                fail(new RelayKitError("io", `the response is larger than ${input.maxResponseBytes} bytes`));
                return;
              }
              chunks.push(chunk);
            });
            response.on("error", fail);
            response.on("end", () => {
              if (settled) return;
              settled = true;
              resolve({ status: response.statusCode ?? 0, headers: response.headers, body: new Uint8Array(Buffer.concat(chunks)), spkiSha256: observed });
            });
          },
        );
        request.on("error", fail);
        if (input.body !== undefined) request.write(Buffer.from(input.body));
        request.end();
      });
    });
  } finally {
    if (timer !== null) clearTimeout(timer);
    (socket as TLSSocket | null)?.destroy();
    closeTunnel(opened);
  }
}

/** Close a tunnel with a normal close frame, and drop it if the entry does not answer in time. */
function closeTunnel(opened: OpenTunnel): void {
  const { ws } = opened;
  if (ws.readyState === WebSocket.CLOSED) return;
  const drop = setTimeout(() => ws.terminate(), CLOSE_GRACE_MS);
  drop.unref();
  ws.once("close", () => clearTimeout(drop));
  try {
    ws.close(1000);
  } catch {
    ws.terminate();
  }
}

/** The refusal's code: the lane's `{"error":"<code>"}` or `{"error":{"code":"<code>"}}`; null when there is none. */
function readRefusal(response: IncomingMessage): Promise<string | null> {
  return new Promise((resolve) => {
    const chunks: Buffer[] = [];
    let size = 0;
    const done = (): void => {
      const text = Buffer.concat(chunks).toString("utf8");
      let code: string | null = null;
      try {
        const value = parsePlain(text) as { readonly error?: unknown; readonly code?: unknown };
        const error = value.error;
        if (typeof error === "string") code = error;
        else if (typeof error === "object" && error !== null && typeof (error as { code?: unknown }).code === "string") code = (error as { code: string }).code;
        else if (typeof value.code === "string") code = value.code;
      } catch {
        code = null;
      }
      resolve(code !== null && /^[a-z0-9_]{1,64}$/u.test(code) ? code : null);
    };
    response.on("data", (chunk: Buffer) => {
      size += chunk.length;
      if (size <= MAX_REFUSAL_BYTES) chunks.push(chunk);
      else response.destroy();
    });
    response.once("end", done);
    response.once("close", done);
    response.once("error", done);
  });
}

/** What a refusal means to the relay, in English (§3.5, §5). */
export function refusalMessage(entryHost: string, relayId: string, status: number, code: string | null): string {
  const named = code === null ? `${status}` : `${status} ${code}`;
  const why =
    code === "peer_link_unavailable"
      ? `the entry's link service is not answering (the entry is restarting or overloaded); gray-assistant retries`
      : code === "peer_relay_unknown" || (code === null && status === 404)
      ? `the entry knows no relay-stack relay ${relayId}; check relay_id and that Gray provisioned your VM`
      : code === "peer_session_missing" || (code === null && status === 503)
        ? `your VM has no session to the entry right now (it is booting, rebooting or cannot reach Gray); gray-assistant retries`
        : code === "peer_tunnel_busy" || status === 429
          ? `too many tunnels to ${relayId} are open at once; gray-assistant retries`
          : "the entry did not open the tunnel";
  return `Gray's entry ${entryHost} refused the tunnel to ${relayId} (${named}): ${why}`;
}

/** SHA-256 of the DER SubjectPublicKeyInfo, as ACI's `tls_public_keys` names it (`https.ts`). */
function spkiOf(certificate: PeerCertificate): string {
  const key = new X509Certificate(certificate.raw).publicKey.export({ type: "spki", format: "der" });
  return createHash("sha256").update(key).digest("hex");
}

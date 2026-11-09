/**
 * One HTTPS request, with the TLS peer's SPKI captured and no insecure mode.
 *
 * `node:https` rather than `fetch` because the lane's trust story includes the certificate the client
 * actually saw: `@gray/lane-verify` checks that digest against the keyset's `tls_public_keys`, and a
 * `fetch` wrapper does not expose it. The default trust store is Node's WebPKI; `--ca` adds a private
 * anchor for a deployment's own CA. There is deliberately no `rejectUnauthorized: false` path.
 *
 * Redirects are not followed: a 3xx is a response the caller reports, not a second connection to an
 * origin the caller did not verify. The body cap is enforced while reading, so a hostile server
 * cannot exhaust memory before the cap is checked.
 */
import { createHash, X509Certificate } from "node:crypto";
import { request as httpsRequest } from "node:https";
import { checkServerIdentity as defaultCheckServerIdentity, type PeerCertificate, type TLSSocket } from "node:tls";
import { RelayKitError } from "../errors.ts";
import { tunnelRequestOf } from "../lane-origin.ts";
import { tunnelRequestOnce } from "./peer-tunnel.ts";

export interface HttpsRequestInput {
  readonly url: string;
  readonly method: "GET" | "POST";
  readonly headers: Readonly<Record<string, string>>;
  readonly body?: Uint8Array;
  /**
   * Pin the TLS peer: the SHA-256 hex of the SPKI in the certificate the server presents must equal
   * this value (from the verified report's `tls_spki_sha256`). Checked in `checkServerIdentity`,
   * after the normal CA validation and before a byte of the request body leaves the machine; a
   * mismatch fails the request with `tls_spki_mismatch`. Through a tunnel origin the pin is the only
   * check of the VM's certificate, and a request with a body is refused without one.
   */
  readonly expectedSpkiSha256?: string;
  /** A private trust anchor (PEM), on top of Node's roots; through a tunnel, for the entry's certificate only. */
  readonly ca?: string;
  /** Through a tunnel origin, the keyset digest of the boot to reach (`peer-tunnel.ts`); ignored for a direct origin. */
  readonly tunnelKeyset?: string;
  readonly timeoutMs: number;
  readonly maxResponseBytes: number;
}

export interface HttpsResponse {
  readonly status: number;
  readonly headers: Readonly<Record<string, string | string[] | undefined>>;
  readonly body: Uint8Array;
  /** The leaf certificate's SPKI as SHA-256 hex, when the server presented one. */
  readonly spkiSha256: string | null;
}

/** Send one HTTPS request and read at most `maxResponseBytes` of its answer. */
export function httpsRequestOnce(input: HttpsRequestInput): Promise<HttpsResponse> {
  let url: URL;
  try {
    url = new URL(input.url);
  } catch {
    return Promise.reject(new RelayKitError("io", "not a URL"));
  }
  if (url.protocol !== "https:") return Promise.reject(new RelayKitError("io", "only https is supported"));
  if (url.username !== "" || url.password !== "") return Promise.reject(new RelayKitError("io", "the URL must not carry credentials"));
  // A tunnel origin (`https://<entry>/v1/peer/tunnel/<relay>`): TLS to the VM inside the entry's WebSocket, pinned by
  // the attestation, with no WebPKI step for the VM (`peer-tunnel.ts`). Every caller of this function gets it.
  let tunnel;
  try {
    tunnel = tunnelRequestOf(url);
  } catch {
    return Promise.reject(new RelayKitError("io", "the tunnel URL names no relay id"));
  }
  if (tunnel !== null) {
    return tunnelRequestOnce({
      tunnel,
      method: input.method,
      headers: input.headers,
      ...(input.body === undefined ? {} : { body: input.body }),
      ...(input.expectedSpkiSha256 === undefined ? {} : { expectedSpkiSha256: input.expectedSpkiSha256 }),
      ...(input.ca === undefined ? {} : { ca: input.ca }),
      ...(input.tunnelKeyset === undefined ? {} : { keyset: input.tunnelKeyset }),
      timeoutMs: input.timeoutMs,
      maxResponseBytes: input.maxResponseBytes,
    });
  }

  return new Promise((resolve, reject) => {
    let settled = false;
    const fail = (error: unknown): void => {
      if (settled) return;
      settled = true;
      reject(error instanceof RelayKitError ? error : new RelayKitError("io", "the HTTPS request failed"));
    };
    const expectedSpki = input.expectedSpkiSha256?.toLowerCase();
    const request = httpsRequest(
      url.toString(),
      {
        method: input.method,
        ...(input.ca === undefined ? {} : { ca: input.ca }),
        // One connection per request. Node's process-global agent keeps idle sockets alive, and the
        // peer's keep-alive timeout is wall-clock time; under load a request could be handed a socket
        // the server was closing, failing an otherwise healthy fetch. A pinned fetch must also see
        // the certificate on the connection it actually uses, so there is nothing to reuse.
        agent: false,
        headers: { ...input.headers, connection: "close" },
        timeout: input.timeoutMs,
        ...(expectedSpki === undefined
          ? {}
          : {
              checkServerIdentity: (hostname: string, certificate: PeerCertificate) => {
                // Runs inside TLS cert validation — after WebPKI/CA checks and before the request
                // line or body is sent. Returning an Error aborts the handshake. Keep the default
                // hostname verification: this hook replaces it.
                const hostnameError = defaultCheckServerIdentity(hostname, certificate);
                if (hostnameError) return hostnameError;
                let observed: string | null = null;
                try {
                  if (certificate !== null && certificate !== undefined && certificate.raw !== undefined) {
                    observed = spkiOf(certificate);
                  }
                } catch {
                  observed = null;
                }
                if (observed !== expectedSpki) {
                  return new RelayKitError(
                    "tls_spki_mismatch",
                    "the peer's TLS certificate does not match the verified report's tls_spki_sha256",
                  );
                }
                return undefined;
              },
            }),
      },
      (response) => {
        const socket = response.socket as TLSSocket;
        let spkiSha256: string | null = null;
        try {
          const certificate = socket.getPeerCertificate(false);
          if (certificate !== null && certificate !== undefined && certificate.raw !== undefined) spkiSha256 = spkiOf(certificate);
        } catch {
          spkiSha256 = null;
        }
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
          resolve({
            status: response.statusCode ?? 0,
            headers: response.headers,
            body: new Uint8Array(Buffer.concat(chunks)),
            spkiSha256,
          });
        });
      },
    );
    request.on("timeout", () => {
      request.destroy();
      fail(new RelayKitError("io", "the HTTPS request timed out"));
    });
    request.on("error", fail);
    if (input.body !== undefined) request.write(Buffer.from(input.body));
    request.end();
  });
}

/**
 * The SPKI digest of a peer certificate: SHA-256 of the DER SubjectPublicKeyInfo.
 *
 * Node's `PeerCertificate.pubkey` is the raw public key, which for an EC certificate is the
 * uncompressed point rather than the SPKI DER; exporting the SPKI from the certificate's DER is the
 * one form that means the same thing for RSA and EC, and it is the form ACI's `tls_public_keys`
 * names.
 */
function spkiOf(certificate: PeerCertificate): string {
  const key = new X509Certificate(certificate.raw).publicKey.export({ type: "spki", format: "der" });
  return createHash("sha256").update(key).digest("hex");
}

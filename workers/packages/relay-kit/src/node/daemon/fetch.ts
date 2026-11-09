/**
 * The daemon's HTTPS fetch, Node side: `httpsRequestOnce` with the verified report's SPKI checked
 * inside TLS validation. This is the adapter K1's `uploadToLane` and `attestLane` already use, so the
 * daemon and the CLI cannot disagree about what a pinned lane connection means.
 *
 * A RelayKitError's closed code is carried across as `DaemonTransportError.code`; the daemon maps
 * `tls_spki_mismatch` to re-attestation and every other code to a bounded retry.
 */
import { RelayKitError } from "../../errors.ts";
import { DaemonTransportError, type DaemonFetch, type DaemonHttpResponse } from "../../daemon/types.ts";
import { httpsRequestOnce } from "../https.ts";

/** A response cap large enough for a 4 MiB policy module in base64 plus the JSON framing. */
export const DEFAULT_DAEMON_RESPONSE_BYTES = 16 * 1024 * 1024;

export interface PinnedDaemonFetchOptions {
  /** A private trust anchor for a deployment's own CA; on top of Node's WebPKI roots. */
  readonly ca?: string;
  /** The default per-request timeout when the daemon does not name one. */
  readonly timeoutMs?: number;
  readonly maxResponseBytes?: number;
}

/** One `DaemonFetch` over Node's HTTPS client. No insecure mode exists. */
export function createPinnedDaemonFetch(options: PinnedDaemonFetchOptions = {}): DaemonFetch {
  return async (url, init): Promise<DaemonHttpResponse> => {
    try {
      const response = await httpsRequestOnce({
        url,
        method: init.method,
        headers: init.headers ?? {},
        ...(init.body === undefined ? {} : { body: init.body }),
        ...(init.expectedSpkiSha256 === undefined ? {} : { expectedSpkiSha256: init.expectedSpkiSha256 }),
        ...(init.tunnelKeyset === undefined ? {} : { tunnelKeyset: init.tunnelKeyset }),
        ...(options.ca === undefined ? {} : { ca: options.ca }),
        timeoutMs: init.timeoutMs ?? options.timeoutMs ?? 60_000,
        maxResponseBytes: options.maxResponseBytes ?? DEFAULT_DAEMON_RESPONSE_BYTES,
      });
      return { status: response.status, headers: response.headers, body: response.body, spkiSha256: response.spkiSha256 };
    } catch (error) {
      if (error instanceof RelayKitError) throw new DaemonTransportError(error.code);
      if (error instanceof DaemonTransportError) throw error;
      throw new DaemonTransportError("io");
    }
  };
}

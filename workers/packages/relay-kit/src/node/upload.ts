/**
 * One upload to a lane origin, as a library: the same HTTPS request `gray-assistant upload` makes.
 *
 * The caller classifies the document (`classifyUpload` in the pure entry) and decides whether the
 * peer must be pinned to a verified report's SPKI. A policy bundle always passes the pin (the module
 * is plaintext); a sealed credential envelope may upload without one. The pin is enforced inside
 * certificate validation by `httpsRequestOnce`, before a byte of the body is written, so an
 * endpoint with a merely WebPKI-valid certificate never receives the document.
 */
import { RELAY_KIT_VERSION } from "../endpoints.ts";
import { httpsRequestOnce, type HttpsResponse } from "./https.ts";

/** The largest answer an upload reads; the lane's intake answers are short JSON documents. */
export const DEFAULT_MAX_UPLOAD_RESPONSE_BYTES = 64 * 1024;

/** One lane upload, exactly the request the CLI sends. */
export interface UploadLaneOptions {
  /** A normalized `https://host[:port]`. */
  readonly origin: string;
  /** The lane path from `classifyUpload` (`/v1/aci/…`). */
  readonly path: string;
  /** The document bytes, uploaded unchanged. */
  readonly body: Uint8Array;
  /** The TLS SPKI from the verified report; required for a policy bundle by the CLI's rules. */
  readonly pinnedSpkiSha256?: string | null;
  /** A private CA for the lane's certificate. */
  readonly ca?: string;
  readonly timeoutMs?: number;
  readonly maxResponseBytes?: number;
}

/** The lane's answer; `ok` follows the CLI's exit rule (any 2xx is success). */
export interface UploadLaneResult extends HttpsResponse {
  readonly ok: boolean;
}

/** POST one document to a lane origin. Network/TLS failures throw `RelayKitError`. */
export async function uploadToLane(options: UploadLaneOptions): Promise<UploadLaneResult> {
  const response = await httpsRequestOnce({
    url: `${options.origin}${options.path}`,
    method: "POST",
    headers: { "content-type": "application/json", accept: "application/json", "user-agent": `gray-assistant/${RELAY_KIT_VERSION}` },
    body: options.body,
    ...(options.pinnedSpkiSha256 === undefined || options.pinnedSpkiSha256 === null ? {} : { expectedSpkiSha256: options.pinnedSpkiSha256 }),
    ...(options.ca === undefined ? {} : { ca: options.ca }),
    timeoutMs: options.timeoutMs ?? 60_000,
    maxResponseBytes: options.maxResponseBytes ?? DEFAULT_MAX_UPLOAD_RESPONSE_BYTES,
  });
  return { ...response, ok: response.status >= 200 && response.status < 300 };
}
/**
 * The closed failure vocabulary of the relay's tooling.
 *
 * A message never carries a secret: no seed, no token, no credential value and no fragment of a file
 * that may hold one. Where a lower layer throws, the caller maps it to a code and, at most, the JSON
 * path of the member that failed (for example `accounts.2.credential`), which is the account's own
 * metadata and never its value. This is why a JSON syntax error from a secret-bearing file is
 * replaced by "not JSON" instead of the platform's message: V8 echoes a snippet of the input in
 * some of its parse errors.
 */

/** Why a `gray-assistant` command stopped. */
export type RelayKitErrorCode =
  | "usage"
  | "io"
  | "invalid_key_file"
  | "unsafe_key_file"
  | "invalid_version"
  | "invalid_module"
  | "invalid_templates"
  | "invalid_accounts"
  | "invalid_token"
  | "invalid_policy_bundle"
  | "invalid_verified_report"
  | "report_unverified"
  | "report_unpinned"
  | "report_stale"
  | "report_tampered"
  | "report_origin_mismatch"
  | "tls_spki_mismatch"
  /** Gray's entry answered the tunnel route (`/v1/peer/tunnel/<relay>`) with a refusal instead of opening it. */
  | "tunnel_refused"
  | "duplicate_replica"
  | "invalid_envelope"
  | "invalid_scheduler_config"
  | "invalid_source_config"
  | "source_unreachable"
  | "source_unauthorized"
  | "source_not_found"
  | "source_bad_response"
  | "source_shape_changed"
  | "source_unsupported"
  | "invalid_login"
  | "login_failed"
  | "attestation_failed"
  | "upload_failed"
  | "unsupported_document"
  | "relay_connector"
  | "relay_policy";

/** An error the CLI prints as `gray-assistant: <code>[: <detail>]`, never with a secret in it. */
export class RelayKitError extends Error {
  override readonly name = "RelayKitError";
  readonly code: RelayKitErrorCode;
  /** A safe member path or fixed sentence; never a value read from a secret-bearing file. */
  readonly detail: string | null;

  constructor(code: RelayKitErrorCode, detail: string | null = null) {
    super(detail === null ? `relay-kit/${code}` : `relay-kit/${code}: ${detail}`);
    this.code = code;
    this.detail = detail;
  }
}

/** Whether an error is one this package produced (and may print). */
export function isRelayKitError(error: unknown): error is RelayKitError {
  return error instanceof RelayKitError;
}

/** The exit code a `RelayKitError` maps to: usage and I/O are 2, every refusal is 1. */
export function exitCodeFor(error: RelayKitError): number {
  return error.code === "usage" || error.code === "io" ? 2 : 1;
}

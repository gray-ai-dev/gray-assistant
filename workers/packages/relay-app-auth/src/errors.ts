/**
 * Why a computation of this package refused its input. The codes are the ones gray-assistant prints for the same
 * refusals (relay-kit's `RelayKitError`, which wraps this one), so a message never names a secret: no key, no
 * signature, only the member or the rule that failed.
 */
export type AppAuthErrorCode =
  /** A value the caller gave is not of the form the contract takes (an address, a hash, a relay id). */
  | "usage"
  /** The chain answered something the contract never answers (a release kind other than 0 and 1). */
  | "chain_refused"
  /** A signing key is not the signer the message names. */
  | "invalid_key_file";

export class AppAuthError extends Error {
  override readonly name = "AppAuthError";
  readonly code: AppAuthErrorCode;
  readonly detail: string;

  constructor(code: AppAuthErrorCode, detail: string) {
    super(`relay-app-auth/${code}: ${detail}`);
    this.code = code;
    this.detail = detail;
  }
}

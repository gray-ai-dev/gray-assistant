/**
 * The relay's contract as the kit computes it before it exists: `@gray/relay-app-auth`'s address, init code and
 * runtime code (docs/design/relay-no-always-on-host.md 13.8, C12), which Gray's console and provisioner share. The
 * functions that refuse an input refuse it here as a `RelayKitError` with the same code and words, so the CLI prints
 * them as before.
 */
import {
  AppAuthError,
  appAuthAddress as sharedAddress,
  appAuthDeployCalldata as sharedDeployCalldata,
  appAuthInitCode as sharedInitCode,
  appAuthSalt as sharedSalt,
  checkedAddress as sharedCheckedAddress,
  releaseHash as sharedReleaseHash,
  releaseKindOf as sharedReleaseKindOf,
} from "@gray/relay-app-auth";
import { RelayKitError } from "../errors.ts";

export {
  APP_AUTH_ABI,
  APP_AUTH_CODE,
  APP_AUTH_DELAY_SECONDS,
  APP_AUTH_DOMAIN_NAME,
  APP_AUTH_DOMAIN_VERSION,
  APP_AUTH_SALT_PREFIX,
  BASE_CHAIN_ID,
  BASE_DSTACK_KMS,
  CREATE2_PROXY,
  RELEASE_KIND_NUMBER,
  appAuthCodeFromArtifact,
  appAuthCodeHash,
  appAuthDomainSeparator,
  appAuthRuntimeCode,
  type AppAuthCode,
  type AppAuthDeployment,
  type ReleaseKind,
} from "@gray/relay-app-auth";

/** The shared package's refusal as the kit's own error, same code and words; anything else unchanged. */
export function asKitError(error: unknown): unknown {
  return error instanceof AppAuthError ? new RelayKitError(error.code, error.detail) : error;
}

/** `fn` with the shared package's refusals turned into the kit's. */
export function kitRefusals<A extends unknown[], R>(fn: (...args: A) => R): (...args: A) => R {
  return (...args: A): R => {
    try {
      return fn(...args);
    } catch (error) {
      throw asKitError(error);
    }
  };
}

/** `fn` (async) with the shared package's refusals turned into the kit's. */
export function kitRefusalsAsync<A extends unknown[], R>(fn: (...args: A) => Promise<R>): (...args: A) => Promise<R> {
  return async (...args: A): Promise<R> => {
    try {
      return await fn(...args);
    } catch (error) {
      throw asKitError(error);
    }
  };
}

export const releaseKindOf = kitRefusals(sharedReleaseKindOf);
export const releaseHash = kitRefusals(sharedReleaseHash);
export const checkedAddress = kitRefusals(sharedCheckedAddress);
export const appAuthSalt = kitRefusals(sharedSalt);
export const appAuthInitCode = kitRefusals(sharedInitCode);
export const appAuthAddress = kitRefusals(sharedAddress);
export const appAuthDeployCalldata = kitRefusals(sharedDeployCalldata);

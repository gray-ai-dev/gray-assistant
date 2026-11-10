/**
 * The guardian's EIP-712 messages to the relay's contract: `@gray/relay-app-auth`'s (Approve, Veto, Remove, Pause and
 * Unpause, each with the version of the state it decides), which Gray's console checks with the same code. Signing
 * refuses a key that is not the signer as a `RelayKitError`, as before.
 */
import { pairingGuardianPart as sharedPairingGuardianPart, signGuardianAction as sharedSignGuardianAction } from "@gray/relay-app-auth";
import { kitRefusalsAsync } from "./app-auth.ts";

export {
  APP_AUTH_TYPES,
  PAIRING_APPROVAL_LIFETIME_SECONDS,
  bySigCalldata,
  guardianDigest,
  guardianTypedData,
  pairingGuardianJson,
  signedActionJson,
  signedActionSigner,
  type GuardianAction,
  type GuardianMessageContext,
  type PairingApproval,
  type PairingGuardianPart,
  type SignedGuardianAction,
} from "@gray/relay-app-auth";

export const signGuardianAction = kitRefusalsAsync(sharedSignGuardianAction);
export const pairingGuardianPart = kitRefusalsAsync(sharedPairingGuardianPart);

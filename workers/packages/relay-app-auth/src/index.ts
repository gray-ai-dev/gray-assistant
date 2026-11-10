/**
 * `@gray/relay-app-auth`: the relay's contract, `GrayRelayAppAuth` (contracts/relay-app-auth), as the code around it
 * computes it (docs/design/relay-no-always-on-host.md 3.2, 13.8, 13.11): the exported artifact, the CREATE2 address and
 * runtime code, the guardian's EIP-712 messages and the pairing's guardian part. gray-assistant (relay-kit) signs with
 * it; Gray's console checks the pairing with it; Gray's provisioner deploys the contract with it. Pure: no `node:*`, no
 * network, no clock; viem does the hashing, the ABI and the signatures.
 */
export {
  APP_AUTH_ABI,
  APP_AUTH_CODE,
  APP_AUTH_DELAY_SECONDS,
  APP_AUTH_DOMAIN_NAME,
  APP_AUTH_DOMAIN_VERSION,
  APP_AUTH_IMPLEMENTATION_SALT,
  APP_AUTH_SALT_PREFIX,
  BASE_CHAIN_ID,
  BASE_DSTACK_KMS,
  CREATE2_PROXY,
  ERC1967_IMPLEMENTATION_SLOT,
  RELEASE_KIND_NUMBER,
  appAuthAddress,
  appAuthDeployCalldata,
  appAuthDomainSeparator,
  appAuthImplementationAddress,
  appAuthImplementationCodeHash,
  appAuthImplementationDeployCalldata,
  appAuthImplementationRuntimeCode,
  appAuthInitCode,
  appAuthInitData,
  appAuthProxyCodeHash,
  appAuthSalt,
  appAuthUpgradeId,
  checkedAddress,
  implementationFromSlot,
  publishedImplementation,
  publishedUpgrade,
  releaseHash,
  releaseKindOf,
  type AppAuthCode,
  type AppAuthDeployment,
  type ReleaseKind,
} from "./app-auth.ts";
export { APP_AUTH_COMPILER, APP_AUTH_EVM_VERSION } from "./artifact.ts";
export { renderAppAuthArtifact } from "./artifact-render.ts";
export { AppAuthError, type AppAuthErrorCode } from "./errors.ts";
export {
  APP_AUTH_TYPES,
  PAIRING_APPROVAL_LIFETIME_SECONDS,
  bySigCalldata,
  guardianDigest,
  guardianTypedData,
  pairingGuardianJson,
  pairingGuardianPart,
  signedActionJson,
  signedActionSigner,
  signGuardianAction,
  type GuardianAction,
  type GuardianMessageContext,
  type PairingApproval,
  type PairingGuardianPart,
  type SignedGuardianAction,
} from "./guardian.ts";
export {
  PROPOSALS_SCHEMA,
  PROPOSE_TYPES,
  keyAddress,
  parseProposerItem,
  proposerCalldata,
  proposerDigest,
  proposerItemJson,
  proposerItemSigner,
  proposerTypedData,
  proposerWalletTypedData,
  signProposerItem,
  type ProposerItem,
} from "./proposer.ts";
export { checkPairingGuardian, type PairingGuardianCheck, type PairingGuardianProblem, type PairingGuardianWire, type PairingTerms } from "./pairing.ts";

/**
 * Gray's check of a pairing's guardian part (docs/design/relay-no-always-on-host.md 3.2, 4, 13.3; the console's
 * lane-stack/pairing.ts): the contract gray-assistant computed is the one Gray will deploy for this relay, and every
 * approval is the guardian's EIP-712 `Approve` of the first release, which Gray's relayer can submit once the contract
 * exists. Gray recomputes everything from its own terms (the relay id, its proposer, the chain, the release Deploy boots)
 * and the part's guardian and recovery address; nothing the part claims about the release is taken.
 *
 * The approvals are exactly the ones `pairingGuardianPart` makes for a release of one compose hash and one OS image hash:
 * the compose hash at nonce 0, the OS image hash at nonce 1, each at version 0 (a release's state before its first
 * decision, which a fresh deployment leaves), each with a deadline still ahead. A signature must recover to the guardian
 * (ECDSA): the guardian is the key gray-assistant holds.
 *
 * Pure: no network; the caller gives the time.
 */
import { getAddress, isAddress, zeroAddress, type Address, type Hex } from "viem";
import { APP_AUTH_DELAY_SECONDS, appAuthAddress, type ReleaseKind } from "./app-auth.ts";
import { signedActionSigner, type SignedGuardianAction } from "./guardian.ts";

/** The pairing's guardian part as JSON (relay-kit `pairingGuardianJson`, signed approvals only). */
export interface PairingGuardianWire {
  readonly guardian: string;
  /** Required: a pairing without a recovery address is refused (`recovery`). */
  readonly recovery: string | null;
  readonly chain_id: number;
  readonly contract: string;
  /** The relay's release delay in seconds, 0 to 7 days (13.13), decimal; absent from a kit before it: 7 days. */
  readonly delay_seconds?: string;
  readonly approvals: readonly {
    readonly kind: ReleaseKind;
    readonly hash: string;
    readonly version: string;
    readonly nonce: string;
    readonly deadline: string;
    readonly signature: string;
  }[];
}

/** Gray's side of the address: what the relay's contract will be deployed with, but the guardian. */
export interface PairingTerms {
  readonly relayId: string;
  readonly proposer: Address;
  /** Gray's proposer recovery key. */
  readonly proposerRecovery: Address;
  readonly chainId: number;
  /** The release Deploy boots: Phala's measured compose hash and the OS image hash, 0x and 64 lower hex. */
  readonly composeHash: Hex;
  readonly osImageHash: Hex;
}

/** Why a guardian part is refused: one closed word each, for the audit (never a value from the part). */
export type PairingGuardianProblem = "chain" | "guardian" | "recovery" | "delay" | "contract" | "approvals" | "deadline" | "signature";

export type PairingGuardianCheck =
  | {
      readonly ok: true;
      readonly guardian: Address;
      readonly recovery: Address;
      readonly contract: Address;
      /** The relay's release delay in seconds, which the contract is initialised with. */
      readonly delaySeconds: bigint;
      /** The approvals in submission order (nonce 0, 1), as the relayer submits them. */
      readonly approvals: readonly SignedGuardianAction[];
    }
  | { readonly ok: false; readonly problem: PairingGuardianProblem };

function address(value: string | null): Address | null {
  if (value === null || !isAddress(value, { strict: false })) return null;
  const checked = getAddress(value);
  return checked === zeroAddress ? null : checked;
}

/** Check a pairing's guardian part against Gray's terms at `nowSeconds` (Unix seconds). */
export async function checkPairingGuardian(part: PairingGuardianWire, terms: PairingTerms, nowSeconds: bigint): Promise<PairingGuardianCheck> {
  if (part.chain_id !== terms.chainId) return { ok: false, problem: "chain" };
  // Gray's own proposer as the relay's guardian would let Gray approve its own releases: never the relay's choice.
  const proposer = getAddress(terms.proposer);
  const guardian = address(part.guardian);
  if (guardian === null || guardian === proposer) return { ok: false, problem: "guardian" };
  // The recovery address is required (it alone replaces a lost or stolen guardian) and is another key than the guardian.
  const recovery = address(part.recovery);
  const proposerRecovery = getAddress(terms.proposerRecovery);
  if (guardian === proposerRecovery) return { ok: false, problem: "guardian" };
  if (recovery === null || recovery === proposer || recovery === proposerRecovery || recovery === guardian) return { ok: false, problem: "recovery" };
  // The relay's choice; part of the address, so the contract recomputed below is refused for any other.
  const delaySeconds = part.delay_seconds === undefined ? APP_AUTH_DELAY_SECONDS : /^(0|[1-9][0-9]{0,6})$/.test(part.delay_seconds) ? BigInt(part.delay_seconds) : null;
  if (delaySeconds === null || delaySeconds > APP_AUTH_DELAY_SECONDS) return { ok: false, problem: "delay" };
  const contract = appAuthAddress({
    relayId: terms.relayId,
    proposer,
    proposerRecovery,
    guardian,
    recovery,
    delaySeconds,
    composeHashes: [terms.composeHash],
    osImageHashes: [terms.osImageHash],
  });
  if (address(part.contract) !== contract) return { ok: false, problem: "contract" };
  const expected: readonly { kind: ReleaseKind; hash: Hex }[] = [
    { kind: "compose", hash: terms.composeHash },
    { kind: "os_image", hash: terms.osImageHash },
  ];
  if (part.approvals.length !== expected.length) return { ok: false, problem: "approvals" };
  const approvals: SignedGuardianAction[] = [];
  for (const [index, want] of expected.entries()) {
    const approval = part.approvals[index]!;
    if (approval.kind !== want.kind || approval.hash !== want.hash || approval.version !== "0" || approval.nonce !== String(index)) return { ok: false, problem: "approvals" };
    const deadline = BigInt(approval.deadline);
    if (deadline <= nowSeconds) return { ok: false, problem: "deadline" };
    const signed: SignedGuardianAction = {
      action: "approve",
      kind: want.kind,
      hash: want.hash,
      chainId: terms.chainId,
      contract,
      version: 0n,
      signer: guardian,
      nonce: BigInt(index),
      deadline,
      signature: approval.signature as Hex,
    };
    let signer: Address;
    try {
      signer = await signedActionSigner(signed);
    } catch {
      return { ok: false, problem: "signature" };
    }
    if (signer !== guardian) return { ok: false, problem: "signature" };
    approvals.push(signed);
  }
  return { ok: true, guardian, recovery, contract, delaySeconds, approvals };
}

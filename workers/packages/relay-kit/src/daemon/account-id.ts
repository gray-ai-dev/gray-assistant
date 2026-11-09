/**
 * The lane account id the daemon invents (design v2 §A.3, research F9):
 *
 *     "a" + lower-case hex( SHA-256( relay_id || 0x00 || source kind || 0x00 || source id ) )[:32]
 *
 * The TEE sees only this id, so an e-mail address a source uses as its account handle never reaches
 * the lane, and two relays that both call an account `acc-1` cannot collide inside one TEE. The
 * hash is domain-separated by NUL bytes, which can appear in neither a relay id nor a source id in
 * the source contract, so a different split of the same concatenation names a different account.
 * 128 bits of hex is the collision bound the TEE's global account map needs; the `a` prefix keeps
 * the id inside the connector's `RESOURCE_ID` alphabet whatever the hex is.
 *
 * The relay-stack origin is the one exception (daemon `#laneAccountId`): it takes the source id
 * itself, which must be the account's id in Gray's panel, because the entry joins the panel's
 * accounts to sealed credentials by that id and the operator already gives Gray that id.
 */
import { sha256 } from "@noble/hashes/sha2";
import { bytesToHex } from "@noble/hashes/utils";

/** The number of hex digits kept: 16 bytes, 128 bits. */
export const LANE_ACCOUNT_ID_HEX_LENGTH = 32;

/** Derive one lane account id. The source kind is the adapter's `kind`, never a display name. */
export function deriveLaneAccountId(relayId: string, sourceKind: string, sourceId: string): string {
  const preimage = new TextEncoder().encode(`${relayId}\u0000${sourceKind}\u0000${sourceId}`);
  return `a${bytesToHex(sha256(preimage)).slice(0, LANE_ACCOUNT_ID_HEX_LENGTH)}`;
}

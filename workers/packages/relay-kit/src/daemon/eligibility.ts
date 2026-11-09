/**
 * Account eligibility (DeepSeek review B4): the TEE refuses a whole credential bundle when one
 * account's secret does not match its vendor's format class. Real pools hold console tokens,
 * third-party keys and `sk-admin-` keys, so the daemon must never let one such account take the lane
 * down, and must never drop it silently either.
 *
 * The rule:
 *
 * - The vendor × credential-type matrix is checked from metadata alone, before a secret is read.
 *   A pair the TEE has no class for is parked.
 * - When a secret is actually read (only while building a bundle or an update), it is validated by
 *   `@gray/relay-connector`'s own `assertCredentialFormat` — the same function the TEE runs. A
 *   refusal parks that account with a closed reason.
 * - A parked account is excluded from every bundle and every pick, and appears in `status()` with
 *   its lane id, vendor and reason. It is never silently truncated from the bundle.
 * - A park is cleared only when the source's `changeMark` changes or the account disappears: the
 *   source says something about that account changed, so the new secret is tried again.
 */
import { RelayConnectorError, assertCredentialFormat, credentialClass, type Credential, type Vendor } from "@gray/relay-connector";
import type { SourceAccount, SourceKind } from "../source/types.ts";
import { deriveLaneAccountId } from "./account-id.ts";
import type { DaemonParkedAccount } from "./types.ts";

/** The closed reasons an account is parked. */
export type ParkReason =
  | "unsupported_credential_type"
  | "invalid_credential_format"
  | "invalid_egress_format"
  | "credential_unreadable"
  | "missing_credential";

/** One source account as the daemon plans it: the lane id and the metadata the pool needs. */
export interface PlannedAccount {
  readonly account: SourceAccount;
  readonly accountId: string;
  readonly vendor: Vendor;
  readonly credentialType: Credential["type"];
}

/** Plan one source account: derive its lane id and copy the metadata, never the secret. */
export function planAccount(relayId: string, kind: SourceKind, account: SourceAccount): PlannedAccount {
  return {
    account,
    accountId: deriveLaneAccountId(relayId, kind, account.sourceId),
    vendor: account.vendor,
    credentialType: account.credentialType,
  };
}

/** The metadata-only check: does the TEE have a credential class for this vendor/type pair? */
export function metadataParkReason(account: SourceAccount): ParkReason | null {
  return credentialClass(account.vendor, account.credentialType) === null ? "unsupported_credential_type" : null;
}

/**
 * Validate one secret with the TEE's own format rule. Returns the park reason, or null when the
 * account may be sealed. The credential value is never put in a message, a reason or a log event.
 */
export function credentialParkReason(vendor: Vendor, credential: Credential): ParkReason | null {
  if (typeof credential.value !== "string" || credential.value.length === 0) return "missing_credential";
  try {
    assertCredentialFormat(vendor, credential);
    return null;
  } catch (error) {
    if (error instanceof RelayConnectorError) return "invalid_credential_format";
    return "credential_unreadable";
  }
}

interface ParkedEntry {
  readonly vendor: Vendor;
  readonly reason: ParkReason;
  readonly changeMark: string;
  readonly sourceId: string | undefined;
}

/** The parked set, keyed by lane account id. */
export class ParkRegistry {
  readonly #parked = new Map<string, ParkedEntry>();

  /** `sourceId`: the source's own id of the account, which the agent status names (S45); the daemon always gives it. */
  park(accountId: string, vendor: Vendor, reason: ParkReason, changeMark: string, sourceId?: string): void {
    this.#parked.set(accountId, { vendor, reason, changeMark, sourceId });
  }

  has(accountId: string): boolean {
    return this.#parked.has(accountId);
  }

  reason(accountId: string): ParkReason | null {
    return this.#parked.get(accountId)?.reason ?? null;
  }

  /**
   * Drop parks whose account disappeared or whose `changeMark` changed. Called after every source
   * poll; an unchanged mark keeps the park, so a format failure does not retry on every poll.
   */
  prune(accounts: readonly SourceAccount[], accountIds: ReadonlyMap<string, string>): void {
    const present = new Map<string, SourceAccount>();
    for (const account of accounts) {
      const id = accountIds.get(account.sourceId);
      if (id !== undefined) present.set(id, account);
    }
    for (const [accountId, entry] of this.#parked) {
      const account = present.get(accountId);
      if (account === undefined || account.changeMark !== entry.changeMark) this.#parked.delete(accountId);
    }
  }

  /** The operator view; sorted and content-free. */
  list(): readonly DaemonParkedAccount[] {
    return [...this.#parked.entries()]
      .map(([accountId, entry]) => ({ accountId, vendor: entry.vendor, reason: entry.reason, ...(entry.sourceId === undefined ? {} : { sourceId: entry.sourceId }) }))
      .sort((left, right) => left.accountId.localeCompare(right.accountId));
  }

  clear(): void {
    this.#parked.clear();
  }
}

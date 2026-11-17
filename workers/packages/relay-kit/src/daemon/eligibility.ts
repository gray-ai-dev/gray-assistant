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
import { RelayConnectorError, assertCredentialFormat, credentialClass, egressSchema, type Credential, type EgressSpec, type Vendor } from "@gray/relay-connector";
import { RelayKitError } from "../errors.ts";
import type { SourceAccount, SourceCredential, SourceEgress, SourceKind } from "../source/types.ts";
import { deriveLaneAccountId } from "./account-id.ts";
import type { DaemonParkedAccount, DaemonSourceProxy } from "./types.ts";

/** The closed reasons an account is parked. */
export type ParkReason =
  | "unsupported_credential_type"
  | "invalid_credential_format"
  | "invalid_egress_format"
  | "credential_unreadable"
  | "missing_credential"
  | "unknown_proxy";

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

/**
 * The metadata-only check: does the TEE have a credential class for this vendor/type pair, and can the source hand
 * the account over as it is written (`leftOut`)?
 */
export function metadataParkReason(account: SourceAccount): ParkReason | null {
  if (credentialClass(account.vendor, account.credentialType) === null) return "unsupported_credential_type";
  return account.leftOut ?? null;
}

/**
 * Validate one secret with the TEE's own format rule. Returns the park reason, or null when the
 * account may be sealed. The credential value is never put in a message, a reason or a log event.
 *
 * A `sign_in` credential is its type alone (docs/design/relay-sign-in-in-vm.md §1: a subscription account with no secret,
 * sealed as it is and signed in inside the VM with `gray-assistant login`): its empty value is its form, which the
 * format rule holds it to, never a missing secret. Read as one, no kit could seal such an account, and `deliver` and
 * `accounts push` refused a relay whose accounts were all subscriptions (`no_account_sealed`; roteo, 2026-11-14).
 */
export function credentialParkReason(vendor: Vendor, credential: Credential): ParkReason | null {
  if (typeof credential.value !== "string") return "missing_credential";
  if (credential.value.length === 0 && credential.type !== "sign_in") return "missing_credential";
  try {
    assertCredentialFormat(vendor, credential);
    return null;
  } catch (error) {
    if (error instanceof RelayConnectorError) return "invalid_credential_format";
    return "credential_unreadable";
  }
}

/**
 * What `invalid_credential_format` asks of a credential, for `doctor` and `deliver` to print beside it. The validator
 * (`assertCredentialFormat`) refuses with one closed reason and does not say which part failed, so this names the
 * form, never the value.
 */
export function credentialFormatHint(vendor: Vendor, type: string): string {
  if (vendor === "chatgpt_codex" && type === "oauth_access_token") {
    return "a chatgpt_codex oauth_access_token is a JWT whose payload has an integer exp and the https://api.openai.com/auth object with chatgpt_account_id (the integration standard, section 8)";
  }
  return `the value does not have the ${vendor} ${type} format (the integration standard, section 8)`;
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

/**
 * The sealed egress member for one source account, or `"invalid"` when the source's fields fail the
 * connector's own E2 rules. The password is the one secret half of the proxy (K4-1); a username with
 * no declared password is sealed with an empty password, which is the one wire form E2 has for it.
 * Nothing here logs or returns a value in an error.
 */
export function egressOf(planned: PlannedAccount, read: SourceCredential): EgressSpec | undefined | "invalid" {
  const declared = planned.account.egress;
  if (declared === undefined) {
    // A password without a declared proxy has no wire form.
    return read.egressPassword === undefined ? undefined : "invalid";
  }
  if (declared.username === undefined && read.egressPassword !== undefined) return "invalid";
  const candidate = {
    type: declared.type,
    host: declared.host,
    port: declared.port,
    ...(declared.username === undefined ? {} : { username: declared.username, password: read.egressPassword ?? "" }),
  };
  const parsed = egressSchema.safeParse(candidate);
  return parsed.success ? parsed.data : "invalid";
}

/**
 * The proxy a source account declares, as the agent status reports it (`DaemonSourceAccount.proxy`): its type, host and
 * port only, null for none, undefined when those fail the connector's own rules (it would not be sealed).
 */
export function sourceProxyOf(declared: SourceEgress | undefined): DaemonSourceProxy | null | undefined {
  if (declared === undefined) return null;
  const parsed = egressSchema.safeParse({ type: declared.type, host: declared.host, port: declared.port });
  return parsed.success ? { type: parsed.data.type, host: parsed.data.host, port: parsed.data.port } : undefined;
}

/** R04: a source error that names one account, so the rest of the bundle can still install. */
export function isPerAccountSourceError(error: unknown): boolean {
  return error instanceof RelayKitError && (error.code === "source_not_found" || error.code === "source_shape_changed");
}

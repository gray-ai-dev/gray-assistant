/**
 * The relay's accounts read once for a phase-2 delivery (`deliver`, `accounts push`; docs/design/relay-no-always-on-host.md
 * §3.3, H7): the source in `gray-assistant.jsonc` listed and each account's secret read a single time, under the ids the
 * relay-stack origin holds them by, exactly as the agent's credential intake builds its bundle for that origin:
 *
 * - each account is planned (`planAccount`) and checked on its metadata first (`metadataParkReason`);
 * - its id is its panel id: the source's own id when the panel takes it, else its alias (S59), given here at first sight
 *   and kept in `account-aliases.json` before it is used, as the agent does, so an id that reached Gray is never given
 *   again;
 * - its secret is read and held to the TEE's own format rule (`credentialParkReason`), its proxy to the connector's
 *   (`egressOf`); a per-account read failure skips that account, a source-wide one fails the read.
 *
 * A skipped account is named by its panel id when it has one, else only by its vendor (a source id may be an e-mail
 * address), with a closed reason. Nothing here prints or logs a secret.
 */
import type { Account, Vendor } from "@gray/relay-connector";
import { RelayKitError } from "../errors.ts";
import { newAccountAliases, panelIdLookup, type AccountAliasStore } from "../daemon/account-aliases.ts";
import { egressOf, isPerAccountSourceError } from "../daemon/daemon.ts";
import { credentialParkReason, metadataParkReason, planAccount } from "../daemon/eligibility.ts";
import type { SourceAdapter, SourceCredential } from "../source/types.ts";
import type { LoadedRelayConfig } from "./config-file.ts";

/** One account the read left out, and why (a closed word). */
export interface SkippedAccount {
  readonly vendor: Vendor;
  readonly panelId: string | null;
  readonly reason: "unsupported_credential_type" | "invalid_credential_format" | "invalid_egress_format" | "credential_unreadable" | "missing_credential" | "no_panel_id";
}

export interface ReadAccounts {
  /** The bundle's accounts, by panel id, sorted. */
  readonly accounts: readonly Account[];
  readonly skipped: readonly SkippedAccount[];
  /** How many accounts the source listed. */
  readonly listed: number;
}

export interface ReadAccountsDeps {
  readonly adapter: SourceAdapter;
  readonly aliases: AccountAliasStore;
  readonly nowMs: number;
  readonly signal: AbortSignal;
}

/** Read the source once (see the module comment). Throws RelayKitError on a source-wide failure. */
export async function readAccountsOnce(config: LoadedRelayConfig, deps: ReadAccountsDeps): Promise<ReadAccounts> {
  const { adapter, signal } = deps;
  const snapshot = await adapter.list(signal);
  const seen = new Set<string>();
  for (const account of snapshot.accounts) {
    if (seen.has(account.sourceId)) throw new RelayKitError("source_shape_changed", "the source lists one account id twice");
    seen.add(account.sourceId);
  }
  const planned = snapshot.accounts.map((account) => planAccount(config.daemon.relayId, adapter.kind, account));
  const kept = await deps.aliases.read();
  if (kept === null) throw new RelayKitError("io", "account-aliases.json beside the state file does not read; nothing was sent (fix or restore it, never delete it: it holds the panel ids Gray knows)");
  const added = newAccountAliases(kept, planned.map((p) => ({ vendor: p.vendor, sourceId: p.account.sourceId })), deps.nowMs);
  if (added.length > 0) await deps.aliases.write([...kept, ...added]);
  const panelId = panelIdLookup([...kept, ...added]);

  const accounts: Account[] = [];
  const skipped: SkippedAccount[] = [];
  for (const entry of planned) {
    const id = panelId(entry.vendor, entry.account.sourceId);
    const skip = (reason: SkippedAccount["reason"]): void => void skipped.push({ vendor: entry.vendor, panelId: id, reason });
    const metadata = metadataParkReason(entry.account);
    if (metadata !== null) {
      skip(metadata);
      continue;
    }
    if (id === null) {
      skip("no_panel_id");
      continue;
    }
    let read: SourceCredential;
    try {
      read = await adapter.credential(entry.account.sourceId, signal);
    } catch (error) {
      if (isPerAccountSourceError(error)) {
        skip("credential_unreadable");
        continue;
      }
      throw error;
    }
    const reason = credentialParkReason(entry.vendor, read.credential);
    if (reason !== null) {
      skip(reason);
      continue;
    }
    const egress = egressOf(entry, read);
    if (egress === "invalid") {
      skip("invalid_egress_format");
      continue;
    }
    accounts.push({ account_id: id, vendor: entry.vendor, credential: read.credential, ...(egress === undefined ? {} : { egress }) });
  }
  accounts.sort((left, right) => (left.account_id < right.account_id ? -1 : left.account_id > right.account_id ? 1 : 0));
  return { accounts, skipped, listed: snapshot.accounts.length };
}

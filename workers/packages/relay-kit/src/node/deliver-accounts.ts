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
 * Tokens the VM's egress refreshed (`refreshed`, asked of the VM first) are written back to the source before its
 * secrets are read: a full bundle replaces the VM's refreshed token, so sealing the source's older one would undo the
 * refresh (OpenAI rotated its refresh token). When the VM could not be asked, a credential that carries a refresh token
 * (one Gray refreshes in the VM) refuses the whole read.
 *
 * A skipped account is named by its panel id when it has one, else only by its vendor (a source id may be an e-mail
 * address), with a closed reason. Nothing here prints or logs a secret.
 */
import type { Account, RefreshedToken, Vendor } from "@gray/relay-connector";
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
  /** The credential's type, once its secret was read (`credentialFormatHint` names the form it needs). */
  readonly credentialType?: string;
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
  /** The tokens the VM's egress refreshed, by panel id; `unavailable` when the VM could not be asked. Absent: none. */
  readonly refreshed?: readonly RefreshedToken[] | "unavailable";
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
    const skip = (reason: SkippedAccount["reason"], credentialType?: string): void =>
      void skipped.push({ vendor: entry.vendor, panelId: id, reason, ...(credentialType === undefined ? {} : { credentialType }) });
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
      const newer = deps.refreshed === "unavailable" ? undefined : deps.refreshed?.find((token) => token.account_id === id);
      if (newer !== undefined && adapter.writeCredential !== undefined) await adapter.writeCredential(entry.account.sourceId, newer.credential, signal);
      read = await adapter.credential(entry.account.sourceId, signal);
    } catch (error) {
      if (isPerAccountSourceError(error)) {
        skip("credential_unreadable");
        continue;
      }
      throw error;
    }
    if (deps.refreshed === "unavailable" && read.credential.refresh_token !== undefined) {
      throw new RelayKitError("io", `the VM's refreshed tokens could not be read, and ${id} is refreshed in the VM: sealing this host's copy would undo its refresh; nothing was sent, run the command again`);
    }
    const reason = credentialParkReason(entry.vendor, read.credential);
    if (reason !== null) {
      skip(reason, read.credential.type);
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

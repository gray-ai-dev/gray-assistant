/**
 * The local page's view of the `file` source (`../source/file.ts`) and its three edits: add an account, replace an
 * account's credential, remove an account.
 *
 * Every edit runs under `<accounts.json>.lock` (the CLI's control lock), reads the file as a private file, changes only
 * the one member it means with jsonc-parser's `modify` (so the operator's own layout and every other entry stay byte
 * for byte), checks the result with the file source's own parser, which is the agent's, and replaces the file by an
 * atomic rename as 0600. A result the agent would refuse is never written. The agent's next source poll sees the new
 * entry's change mark and seals it with a version of its own ledger, so nothing here picks a version.
 *
 * Nothing returned here carries a credential, a proxy password or a change mark; refusals name a member, never a value.
 */
import { accessSync, constants, existsSync } from "node:fs";
import { dirname } from "node:path";
import { get, parseStrict, type Json } from "@gray/json";
import { RESOURCE_ID, RelayConnectorError, VENDORS, assertCredentialFormat, credentialClass, type CredentialType, type Vendor } from "@gray/relay-connector";
import { applyEdits, modify, type FormattingOptions } from "jsonc-parser";
import { RelayKitError } from "../../errors.ts";
import type { SourceEgress } from "../../source/types.ts";
import { acquireControlLock } from "../control-lock.ts";
import { writeAtomicPrivateFile } from "../daemon/atomic-file.ts";
import { readPrivateFile } from "../files.ts";
import { LOGIN_NAME, type LoginRecord } from "../login/record.ts";
import type { ResolvedSourceConfig, SourceFileConfig } from "../source/config-types.ts";
import { parseEgressUrl } from "../source/egress.ts";
import { parseAccountsSourceText } from "../source/file.ts";
import { MAX_SOURCE_FILE_BYTES, MODEL_ID } from "../source/limits.ts";
import { selectedBy } from "../source/select.ts";
import { UiRefusal } from "./refusal.ts";

/** How a credential reaches the account: a pasted secret, or one of the relay's own logins. */
export type UiCredentialType = CredentialType | "oauth_login";

/** One account as the page lists it. */
export interface UiAccount {
  readonly accountId: string;
  readonly vendor: Vendor;
  readonly credentialType: UiCredentialType;
  /** The relay login an `oauth_login` credential names; null otherwise. */
  readonly login: string | null;
  /** The status the entry sets (`active` when it sets none). */
  readonly status: string;
  readonly models: readonly string[] | "*";
  /** The proxy's metadata; its password stays in the file. */
  readonly proxy: SourceEgress | null;
  /** When the credential the entry holds (or its login's access token) expires, when known. */
  readonly credentialExpiresAtMs: number | null;
  /** Whether the config's `source.select` lets the agent serve it. */
  readonly selected: boolean;
}

/** What the page shows for the source: where accounts come from and whether this page can change them. */
export interface UiAccountsView {
  readonly kind: ResolvedSourceConfig["kind"];
  /** `file` only: the accounts file. */
  readonly path: string | null;
  /** `http`/`cliproxyapi` only: the software the agent reads accounts from. */
  readonly url: string | null;
  /** The file exists; false before the first account is added. */
  readonly exists: boolean;
  /** This process can replace the file (its directory is writable). */
  readonly writable: boolean;
  /** Why the file cannot be read, as one closed code and the member it names; null when it reads. */
  readonly problem: { readonly code: string; readonly detail: string } | null;
  readonly accounts: readonly UiAccount[];
}

/** An account to add, as the page sends it. */
export interface NewAccountInput {
  readonly accountId: string;
  readonly vendor: Vendor;
  /** A pasted secret, or the relay login the account will use. */
  readonly credential: { readonly type: CredentialType; readonly value: string } | { readonly type: "oauth_login"; readonly login: string };
  /** Null: every model of the vendor. */
  readonly models: readonly string[] | null;
  /** A proxy URL (`socks5://user:password@host:port`); null for none. */
  readonly proxy: string | null;
}

/** A refusal the page shows beside one field: the field and a closed code, never the value. */
function fieldRefusal(field: "account_id" | "vendor" | "credential" | "login" | "models" | "proxy", code: string): UiRefusal {
  return new UiRefusal(422, code, field);
}

const FORMATTING: FormattingOptions = { insertSpaces: true, tabSize: 2, eol: "\n" };

function fileConfig(source: ResolvedSourceConfig): SourceFileConfig {
  if (source.kind !== "file") throw new UiRefusal(409, "source_not_file");
  return source;
}

function directoryWritable(path: string): boolean {
  try {
    accessSync(dirname(path), constants.W_OK);
    return existsSync(path) ? (accessSync(path, constants.R_OK), true) : true;
  } catch {
    return false;
  }
}

function text(value: Json | undefined): string | null {
  return typeof value === "string" ? value : null;
}

/** List the source's accounts for the page; a `file` source is read here, a remote one is only named. */
export function readAccountsView(
  source: ResolvedSourceConfig,
  options: { readonly readLogin?: (name: string) => LoginRecord | null; readonly nowMs: number },
): UiAccountsView {
  if (source.kind !== "file") {
    return { kind: source.kind, path: null, url: source.url, exists: true, writable: false, problem: null, accounts: [] };
  }
  const writable = directoryWritable(source.path);
  if (!existsSync(source.path)) return { kind: "file", path: source.path, url: null, exists: false, writable, problem: null, accounts: [] };
  let raw: string;
  try {
    raw = readPrivateFile(source.path, "source accounts file", MAX_SOURCE_FILE_BYTES);
  } catch (error) {
    const code = error instanceof RelayKitError ? error.code : "io";
    return { kind: "file", path: source.path, url: null, exists: true, writable, problem: { code, detail: "accounts file" }, accounts: [] };
  }
  let parsed;
  try {
    parsed = parseAccountsSourceText(raw, {
      maxAccounts: source.maxAccounts,
      ...(options.readLogin === undefined ? {} : { readLogin: options.readLogin }),
      nowMs: options.nowMs,
      loginServeMarginSeconds: source.logins.serveMarginSeconds,
    });
  } catch (error) {
    const known = error instanceof RelayKitError;
    return { kind: "file", path: source.path, url: null, exists: true, writable, problem: { code: known ? error.code : "source_bad_response", detail: known ? (error.detail ?? "accounts") : "accounts" }, accounts: [] };
  }
  // The document parsed with the agent's own rules, so each entry's members are well formed.
  const entries = (get(parseStrict(raw), "accounts") ?? []) as Json[];
  const accounts: UiAccount[] = [];
  for (const [index, account] of parsed.accounts.entries()) {
    const entry = entries[index];
    const credential = get(entry, "credential");
    const type = text(get(credential, "type")) as UiCredentialType;
    accounts.push({
      accountId: account.sourceId,
      vendor: account.vendor,
      credentialType: type,
      login: type === "oauth_login" ? text(get(credential, "login")) : null,
      status: text(get(entry, "status")) ?? "active",
      models: account.models,
      proxy: account.egress ?? null,
      credentialExpiresAtMs: account.credentialExpiresAtMs ?? null,
      selected: selectedBy(source.select, account),
    });
  }
  return { kind: "file", path: source.path, url: null, exists: true, writable, problem: null, accounts };
}

/** Check one new account's members; refusals name the field and a closed code, never the value. */
function newEntry(input: NewAccountInput): Record<string, unknown> {
  if (!RESOURCE_ID.test(input.accountId)) throw fieldRefusal("account_id", "invalid");
  if (!(VENDORS as readonly string[]).includes(input.vendor)) throw fieldRefusal("vendor", "invalid");
  let credential: Record<string, unknown>;
  if (input.credential.type === "oauth_login") {
    if (input.vendor !== "chatgpt_codex") throw fieldRefusal("credential", "login_vendor");
    if (!LOGIN_NAME.test(input.credential.login)) throw fieldRefusal("login", "invalid");
    credential = { type: "oauth_login", login: input.credential.login };
  } else {
    credential = checkedCredential(input.vendor, input.credential);
  }
  const entry: Record<string, unknown> = { account_id: input.accountId, vendor: input.vendor, credential };
  if (input.models !== null) {
    if (input.models.length === 0 || input.models.length > 256 || input.models.some((model) => !MODEL_ID.test(model))) throw fieldRefusal("models", "invalid");
    entry["models"] = [...new Set(input.models)];
  }
  if (input.proxy !== null) {
    let proxy;
    try {
      proxy = parseEgressUrl(input.proxy, "proxy");
    } catch {
      throw fieldRefusal("proxy", "invalid");
    }
    entry["egress"] = {
      type: proxy.egress.type,
      host: proxy.egress.host,
      port: proxy.egress.port,
      ...(proxy.egress.username === undefined ? {} : { username: proxy.egress.username }),
      ...(proxy.password === undefined ? {} : { password: proxy.password }),
    };
  }
  return entry;
}

/** A pasted secret, checked with the TEE's own format rule for its vendor (`invalid_credential` names no value). */
function checkedCredential(vendor: Vendor, credential: { readonly type: CredentialType; readonly value: string }): Record<string, unknown> {
  const value = credential.value.trim();
  if (credentialClass(vendor, credential.type) === null) throw fieldRefusal("credential", "type_vendor");
  try {
    assertCredentialFormat(vendor, { type: credential.type, value });
  } catch (error) {
    if (error instanceof RelayConnectorError) throw fieldRefusal("credential", "format");
    throw error;
  }
  return { type: credential.type, value };
}

/** The index of an account in the document, or -1. */
function indexOf(document: Json, accountId: string): number {
  const entries = get(document, "accounts");
  if (!Array.isArray(entries)) return -1;
  return entries.findIndex((entry) => get(entry, "account_id") === accountId);
}

/**
 * Edit the accounts file under its lock: read it (or start a new document for the config's relay), apply `edit`,
 * check the result as the agent will, write it atomically as 0600.
 */
async function editAccountsFile(source: ResolvedSourceConfig, relayId: string, edit: (text: string, document: Json) => string): Promise<void> {
  const config = fileConfig(source);
  if (!directoryWritable(config.path)) throw new UiRefusal(409, "source_read_only");
  const lock = await acquireControlLock(`${config.path}.lock`);
  try {
    const current = existsSync(config.path)
      ? readPrivateFile(config.path, "source accounts file", MAX_SOURCE_FILE_BYTES)
      : `{\n  "relay_id": ${JSON.stringify(relayId)},\n  "accounts": []\n}\n`;
    let document: Json;
    try {
      document = parseStrict(current);
    } catch {
      throw new UiRefusal(409, "source_unreadable");
    }
    // A file the agent refuses now is not one to edit: the operator fixes it first.
    try {
      parseAccountsSourceText(current, { maxAccounts: config.maxAccounts });
    } catch {
      throw new UiRefusal(409, "source_unreadable");
    }
    const next = edit(current, document);
    // The edit's own result: refused only for a value the field checks above did not catch (a limit, a duplicate).
    try {
      parseAccountsSourceText(next, { maxAccounts: config.maxAccounts });
    } catch (error) {
      throw new UiRefusal(422, "refused_by_source", null, error instanceof RelayKitError ? error.detail : null);
    }
    writeAtomicPrivateFile(config.path, next.endsWith("\n") ? next : `${next}\n`);
  } finally {
    lock.release();
  }
}

/** Add one account at the end of the list. */
export async function addAccount(source: ResolvedSourceConfig, relayId: string, input: NewAccountInput): Promise<void> {
  const entry = newEntry(input);
  await editAccountsFile(source, relayId, (current, document) => {
    if (indexOf(document, input.accountId) >= 0) throw fieldRefusal("account_id", "taken");
    return applyEdits(current, modify(current, ["accounts", -1], entry, { isArrayInsertion: true, formattingOptions: FORMATTING }));
  });
}

/**
 * What `gray-assistant login codex` does for the account its login serves, so the operator never writes accounts.json's
 * entry by hand under the panel's ID (2026-10-31's manual step 12). `add`: no entry names the login (or `--account`
 * names a further one) and the ID is free, so the sign-in ends with `addAccount`; `named`: the account is there already
 * (a second sign-in, or the page added it first); `by_hand`: this process cannot change the file (read-only, or one the
 * agent refuses), so the sign-in goes on and the operator adds the entry. An ID another entry holds is refused before
 * the sign-in, so no one-time code is spent on it.
 */
export type LoginAccountPlan =
  | { readonly kind: "add"; readonly accountId: string }
  | { readonly kind: "named"; readonly accountIds: readonly string[] }
  | { readonly kind: "by_hand"; readonly accountId: string; readonly code: string };

/** `account` is `--account`, or null for the default: the login's own name. */
export function loginAccountPlan(view: UiAccountsView, login: string, account: string | null): LoginAccountPlan {
  const accountId = account ?? login;
  if (!RESOURCE_ID.test(accountId)) throw new RelayKitError("usage", "--account must be the account's ID in Gray's panel ([A-Za-z0-9._:-]{1,128})");
  if (view.problem !== null) return { kind: "by_hand", accountId, code: view.problem.code };
  const named = view.accounts.filter((entry) => entry.login === login).map((entry) => entry.accountId);
  if (named.includes(accountId) || (account === null && named.length > 0)) return { kind: "named", accountIds: named };
  if (view.accounts.some((entry) => entry.accountId === accountId)) {
    throw new RelayKitError("usage", `accounts.json has an account ${accountId} with another credential; pass --account with the panel's ID of the account this login serves`);
  }
  if (!view.writable) return { kind: "by_hand", accountId, code: "source_read_only" };
  return { kind: "add", accountId };
}

/** Replace the credential of one account that holds a pasted secret. */
export async function replaceCredential(
  source: ResolvedSourceConfig,
  relayId: string,
  accountId: string,
  credential: { readonly type: CredentialType; readonly value: string },
): Promise<void> {
  await editAccountsFile(source, relayId, (current, document) => {
    const index = indexOf(document, accountId);
    if (index < 0) throw new UiRefusal(404, "account_not_found");
    const entries = get(document, "accounts") as Json[];
    const vendor = get(entries[index], "vendor") as Vendor;
    if (get(get(entries[index], "credential"), "type") === "oauth_login") throw fieldRefusal("credential", "login_account");
    return applyEdits(current, modify(current, ["accounts", index, "credential"], checkedCredential(vendor, credential), { formattingOptions: FORMATTING }));
  });
}

/** Remove one account; the agent revokes it from every replica at its next poll. */
export async function removeAccount(source: ResolvedSourceConfig, relayId: string, accountId: string): Promise<void> {
  await editAccountsFile(source, relayId, (current, document) => {
    const index = indexOf(document, accountId);
    if (index < 0) throw new UiRefusal(404, "account_not_found");
    return applyEdits(current, modify(current, ["accounts", index], undefined, { formattingOptions: FORMATTING }));
  });
}

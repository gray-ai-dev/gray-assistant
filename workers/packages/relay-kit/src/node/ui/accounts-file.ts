/**
 * The local page's view of the `file` source (`../source/file.ts`) and its edits: add an account, replace an
 * account's credential, remove an account, and the file's proxy list (docs/design/relay-operator-page.md section 6):
 * list it, add to it, remove from it, give accounts one of its entries, add several API-key accounts at once. The
 * page and the commands (`gray-assistant proxies`, `accounts proxy`, `accounts add`) call the same functions.
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
import type { ResolvedSourceConfig, SourceFileConfig } from "../source/config-types.ts";
import { parseEgressUrl, parseEgressValue, type ParsedEgress } from "../source/egress.ts";
import { isProxyId, parseAccountsSourceText } from "../source/file.ts";
import { MAX_SOURCE_FILE_BYTES, MODEL_ID } from "../source/limits.ts";
import { selectedBy } from "../source/select.ts";
import { UiRefusal } from "./refusal.ts";

/** The credential type an entry names. */
export type UiCredentialType = CredentialType;

/** One account as the page lists it. */
export interface UiAccount {
  readonly accountId: string;
  readonly vendor: Vendor;
  readonly credentialType: UiCredentialType;
  /** The status the entry sets (`active` when it sets none). */
  readonly status: string;
  readonly models: readonly string[] | "*";
  /** The proxy's metadata; its password stays in the file. */
  readonly proxy: SourceEgress | null;
  /** The entry of the file's proxy list the account names; null for none or an inline `egress`. */
  readonly proxyId: string | null;
  /** When the credential the entry holds expires, when known. */
  readonly credentialExpiresAtMs: number | null;
  /** Whether the config's `source.select` lets the agent serve it. */
  readonly selected: boolean;
}

/** What the page shows for the source: where accounts come from and whether this page can change them. */
export interface UiAccountsView {
  readonly kind: ResolvedSourceConfig["kind"];
  /** `file` only: the accounts file. */
  readonly path: string | null;
  /** `http` only: the software the agent reads accounts from. */
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
  /** A pasted secret. */
  readonly credential: { readonly type: CredentialType; readonly value: string };
  /** Null: every model of the vendor. */
  readonly models: readonly string[] | null;
  /** A proxy URL (`socks5://user:password@host:port`), or the id of an entry of the file's proxy list; null for none. */
  readonly proxy: string | null;
}

/** A refusal the page shows beside one field: the field and a closed code, never the value. */
function fieldRefusal(
  field: "account_id" | "account_ids" | "vendor" | "credential" | "models" | "proxy" | "proxy_id" | "keys" | "id_prefix",
  code: string,
  detail: string | null = null,
): UiRefusal {
  return new UiRefusal(422, code, field, detail);
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
export function readAccountsView(source: ResolvedSourceConfig): UiAccountsView {
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
    parsed = parseAccountsSourceText(raw, { maxAccounts: source.maxAccounts });
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
      status: text(get(entry, "status")) ?? "active",
      models: account.models,
      proxy: account.egress ?? null,
      proxyId: text(get(entry, "proxy")),
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
  const credential = checkedCredential(input.vendor, input.credential);
  const entry: Record<string, unknown> = { account_id: input.accountId, vendor: input.vendor, credential };
  if (input.models !== null) {
    if (input.models.length === 0 || input.models.length > 256 || input.models.some((model) => !MODEL_ID.test(model))) throw fieldRefusal("models", "invalid");
    entry["models"] = [...new Set(input.models)];
  }
  // A list id has no `/`, a URL always has one, so the text is one or the other (as `ensureSignInAccount` reads it).
  if (input.proxy !== null) {
    if (isProxyId(input.proxy)) entry["proxy"] = input.proxy;
    else entry["egress"] = egressEntry(input.proxy);
  }
  return entry;
}

/** A proxy URL as the file's `egress` member; a URL that does not read is the `proxy` field's refusal, never its value. */
function egressEntry(url: string, detail: string | null = null): Record<string, string | number> {
  try {
    return egressMembers(parseEgressUrl(url, "proxy"));
  } catch {
    throw fieldRefusal("proxy", "invalid", detail);
  }
}

/** A read proxy as the file writes it: an `egress` member, or a list entry without its id. */
function egressMembers(proxy: ParsedEgress): Record<string, string | number> {
  return {
    type: proxy.egress.type,
    host: proxy.egress.host,
    port: proxy.egress.port,
    ...(proxy.egress.username === undefined ? {} : { username: proxy.egress.username }),
    ...(proxy.password === undefined ? {} : { password: proxy.password }),
  };
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
    if (typeof entry["proxy"] === "string" && proxyIndex(document, entry["proxy"]) < 0) throw fieldRefusal("proxy", "unknown");
    return applyEdits(current, modify(current, ["accounts", -1], entry, { isArrayInsertion: true, formattingOptions: FORMATTING }));
  });
}

/** What `ensureSignInAccount` did to the file. */
export type SignInAccountChange = "added" | "proxy_set" | "unchanged";

/**
 * A subscription account as a `sign_in` account of the file source (no token: it is signed in inside the VM), for
 * `gray-assistant login <account> --vendor <vendor> [--proxy <url>]`. An account the file does not name is added at the
 * end. One it names must already be that vendor's `sign_in` account (`account_id` `taken` otherwise: this never turns
 * an account with a key or a token into another kind); a proxy given here then replaces its proxy, and none given
 * leaves it as it is. The proxy is a URL, written as the account's own `egress`, or the id of an entry of the file's
 * proxy list, written as its `proxy` (an id the list lacks is the `proxy` field's `unknown`). Refusals name the field
 * and a closed code, never a value.
 */
export async function ensureSignInAccount(
  source: ResolvedSourceConfig,
  relayId: string,
  input: { readonly accountId: string; readonly vendor: Vendor; readonly proxy: string | null },
): Promise<SignInAccountChange> {
  if (!RESOURCE_ID.test(input.accountId)) throw fieldRefusal("account_id", "invalid");
  if (!(VENDORS as readonly string[]).includes(input.vendor) || credentialClass(input.vendor, "sign_in") === null) throw fieldRefusal("vendor", "no_sign_in");
  // A list id has no `/`, a URL always has one, so the text is one or the other.
  const proxyId = input.proxy !== null && isProxyId(input.proxy) ? input.proxy : null;
  const egress = input.proxy === null || proxyId !== null ? null : egressEntry(input.proxy);
  let change: SignInAccountChange = "unchanged";
  await editAccountsFile(source, relayId, (current, document) => {
    if (proxyId !== null && proxyIndex(document, proxyId) < 0) throw fieldRefusal("proxy", "unknown");
    const index = indexOf(document, input.accountId);
    if (index < 0) {
      change = "added";
      const entry = { account_id: input.accountId, vendor: input.vendor, credential: { type: "sign_in" }, ...(egress === null ? {} : { egress }), ...(proxyId === null ? {} : { proxy: proxyId }) };
      return applyEdits(current, modify(current, ["accounts", -1], entry, { isArrayInsertion: true, formattingOptions: FORMATTING }));
    }
    const listed = (get(document, "accounts") as Json[])[index];
    if (get(listed, "vendor") !== input.vendor || get(get(listed, "credential"), "type") !== "sign_in") throw fieldRefusal("account_id", "taken");
    if (proxyId !== null) {
      if (get(listed, "proxy") === proxyId) return current;
      change = "proxy_set";
      return withProxy(current, index, listed, proxyId);
    }
    if (egress === null) return current;
    const now = get(listed, "egress");
    const same = now !== undefined && (["type", "host", "username", "password"] as const).every((member) => get(now, member) === egress[member]) && Number(get(now, "port")) === egress["port"];
    if (same) return current;
    change = "proxy_set";
    // An account names `proxy` or `egress`, never both: the URL given takes the place of a list entry it named.
    const text = get(listed, "proxy") === undefined ? current : applyEdits(current, modify(current, ["accounts", index, "proxy"], undefined, { formattingOptions: FORMATTING }));
    return applyEdits(text, modify(text, ["accounts", index, "egress"], egress, { formattingOptions: FORMATTING }));
  });
  return change;
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

// The proxy list (docs/design/relay-operator-page.md section 6).

/** One entry of the file's proxy list as the page and `gray-assistant proxies` show it: never its password. */
export interface UiProxy {
  readonly id: string;
  readonly type: SourceEgress["type"];
  readonly host: string;
  readonly port: number;
  readonly username: string | null;
  /** Whether the entry holds a password; the password itself stays in the file. */
  readonly hasPassword: boolean;
  /** The accounts that name it, in the file's order. */
  readonly usedBy: readonly string[];
}

/** A proxy to add: its URL (`scheme://[user:password@]host:port`) or its members; `id` when the caller names it. */
export type NewProxyInput =
  | string
  | { readonly id?: string; readonly url: string }
  | { readonly id?: string; readonly type: SourceEgress["type"]; readonly host: string; readonly port: number; readonly username?: string; readonly password?: string };

/** What `addProxies` did with one input: the entry's id, and whether it is new to the list. */
export interface AddedProxy {
  readonly id: string;
  readonly added: boolean;
}

/** Several API-key accounts to add at once. */
export interface KeyAccountsInput {
  readonly vendor: Vendor;
  /** Pasted API keys, one an account; a blank one is passed over. */
  readonly keys: readonly string[];
  /** The entry of the file's proxy list every one of them leaves through; null for none. */
  readonly proxyId: string | null;
  /** The new ids are `<prefix>-<n>`; null: the vendor. */
  readonly idPrefix: string | null;
}

/** The start of a derived account id: `<prefix>-<n>` stays an account id with room for the number. */
const ID_PREFIX = /^[A-Za-z0-9._:-]{1,100}$/;

/** The index of a proxy in the document's list, or -1. */
function proxyIndex(document: Json, proxyId: string): number {
  const entries = get(document, "proxies");
  if (!Array.isArray(entries)) return -1;
  return entries.findIndex((entry) => get(entry, "id") === proxyId);
}

/** Point one account at a list entry (null: at none); an inline `egress` goes, as an account names one or the other. */
function withProxy(current: string, index: number, listed: Json | undefined, proxyId: string | null): string {
  const text = get(listed, "egress") === undefined ? current : applyEdits(current, modify(current, ["accounts", index, "egress"], undefined, { formattingOptions: FORMATTING }));
  return applyEdits(text, modify(text, ["accounts", index, "proxy"], proxyId ?? undefined, { formattingOptions: FORMATTING }));
}

/** The lowest `<prefix>-<n>` not taken, which is then taken. */
function nextId(prefix: string, taken: Set<string>): string {
  for (let n = 1; ; n += 1) {
    const id = `${prefix}-${n}`;
    if (taken.has(id)) continue;
    taken.add(id);
    return id;
  }
}

/** Two proxies are one when every member is equal, the password too; compared in memory, never returned. */
function proxyKey(members: Record<string, string | number>): string {
  return JSON.stringify([members["type"], members["host"], members["port"], members["username"] ?? null, members["password"] ?? null]);
}

/** The file's proxy list, each entry with the accounts that name it. Never a password: only whether one is set. */
export function listProxies(source: ResolvedSourceConfig): readonly UiProxy[] {
  const config = fileConfig(source);
  if (!existsSync(config.path)) return [];
  let raw: string;
  let parsed;
  try {
    raw = readPrivateFile(config.path, "source accounts file", MAX_SOURCE_FILE_BYTES);
    parsed = parseAccountsSourceText(raw, { maxAccounts: config.maxAccounts });
  } catch {
    throw new UiRefusal(409, "source_unreadable");
  }
  const usedBy = new Map<string, string[]>();
  for (const entry of (get(parseStrict(raw), "accounts") ?? []) as Json[]) {
    const proxyId = text(get(entry, "proxy"));
    if (proxyId !== null) usedBy.set(proxyId, [...(usedBy.get(proxyId) ?? []), get(entry, "account_id") as string]);
  }
  return parsed.proxies.map((proxy) => ({
    id: proxy.id,
    type: proxy.egress.type,
    host: proxy.egress.host,
    port: proxy.egress.port,
    username: proxy.egress.username ?? null,
    hasPassword: proxy.hasPassword,
    usedBy: usedBy.get(proxy.id) ?? [],
  }));
}

/**
 * Add proxies to the file's list, all or none. One given no id gets `proxy-<n>`; one equal in every member to an entry
 * the list has is not added again and answers that entry's id, so a list pasted twice adds nothing. A refusal names
 * the input by its place (`proxies.<n>`), never its value.
 */
export async function addProxies(source: ResolvedSourceConfig, relayId: string, proxies: readonly NewProxyInput[]): Promise<readonly AddedProxy[]> {
  if (proxies.length === 0) throw fieldRefusal("proxy", "empty");
  const wanted = proxies.map((input, index) => {
    const detail = `proxies.${index}`;
    const id = typeof input === "string" ? undefined : input.id;
    if (id !== undefined && !isProxyId(id)) throw fieldRefusal("proxy_id", "invalid", detail);
    if (typeof input === "string") return { id, members: egressEntry(input, detail) };
    if ("url" in input) return { id, members: egressEntry(input.url, detail) };
    try {
      const { id: _id, ...members } = input;
      return { id, members: egressMembers(parseEgressValue(members, "proxy")) };
    } catch {
      throw fieldRefusal("proxy", "invalid", detail);
    }
  });
  const out: AddedProxy[] = [];
  await editAccountsFile(source, relayId, (current, document) => {
    out.length = 0;
    const listed = ((get(document, "proxies") ?? []) as Json[]).map((entry) => {
      const { id, ...members } = entry as Record<string, Json>;
      return { id: id as string, key: proxyKey(egressMembers(parseEgressValue(members, "proxies"))) };
    });
    const taken = new Set(listed.map((entry) => entry.id));
    // A new list goes before the accounts, where a person reading the file looks for it.
    let next =
      get(document, "proxies") !== undefined
        ? current
        : applyEdits(current, modify(current, ["proxies"], [], { formattingOptions: FORMATTING, getInsertionIndex: (members) => (members.includes("accounts") ? members.indexOf("accounts") : members.length) }));
    for (const [index, want] of wanted.entries()) {
      const key = proxyKey(want.members);
      const same = listed.find((entry) => (want.id === undefined ? entry.key === key : entry.id === want.id));
      if (same !== undefined) {
        if (same.key !== key) throw fieldRefusal("proxy_id", "taken", `proxies.${index}`);
        out.push({ id: same.id, added: false });
        continue;
      }
      const id = want.id ?? nextId("proxy", taken);
      taken.add(id);
      listed.push({ id, key });
      next = applyEdits(next, modify(next, ["proxies", -1], { id, ...want.members }, { isArrayInsertion: true, formattingOptions: FORMATTING }));
      out.push({ id, added: true });
    }
    return out.some((proxy) => proxy.added) ? next : current;
  });
  return out;
}

/** Remove one proxy from the list; refused while an account names it (`proxy_in_use`, the detail names the accounts). */
export async function removeProxy(source: ResolvedSourceConfig, relayId: string, proxyId: string): Promise<void> {
  await editAccountsFile(source, relayId, (current, document) => {
    const index = proxyIndex(document, proxyId);
    if (index < 0) throw new UiRefusal(404, "proxy_not_found");
    const users = ((get(document, "accounts") ?? []) as Json[]).filter((entry) => get(entry, "proxy") === proxyId).map((entry) => get(entry, "account_id") as string);
    if (users.length > 0) throw new UiRefusal(409, "proxy_in_use", "proxy_id", `${users.slice(0, 10).join(",")}${users.length > 10 ? ",…" : ""}`);
    return applyEdits(current, modify(current, ["proxies", index], undefined, { formattingOptions: FORMATTING }));
  });
}

/**
 * Make accounts leave through one entry of the list, or through none (null: the VM's own address), all or none. An
 * inline `egress` an account had goes. Answers the accounts it changed; one that already was so is not among them. An
 * unknown account is named by its place in `accountIds`, never by the text given.
 */
export async function setAccountsProxy(source: ResolvedSourceConfig, relayId: string, accountIds: readonly string[], proxyId: string | null): Promise<readonly string[]> {
  if (accountIds.length === 0) throw fieldRefusal("account_ids", "empty");
  const changed: string[] = [];
  await editAccountsFile(source, relayId, (current, document) => {
    changed.length = 0;
    if (proxyId !== null && proxyIndex(document, proxyId) < 0) throw new UiRefusal(404, "proxy_not_found", "proxy_id");
    const entries = (get(document, "accounts") ?? []) as Json[];
    let next = current;
    for (const [at, accountId] of accountIds.entries()) {
      const index = indexOf(document, accountId);
      if (index < 0) throw new UiRefusal(404, "account_not_found", "account_ids", `account_ids.${at}`);
      const listed = entries[index];
      if (changed.includes(accountId) || ((get(listed, "proxy") ?? null) === proxyId && get(listed, "egress") === undefined)) continue;
      next = withProxy(next, index, listed, proxyId);
      changed.push(accountId);
    }
    return next;
  });
  return changed;
}

/**
 * Add one `api_key` account per key, all or none, at the end of the list: ids `<prefix>-<n>` from the lowest numbers
 * not taken, in the keys' order, each leaving through `proxyId` when one is given. A key is held to its vendor's form;
 * one given twice, or one an account of that vendor already holds, is refused. A refusal names a key by its place
 * (`keys.<n>`), never its value. Answers the new ids.
 */
export async function addKeyAccounts(source: ResolvedSourceConfig, relayId: string, input: KeyAccountsInput): Promise<readonly string[]> {
  if (!(VENDORS as readonly string[]).includes(input.vendor)) throw fieldRefusal("vendor", "invalid");
  if (credentialClass(input.vendor, "api_key") === null) throw fieldRefusal("vendor", "no_api_key");
  const prefix = input.idPrefix ?? input.vendor;
  if (!ID_PREFIX.test(prefix)) throw fieldRefusal("id_prefix", "invalid");
  if (input.proxyId !== null && !isProxyId(input.proxyId)) throw fieldRefusal("proxy_id", "invalid");
  const keys: { readonly at: number; readonly value: string }[] = [];
  for (const [at, key] of input.keys.entries()) {
    const value = key.trim();
    if (value === "") continue;
    try {
      assertCredentialFormat(input.vendor, { type: "api_key", value });
    } catch (error) {
      if (error instanceof RelayConnectorError) throw fieldRefusal("keys", "format", `keys.${at}`);
      throw error;
    }
    if (keys.some((seen) => seen.value === value)) throw fieldRefusal("keys", "duplicate", `keys.${at}`);
    keys.push({ at, value });
  }
  if (keys.length === 0) throw fieldRefusal("keys", "empty");
  const ids: string[] = [];
  await editAccountsFile(source, relayId, (current, document) => {
    ids.length = 0;
    if (input.proxyId !== null && proxyIndex(document, input.proxyId) < 0) throw new UiRefusal(404, "proxy_not_found", "proxy_id");
    const entries = (get(document, "accounts") ?? []) as Json[];
    const held = new Set(entries.filter((entry) => get(entry, "vendor") === input.vendor).map((entry) => get(get(entry, "credential"), "value")));
    const taken = new Set(entries.map((entry) => get(entry, "account_id") as string));
    let next = current;
    for (const key of keys) {
      if (held.has(key.value)) throw fieldRefusal("keys", "taken", `keys.${key.at}`);
      const id = nextId(prefix, taken);
      const entry = { account_id: id, vendor: input.vendor, credential: { type: "api_key", value: key.value }, ...(input.proxyId === null ? {} : { proxy: input.proxyId }) };
      next = applyEdits(next, modify(next, ["accounts", -1], entry, { isArrayInsertion: true, formattingOptions: FORMATTING }));
      ids.push(id);
    }
    return next;
  });
  return ids;
}

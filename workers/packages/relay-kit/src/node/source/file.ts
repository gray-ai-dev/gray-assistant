/**
 * The `file` source: relay-kit's `accounts.json`, extended with per-account metadata.
 *
 * ```json
 * {"relay_id":"relay-1","issued_at":1790000000,"expires_at":1790003600,
 *  "accounts":[
 *    {"account_id":"acc-1","vendor":"anthropic",
 *     "credential":{"type":"oauth_access_token","value":"sk-ant-oat01-…","expires_at":1790003600},
 *     "status":"active","models":["claude-sonnet-4-5"],"weight":2,"max_concurrency":4,
 *     "egress":{"type":"http","host":"127.0.0.1","port":3128,"username":"lane","password":"…"}}
 *  ]}
 * ```
 *
 * The file holds the secrets, so `list` necessarily reads them even though it returns only metadata.
 * `changeMark` is the SHA-256 of the account entry's canonical JSON bytes: a rewritten key order does
 * not change it, and the mark is opaque (it is never logged, and it is not the secret).
 *
 * A `chatgpt_codex` account may instead name one of the relay's own logins,
 * `"credential": {"type": "oauth_login", "login": "codex-relay-1"}` (`../login/record.ts`): the
 * token family is then in the agent's state volume, and the agent refreshes it itself
 * (`../login/refresher.ts`). Such an account is listed with the login's current access token as an
 * `oauth_access_token` and that token's expiry; its `changeMark` also covers the login record's
 * family, generation and failure, so every rotation is pushed. While the login is missing, broken,
 * failed, or within `logins.serve_margin` of its access token's expiry, the account is `disabled`
 * and `credential` refuses it (`source_not_found`), so an expired token is never sealed or picked.
 */
import { jcsBytes, sha256BareHex } from "@gray/attest";
import { parseStrict, type Json } from "@gray/json";
import {
  MAX_CREDENTIAL_LENGTH,
  MAX_PASSWORD_LENGTH,
  MAX_USERNAME_LENGTH,
  RESOURCE_ID,
  VENDORS,
  credentialClass,
  normalizeTotpSecret,
  type Credential,
  type Vendor,
} from "@gray/relay-connector";
import { z } from "zod";
import { RelayKitError } from "../../errors.ts";
import type { SourceAccount, SourceAccountStatus, SourceAdapter, SourceCredential, SourceEgress, SourceRefresh } from "../../source/types.ts";
import type { SourceFileConfig } from "./config-types.ts";
import { parseEgressValue, sourceEgressSchema } from "./egress.ts";
import { MAX_SOURCE_ACCOUNTS, MODEL_ID, U64_MAX } from "./limits.ts";
import { selectAccounts } from "./select.ts";
import { LOGIN_NAME, loginMark, loginUsable, type LoginRecord } from "../login/record.ts";

const integer = (minimum: bigint, maximum: bigint) =>
  z.union([z.bigint().min(minimum).max(maximum), z.number().int().min(Number(minimum)).max(Number(maximum))]);

const u64 = z.union([z.bigint().min(0n).max(U64_MAX), z.number().int().min(0).max(Number.MAX_SAFE_INTEGER)]);

const credentialSchema = z
  .object({
    type: z.enum(["api_key", "oauth_access_token"]),
    value: z.string().min(1).max(MAX_CREDENTIAL_LENGTH),
    expires_at: u64.optional(),
  })
  .strict();

/**
 * A ChatGPT account's sign-in, sealed so the relay's own software signs it in inside the VM
 * (docs/design/relay-in-cvm-login.md): the e-mail, the password as `value` and the optional TOTP secret, as an
 * authenticator app shows it (spaces and case do not matter). `@gray/relay-connector` checks the form when it is sealed.
 */
const passwordCredentialSchema = z
  .object({
    type: z.literal("password"),
    username: z.string().min(1).max(MAX_USERNAME_LENGTH),
    value: z.string().min(1).max(MAX_PASSWORD_LENGTH),
    totp_secret: z.string().min(1).max(256).optional(),
  })
  .strict();

/** A relay login the agent signs in and refreshes itself; no token in `accounts.json`. */
const loginCredentialSchema = z
  .object({
    type: z.literal("oauth_login"),
    login: z.string().regex(LOGIN_NAME),
  })
  .strict();

const accountSchema = z
  .object({
    account_id: z.string().regex(RESOURCE_ID),
    vendor: z.enum(VENDORS),
    credential: z.union([credentialSchema, loginCredentialSchema, passwordCredentialSchema]),
    status: z.enum(["active", "limited", "banned", "disabled"]).optional(),
    models: z.union([z.array(z.string().regex(MODEL_ID)).min(1).max(256), z.literal("*")]).optional(),
    weight: integer(1n, 1_000_000n).optional(),
    max_concurrency: integer(1n, 10_000n).optional(),
    egress: sourceEgressSchema.optional(),
  })
  .strict();

function throwIfAborted(signal: AbortSignal): void {
  if (signal.aborted) throw new RelayKitError("source_unreachable", "aborted");
}

const fileSchema = z
  .object({
    relay_id: z.string().regex(RESOURCE_ID),
    issued_at: u64.optional(),
    expires_at: u64.optional(),
    // R10: an empty list is valid. It is how the operator revokes the last account; refusing the
    // document kept the old snapshot (and the account serving) until its lease ended.
    accounts: z.array(z.unknown()).max(MAX_SOURCE_ACCOUNTS),
  })
  .strict();

/** One parsed `accounts.json`: metadata for the daemon, and the secret by id for the push path. */
export interface ParsedAccountsFile {
  readonly relayId: string;
  readonly accounts: readonly SourceAccount[];
  credentialOf(sourceId: string): SourceCredential | null;
}

export interface ParseAccountsOptions {
  readonly maxAccounts: number;
  /**
   * Reads a relay login for an `oauth_login` credential: null when it was never signed in, a throw
   * when it is broken. Absent, every such account is `disabled`.
   */
  readonly readLogin?: (name: string) => LoginRecord | null;
  /** The wall clock, for a login's serve margin. Required with `readLogin`. */
  readonly nowMs?: number;
  /** `logins.serve_margin`: an access token this close to its expiry is not served. */
  readonly loginServeMarginSeconds?: number;
}

/** What one login-backed entry resolves to: its usable credential (or none) and its mark. */
interface LoginResolution {
  readonly credential: Credential | null;
  readonly expiresAtMs: number | undefined;
  readonly mark: string;
}

function resolveLogin(name: string, options: ParseAccountsOptions): LoginResolution {
  if (options.readLogin === undefined) return { credential: null, expiresAtMs: undefined, mark: "unconfigured" };
  let record: LoginRecord | null;
  try {
    record = options.readLogin(name);
  } catch {
    return { credential: null, expiresAtMs: undefined, mark: "unreadable" };
  }
  if (record === null) return { credential: null, expiresAtMs: undefined, mark: "missing" };
  const nowSecs = Math.floor((options.nowMs ?? 0) / 1000);
  const usable = loginUsable(record, nowSecs, options.loginServeMarginSeconds ?? 0);
  return {
    credential: usable ? { type: "oauth_access_token", value: record.accessToken, expires_at: BigInt(record.accessExpiresAt) } : null,
    expiresAtMs: record.accessExpiresAt * 1000,
    mark: loginMark(record),
  };
}

function toBigInt(value: bigint | number): bigint {
  return typeof value === "bigint" ? value : BigInt(value);
}

function expiresAtMs(credential: Credential, detail: string): number | undefined {
  if (credential.expires_at === undefined) return undefined;
  const ms = credential.expires_at * 1000n;
  if (ms > BigInt(Number.MAX_SAFE_INTEGER)) throw new RelayKitError("source_shape_changed", detail);
  return Number(ms);
}

/**
 * Parse an already-decoded accounts document. `parseStrict` is the caller's job for text so a JSON
 * syntax error can become one fixed sentence (V8 echoes input snippets in its own parse errors).
 */
export function parseAccountsSourceValue(value: unknown, options: ParseAccountsOptions): ParsedAccountsFile {
  const parsed = fileSchema.safeParse(value);
  if (!parsed.success) {
    const issue = parsed.error.issues[0];
    const path = issue === undefined ? "" : issue.path.map(String).join(".");
    throw new RelayKitError("source_shape_changed", path === "" ? "accounts" : path);
  }
  if (parsed.data.accounts.length > options.maxAccounts) {
    throw new RelayKitError("source_shape_changed", "accounts");
  }
  const credentials = new Map<string, SourceCredential>();
  const accounts: SourceAccount[] = [];
  const seen = new Set<string>();
  for (let index = 0; index < parsed.data.accounts.length; index += 1) {
    const raw = parsed.data.accounts[index];
    const entry = accountSchema.safeParse(raw);
    if (!entry.success) {
      throw new RelayKitError("source_shape_changed", `accounts.${index}.${entry.error.issues[0]?.path.map(String).join(".") ?? "member"}`);
    }
    const data = entry.data;
    const vendor = data.vendor as Vendor;
    if (seen.has(data.account_id)) throw new RelayKitError("source_shape_changed", `accounts.${index}.account_id`);
    seen.add(data.account_id);
    const parsedEgress = data.egress === undefined ? undefined : parseEgressValue(data.egress, `accounts.${index}.egress`);
    let status = (data.status ?? "active") as SourceAccountStatus;
    let credential: Credential | null;
    let expires: number | undefined;
    let changeMark: string;
    if (data.credential.type === "oauth_login") {
      // Only the Codex device-code login is implemented (`../login/codex-oauth.ts`).
      if (vendor !== "chatgpt_codex") throw new RelayKitError("source_shape_changed", `accounts.${index}.credential.type`);
      const login = resolveLogin(data.credential.login, options);
      credential = login.credential;
      expires = login.expiresAtMs;
      if (credential === null) status = "disabled";
      changeMark = sha256BareHex(jcsBytes({ entry: canonicalValue(raw), login: login.mark }));
    } else if (data.credential.type === "password") {
      if (credentialClass(vendor, "password") === null) throw new RelayKitError("source_shape_changed", `accounts.${index}.credential.type`);
      const secret = data.credential.totp_secret === undefined ? undefined : normalizeTotpSecret(data.credential.totp_secret);
      if (secret === null) throw new RelayKitError("source_shape_changed", `accounts.${index}.credential.totp_secret`);
      credential = { type: "password", value: data.credential.value, username: data.credential.username, ...(secret === undefined ? {} : { totp_secret: secret }) };
      expires = undefined;
      changeMark = sha256BareHex(accountEntryBytes(raw));
    } else {
      if (credentialClass(vendor, data.credential.type) === null) {
        throw new RelayKitError("source_shape_changed", `accounts.${index}.credential.type`);
      }
      credential = {
        type: data.credential.type,
        value: data.credential.value,
        ...(data.credential.expires_at === undefined ? {} : { expires_at: toBigInt(data.credential.expires_at) }),
      };
      expires = expiresAtMs(credential, `accounts.${index}.credential.expires_at`);
      changeMark = sha256BareHex(accountEntryBytes(raw));
    }
    // The proxy password is held only by this parsed document, beside the account credential; it is
    // not a member of the `SourceAccount` metadata the daemon lists, logs or stores (K4-1).
    if (credential !== null) {
      credentials.set(data.account_id, {
        credential,
        ...(parsedEgress?.password === undefined ? {} : { egressPassword: parsedEgress.password }),
      });
    }
    accounts.push({
      sourceId: data.account_id,
      vendor,
      // A login's token is an OAuth access token, which is what the TEE's credential class checks.
      credentialType: data.credential.type === "oauth_login" ? "oauth_access_token" : data.credential.type,
      models: data.models === undefined ? "*" : data.models === "*" ? "*" : [...data.models],
      weight: data.weight === undefined ? 1n : toBigInt(data.weight),
      maxConcurrency: data.max_concurrency === undefined ? 1n : toBigInt(data.max_concurrency),
      status,
      ...(expires === undefined ? {} : { credentialExpiresAtMs: expires }),
      changeMark,
      ...(parsedEgress === undefined ? {} : { egress: parsedEgress.egress }),
      ...(data.credential.type === "oauth_login" ? { login: data.credential.login } : {}),
    });
  }
  return {
    relayId: parsed.data.relay_id,
    accounts,
    credentialOf(sourceId: string): SourceCredential | null {
      return credentials.get(sourceId) ?? null;
    },
  };
}

/**
 * The accounts each relay login serves (the agent status, S45): login name → the `account_id`s whose credential is
 * `{"type": "oauth_login", "login": name}`, in file order. Reads only those two members of each entry; an entry that
 * is not an account is skipped (the source's own read refuses the file and says why). Keeps no secret.
 */
export function loginAccountIds(value: unknown): Map<string, string[]> {
  const out = new Map<string, string[]>();
  const parsed = fileSchema.safeParse(value);
  if (!parsed.success) return out;
  for (const raw of parsed.data.accounts) {
    const entry = accountSchema.safeParse(raw);
    if (!entry.success || entry.data.credential.type !== "oauth_login") continue;
    const ids = out.get(entry.data.credential.login) ?? [];
    if (!ids.includes(entry.data.account_id)) ids.push(entry.data.account_id);
    out.set(entry.data.credential.login, ids);
  }
  return out;
}

/**
 * The proxy each relay login's exchanges go through (`../login/proxy.ts`): login name → the first entry (file order)
 * whose credential is `{"type": "oauth_login", "login": name}` and that declares an `egress`, with its password. A
 * login whose entries declare none is absent (it takes `source.logins.proxy`). Unlike `loginAccountIds` this reads
 * the whole document strictly: a document the source refuses throws `source_shape_changed` (a member path, never a
 * value), so no caller takes the default for a login whose proxy it could not read.
 */
export function loginAccountProxies(value: unknown): Map<string, { readonly accountId: string; readonly egress: SourceEgress; readonly password?: string }> {
  const parsed = fileSchema.safeParse(value);
  if (!parsed.success) throw new RelayKitError("source_shape_changed", "accounts");
  const out = new Map<string, { readonly accountId: string; readonly egress: SourceEgress; readonly password?: string }>();
  for (const [index, raw] of parsed.data.accounts.entries()) {
    const entry = accountSchema.safeParse(raw);
    if (!entry.success) throw new RelayKitError("source_shape_changed", `accounts.${index}.${entry.error.issues[0]?.path.map(String).join(".") ?? "member"}`);
    const { credential, egress, account_id: accountId } = entry.data;
    if (credential.type !== "oauth_login" || egress === undefined || out.has(credential.login)) continue;
    const proxy = parseEgressValue(egress, `accounts.${index}.egress`);
    out.set(credential.login, { accountId, egress: proxy.egress, ...(proxy.password === undefined ? {} : { password: proxy.password }) });
  }
  return out;
}

/** Parse `accounts.json` text. A syntax error is one sentence, never the parser's echo. */
export function parseAccountsSourceText(text: string, options: ParseAccountsOptions): ParsedAccountsFile {
  let value: unknown;
  try {
    value = parseStrict(text);
  } catch {
    throw new RelayKitError("source_bad_response", "accounts");
  }
  return parseAccountsSourceValue(value, options);
}

export interface FileAdapterDeps {
  readonly readAccountsFile: (path: string) => string;
  /** Reads a relay login record; see `ParseAccountsOptions.readLogin`. */
  readonly readLogin?: (name: string) => LoginRecord | null;
  readonly now?: () => number;
}

/** The `file` adapter. `refresh` is always `unknown`: the file does not say who refreshes it. */
export function fileAdapter(config: SourceFileConfig, deps: FileAdapterDeps): SourceAdapter {
  const now = deps.now ?? Date.now;
  const parse = (): ParsedAccountsFile =>
    parseAccountsSourceText(deps.readAccountsFile(config.path), {
      maxAccounts: config.maxAccounts,
      ...(deps.readLogin === undefined ? {} : { readLogin: deps.readLogin }),
      nowMs: now(),
      loginServeMarginSeconds: config.logins.serveMarginSeconds,
    });
  return {
    kind: "file",
    async probe(signal: AbortSignal): Promise<{ software: string; version: string | null; credentialReadable: boolean }> {
      throwIfAborted(signal);
      return { software: "file", version: null, credentialReadable: true };
    },
    async list(signal: AbortSignal): Promise<{ accounts: readonly SourceAccount[]; refresh: SourceRefresh }> {
      throwIfAborted(signal);
      const parsed = parse();
      return { accounts: selectAccounts(config.select, parsed.accounts), refresh: "unknown" };
    },
    async credential(sourceId: string, signal: AbortSignal): Promise<SourceCredential> {
      throwIfAborted(signal);
      const parsed = parse();
      const credential = parsed.credentialOf(sourceId);
      if (credential === null) throw new RelayKitError("source_not_found", "credential");
      return credential;
    },
  };
}

/** Convert a plain JSON read (numbers) to `@gray/json`'s serde form (integers as bigint). */
function canonicalValue(value: unknown): Json {
  if (value === null || typeof value === "boolean" || typeof value === "string" || typeof value === "bigint") return value;
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) throw new RelayKitError("source_shape_changed", "accounts");
    return BigInt(value);
  }
  if (Array.isArray(value)) return value.map((item) => canonicalValue(item));
  if (typeof value === "object") {
    const out: Record<string, Json> = {};
    for (const [key, item] of Object.entries(value as Record<string, unknown>)) out[key] = canonicalValue(item);
    return out;
  }
  throw new RelayKitError("source_shape_changed", "accounts");
}

/** The canonical bytes of one account entry, exported for the vector fixture and diagnostics. */
export function accountEntryBytes(value: unknown): Uint8Array {
  return jcsBytes(canonicalValue(value));
}

/** The SHA-256 the `file` adapter uses; exported so tests can pin the golden mark. */
export function accountChangeMark(value: unknown): string {
  return sha256BareHex(accountEntryBytes(value));
}

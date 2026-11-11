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
 *
 * An `oauth_access_token` may carry the `refresh_token` it was issued with,
 * `{"type":"oauth_access_token","value":"…","expires_at":1790003600,"refresh_token":"…"}`: it is sealed beside the
 * access token, for relay software that only refreshes (it has no sign-in of its own) to refresh the account inside
 * the VM from then on. An `api_key` has none.
 * `changeMark` is the SHA-256 of the account entry's canonical JSON bytes: a rewritten key order does
 * not change it, and the mark is opaque (it is never logged, and it is not the secret).
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
import type { SourceAccount, SourceAccountStatus, SourceAdapter, SourceCredential, SourceRefresh } from "../../source/types.ts";
import type { SourceFileConfig } from "./config-types.ts";
import { parseEgressValue, sourceEgressSchema } from "./egress.ts";
import { MAX_SOURCE_ACCOUNTS, MODEL_ID, PRINTABLE_CREDENTIAL, U64_MAX } from "./limits.ts";
import { selectAccounts } from "./select.ts";

const integer = (minimum: bigint, maximum: bigint) =>
  z.union([z.bigint().min(minimum).max(maximum), z.number().int().min(Number(minimum)).max(Number(maximum))]);

const u64 = z.union([z.bigint().min(0n).max(U64_MAX), z.number().int().min(0).max(Number.MAX_SAFE_INTEGER)]);

const credentialSchema = z
  .object({
    type: z.enum(["api_key", "oauth_access_token"]),
    value: z.string().min(1).max(MAX_CREDENTIAL_LENGTH),
    expires_at: u64.optional(),
    // An access token's refresh token (the same bounds as the `http` source's), for the relay software in the VM.
    refresh_token: z.string().min(1).max(MAX_CREDENTIAL_LENGTH).regex(PRINTABLE_CREDENTIAL).optional(),
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

/**
 * A subscription account with no token at all (docs/design/relay-sign-in-in-vm.md §1): sealed as it is, then signed in
 * inside the VM by the relay's own software with `gray-assistant login <account>`. Only the vendor and the type.
 */
const signInCredentialSchema = z.object({ type: z.literal("sign_in") }).strict();

const accountSchema = z
  .object({
    account_id: z.string().regex(RESOURCE_ID),
    vendor: z.enum(VENDORS),
    credential: z.union([credentialSchema, passwordCredentialSchema, signInCredentialSchema]),
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
    const status = (data.status ?? "active") as SourceAccountStatus;
    let credential: Credential;
    let expires: number | undefined;
    let changeMark: string;
    if (data.credential.type === "sign_in") {
      if (credentialClass(vendor, "sign_in") === null) throw new RelayKitError("source_shape_changed", `accounts.${index}.credential.type`);
      credential = { type: "sign_in", value: "" };
      expires = undefined;
      changeMark = sha256BareHex(accountEntryBytes(raw));
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
      // Only an access token has a refresh token (`@gray/relay-connector` refuses any other bundle).
      if (data.credential.refresh_token !== undefined && data.credential.type !== "oauth_access_token") {
        throw new RelayKitError("source_shape_changed", `accounts.${index}.credential.refresh_token`);
      }
      credential = {
        type: data.credential.type,
        value: data.credential.value,
        ...(data.credential.expires_at === undefined ? {} : { expires_at: toBigInt(data.credential.expires_at) }),
        ...(data.credential.refresh_token === undefined ? {} : { refresh_token: data.credential.refresh_token }),
      };
      expires = expiresAtMs(credential, `accounts.${index}.credential.expires_at`);
      changeMark = sha256BareHex(accountEntryBytes(raw));
    }
    // The proxy password is held only by this parsed document, beside the account credential; it is
    // not a member of the `SourceAccount` metadata the daemon lists, logs or stores (K4-1).
    credentials.set(data.account_id, {
      credential,
      ...(parsedEgress?.password === undefined ? {} : { egressPassword: parsedEgress.password }),
    });
    accounts.push({
      sourceId: data.account_id,
      vendor,
      credentialType: data.credential.type,
      models: data.models === undefined ? "*" : data.models === "*" ? "*" : [...data.models],
      weight: data.weight === undefined ? 1n : toBigInt(data.weight),
      maxConcurrency: data.max_concurrency === undefined ? 1n : toBigInt(data.max_concurrency),
      status,
      ...(expires === undefined ? {} : { credentialExpiresAtMs: expires }),
      changeMark,
      ...(parsedEgress === undefined ? {} : { egress: parsedEgress.egress }),
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
}

/** The `file` adapter. `refresh` is always `unknown`: the file does not say who refreshes it. */
export function fileAdapter(config: SourceFileConfig, deps: FileAdapterDeps): SourceAdapter {
  const parse = (): ParsedAccountsFile => parseAccountsSourceText(deps.readAccountsFile(config.path), { maxAccounts: config.maxAccounts });
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

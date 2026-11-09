/**
 * The `http` source: the two read-only routes a relay's own software serves so gray-assistant can read its accounts
 * (the relay integration standard, "Account source"; JSON Schema `source-http-contract.schema.json`).
 *
 * ```
 * GET {url}/accounts
 * Authorization: Bearer <token_file>
 * -> {"accounts":[{"id":"ant-1","vendor":"anthropic","credential_type":"oauth_access_token",
 *                  "status":"active","change_mark":"2026-11-03T08:00:00Z",
 *                  "models":["claude-sonnet-4-6"],"weight":2,"max_concurrency":4,
 *                  "limited_until_ms":1790000000000,"expires_at_ms":1790003600000,
 *                  "labels":["lane"],"egress":{"type":"http","host":"proxy.internal","port":3128,"username":"u"}}]}
 *
 * GET {url}/accounts/{id}/credential
 * Authorization: Bearer <token_file>
 * -> {"type":"oauth_access_token","value":"sk-ant-oat01-…","expires_at_ms":1790003600000,"egress_password":"…"}
 * ```
 *
 * The list is metadata only and is read on every poll; the credential answer is the one secret, read only when the
 * daemon seals or pushes that account. Both are validated strictly within the configured caps, and a refusal names a
 * member path, never a value. The relay's software refreshes its subscription tokens itself, ahead of expiry and
 * without traffic (the lane serves the account, so the software sees none); this adapter never refreshes one.
 *
 * An account whose `vendor` is a vendor name this gray-assistant does not serve yet (the vendor list grows) is left out
 * of the snapshot and named in `skipped`, rather than failing the whole list: a relay's software may list it before
 * its gray-assistant is updated.
 */
import { z } from "zod";
import { CREDENTIAL_TYPES, MAX_CREDENTIAL_LENGTH, MAX_USERNAME_LENGTH, VENDORS, credentialClass, normalizeTotpSecret, type Credential, type Vendor } from "@gray/relay-connector";
import { RelayKitError } from "../../errors.ts";
import type { SourceAccount, SourceAccountStatus, SourceAdapter, SourceCredential, SourceSkippedAccount } from "../../source/types.ts";
import type { SourceHttpConfig } from "./config-types.ts";
import { parseEgressValue } from "./egress.ts";
import { fetchJson, fetchText, joinSourceUrl } from "./http-client.ts";
import { CHANGE_MARK, MODEL_ID, PRINTABLE_CREDENTIAL, SOURCE_TAG } from "./limits.ts";
import { selectedBy } from "./select.ts";

export type HttpSourceConfig = SourceHttpConfig;

/** An account id on the wire: one URL path segment with nothing to escape but `@`/`+`/`:`. */
export const HTTP_ACCOUNT_ID = /^[A-Za-z0-9._:@+-]{1,256}$/u;

/** A vendor name as the wire writes it; whether this gray-assistant serves it is a separate question. */
const VENDOR_NAME = /^[a-z][a-z0-9_]{0,31}$/u;

/** The wire statuses and the daemon's: `paused` is the relay's own off switch. */
export const HTTP_ACCOUNT_STATUSES = ["active", "limited", "paused", "banned"] as const;
const STATUS_OF: Readonly<Record<(typeof HTTP_ACCOUNT_STATUSES)[number], SourceAccountStatus>> = {
  active: "active",
  limited: "limited",
  paused: "disabled",
  banned: "banned",
};

const timeMs = z.number().int().min(0).max(Number.MAX_SAFE_INTEGER);

const egressSchema = z
  .object({
    type: z.enum(["http", "https", "socks5", "socks5h"]),
    host: z.string().min(1).max(255),
    port: z.number().int().min(1).max(65_535),
    username: z.string().min(1).max(255).optional(),
  })
  .strict();

const accountSchema = z
  .object({
    id: z.string().regex(HTTP_ACCOUNT_ID),
    vendor: z.string().regex(VENDOR_NAME),
    credential_type: z.enum(CREDENTIAL_TYPES),
    status: z.enum(HTTP_ACCOUNT_STATUSES),
    change_mark: z.string().regex(CHANGE_MARK),
    models: z.union([z.array(z.string().regex(MODEL_ID)).min(1).max(256), z.literal("*")]).optional(),
    weight: z.number().int().min(1).max(1_000_000).optional(),
    max_concurrency: z.number().int().min(1).max(10_000).optional(),
    limited_until_ms: timeMs.optional(),
    expires_at_ms: timeMs.optional(),
    labels: z.array(z.string().regex(SOURCE_TAG)).max(64).optional(),
    egress: egressSchema.optional(),
  })
  .strict();

const accountsSchema = z.object({ accounts: z.array(z.unknown()) }).strict();

const credentialSchema = z
  .object({
    type: z.enum(CREDENTIAL_TYPES),
    // A token or key is printable ASCII; a password (`type: "password"`) may hold spaces and letters beyond ASCII,
    // which @gray/relay-connector's own check bounds when it is sealed.
    value: z.string().min(1).max(MAX_CREDENTIAL_LENGTH),
    expires_at_ms: timeMs.optional(),
    egress_password: z.string().min(1).max(255).optional(),
    // An access token's refresh token, for an account Gray refreshes inside the VM (`refresh: "gray"`).
    refresh_token: z.string().min(1).max(MAX_CREDENTIAL_LENGTH).regex(PRINTABLE_CREDENTIAL).optional(),
    // A password's sign-in e-mail and TOTP secret (docs/design/relay-in-cvm-login.md); the secret as an authenticator
    // shows it (spaces and case do not matter).
    username: z.string().min(1).max(MAX_USERNAME_LENGTH).optional(),
    totp_secret: z.string().min(1).max(256).optional(),
  })
  .strict()
  .refine((c) => c.type === "password" || PRINTABLE_CREDENTIAL.test(c.value), { message: "a token or key is printable ASCII", path: ["value"] })
  .refine((c) => c.refresh_token === undefined || c.type === "oauth_access_token", { message: "only an access token has a refresh token", path: ["refresh_token"] })
  .refine((c) => (c.type === "password") === (c.username !== undefined), { message: "a password, and only a password, has a username", path: ["username"] })
  .refine((c) => c.totp_secret === undefined || c.type === "password", { message: "only a password has a TOTP secret", path: ["totp_secret"] })
  .refine((c) => c.type !== "password" || c.expires_at_ms === undefined, { message: "a password has no expiry", path: ["expires_at_ms"] });

export interface ParsedHttpAccounts {
  readonly accounts: readonly SourceAccount[];
  /** Each listed account's labels, for `select.tags`; never returned to the daemon. */
  readonly labels: ReadonlyMap<string, readonly string[]>;
  readonly skipped: readonly SourceSkippedAccount[];
}

function memberPath(issues: readonly { readonly path: readonly PropertyKey[] }[], prefix: string): string {
  const path = issues[0]?.path.map(String).join(".") ?? "";
  return path === "" ? prefix : `${prefix}.${path}`;
}

/** Validate one `GET /accounts` answer. Refusals name a member path, never a value. */
export function parseHttpAccounts(value: unknown, maxAccounts: number): ParsedHttpAccounts {
  const parsed = accountsSchema.safeParse(value);
  if (!parsed.success) throw new RelayKitError("source_shape_changed", memberPath(parsed.error.issues, "(root)"));
  if (parsed.data.accounts.length > maxAccounts) throw new RelayKitError("source_shape_changed", "accounts");
  const seen = new Set<string>();
  const accounts: SourceAccount[] = [];
  const labels = new Map<string, readonly string[]>();
  const skipped: SourceSkippedAccount[] = [];
  for (let index = 0; index < parsed.data.accounts.length; index += 1) {
    const detail = `accounts.${index}`;
    const entry = accountSchema.safeParse(parsed.data.accounts[index]);
    if (!entry.success) throw new RelayKitError("source_shape_changed", memberPath(entry.error.issues, detail));
    const data = entry.data;
    if (seen.has(data.id)) throw new RelayKitError("source_shape_changed", `${detail}.id`);
    seen.add(data.id);
    if (!(VENDORS as readonly string[]).includes(data.vendor)) {
      skipped.push({ sourceId: data.id, vendor: data.vendor });
      continue;
    }
    const vendor = data.vendor as Vendor;
    if (credentialClass(vendor, data.credential_type) === null) throw new RelayKitError("source_shape_changed", `${detail}.credential_type`);
    if (data.limited_until_ms !== undefined && data.status !== "limited") throw new RelayKitError("source_shape_changed", `${detail}.limited_until_ms`);
    const egress = data.egress === undefined ? undefined : parseEgressValue(data.egress, `${detail}.egress`).egress;
    labels.set(data.id, [...new Set(data.labels ?? [])]);
    accounts.push({
      sourceId: data.id,
      vendor,
      credentialType: data.credential_type,
      models: data.models === undefined || data.models === "*" ? "*" : [...data.models],
      weight: BigInt(data.weight ?? 1),
      maxConcurrency: BigInt(data.max_concurrency ?? 1),
      status: STATUS_OF[data.status],
      ...(data.limited_until_ms === undefined ? {} : { limitedUntilMs: data.limited_until_ms }),
      ...(data.expires_at_ms === undefined ? {} : { credentialExpiresAtMs: data.expires_at_ms }),
      changeMark: data.change_mark,
      ...(egress === undefined ? {} : { egress }),
    });
  }
  return { accounts, labels, skipped };
}

/** One `GET /accounts/{id}/credential` answer: the credential, and the proxy password when the account has one. */
export interface ParsedHttpCredential extends SourceCredential {
  /** The answer's `expires_at_ms`, for `source check` to compare with the list's. */
  readonly expiresAtMs?: number;
}

/** Validate one `GET /accounts/{id}/credential` answer. */
export function parseHttpCredential(value: unknown): ParsedHttpCredential {
  const parsed = credentialSchema.safeParse(value);
  if (!parsed.success) throw new RelayKitError("source_shape_changed", memberPath(parsed.error.issues, "credential"));
  const { type, value: secret, expires_at_ms: expiresAtMs, egress_password: egressPassword, refresh_token: refreshToken, username, totp_secret: totp } = parsed.data;
  const totpSecret = totp === undefined ? undefined : normalizeTotpSecret(totp);
  if (totpSecret === null) throw new RelayKitError("source_shape_changed", "credential.totp_secret");
  const credential: Credential = {
    type,
    value: secret,
    ...(expiresAtMs === undefined ? {} : { expires_at: BigInt(Math.floor(expiresAtMs / 1000)) }),
    ...(refreshToken === undefined ? {} : { refresh_token: refreshToken }),
    ...(username === undefined ? {} : { username }),
    ...(totpSecret === undefined ? {} : { totp_secret: totpSecret }),
  };
  return {
    credential,
    ...(egressPassword === undefined ? {} : { egressPassword }),
    ...(expiresAtMs === undefined ? {} : { expiresAtMs }),
  };
}

/** The token file is a bearer secret: one line, printable, never echoed. */
export function readHttpSourceToken(readTokenFile: (path: string) => string, path: string): string {
  const token = readTokenFile(path).trim();
  if (token.length === 0 || token.length > 8192 || !PRINTABLE_CREDENTIAL.test(token)) {
    throw new RelayKitError("source_bad_response", "token_file");
  }
  return token;
}

/** The two routes under a base URL (a reverse proxy's path prefix is kept). */
export function httpSourceRoutes(url: string): { readonly accounts: string; credential(id: string): string } {
  return {
    accounts: joinSourceUrl(url, "accounts"),
    credential: (id: string) => joinSourceUrl(url, "accounts", encodeURIComponent(id), "credential"),
  };
}

export interface HttpAdapterDeps {
  readonly fetch: typeof fetch;
  readonly readTokenFile: (path: string) => string;
  readonly now: () => number;
}

/** The `http` adapter: two routes and a bearer token. */
export function httpAdapter(config: HttpSourceConfig, deps: HttpAdapterDeps): SourceAdapter {
  const routes = httpSourceRoutes(config.url);
  const list = async (signal: AbortSignal) => {
    const token = readHttpSourceToken(deps.readTokenFile, config.tokenFile);
    const value = await fetchJson(routes.accounts, {
      fetch: deps.fetch,
      signal,
      timeoutMs: config.requestTimeoutMs,
      maxBytes: config.maxResponseBytes,
      headers: { authorization: `Bearer ${token}` },
      label: "accounts",
    });
    const parsed = parseHttpAccounts(value, config.maxAccounts);
    const accounts = parsed.accounts.filter((account) =>
      selectedBy(config.select, { sourceId: account.sourceId, vendor: account.vendor, tags: parsed.labels.get(account.sourceId) ?? [] }),
    );
    // The standard requires the software to refresh ahead of expiry without traffic.
    return { accounts, refresh: "proactive" as const, skipped: parsed.skipped };
  };
  return {
    kind: "http",
    async probe(signal) {
      await list(signal);
      return { software: "http", version: null, credentialReadable: true };
    },
    list,
    async credential(sourceId: string, signal: AbortSignal): Promise<SourceCredential> {
      if (!HTTP_ACCOUNT_ID.test(sourceId)) throw new RelayKitError("source_not_found", "credential");
      const token = readHttpSourceToken(deps.readTokenFile, config.tokenFile);
      const value = await fetchJson(routes.credential(sourceId), {
        fetch: deps.fetch,
        signal,
        timeoutMs: config.requestTimeoutMs,
        maxBytes: config.maxCredentialBytes,
        headers: { authorization: `Bearer ${token}` },
        label: "credential",
        notFoundCode: "source_not_found",
      });
      const { credential, egressPassword } = parseHttpCredential(value);
      return { credential, ...(egressPassword === undefined ? {} : { egressPassword }) };
    },
    /**
     * `PUT {url}/accounts/{id}/credential` (standard "Account source", optional): a token Gray refreshed inside the
     * VM, as `{type, value, expires_at_ms?, refresh_token?}`. 2xx is written; 404 or 405 says the source has no such
     * route; anything else is a failed write the daemon tries again.
     */
    async writeCredential(sourceId: string, credential: Credential, signal: AbortSignal): Promise<void> {
      if (!HTTP_ACCOUNT_ID.test(sourceId)) throw new RelayKitError("source_not_found", "credential_write");
      const token = readHttpSourceToken(deps.readTokenFile, config.tokenFile);
      const body = JSON.stringify({
        type: credential.type,
        value: credential.value,
        ...(credential.expires_at === undefined ? {} : { expires_at_ms: Number(credential.expires_at) * 1000 }),
        ...(credential.refresh_token === undefined ? {} : { refresh_token: credential.refresh_token }),
      });
      const response = await fetchText(routes.credential(sourceId), {
        fetch: deps.fetch,
        signal,
        timeoutMs: config.requestTimeoutMs,
        maxBytes: 64 * 1024,
        headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
        label: "credential_write",
        method: "PUT",
        body,
      });
      if (response.status === 401 || response.status === 403) throw new RelayKitError("source_unauthorized", "credential_write");
      if (response.status === 404 || response.status === 405) throw new RelayKitError("source_not_found", "credential_write");
      if (response.status < 200 || response.status > 299) throw new RelayKitError("source_bad_response", "credential_write");
    },
  };
}

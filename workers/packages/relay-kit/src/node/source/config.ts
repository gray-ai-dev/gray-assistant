/**
 * The `source` section of the relay daemon's configuration, and the one factory that turns it into a
 * `SourceAdapter` (relay SDK design v2 §A.8, §E K3).
 *
 * ```jsonc
 * {"source": {
 *   "kind": "http",                        // file | http | cliproxyapi
 *   "url": "https://127.0.0.1:8317",       // http/cliproxyapi; http only to loopback unless allowed
 *   "token_file": "/run/secrets/management-key",
 *   "select": {"vendors": ["anthropic"], "tags": ["lane"], "ids": ["ant-1"]},
 *   "allow_plain_http": false,
 *   "request_timeout_ms": 10000,
 *   "probe_timeout_ms": 2000,
 *   "max_response_bytes": 8388608,
 *   "max_credential_bytes": 32768,
 *   "max_accounts": 1000
 * }}
 * ```
 *
 * Every default and bound is here rather than in `@gray/config`: the daemon's config is one file
 * validated at start (design v2 §A.1), and these values change per relay, not per deployment region.
 * The parser refuses an unknown member, a missing kind-specific member, a credential-bearing URL, a
 * clear-text URL to a non-loopback host, and a selection criterion the chosen kind cannot honour.
 *
 * The token file and the `file` source's `accounts.json` are read as private files: no symlink, no
 * group/other bits (K4-3), the same rule as relay-kit's relay key. Both hold secrets — the admin
 * token controls the relay's panel, and `accounts.json` holds the account credentials — so a file
 * another local account can read is refused in the daemon and in `credentials seal` alike.
 */
import { RESOURCE_ID, VENDORS } from "@gray/relay-connector";
import { z } from "zod";
import { RelayKitError } from "../../errors.ts";
import { SOURCE_KINDS, type SourceAdapter } from "../../source/types.ts";
import { readPrivateFile } from "../files.ts";
import type { ResolvedSourceConfig, SourceCommonConfig, SourceDeps, SourceSelection } from "./config-types.ts";
import { checkHttpSource, type SourceCheckReport } from "./check.ts";
import { cliproxyAdapter } from "./cliproxyapi.ts";
import { fileAdapter } from "./file.ts";
import { httpAdapter } from "./http.ts";
import {
  DEFAULT_MAX_CREDENTIAL_BYTES,
  DEFAULT_MAX_RESPONSE_BYTES,
  DEFAULT_PROBE_TIMEOUT_MS,
  DEFAULT_REQUEST_TIMEOUT_MS,
  MAX_MAX_CREDENTIAL_BYTES,
  MAX_MAX_RESPONSE_BYTES,
  MAX_PATH_LENGTH,
  MAX_PROBE_TIMEOUT_MS,
  MAX_REQUEST_TIMEOUT_MS,
  MAX_SOURCE_ACCOUNTS,
  MAX_SOURCE_FILE_BYTES,
  MAX_SOURCE_TOKEN_BYTES,
  MAX_URL_LENGTH,
  MIN_MAX_CREDENTIAL_BYTES,
  MIN_MAX_RESPONSE_BYTES,
  MIN_PROBE_TIMEOUT_MS,
  MIN_REQUEST_TIMEOUT_MS,
  SOURCE_ID,
  SOURCE_TAG,
} from "./limits.ts";

const boundedInt = (minimum: number, maximum: number) => z.number().int().min(minimum).max(maximum);

/** The raw `select` object. `groups` is an alias of `tags`; both together are refused as ambiguous. */
export const sourceSelectSchema = z
  .object({
    vendors: z.array(z.enum(VENDORS)).min(1).max(VENDORS.length).optional(),
    platforms: z.array(z.enum(VENDORS)).min(1).max(VENDORS.length).optional(),
    tags: z.array(z.string().regex(SOURCE_TAG)).min(1).max(256).optional(),
    groups: z.array(z.string().regex(SOURCE_TAG)).min(1).max(256).optional(),
    ids: z.array(z.string().regex(SOURCE_ID)).min(1).max(MAX_SOURCE_ACCOUNTS).optional(),
    source_ids: z.array(z.string().regex(SOURCE_ID)).min(1).max(MAX_SOURCE_ACCOUNTS).optional(),
  })
  .strict();

/** The raw `source` section, exactly as the daemon's config file carries it. */
export const sourceConfigSchema = z
  .object({
    kind: z.enum(SOURCE_KINDS),
    url: z.string().min(1).max(MAX_URL_LENGTH).optional(),
    path: z.string().min(1).max(MAX_PATH_LENGTH).optional(),
    token_file: z.string().min(1).max(MAX_PATH_LENGTH).optional(),
    allow_plain_http: z.boolean().optional(),
    request_timeout_ms: boundedInt(MIN_REQUEST_TIMEOUT_MS, MAX_REQUEST_TIMEOUT_MS).optional(),
    probe_timeout_ms: boundedInt(MIN_PROBE_TIMEOUT_MS, MAX_PROBE_TIMEOUT_MS).optional(),
    max_response_bytes: boundedInt(MIN_MAX_RESPONSE_BYTES, MAX_MAX_RESPONSE_BYTES).optional(),
    max_credential_bytes: boundedInt(MIN_MAX_CREDENTIAL_BYTES, MAX_MAX_CREDENTIAL_BYTES).optional(),
    max_accounts: boundedInt(1, MAX_SOURCE_ACCOUNTS).optional(),
    select: sourceSelectSchema.optional(),
  })
  .strict();

/** Whether a URL host is loopback without any DNS lookup (localhost, 127/8, ::1). */
export function isLoopbackHost(hostname: string): boolean {
  const host = hostname.trim().toLowerCase().replace(/^\[/u, "").replace(/\]$/u, "");
  if (host === "localhost" || host === "::1" || host === "0:0:0:0:0:0:0:1") return true;
  const ipv4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/u.exec(host);
  return ipv4 !== null && ipv4[1] === "127";
}

function pathMember(value: string, detail: string): string {
  if (value.includes("\u0000")) throw new RelayKitError("invalid_source_config", detail);
  return value;
}

/** Normalize a base URL; the query, fragment and any userinfo are refused, not stripped. */
function baseUrl(raw: string, allowPlainHttp: boolean): string {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new RelayKitError("invalid_source_config", "url");
  }
  if (url.protocol !== "https:" && url.protocol !== "http:") throw new RelayKitError("invalid_source_config", "url");
  if (url.protocol === "http:" && !allowPlainHttp && !isLoopbackHost(url.hostname)) {
    // Design v2 §A.8 minor 3: the admin token controls the relay's panel; clear text only on a
    // loopback or a compose network the operator explicitly allows.
    throw new RelayKitError("invalid_source_config", "url (http requires allow_plain_http off loopback)");
  }
  if (url.username !== "" || url.password !== "") throw new RelayKitError("invalid_source_config", "url");
  if (url.search !== "" || url.hash !== "") throw new RelayKitError("invalid_source_config", "url");
  if (url.hostname === "" || url.port === "0") throw new RelayKitError("invalid_source_config", "url");
  const path = url.pathname.replace(/\/+$/u, "");
  return `${url.origin}${path === "" || path === "/" ? "" : path}`;
}

function unique<T>(values: readonly T[]): T[] {
  return [...new Set(values)];
}

function selectionOf(raw: z.infer<typeof sourceSelectSchema> | undefined, kind: ResolvedSourceConfig["kind"]): SourceSelection {
  if (raw === undefined) return { vendors: [], tags: [], ids: [] };
  if (raw.tags !== undefined && raw.groups !== undefined) {
    throw new RelayKitError("invalid_source_config", "select.tags and select.groups are aliases; use one");
  }
  if (raw.vendors !== undefined && raw.platforms !== undefined) {
    throw new RelayKitError("invalid_source_config", "select.vendors and select.platforms are aliases; use one");
  }
  if (raw.ids !== undefined && raw.source_ids !== undefined) {
    throw new RelayKitError("invalid_source_config", "select.ids and select.source_ids are aliases; use one");
  }
  const tags = unique(raw.tags ?? raw.groups ?? []);
  if (tags.length > 0 && kind === "file") {
    // `file` has no group/tag member. Refusing beats silently selecting nothing, which would look
    // like an empty pool. (`http` has `labels`, `cliproxyapi` its `label`.)
    throw new RelayKitError("source_unsupported", `select.tags is not available for kind ${kind}`);
  }
  const ids = unique(raw.ids ?? raw.source_ids ?? []);
  if (kind === "file" && ids.some((id) => !RESOURCE_ID.test(id))) {
    throw new RelayKitError("invalid_source_config", "select.ids");
  }
  return { vendors: unique(raw.vendors ?? raw.platforms ?? []), tags, ids };
}

/** Parse and resolve the `source` section. Refusals name a member path, never a value. */
export function parseSourceConfig(value: unknown): ResolvedSourceConfig {
  const parsed = sourceConfigSchema.safeParse(value);
  if (!parsed.success) {
    const issue = parsed.error.issues[0];
    const path = issue === undefined ? "" : issue.path.map(String).join(".");
    throw new RelayKitError("invalid_source_config", path === "" ? "(root)" : path);
  }
  const data = parsed.data;
  const allowPlainHttp = data.allow_plain_http ?? false;
  const requestTimeoutMs = data.request_timeout_ms ?? DEFAULT_REQUEST_TIMEOUT_MS;
  const probeTimeoutMs = data.probe_timeout_ms ?? DEFAULT_PROBE_TIMEOUT_MS;
  const maxResponseBytes = data.max_response_bytes ?? DEFAULT_MAX_RESPONSE_BYTES;
  const maxCredentialBytes = data.max_credential_bytes ?? DEFAULT_MAX_CREDENTIAL_BYTES;
  const maxAccounts = data.max_accounts ?? MAX_SOURCE_ACCOUNTS;
  if (maxCredentialBytes > maxResponseBytes) {
    throw new RelayKitError("invalid_source_config", "max_credential_bytes is larger than max_response_bytes");
  }
  const common: SourceCommonConfig = {
    allowPlainHttp,
    requestTimeoutMs,
    probeTimeoutMs,
    maxResponseBytes,
    maxCredentialBytes,
    maxAccounts,
    select: selectionOf(data.select, data.kind),
  };
  if (data.kind === "file") {
    if (data.path === undefined) throw new RelayKitError("invalid_source_config", "path");
    if (data.url !== undefined) throw new RelayKitError("invalid_source_config", "url is not used by kind file");
    if (data.token_file !== undefined) throw new RelayKitError("invalid_source_config", "token_file is not used by kind file");
    return { ...common, kind: "file", path: pathMember(data.path, "path"), url: null, tokenFile: null };
  }
  if (data.url === undefined) throw new RelayKitError("invalid_source_config", "url");
  if (data.token_file === undefined) throw new RelayKitError("invalid_source_config", "token_file");
  if (data.path !== undefined) throw new RelayKitError("invalid_source_config", "path is not used by a remote kind");
  return {
    ...common,
    kind: data.kind,
    url: baseUrl(data.url, allowPlainHttp),
    path: null,
    tokenFile: pathMember(data.token_file, "token_file"),
  };
}

/**
 * Build the adapter for a parsed config. The dependencies default to the real ones: `globalThis.fetch`,
 * `Date.now`, and `readPrivateFile` for the token and accounts files. A caller that passes `deps`
 * (the tests, a future daemon with its own file policy) replaces only what it names.
 */
export function createSourceAdapter(config: ResolvedSourceConfig, deps: SourceDeps = {}): SourceAdapter {
  const fetchImpl: typeof fetch = deps.fetch ?? ((input, init) => globalThis.fetch(input, init));
  const now = deps.now ?? Date.now;
  const readTokenFile =
    deps.readTokenFile ?? ((path: string): string => readPrivateFile(path, "source token file", MAX_SOURCE_TOKEN_BYTES));
  const readAccountsFile =
    deps.readAccountsFile ?? ((path: string): string => readPrivateFile(path, "source accounts file", MAX_SOURCE_FILE_BYTES));
  switch (config.kind) {
    case "file":
      return fileAdapter(config, { readAccountsFile });
    case "http":
      return httpAdapter(config, { fetch: fetchImpl, readTokenFile, now });
    case "cliproxyapi":
      return cliproxyAdapter(config, { fetch: fetchImpl, readTokenFile, now });
  }
}

/**
 * `gray-assistant source check` and `doctor`'s `source_contract`: the `http` source's two routes against the standard's
 * "Account source" (`check.ts`). The other kinds are gray-assistant's own adapters and have nothing for a relay to check.
 */
export async function checkSourceContract(config: ResolvedSourceConfig, deps: SourceDeps = {}): Promise<SourceCheckReport> {
  if (config.kind !== "http") throw new RelayKitError("source_unsupported", `source check reads the http source; this config's source is ${config.kind}`);
  return checkHttpSource(config, {
    fetch: deps.fetch ?? ((input, init) => globalThis.fetch(input, init)),
    readTokenFile: deps.readTokenFile ?? ((path: string): string => readPrivateFile(path, "source token file", MAX_SOURCE_TOKEN_BYTES)),
    now: deps.now ?? Date.now,
  });
}

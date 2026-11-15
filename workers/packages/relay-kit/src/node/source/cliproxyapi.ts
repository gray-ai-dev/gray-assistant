/**
 * The CLIProxyAPI source: management API v8, read-only.
 *
 * `GET /v8/management/credentials` lists credentials with non-secret state; the adapter maps
 * provider → vendor, `status`/`disabled`/`next_retry_after` → the lane's status, and the modification
 * and refresh timestamps → an opaque `changeMark`.
 *
 * An account's proxy is not in that list. CLIProxyAPI keeps it in the auth file (`proxy_url`) and reads it the way
 * `sdk/proxyutil` `Parse` does: a URL is the account's own proxy, `direct` or `none` is no proxy, and an empty or
 * missing member inherits the global `requests.proxy-url` of the config. So `list()` reads each selected account's
 * auth file for that one member, and the config once when an account inherits, and declares the result as the
 * account's `egress`: the account leaves the VM the way it leaves CLIProxyAPI. A proxy that cannot be read is never
 * taken for "none": the read fails and names the member (`files.<n>.proxy_url`, `config.requests.proxy-url`), and
 * `credential()` refuses an account whose proxy is no longer the one the list declared. Checked against the published
 * image (v8.0.72, 2026-11-15; `test/source/fixtures/cliproxyapi-real/`): the list has no proxy member at all.
 *
 * Every account serves every model of its vendor (`models: "*"`): the list carries no
 * models, and the only per-credential list, `GET /credentials/models?name=`, is CLIProxyAPI's own
 * model registry for that client (its built-in catalog after `oauth-model-alias` and
 * `excluded-models`), the names its customers call rather than the vendor's names Gray's routes
 * send (`upstream_model`); restricting an account to them would take it out of a route whose
 * vendor's name an alias renamed. On Gray the relay's routes say which models it serves.
 * `GET /v8/management/credentials/download?name=<file>` returns the auth file, whose
 * provider-specific token fields become the credential. CLIProxyAPI runs its own proactive refresh
 * loop, so `refresh` is `"proactive"`; the daemon never calls a vendor token endpoint.
 *
 * Pinned reference: router-for-me/CLIProxyAPI commit
 * `ad8bdd3f20bef44f0684b8a6096a216b2c76040d` (2026-10-27), the commit the reference port builds:
 * - `docs/management-api-v8.md` lines 1-17 and 85-125: the routes and the bearer management key.
 * - `internal/api/server_routes.go` 140-150: `GET /` message used before a token is sent.
 * - `internal/api/server_management_v8.go` 45-49: `GET /credentials`, `GET /credentials/models`,
 *   `GET /credentials/download`.
 * - `internal/api/handlers/management/auth_files.go` 106-176, 221-230, 649-803: the list answer
 *   (`buildAuthFileEntryLocked`: no `models`, `weight`, `max_concurrency` or `proxy_url` member);
 *   335-381: `GetAuthFileModels`, the registry's models for one credential.
 * - `internal/api/handlers/management/auth_files_crud.go` 28-50: the download answer (raw auth JSON).
 * - `internal/auth/claude/token.go` 19-56 and `internal/auth/codex/token.go` 230-262: the auth files.
 * - `sdk/cliproxy/auth/metadata_keys.go` 23-24 and `internal/watcher/synthesizer/file.go` 151-228:
 *   `proxy_url` is an auth-file member; the list does not include it.
 * - `sdk/proxyutil/proxy.go` `Parse`: inherit, `direct`/`none`, or a `socks5`/`socks5h`/`http`/`https` URL.
 * - `internal/api/server_management_v8.go`: `GET /config` (the whole config as JSON; `requests.proxy-url` is the
 *   global proxy, and a member that is not set is left out).
 *
 * Shape changes are closed: `source_shape_changed` names a member path. The daemon keeps the last
 * good snapshot; this adapter never guesses. Unknown members are stripped, so a newer release that
 * adds fields does not break the adapter.
 */
import { jcsBytes, sha256BareHex } from "@gray/attest";
import {
  MAX_CREDENTIAL_LENGTH,
  VENDORS,
  type Credential,
  type Vendor,
} from "@gray/relay-connector";
import { z } from "zod";
import { RelayKitError } from "../../errors.ts";
import type { SourceAccount, SourceAccountStatus, SourceAdapter, SourceCredential } from "../../source/types.ts";
import type { SourceCliproxyConfig } from "./config-types.ts";
import { detectSourceSoftware } from "./detect.ts";
import { parseEgressUrl, type ParsedEgress } from "./egress.ts";
import { fetchJson, joinSourceUrl, withQuery } from "./http-client.ts";
import {
  PRINTABLE_CREDENTIAL,
  SOURCE_ID,
  SOURCE_TAG,
} from "./limits.ts";
import { selectedBy } from "./select.ts";

export type CliproxySourceConfig = SourceCliproxyConfig;

/** The list entry fields this adapter reads. Everything else is stripped before validation. */
const listEntrySchema = z.object({
  id: z.string().optional(),
  name: z.string().optional(),
  provider: z.string().optional(),
  type: z.string().optional(),
  status: z.string().optional(),
  disabled: z.boolean().optional(),
  unavailable: z.boolean().optional(),
  next_retry_after: z.union([z.string(), z.null()]).optional(),
  updated_at: z.union([z.string(), z.null()]).optional(),
  modtime: z.union([z.string(), z.null()]).optional(),
  last_refresh: z.union([z.string(), z.null()]).optional(),
  size: z.number().optional(),
  label: z.string().optional(),
  weight: z.number().optional(),
  expired: z.union([z.string(), z.null()]).optional(),
  expires_at: z.union([z.string(), z.number(), z.null()]).optional(),
  expires_at_ms: z.union([z.number(), z.null()]).optional(),
  credential_expires_at_ms: z.union([z.number(), z.null()]).optional(),
  max_concurrency: z.number().optional(),
});

const listSchema = z.object({
  files: z.array(z.unknown()),
});

/** One parsed list: metadata plus the label used by `select.tags` (never returned to the daemon). No proxy: see the header. */
export interface ParsedCliproxyList {
  readonly accounts: readonly SourceAccount[];
  readonly labels: ReadonlyMap<string, string>;
  /** Each account's place in the answer's `files`, for a member path (`files.<n>.proxy_url`). */
  readonly places: ReadonlyMap<string, number>;
}

/** CLIProxyAPI's reading of one proxy setting (`sdk/proxyutil` `Parse`). */
export type CliproxyProxySetting =
  | { readonly mode: "inherit" }
  | { readonly mode: "direct" }
  | { readonly mode: "proxy"; readonly proxy: ParsedEgress };

/**
 * One proxy setting as CLIProxyAPI reads it: missing or empty inherits the global one, `direct` or `none` (any case)
 * is no proxy, anything else must be a proxy URL the lane can seal. `detail` is a member path; it never holds the value.
 */
export function parseCliproxyProxySetting(raw: unknown, detail: string): CliproxyProxySetting {
  if (raw === undefined || raw === null) return { mode: "inherit" };
  if (typeof raw !== "string") throw new RelayKitError("source_shape_changed", detail);
  const text = raw.trim();
  if (text === "") return { mode: "inherit" };
  const word = text.toLowerCase();
  if (word === "direct" || word === "none") return { mode: "direct" };
  return { mode: "proxy", proxy: parseEgressUrl(text, detail) };
}

/** An auth file's own proxy setting (its `proxy_url` member). */
export function parseCliproxyAuthFileProxy(value: unknown, detail = "credential.proxy_url"): CliproxyProxySetting {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new RelayKitError("source_shape_changed", detail);
  return parseCliproxyProxySetting((value as Record<string, unknown>)["proxy_url"], detail);
}

const globalProxySchema = z.object({
  requests: z.object({ "proxy-url": z.unknown().optional() }).optional(),
});

/** The global proxy of `GET /config`: `requests.proxy-url`, left out of the answer when it is not set. */
export function parseCliproxyGlobalProxy(value: unknown): CliproxyProxySetting {
  const parsed = globalProxySchema.safeParse(value);
  if (!parsed.success) throw new RelayKitError("source_shape_changed", "config.requests");
  return parseCliproxyProxySetting(parsed.data.requests?.["proxy-url"], "config.requests.proxy-url");
}

const NO_GLOBAL: CliproxyProxySetting = { mode: "inherit" };

/** The proxy an account leaves through: its own, else the global one; null for none. */
export function resolveCliproxyProxy(own: CliproxyProxySetting, global: CliproxyProxySetting): ParsedEgress | null {
  if (own.mode === "proxy") return own.proxy;
  if (own.mode === "direct") return null;
  return global.mode === "proxy" ? global.proxy : null;
}

function sameProxy(left: ParsedEgress | null, right: ParsedEgress | null): boolean {
  if (left === null || right === null) return left === right;
  return (
    left.egress.type === right.egress.type &&
    left.egress.host === right.egress.host &&
    left.egress.port === right.egress.port &&
    left.egress.username === right.egress.username &&
    left.password === right.password
  );
}

/** A listed account with the proxy its auth file (or the global setting) names; the mark moves with the proxy. */
function withProxy(account: SourceAccount, proxy: ParsedEgress): SourceAccount {
  const signals = [account.changeMark, proxy.egress.type, proxy.egress.host, String(proxy.egress.port), proxy.egress.username ?? "", proxy.password ?? ""];
  return { ...account, changeMark: sha256BareHex(jcsBytes(signals)), egress: proxy.egress };
}

const RFC3339 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/u;

/** A timestamp as CLIProxyAPI writes Go's `time.Time`, in Unix milliseconds. */
export function parseRfc3339Ms(text: string, detail: string): number {
  if (!RFC3339.test(text)) throw new RelayKitError("source_shape_changed", detail);
  const ms = Date.parse(text);
  if (!Number.isFinite(ms) || ms < 0) throw new RelayKitError("source_shape_changed", detail);
  return ms;
}

function expiryFromEntry(entry: z.infer<typeof listEntrySchema>, detail: string): number | undefined {
  const values: number[] = [];
  if (entry.credential_expires_at_ms !== undefined && entry.credential_expires_at_ms !== null) {
    values.push(entry.credential_expires_at_ms);
  }
  if (entry.expires_at_ms !== undefined && entry.expires_at_ms !== null) values.push(entry.expires_at_ms);
  if (entry.expired !== undefined && entry.expired !== null && entry.expired !== "") {
    values.push(parseRfc3339Ms(entry.expired, `${detail}.expired`));
  }
  if (entry.expires_at !== undefined && entry.expires_at !== null) {
    if (typeof entry.expires_at === "number") values.push(entry.expires_at * 1000);
    else if (entry.expires_at !== "") values.push(parseRfc3339Ms(entry.expires_at, `${detail}.expires_at`));
  }
  if (values.length === 0) return undefined;
  const first = values[0] as number;
  for (const value of values) {
    if (!Number.isSafeInteger(value) || value < 0 || value !== first) {
      throw new RelayKitError("source_shape_changed", `${detail}.expires_at`);
    }
  }
  return first;
}

interface ProviderMap {
  readonly vendor: Vendor;
  readonly credentialType: "api_key" | "oauth_access_token";
}

function providerOf(entry: z.infer<typeof listEntrySchema>): ProviderMap | null {
  const provider = (entry.provider ?? entry.type ?? "").trim().toLowerCase();
  switch (provider) {
    case "claude":
    case "anthropic":
      return { vendor: "anthropic", credentialType: "oauth_access_token" };
    case "codex":
      return { vendor: "chatgpt_codex", credentialType: "oauth_access_token" };
    case "openai":
      return { vendor: "openai", credentialType: "api_key" };
    default:
      return null;
  }
}

function statusOf(
  entry: z.infer<typeof listEntrySchema>,
  limitedUntilMs: number | undefined,
): { readonly status: SourceAccountStatus; readonly limitedUntilMs: number | undefined } {
  if (entry.disabled === true || entry.status === "disabled") {
    return { status: "disabled", limitedUntilMs: undefined };
  }
  const status = (entry.status ?? "").trim().toLowerCase();
  const limited = status === "error" || status === "pending" || status === "refreshing" || status === "unknown" || entry.unavailable === true || limitedUntilMs !== undefined;
  if (!limited) return { status: "active", limitedUntilMs: undefined };
  // A status value a newer release introduces is a temporary unavailability, not an active
  // credential: the safe reading. There is no "banned" in CLIProxyAPI's lifecycle enum, so a
  // generic error is never promoted to a permanent ban.
  return { status: "limited", limitedUntilMs };
}

function changeMarkOf(entry: z.infer<typeof listEntrySchema>, detail: string, expiryMs: number | undefined): string {
  // The modification timestamps are opaque signals here: Go writes them as RFC3339, but a future
  // release may change the text and the mark should still track it rather than fail the snapshot.
  const signals = [
    entry.updated_at ?? "",
    entry.modtime ?? "",
    entry.last_refresh ?? "",
    entry.size === undefined ? "" : String(entry.size),
    expiryMs === undefined ? "" : String(expiryMs),
    // The place the list's proxy once had (the list has none): kept, so an account without a proxy keeps its mark.
    "",
  ];
  if (signals[0] === "" && signals[1] === "" && signals[2] === "" && signals[3] === "") {
    // Without a modification or refresh signal the adapter cannot tell whether the secret
    // changed; a constant mark would silently stop the push path.
    throw new RelayKitError("source_shape_changed", `${detail}.updated_at`);
  }
  return sha256BareHex(jcsBytes(signals));
}

/** Parse the `GET /credentials` answer. `nowMs` decides whether a cooldown is still in the future. */
export function parseCliproxyCredentialList(value: unknown, maxAccounts: number, nowMs: number): ParsedCliproxyList {
  // `nowMs` is kept in the signature (callers and golden vectors pass their clock); an expired
  // `next_retry_after` is now retained rather than discarded (R11).
  void nowMs;
  const parsed = listSchema.safeParse(value);
  if (!parsed.success) throw new RelayKitError("source_shape_changed", "files");
  if (parsed.data.files.length > maxAccounts) throw new RelayKitError("source_shape_changed", "files");
  const accounts: SourceAccount[] = [];
  const labels = new Map<string, string>();
  const places = new Map<string, number>();
  const seen = new Set<string>();
  for (let index = 0; index < parsed.data.files.length; index += 1) {
    const entry = listEntrySchema.safeParse(parsed.data.files[index]);
    if (!entry.success) throw new RelayKitError("source_shape_changed", `files.${index}`);
    const detail = `files.${index}`;
    const providerName = entry.data.provider ?? entry.data.type;
    if (typeof providerName !== "string" || providerName.trim() === "") {
      // An entry without a provider cannot be mapped; that is a shape change, not an unsupported
      // software (which is present and recognizable, just not a lane vendor in v1).
      throw new RelayKitError("source_shape_changed", `${detail}.provider`);
    }
    const provider = providerOf(entry.data);
    if (provider === null) continue; // Gemini, Antigravity, Kimi, …: not a lane vendor in v1.
    const sourceId = (entry.data.name ?? entry.data.id ?? "").trim();
    if (sourceId === "" || !SOURCE_ID.test(sourceId)) throw new RelayKitError("source_shape_changed", `${detail}.name`);
    if (seen.has(sourceId)) throw new RelayKitError("source_shape_changed", `${detail}.name`);
    seen.add(sourceId);
    if (entry.data.weight !== undefined) {
      if (!Number.isInteger(entry.data.weight) || entry.data.weight < 0 || entry.data.weight > 1_000_000) {
        throw new RelayKitError("source_shape_changed", `${detail}.weight`);
      }
    }
    if (entry.data.max_concurrency !== undefined && (!Number.isInteger(entry.data.max_concurrency) || entry.data.max_concurrency < 1 || entry.data.max_concurrency > 10_000)) {
      throw new RelayKitError("source_shape_changed", `${detail}.max_concurrency`);
    }
    const expiryMs = expiryFromEntry(entry.data, detail);
    let limitedUntilMs: number | undefined;
    if (entry.data.next_retry_after !== undefined && entry.data.next_retry_after !== null && entry.data.next_retry_after !== "") {
      // R11: keep the deadline even after it has passed. An entry still marked error/unavailable
      // is then `limited` with an expired deadline, which the daemon's eligibility check admits;
      // dropping it made the exclusion permanent with no deadline at all.
      limitedUntilMs = parseRfc3339Ms(entry.data.next_retry_after, `${detail}.next_retry_after`);
    }
    const status = statusOf(entry.data, limitedUntilMs);
    const weight = entry.data.weight === 0 ? 1n : BigInt(entry.data.weight ?? 1);
    const sourceStatus = entry.data.weight === 0 && status.status === "active" ? "disabled" : status.status;
    const label = entry.data.label === undefined ? "" : entry.data.label.trim();
    if (label !== "" && !SOURCE_TAG.test(label)) throw new RelayKitError("source_shape_changed", `${detail}.label`);
    labels.set(sourceId, label);
    places.set(sourceId, index);
    accounts.push({
      sourceId,
      vendor: provider.vendor,
      credentialType: provider.credentialType,
      // Every model of the vendor: see the header (no list member names models; a `models` a
      // release adds is stripped with the other unknown members, never read as a restriction).
      models: "*",
      weight,
      maxConcurrency: BigInt(entry.data.max_concurrency ?? 1),
      status: sourceStatus as SourceAccountStatus,
      ...(status.limitedUntilMs === undefined ? {} : { limitedUntilMs: status.limitedUntilMs }),
      ...(expiryMs === undefined ? {} : { credentialExpiresAtMs: expiryMs }),
      changeMark: changeMarkOf(entry.data, detail, expiryMs),
    });
  }
  return { accounts, labels, places };
}

const authFileSchema = z.object({
  type: z.string(),
  access_token: z.string().optional(),
  api_key: z.string().optional(),
  key: z.string().optional(),
  expired: z.union([z.string(), z.null()]).optional(),
  expires_at: z.union([z.string(), z.number(), z.null()]).optional(),
});

/** The auth file's own expiry, in Unix milliseconds; two different declarations are ambiguous. */
function authExpiryMs(data: z.infer<typeof authFileSchema>): number | undefined {
  const values: number[] = [];
  if (data.expired !== undefined && data.expired !== null && data.expired !== "") {
    values.push(parseRfc3339Ms(data.expired, "credential.expired"));
  }
  if (data.expires_at !== undefined && data.expires_at !== null) {
    if (typeof data.expires_at === "number") values.push(data.expires_at * 1000);
    else if (data.expires_at !== "") values.push(parseRfc3339Ms(data.expires_at, "credential.expires_at"));
  }
  if (values.length === 0) return undefined;
  const first = values[0] as number;
  for (const value of values) {
    if (!Number.isSafeInteger(value) || value < 0 || value !== first) {
      throw new RelayKitError("source_shape_changed", "credential.expires_at");
    }
  }
  return first;
}

/** One auth file's token fields, by provider; the vendor is what the file's `type` says. */
export interface ParsedAuthFile {
  readonly vendor: Vendor;
  readonly credential: Credential;
}

export function parseCliproxyAuthFile(value: unknown): ParsedAuthFile {
  const parsed = authFileSchema.safeParse(value);
  if (!parsed.success) throw new RelayKitError("source_shape_changed", "credential");
  const provider = parsed.data.type.trim().toLowerCase();
  let vendor: Vendor;
  let type: "api_key" | "oauth_access_token";
  let raw: string | undefined;
  switch (provider) {
    case "claude":
    case "anthropic":
      vendor = "anthropic";
      type = "oauth_access_token";
      raw = parsed.data.access_token;
      break;
    case "codex":
      vendor = "chatgpt_codex";
      type = "oauth_access_token";
      raw = parsed.data.access_token;
      break;
    case "openai":
      vendor = "openai";
      type = "api_key";
      raw = parsed.data.api_key ?? parsed.data.key;
      break;
    default:
      throw new RelayKitError("source_unsupported", "credential provider");
  }
  if (raw === undefined || raw.length === 0 || raw.length > MAX_CREDENTIAL_LENGTH || !PRINTABLE_CREDENTIAL.test(raw)) {
    throw new RelayKitError("source_shape_changed", "credential.value");
  }
  const expiry = authExpiryMs(parsed.data);
  const credential: Credential = {
    type,
    value: raw,
    ...(expiry === undefined ? {} : { expires_at: BigInt(Math.floor(expiry / 1000)) }),
  };
  return { vendor, credential };
}

/** A file name the download route can take: no separator, no `..` segment. */
const DOWNLOAD_NAME = /^(?!.*\.\.)[A-Za-z0-9._@+,-]{1,255}\.json$/u;

/** How many auth files `list()` reads at once for their proxy: the source is the relay's own software, beside the agent. */
const PROXY_READS_AT_ONCE = 8;

export interface CliproxyAdapterDeps {
  readonly fetch: typeof fetch;
  readonly readTokenFile: (path: string) => string;
  readonly now: () => number;
}

function readToken(deps: CliproxyAdapterDeps, path: string): string {
  const token = deps.readTokenFile(path).trim();
  if (token.length === 0 || token.length > 8192 || !PRINTABLE_CREDENTIAL.test(token)) {
    throw new RelayKitError("source_bad_response", "token_file");
  }
  return token;
}

/**
 * The `cliproxyapi` adapter. Software detection is cached for the process (K4-2): it runs on the
 * first management call (or `probe()`) and again only after a `source_shape_changed` refusal, which
 * is the one code that means the URL may now be a different software. Until then the management
 * token is never sent to a URL this adapter has not identified.
 */
export function cliproxyAdapter(config: CliproxySourceConfig, deps: CliproxyAdapterDeps): SourceAdapter {
  let detected: { readonly software: string; readonly version: string | null; readonly credentialReadable: boolean } | null = null;
  // The proxy the last list declared for each account it returned (null: none). The password is held here, out of the
  // metadata (K4-1), and `credential()` seals an account only while its auth file still names this proxy.
  const declared = new Map<string, ParsedEgress | null>();
  // The global proxy as that list read it, when an account of it inherited; a credential read uses it, so reading N
  // credentials does not read the config N times.
  let listedGlobal: CliproxyProxySetting | undefined;
  const detect = async (signal: AbortSignal): Promise<{ readonly software: string; readonly version: string | null; readonly credentialReadable: boolean }> => {
    const result = await detectSourceSoftware(config.url, {
      fetch: deps.fetch,
      signal,
      timeoutMs: config.probeTimeoutMs,
      maxResponseBytes: config.maxResponseBytes,
    });
    detected = result;
    return result;
  };
  const assertSoftware = async (signal: AbortSignal): Promise<void> => {
    const probe = detected ?? (await detect(signal));
    if (probe.software !== "cliproxyapi") {
      // The token is not sent: the URL is not (or no longer) CLIProxyAPI.
      throw new RelayKitError("source_unsupported", `software ${probe.software}`);
    }
  };
  /** Clear a cached detection only for the one refusal that can mean "different software now". */
  const withDetectionCache = async <T>(run: () => Promise<T>): Promise<T> => {
    try {
      return await run();
    } catch (error) {
      if (error instanceof RelayKitError && error.code === "source_shape_changed") detected = null;
      throw error;
    }
  };
  const management = (...path: string[]): string => joinSourceUrl(config.url, "v8", "management", ...path);
  /** One auth file, whole. The download route takes a file name, never a path. */
  const download = (sourceId: string, token: string, signal: AbortSignal): Promise<unknown> =>
    fetchJson(withQuery(management("credentials", "download"), "name", sourceId), {
      fetch: deps.fetch,
      signal,
      timeoutMs: config.requestTimeoutMs,
      maxBytes: config.maxCredentialBytes,
      headers: { authorization: `Bearer ${token}` },
      label: "credential",
      notFoundCode: "source_not_found",
    });
  /** The global proxy, read from the config only when an account inherits it. */
  const globalProxy = async (token: string, signal: AbortSignal): Promise<CliproxyProxySetting> =>
    parseCliproxyGlobalProxy(
      await fetchJson(management("config"), {
        fetch: deps.fetch,
        signal,
        timeoutMs: config.requestTimeoutMs,
        maxBytes: config.maxResponseBytes,
        headers: { authorization: `Bearer ${token}` },
        label: "config",
      }),
    );
  return {
    kind: "cliproxyapi",
    async probe(signal) {
      return detected ?? (await detect(signal));
    },
    async list(signal) {
      return withDetectionCache(async () => {
        await assertSoftware(signal);
        const token = readToken(deps, config.tokenFile);
        const value = await fetchJson(management("credentials"), {
          fetch: deps.fetch,
          signal,
          timeoutMs: config.requestTimeoutMs,
          maxBytes: config.maxResponseBytes,
          headers: { authorization: `Bearer ${token}` },
          label: "accounts",
        });
        const parsed = parseCliproxyCredentialList(value, config.maxAccounts, deps.now());
        const selected = parsed.accounts.filter((account) =>
          selectedBy(config.select, { sourceId: account.sourceId, vendor: account.vendor, tags: [parsed.labels.get(account.sourceId) ?? ""] }),
        );
        // Each selected account's proxy, from its auth file (see the header). An account whose file name the download
        // route cannot take is listed without one: `credential()` refuses that name before anything is sealed.
        let global: Promise<CliproxyProxySetting> | undefined;
        const proxyOf = async (account: SourceAccount): Promise<ParsedEgress | null | "gone" | "unreadable"> => {
          if (!DOWNLOAD_NAME.test(account.sourceId)) return "unreadable";
          let file: unknown;
          try {
            file = await download(account.sourceId, token, signal);
          } catch (error) {
            // Deleted between the list and this read: it is no account any more.
            if (error instanceof RelayKitError && error.code === "source_not_found") return "gone";
            throw error;
          }
          const own = parseCliproxyAuthFileProxy(file, `files.${parsed.places.get(account.sourceId) ?? 0}.proxy_url`);
          return resolveCliproxyProxy(own, own.mode === "inherit" ? await (global ??= globalProxy(token, signal)) : NO_GLOBAL);
        };
        const proxies: (ParsedEgress | null | "gone" | "unreadable")[] = new Array(selected.length);
        let next = 0;
        const worker = async (): Promise<void> => {
          for (let at = next++; at < selected.length; at = next++) proxies[at] = await proxyOf(selected[at] as SourceAccount);
        };
        await Promise.all(Array.from({ length: Math.min(PROXY_READS_AT_ONCE, selected.length) }, worker));
        declared.clear();
        listedGlobal = global === undefined ? undefined : await global;
        const accounts: SourceAccount[] = [];
        selected.forEach((account, at) => {
          const proxy = proxies[at] as ParsedEgress | null | "gone" | "unreadable";
          if (proxy === "gone") return;
          if (proxy === "unreadable" || proxy === null) {
            if (proxy === null) declared.set(account.sourceId, null);
            accounts.push(account);
            return;
          }
          declared.set(account.sourceId, proxy);
          accounts.push(withProxy(account, proxy));
        });
        return { accounts, refresh: "proactive" as const };
      });
    },
    async credential(sourceId: string, signal: AbortSignal): Promise<SourceCredential> {
      // The download route takes a file name, never a path. Reject a separator or a `..` segment
      // before the detection request, so the name never reaches a URL.
      if (!SOURCE_ID.test(sourceId) || !DOWNLOAD_NAME.test(sourceId)) {
        throw new RelayKitError("source_shape_changed", "credential.name");
      }
      return withDetectionCache(async () => {
        await assertSoftware(signal);
        const token = readToken(deps, config.tokenFile);
        const value = await download(sourceId, token, signal);
        const credential = parseCliproxyAuthFile(value).credential;
        // The account is sealed with the proxy the last list declared (every caller lists first), and only while the
        // file still names it: a proxy set, changed or removed in the file since the list is the next read's, never a
        // credential sealed for another proxy or for none. An account that inherits is held to the global proxy that
        // list read (the config is read again only when the list read none).
        const listed = declared.get(sourceId);
        if (listed === undefined) throw new RelayKitError("source_shape_changed", "credential.proxy_url");
        const own = parseCliproxyAuthFileProxy(value);
        const now = resolveCliproxyProxy(own, own.mode === "inherit" ? (listedGlobal ??= await globalProxy(token, signal)) : NO_GLOBAL);
        if (!sameProxy(listed, now)) throw new RelayKitError("source_shape_changed", "credential.proxy_url");
        return { credential, ...(listed?.password === undefined ? {} : { egressPassword: listed.password }) };
      });
    },
  };
}

/** The credential class the list's provider implies, exported for the fixture test. */
export function cliproxyCredentialType(provider: string): "api_key" | "oauth_access_token" | null {
  const map = providerOf({ provider } as z.infer<typeof listEntrySchema>);
  return map?.credentialType ?? null;
}

/** The vendor the list's provider implies, exported for the fixture test. */
export function cliproxyVendor(provider: string): Vendor | null {
  const map = providerOf({ provider } as z.infer<typeof listEntrySchema>);
  return map?.vendor ?? null;
}


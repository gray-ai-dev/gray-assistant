/**
 * The CLIProxyAPI source: management API v8, read-only.
 *
 * `GET /v8/management/credentials` lists credentials with non-secret state; the adapter maps
 * provider → vendor, `status`/`disabled`/`next_retry_after` → the lane's status, the modification
 * and refresh timestamps → an opaque `changeMark`, and (when the server exposes it) `proxy_url` →
 * `egress`. `GET /v8/management/credentials/download?name=<file>` returns the auth file, whose
 * provider-specific token fields become the credential. CLIProxyAPI runs its own proactive refresh
 * loop, so `refresh` is `"proactive"`; the daemon never calls a vendor token endpoint.
 *
 * Pinned reference: router-for-me/CLIProxyAPI commit
 * `20c9095cac089c6a8e40554debe4dd8a19d4c14f` (2026-10-20):
 * - `docs/management-api-v8.md` lines 83-118: the routes and the bearer management key.
 * - `internal/api/server_routes.go` 139-148: `GET /` message used before a token is sent.
 * - `internal/api/server_management_v8.go` 43-47: `GET /credentials`, `GET /credentials/download`.
 * - `internal/api/handlers/management/auth_files.go` 104-175, 219-228, 647-799: the list answer.
 * - `internal/api/handlers/management/auth_files_crud.go` 27-50: the download answer (raw auth JSON).
 * - `internal/auth/claude/token.go` 19-56 and `internal/auth/codex/token.go` 230-252: the auth files.
 * - `sdk/cliproxy/auth/metadata_keys.go` 23-24 and `internal/watcher/synthesizer/file.go` 151-228:
 *   `proxy_url` is an auth-file member; the pinned list does not include it.
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
  MODEL_ID,
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
  proxy_url: z.string().optional(),
  expired: z.union([z.string(), z.null()]).optional(),
  expires_at: z.union([z.string(), z.number(), z.null()]).optional(),
  expires_at_ms: z.union([z.number(), z.null()]).optional(),
  credential_expires_at_ms: z.union([z.number(), z.null()]).optional(),
  models: z.union([z.array(z.string()), z.literal("*")]).optional(),
  max_concurrency: z.number().optional(),
});

const listSchema = z.object({
  files: z.array(z.unknown()),
});

/** One parsed list: metadata plus the label used by `select.tags` (never returned to the daemon). */
export interface ParsedCliproxyList {
  readonly accounts: readonly SourceAccount[];
  readonly labels: ReadonlyMap<string, string>;
  /** Proxy passwords by source id, never part of `SourceAccount` (K4-1). */
  readonly egressPasswords: ReadonlyMap<string, string>;
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

function modelsOf(entry: z.infer<typeof listEntrySchema>, detail: string): readonly string[] | "*" {
  if (entry.models === undefined) return "*";
  if (entry.models === "*") return "*";
  const models = [...entry.models];
  if (models.length === 0 || models.length > 256) throw new RelayKitError("source_shape_changed", `${detail}.models`);
  for (const model of models) {
    if (!MODEL_ID.test(model)) throw new RelayKitError("source_shape_changed", `${detail}.models`);
  }
  return models;
}

function changeMarkOf(entry: z.infer<typeof listEntrySchema>, detail: string, expiryMs: number | undefined, proxy: ParsedEgress | undefined): string {
  // The modification timestamps are opaque signals here: Go writes them as RFC3339, but a future
  // release may change the text and the mark should still track it rather than fail the snapshot.
  const signals = [
    entry.updated_at ?? "",
    entry.modtime ?? "",
    entry.last_refresh ?? "",
    entry.size === undefined ? "" : String(entry.size),
    expiryMs === undefined ? "" : String(expiryMs),
    proxy === undefined
      ? ""
      : [proxy.egress.type, proxy.egress.host, String(proxy.egress.port), proxy.egress.username ?? "", proxy.password ?? ""].join("\u0000"),
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
  const egressPasswords = new Map<string, string>();
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
    let proxy: ParsedEgress | undefined;
    if (entry.data.proxy_url !== undefined && entry.data.proxy_url !== "") {
      proxy = parseEgressUrl(entry.data.proxy_url, `${detail}.proxy_url`);
      if (proxy.password !== undefined) egressPasswords.set(sourceId, proxy.password);
    }
    const status = statusOf(entry.data, limitedUntilMs);
    const weight = entry.data.weight === 0 ? 1n : BigInt(entry.data.weight ?? 1);
    const sourceStatus = entry.data.weight === 0 && status.status === "active" ? "disabled" : status.status;
    const label = entry.data.label === undefined ? "" : entry.data.label.trim();
    if (label !== "" && !SOURCE_TAG.test(label)) throw new RelayKitError("source_shape_changed", `${detail}.label`);
    labels.set(sourceId, label);
    accounts.push({
      sourceId,
      vendor: provider.vendor,
      credentialType: provider.credentialType,
      models: modelsOf(entry.data, detail),
      weight,
      maxConcurrency: BigInt(entry.data.max_concurrency ?? 1),
      status: sourceStatus as SourceAccountStatus,
      ...(status.limitedUntilMs === undefined ? {} : { limitedUntilMs: status.limitedUntilMs }),
      ...(expiryMs === undefined ? {} : { credentialExpiresAtMs: expiryMs }),
      changeMark: changeMarkOf(entry.data, detail, expiryMs, proxy),
      ...(proxy === undefined ? {} : { egress: proxy.egress }),
    });
  }
  return { accounts, labels, egressPasswords };
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
  // The list declares the proxy whole; the password is held out of the metadata (K4-1).
  const egressPasswords = new Map<string, string>();
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
  return {
    kind: "cliproxyapi",
    async probe(signal) {
      return detected ?? (await detect(signal));
    },
    async list(signal) {
      return withDetectionCache(async () => {
        await assertSoftware(signal);
        const token = readToken(deps, config.tokenFile);
        const value = await fetchJson(joinSourceUrl(config.url, "v8", "management", "credentials"), {
          fetch: deps.fetch,
          signal,
          timeoutMs: config.requestTimeoutMs,
          maxBytes: config.maxResponseBytes,
          headers: { authorization: `Bearer ${token}` },
          label: "accounts",
        });
        const parsed = parseCliproxyCredentialList(value, config.maxAccounts, deps.now());
        egressPasswords.clear();
        for (const [sourceId, password] of parsed.egressPasswords) egressPasswords.set(sourceId, password);
        const accounts = parsed.accounts.filter((account) =>
          selectedBy(config.select, { sourceId: account.sourceId, vendor: account.vendor, tags: [parsed.labels.get(account.sourceId) ?? ""] }),
        );
        return { accounts, refresh: "proactive" as const };
      });
    },
    async credential(sourceId: string, signal: AbortSignal): Promise<SourceCredential> {
      // The download route takes a file name, never a path. Reject a separator or a `..` segment
      // before the detection request, so the name never reaches a URL.
      if (!SOURCE_ID.test(sourceId) || !/^(?!.*\.\.)[A-Za-z0-9._@+,-]{1,255}\.json$/u.test(sourceId)) {
        throw new RelayKitError("source_shape_changed", "credential.name");
      }
      return withDetectionCache(async () => {
        await assertSoftware(signal);
        const token = readToken(deps, config.tokenFile);
        const url = withQuery(joinSourceUrl(config.url, "v8", "management", "credentials", "download"), "name", sourceId);
        const value = await fetchJson(url, {
          fetch: deps.fetch,
          signal,
          timeoutMs: config.requestTimeoutMs,
          maxBytes: config.maxCredentialBytes,
          headers: { authorization: `Bearer ${token}` },
          label: "credential",
          notFoundCode: "source_not_found",
        });
        const credential = parseCliproxyAuthFile(value).credential;
        const password = egressPasswords.get(sourceId);
        return { credential, ...(password === undefined ? {} : { egressPassword: password }) };
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


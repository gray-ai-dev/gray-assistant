/**
 * Name the relay software behind a URL without credentials. Every probe is a GET to a documented,
 * harmless, unauthenticated route of one project; no `Authorization` header is ever sent, and a
 * token is only sent by an adapter after its kind is known (CLIProxyAPI additionally re-detects
 * before the management request, so a URL that changed software never receives the key).
 *
 * The probes are intentionally conservative. `/api/status` is served by both new-api and one-api
 * (they share an ancestor), so a body that does not carry one project's distinctive member is
 * `unknown`, never a guess. A version is reported only when the project exposes one there.
 *
 * Sources (read-only, pinned commits in `IMPLEMENTATION_NOTES.md`):
 * - CLIProxyAPI `internal/api/server_routes.go` lines 139-148: `GET /` answers
 *   `{"message":"CLI Proxy API Server","endpoints":[...]}`; `/healthz` is generic and unused here.
 * - claude-relay-service `src/app.js` lines 378-430: `GET /health` answers
 *   `{"status":"healthy","service":"claude-relay-service","version":...}`.
 * - sub2api `backend/internal/server/routes/auth.go:246` (`/api/v1/settings/public`) and
 *   `backend/internal/handler/setting_handler.go:39-46,71,99` + `dto/settings.go:367-423`:
 *   `{"code":0,"data":{"version":...,"site_name":...,"registration_enabled":...}}`.
 * - new-api `controller/misc.go:41-185` and `router/api-router.go:28`: `GET /api/status` answers
 *   `{"success":true,"data":{...,"version":...,"theme":...}}`; one-api `controller/misc.go:18-45`
 *   and `router/api.go:17` answers the same envelope with `lark_client_id` instead of new-api's
 *   `theme`/`discord_oauth`/`linuxdo_oauth`/`telegram_oauth` members.
 */
import type { SourceProbe } from "../../source/types.ts";
import { RelayKitError } from "../../errors.ts";
import { fetchText, joinSourceUrl, parseJsonText } from "./http-client.ts";
import { DEFAULT_MAX_RESPONSE_BYTES, DEFAULT_PROBE_TIMEOUT_MS } from "./limits.ts";

/** The software names a probe may return. */
export const DETECTED_SOFTWARE = ["cliproxyapi", "sub2api", "claude-relay-service", "new-api", "one-api", "unknown"] as const;
export type DetectedSoftware = (typeof DETECTED_SOFTWARE)[number];

/** The software whose credential can be read without a person present in v1. */
export const UNATTENDED_CREDENTIAL_SOFTWARE: readonly string[] = ["cliproxyapi", "http", "file"];

export interface DetectSourceOptions {
  readonly fetch?: typeof fetch;
  readonly signal?: AbortSignal;
  readonly timeoutMs?: number;
  readonly maxResponseBytes?: number;
}

type JsonObject = Record<string, unknown>;

function isObject(value: unknown): value is JsonObject {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** A version string from an unauthenticated body; a control character or an overlong text is not one. */
export function exposedVersion(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const text = value.trim();
  if (text.length === 0 || text.length > 64 || /[\u0000-\u001f\u007f]/.test(text)) return null;
  return text;
}

function result(software: DetectedSoftware, version: string | null = null): SourceProbe {
  return { software, version, credentialReadable: UNATTENDED_CREDENTIAL_SOFTWARE.includes(software) };
}

export function classifyCliproxyRoot(value: unknown): SourceProbe | null {
  if (!isObject(value)) return null;
  if (value.message !== "CLI Proxy API Server") return null;
  if (!Array.isArray(value.endpoints)) return null;
  if (!value.endpoints.includes("GET /v1/models")) return null;
  // The root route does not expose a version; /v8/management/server/latest-version needs the key.
  return result("cliproxyapi", null);
}

export function classifyCrsHealth(value: unknown): SourceProbe | null {
  if (!isObject(value)) return null;
  if (value.service !== "claude-relay-service") return null;
  return result("claude-relay-service", exposedVersion(value.version));
}

export function classifySub2apiSettings(value: unknown): SourceProbe | null {
  if (!isObject(value)) return null;
  if (value.code !== 0 || !isObject(value.data)) return null;
  const data = value.data;
  if (typeof data.version !== "string") return null;
  if (typeof data.site_name !== "string" && typeof data.registration_enabled !== "boolean") return null;
  return result("sub2api", exposedVersion(data.version));
}

export function classifyStatus(value: unknown): SourceProbe | null {
  if (!isObject(value)) return null;
  if (value.success !== true || !isObject(value.data)) return null;
  const data = value.data;
  if (typeof data.version !== "string") return null;
  const oneApi = Object.hasOwn(data, "lark_client_id");
  const newApi =
    Object.hasOwn(data, "theme") ||
    Object.hasOwn(data, "discord_oauth") ||
    Object.hasOwn(data, "linuxdo_oauth") ||
    Object.hasOwn(data, "telegram_oauth");
  // Both markers (or neither) means this probe cannot tell them apart; returning one would be a guess.
  if (oneApi === newApi) return null;
  return result(oneApi ? "one-api" : "new-api", exposedVersion(data.version));
}

/**
 * Probe `baseUrl` with GETs to `/`, `/health`, `/api/v1/settings/public` and `/api/status` in that
 * order, and return the first project that answers with its documented shape. A transport failure
 * on the first probe throws `source_unreachable`; an HTTP answer that matches nothing is `unknown`.
 */
export async function detectSourceSoftware(baseUrl: string, options: DetectSourceOptions = {}): Promise<SourceProbe> {
  const fetchImpl: typeof fetch = options.fetch ?? ((input, init) => globalThis.fetch(input, init));
  const timeoutMs = options.timeoutMs ?? DEFAULT_PROBE_TIMEOUT_MS;
  const maxBytes = options.maxResponseBytes ?? DEFAULT_MAX_RESPONSE_BYTES;
  let answered = false;
  const get = async (path: string): Promise<unknown | null> => {
    let response;
    try {
      response = await fetchText(joinSourceUrl(baseUrl, path), {
        fetch: fetchImpl,
        signal: options.signal,
        timeoutMs,
        maxBytes,
        headers: { accept: "application/json" },
        label: "probe",
      });
    } catch (error) {
      if (error instanceof RelayKitError && error.code === "source_unreachable") throw error;
      // An oversize or non-UTF-8 answer still came from a server; it just matched nothing.
      answered = true;
      return null;
    }
    answered = true;
    if (response.status !== 200) return null;
    try {
      return parseJsonText(response.text, "probe");
    } catch {
      return null;
    }
  };

  const root = await get("");
  const named = classifyCliproxyRoot(root);
  if (named !== null) return named;
  const health = await get("health");
  const crs = classifyCrsHealth(health);
  if (crs !== null) return crs;
  const settings = await get("api/v1/settings/public");
  const sub = classifySub2apiSettings(settings);
  if (sub !== null) return sub;
  const status = await get("api/status");
  const go = classifyStatus(status);
  if (go !== null) return go;
  if (!answered) throw new RelayKitError("source_unreachable", "probe");
  return result("unknown", null);
}

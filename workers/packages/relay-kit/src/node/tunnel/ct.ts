/**
 * The relay's own Certificate Transparency monitor (docs/relay-tunnel.md, "Detection"). Gray controls the relays
 * zone's DNS and the rendezvous, so Gray could obtain a certificate for the relay's name and stand in the middle of
 * the tunnel. Every publicly trusted CA logs what it issues (browsers require it), so such a certificate is public:
 * this monitor asks two independent CT search services for every unexpired certificate valid for the relay's name
 * (the name itself or `*.<zone>`) and calls any whose public key the relay's own terminator never served foreign.
 *
 * - Cert Spotter (SSLMate, https://sslmate.com/help/reference/ct_search_api_v1): `GET /v1/issuances?domain=<name>
 *   &match_wildcards=true&expand=dns_names&expand=issuer`, paged with `after`; each issuance carries `pubkey_sha256`,
 *   SHA-256 of the DER SubjectPublicKeyInfo. Unauthenticated: 100 queries an hour (`x-ratelimit-limit`, 2026-10-29);
 *   an API key file raises it.
 * - crt.sh (Sectigo, https://crt.sh/): `?q=<name>&output=json&exclude=expired` and the same for `*.<zone>`; each new
 *   entry's certificate is downloaded (`?d=<id>`) and its key hashed here with Node's X.509 parser.
 *
 * A key is the relay's when its terminator served it (`supervisor.ts` keeps every one); before a key is called
 * foreign, the terminator is read again, so a certificate Caddy obtained a moment ago is not an alert. A foreign
 * certificate is a finding: logged, sent once to the relay's own alert channel (`../alerts.ts`), shown by `doctor`
 * and in the status until the operator acknowledges it (`gray-assistant tunnel ack <cert_sha256>`) or it expires.
 */
import { createHash, X509Certificate } from "node:crypto";
import { parsePlain } from "@gray/json";
import type { TunnelConfig } from "../../daemon/config.ts";
import type { DaemonLogEvent } from "../../daemon/types.ts";
import { readAtomicDocument, writeAtomicPrivateFile } from "../daemon/atomic-file.ts";
import { readPrivateFile } from "../files.ts";

export type CtSource = "certspotter" | "crtsh";

/** One certificate (or precertificate) valid for the name, as a source reported it. */
export interface CtIssuance {
  readonly source: CtSource;
  /** The source's own id (Cert Spotter's issuance id, crt.sh's entry id). */
  readonly id: string;
  /** SHA-256 of the (pre)certificate's DER, when the source gives it. */
  readonly certSha256: string | null;
  readonly pubkeySha256: string;
  readonly dnsNames: readonly string[];
  readonly issuer: string;
  readonly notBeforeMs: number;
  readonly notAfterMs: number;
}

export interface CtFinding extends CtIssuance {
  readonly foundMs: number;
  /** When the alert channel took it; null while it has not (or there is none). */
  readonly alertedMs: number | null;
}

export interface CtSourceState {
  readonly ok: boolean;
  readonly atMs: number;
  /** One word when the last query failed: `rate_limited`, `http_<status>`, `unreachable`, `malformed`. */
  readonly error: string | null;
}

export interface CtState {
  readonly name: string;
  readonly sources: Partial<Record<CtSource, CtSourceState>>;
  /** Cert Spotter's paging cursor: the last issuance id it returned. */
  readonly certspotterAfter: string | null;
  /** crt.sh entries already judged, so each certificate is downloaded once. */
  readonly crtshSeen: readonly string[];
  readonly findings: readonly CtFinding[];
  readonly checkedMs: number | null;
}

/** The monitor's verdict, as `doctor` and the status show it. */
export interface CtView {
  /** `ok`: every source answered within two polls and nothing foreign; `alert`: a foreign certificate; `unknown`: no source answered lately. */
  readonly state: "ok" | "alert" | "unknown";
  readonly checkedMs: number | null;
  readonly sources: Partial<Record<CtSource, CtSourceState>>;
  readonly findings: readonly CtFinding[];
}

const EMPTY_STATE = (name: string): CtState => ({ name, sources: {}, certspotterAfter: null, crtshSeen: [], findings: [], checkedMs: null });
/** At most this many crt.sh certificates are downloaded per poll; the rest wait for the next. */
const CRTSH_DOWNLOADS_PER_POLL = 20;
/** Cert Spotter pages read per poll (each up to the API's page size). */
const CERTSPOTTER_PAGES_PER_POLL = 20;
const REQUEST_TIMEOUT_MS = 30_000;
const MAX_RESPONSE_BYTES = 8 * 1024 * 1024;

export function readCtState(path: string, name: string): CtState {
  const text = readAtomicDocument(path);
  if (text === null) return EMPTY_STATE(name);
  try {
    const value = parsePlain(text) as CtState;
    if (value?.name !== name || !Array.isArray(value.findings) || !Array.isArray(value.crtshSeen)) return EMPTY_STATE(name);
    return value;
  } catch {
    return EMPTY_STATE(name);
  }
}

/** The acknowledged certificates (`gray-assistant tunnel ack` writes them): their cert or key SHA-256 values. */
export function readCtAcks(path: string): Set<string> {
  const text = readAtomicDocument(path);
  if (text === null) return new Set();
  try {
    const value = parsePlain(text) as { acks?: unknown };
    return new Set(Array.isArray(value?.acks) ? value.acks.filter((a): a is string => typeof a === "string" && /^[0-9a-f]{64}$/.test(a)) : []);
  } catch {
    return new Set();
  }
}

export function writeCtAck(path: string, sha256: string): void {
  const acks = readCtAcks(path);
  acks.add(sha256);
  writeAtomicPrivateFile(path, `${JSON.stringify({ acks: [...acks].sort() })}\n`);
}

/** Whether a certificate DNS name makes it valid for `name` under `zone`: the name itself or the one-label wildcard. */
export function coversName(dnsName: string, name: string, zone: string): boolean {
  const lower = dnsName.toLowerCase();
  return lower === name || lower === `*.${zone}`;
}

/** The view from a state: unacknowledged, unexpired findings, and whether the sources answered within two polls. */
export function ctView(state: CtState, acks: ReadonlySet<string>, nowMs: number, pollMs: number): CtView {
  const findings = state.findings.filter((f) => f.notAfterMs > nowMs && !acks.has(f.pubkeySha256) && !(f.certSha256 !== null && acks.has(f.certSha256)));
  const fresh = Object.values(state.sources).some((s) => s !== undefined && s.ok && nowMs - s.atMs <= 2 * pollMs);
  return { state: findings.length > 0 ? "alert" : fresh ? "ok" : "unknown", checkedMs: state.checkedMs, sources: state.sources, findings };
}

type Fetch = (url: string, init: RequestInit) => Promise<Response>;

async function readBody(response: Response): Promise<string> {
  const body = new Uint8Array(await response.arrayBuffer());
  if (body.length > MAX_RESPONSE_BYTES) throw new Error("too large");
  return new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(body);
}

const sourceError = (status: number): string => (status === 429 ? "rate_limited" : `http_${status}`);

/** A UTC instant as crt.sh writes it (`2026-09-14T00:00:00`, no zone) or Cert Spotter (`…Z`). */
function utcMs(text: unknown): number {
  if (typeof text !== "string") return NaN;
  return Date.parse(/[zZ]|[+-]\d\d:\d\d$/.test(text) ? text : `${text}Z`);
}

/** Cert Spotter's unexpired issuances for the name (and its wildcard) after the stored cursor. */
export async function queryCertSpotter(options: {
  readonly config: TunnelConfig;
  readonly after: string | null;
  readonly fetch: Fetch;
}): Promise<{ readonly issuances: CtIssuance[]; readonly after: string | null } | { readonly error: string }> {
  const { config } = options;
  let key: string | null = null;
  if (config.ct.certspotterKeyFile !== null) {
    try {
      key = readPrivateFile(config.ct.certspotterKeyFile, "Cert Spotter API key", 4096).trim();
    } catch {
      return { error: "key_file" };
    }
  }
  const issuances: CtIssuance[] = [];
  let after = options.after;
  for (let page = 0; page < CERTSPOTTER_PAGES_PER_POLL; page += 1) {
    const query = new URLSearchParams({ domain: config.name, match_wildcards: "true" });
    query.append("expand", "dns_names");
    query.append("expand", "issuer");
    if (after !== null) query.set("after", after);
    let response: Response;
    try {
      response = await options.fetch(`${config.ct.certspotterUrl}/v1/issuances?${query.toString()}`, {
        headers: { accept: "application/json", ...(key === null ? {} : { authorization: `Bearer ${key}` }) },
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      });
    } catch {
      return { error: "unreachable" };
    }
    if (response.status !== 200) {
      await response.body?.cancel().catch(() => undefined);
      return { error: sourceError(response.status) };
    }
    let value: unknown;
    try {
      value = parsePlain(await readBody(response));
    } catch {
      return { error: "malformed" };
    }
    if (!Array.isArray(value)) return { error: "malformed" };
    if (value.length === 0) break;
    for (const item of value as Record<string, unknown>[]) {
      const id = typeof item.id === "string" ? item.id : null;
      const pubkey = typeof item.pubkey_sha256 === "string" && /^[0-9a-f]{64}$/.test(item.pubkey_sha256) ? item.pubkey_sha256 : null;
      const names = Array.isArray(item.dns_names) ? item.dns_names.filter((n): n is string => typeof n === "string") : [];
      if (id === null || pubkey === null) return { error: "malformed" };
      after = id;
      if (!names.some((n) => coversName(n, config.name, config.zone))) continue;
      const issuer = typeof item.issuer === "object" && item.issuer !== null ? (item.issuer as Record<string, unknown>) : {};
      issuances.push({
        source: "certspotter",
        id,
        certSha256: typeof item.cert_sha256 === "string" && /^[0-9a-f]{64}$/.test(item.cert_sha256) ? item.cert_sha256 : null,
        pubkeySha256: pubkey,
        dnsNames: names,
        issuer: typeof issuer.friendly_name === "string" ? issuer.friendly_name : typeof issuer.name === "string" ? issuer.name : "unknown",
        notBeforeMs: utcMs(item.not_before),
        notAfterMs: utcMs(item.not_after),
      });
    }
  }
  return { issuances, after };
}

/** The SPKI SHA-256 of a PEM or DER certificate (crt.sh's `?d=` download), or null for anything else. */
export function spkiSha256OfCertificate(body: Uint8Array): string | null {
  try {
    const certificate = new X509Certificate(Buffer.from(body));
    return createHash("sha256").update(certificate.publicKey.export({ type: "spki", format: "der" })).digest("hex");
  } catch {
    return null;
  }
}

/** crt.sh's unexpired entries for the name and `*.<zone>` it has not judged yet, each with its key's hash. */
export async function queryCrtSh(options: {
  readonly config: TunnelConfig;
  readonly seen: ReadonlySet<string>;
  readonly fetch: Fetch;
}): Promise<{ readonly issuances: CtIssuance[]; readonly judged: string[] } | { readonly error: string }> {
  const { config } = options;
  const entries = new Map<string, Record<string, unknown>>();
  for (const q of [config.name, `*.${config.zone}`]) {
    let response: Response;
    try {
      response = await options.fetch(`${config.ct.crtshUrl}/?${new URLSearchParams({ q, output: "json", exclude: "expired" }).toString()}`, { headers: { accept: "application/json" }, signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS) });
    } catch {
      return { error: "unreachable" };
    }
    if (response.status !== 200) {
      await response.body?.cancel().catch(() => undefined);
      return { error: sourceError(response.status) };
    }
    let value: unknown;
    try {
      value = parsePlain(await readBody(response));
    } catch {
      return { error: "malformed" };
    }
    if (!Array.isArray(value)) return { error: "malformed" };
    for (const item of value as Record<string, unknown>[]) {
      const id = typeof item.id === "number" || typeof item.id === "bigint" ? String(item.id) : null;
      if (id === null || !/^[0-9]{1,20}$/.test(id)) return { error: "malformed" };
      entries.set(id, item);
    }
  }
  const issuances: CtIssuance[] = [];
  const judged: string[] = [];
  let downloads = 0;
  for (const [id, item] of entries) {
    if (options.seen.has(id)) continue;
    const names = typeof item.name_value === "string" ? item.name_value.split("\n").map((n) => n.trim()).filter((n) => n.length > 0) : [];
    if (!names.some((n) => coversName(n, config.name, config.zone))) {
      judged.push(id);
      continue;
    }
    if (downloads >= CRTSH_DOWNLOADS_PER_POLL) break;
    downloads += 1;
    let body: Uint8Array;
    try {
      const response = await options.fetch(`${config.ct.crtshUrl}/?d=${id}`, { signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS) });
      if (response.status !== 200) {
        await response.body?.cancel().catch(() => undefined);
        return { error: sourceError(response.status) };
      }
      body = new Uint8Array(await response.arrayBuffer());
    } catch {
      return { error: "unreachable" };
    }
    const pubkey = spkiSha256OfCertificate(body);
    if (pubkey === null) return { error: "malformed" };
    judged.push(id);
    issuances.push({
      source: "crtsh",
      id,
      certSha256: createHash("sha256").update(derOf(body)).digest("hex"),
      pubkeySha256: pubkey,
      dnsNames: names,
      issuer: typeof item.issuer_name === "string" ? item.issuer_name : "unknown",
      notBeforeMs: utcMs(item.not_before),
      notAfterMs: utcMs(item.not_after),
    });
  }
  return { issuances, judged };
}

/** The DER bytes of a PEM or DER certificate (Node's parser reads either; its `raw` is the DER). */
function derOf(body: Uint8Array): Buffer {
  return new X509Certificate(Buffer.from(body)).raw;
}

export interface CtMonitor {
  /** Ask every source now; resolves with the view after the poll. */
  poll(): Promise<CtView>;
  view(): CtView;
  stop(): void;
}

/** The monitor in `run`: polls every `tunnel.ct.poll`, judges each issuance, keeps its state beside the tunnel's files. */
export function startCtMonitor(options: {
  readonly config: TunnelConfig;
  readonly statePath: string;
  readonly acksPath: string;
  /** The keys the terminator has served, and a fresh read of the one it serves now. */
  readonly ownKeys: () => readonly { readonly spki_sha256: string }[];
  readonly recheckOwn: () => Promise<string | null>;
  readonly alert: (finding: CtFinding) => Promise<boolean>;
  readonly log: (event: DaemonLogEvent) => void;
  readonly nowMs: () => number;
  readonly fetch?: Fetch;
  /** Start the timer (false in tests, which call `poll`). */
  readonly timer?: boolean;
}): CtMonitor {
  const { config } = options;
  const fetchImpl: Fetch = options.fetch ?? ((url, init) => fetch(url, init));
  let state = readCtState(options.statePath, config.name);
  let polling: Promise<CtView> | null = null;
  const save = (): void => {
    try {
      writeAtomicPrivateFile(options.statePath, `${JSON.stringify(state)}\n`);
    } catch {
      // Kept in memory; written again after the next poll.
    }
  };
  const view = (): CtView => ctView(state, readCtAcks(options.acksPath), options.nowMs(), config.ct.pollMs);

  const judge = async (issuances: readonly CtIssuance[]): Promise<void> => {
    const now = options.nowMs();
    for (const issuance of issuances) {
      if (!(issuance.notAfterMs > now)) continue;
      if (state.findings.some((f) => f.source === issuance.source && f.id === issuance.id)) continue;
      if (options.ownKeys().some((k) => k.spki_sha256 === issuance.pubkeySha256)) continue;
      // Caddy may have obtained a certificate since the last read: read the terminator again before an alert.
      const served = await options.recheckOwn().catch(() => null);
      if (served === issuance.pubkeySha256 || options.ownKeys().some((k) => k.spki_sha256 === issuance.pubkeySha256)) continue;
      const finding: CtFinding = { ...issuance, foundMs: now, alertedMs: null };
      state = { ...state, findings: [...state.findings, finding] };
      options.log({ level: "error", event: "ct_foreign_certificate", name: config.name, source: issuance.source, id: issuance.id, pubkey_sha256: issuance.pubkeySha256, issuer: issuance.issuer, not_after_ms: issuance.notAfterMs });
    }
  };

  const deliver = async (): Promise<void> => {
    const acks = readCtAcks(options.acksPath);
    const now = options.nowMs();
    const next: CtFinding[] = [];
    for (const finding of state.findings) {
      if (finding.alertedMs !== null || acks.has(finding.pubkeySha256) || finding.notAfterMs <= now) {
        next.push(finding);
        continue;
      }
      const sent = await options.alert(finding).catch(() => false);
      next.push(sent ? { ...finding, alertedMs: options.nowMs() } : finding);
    }
    // Findings past their certificate's expiry are dropped: such a certificate can no longer be used.
    state = { ...state, findings: next.filter((f) => f.notAfterMs > now) };
  };

  const once = async (): Promise<CtView> => {
    const sources = { ...state.sources };
    if (config.ct.sources.includes("certspotter")) {
      const result = await queryCertSpotter({ config, after: state.certspotterAfter, fetch: fetchImpl });
      if ("error" in result) {
        sources.certspotter = { ok: false, atMs: options.nowMs(), error: result.error };
      } else {
        await judge(result.issuances);
        state = { ...state, certspotterAfter: result.after };
        sources.certspotter = { ok: true, atMs: options.nowMs(), error: null };
      }
    }
    if (config.ct.sources.includes("crtsh")) {
      const result = await queryCrtSh({ config, seen: new Set(state.crtshSeen), fetch: fetchImpl });
      if ("error" in result) {
        sources.crtsh = { ok: false, atMs: options.nowMs(), error: result.error };
      } else {
        await judge(result.issuances);
        // Bounded: entries of certificates that expired drop out of crt.sh's answer, so the oldest go first.
        state = { ...state, crtshSeen: [...state.crtshSeen, ...result.judged].slice(-5000) };
        sources.crtsh = { ok: true, atMs: options.nowMs(), error: null };
      }
    }
    state = { ...state, sources, checkedMs: options.nowMs() };
    await deliver();
    save();
    const current = view();
    // The relay's own log (never a Gray alert): an error while CT shows a foreign certificate, a warning while unknown.
    const level = current.state === "alert" ? "error" : current.state === "ok" ? "info" : "warn";
    options.log({ level, event: "ct_checked", name: config.name, state: current.state, findings: current.findings.length });
    return current;
  };

  const poll = (): Promise<CtView> => {
    if (polling === null) polling = once().finally(() => (polling = null));
    return polling;
  };

  let timer: ReturnType<typeof setInterval> | null = null;
  let first: ReturnType<typeof setTimeout> | null = null;
  if (options.timer !== false) {
    // The first poll waits a minute, so the terminator has read (or obtained) its certificate first.
    first = setTimeout(() => void poll(), 60_000);
    timer = setInterval(() => void poll(), config.ct.pollMs);
  }
  return {
    poll,
    view,
    stop() {
      if (timer !== null) clearInterval(timer);
      if (first !== null) clearTimeout(first);
    },
  };
}

import { ed25519VerifyHex, sha256BareHex, utf8Bytes } from "@gray/attest";
import { z } from "zod";
import { LANE_RELAY_ID_PATTERN } from "./endpoint.ts";

/**
 * The relay tunnel (docs/relay-tunnel.md): gray-assistant keeps an outbound connection to Gray's rendezvous, and the
 * rendezvous forwards every TLS connection whose SNI is the relay's name, `<label>.<zone>`, over it without
 * terminating TLS. This file is the contract the three parties share:
 *
 * - the relay's name: `tunnelLabel(relay_id)` under the relays zone, the same in relay-kit (which asks for the
 *   certificate), the console (which publishes the relay's label) and the rendezvous (which routes it);
 * - the login gray-assistant signs with the relay key and sends as the tunnel client's metadata, which the rendezvous's
 *   plugin verifies before the relay may claim its name (`verifyTunnelLogin`);
 * - the agent status's `tunnel` word.
 */

/**
 * frps's shared token (frp's `auth.method = "token"`), the same on the rendezvous and in every gray-assistant. It is not a
 * secret and authenticates nothing: frps needs a value both sides hold, and the plugin verifies every login itself.
 */
export const RENDEZVOUS_FRP_TOKEN = "gray-rendezvous";

/** The agent's tunnel, as the agent status reports it: its one proxy is registered at the rendezvous, or it is not. */
export const TUNNEL_STATES = ["connected", "down"] as const;
export type TunnelState = (typeof TUNNEL_STATES)[number];

/** An LDH label as RFC 1123 §2.1 has it, lower case (DNS compares case-insensitively, so one spelling per name). */
const LDH_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

/** Labels this prefix starts are derived from a relay id (`tunnelLabel`); no relay id is ever one as it is. */
export const TUNNEL_DERIVED_LABEL_PREFIX = "x-";
/** The domain the derived label's hash starts with, so the hash can be read as nothing else. */
export const TUNNEL_LABEL_DOMAIN = "gray-tunnel-label/v1";

/**
 * The relay's DNS label under the relays zone, or null for a string that is no relay id. A relay id that is a
 * lower-case LDH label is its own label. Every other id (upper case, `_`, `.`, `:`, more than 63 characters) gets
 * `x-` and the first 32 hex digits of SHA-256(`gray-tunnel-label/v1\n` || id), so two relays never share a name:
 * - an id starting `x-` is never its own label, so no relay can pick an id equal to another's derived label;
 * - nor is an R-LDH label (hyphens in the third and fourth places, RFC 5890 §2.3.1), which includes the `xn--`
 *   A-labels a browser shows as Unicode: a relay's name must read in the address bar as it is.
 */
export function tunnelLabel(relayId: string): string | null {
  if (!LANE_RELAY_ID_PATTERN.test(relayId)) return null;
  if (LDH_LABEL.test(relayId) && !relayId.startsWith(TUNNEL_DERIVED_LABEL_PREFIX) && relayId.slice(2, 4) !== "--") return relayId;
  return `${TUNNEL_DERIVED_LABEL_PREFIX}${sha256BareHex(utf8Bytes(`${TUNNEL_LABEL_DOMAIN}\n${relayId}`)).slice(0, 32)}`;
}

/**
 * Labels no relay may hold (owner, 2026-10-29: every relay shares one zone, `provider.usefallback.com`, so a relay's
 * name must never read as one of Gray's own or as a mail or network service). No maintained list fits: the npm
 * candidates (`reserved-subdomains` 1.0.4, last released 2021-01; `reserved-usernames` 1.1.6, 2019-03) are unmaintained
 * multi-tenant word lists, so the list is short and each group has its reason:
 *
 * - Gray's own service names, and those it may use: a page at `console.<zone>` or `login.<zone>` would pass for Gray's;
 * - mail role names (RFC 2142 §4–§5) and mail clients' discovery names (`autodiscover`, `autoconfig`): a certificate
 *   or a page for them reads as the zone's mail service;
 * - network services found by name: `wpad` (a browser whose DNS search domain is the zone asks `wpad.<zone>` for its
 *   proxy), `isatap`, name servers and `localhost` (RFC 6761 §6.3).
 *
 * Exact labels only: a prefix rule (`gray-…`) would refuse Gray's own relays (`gray-stg-relay-2`) and many honest names.
 */
export const TUNNEL_RESERVED_LABELS: readonly string[] = Object.freeze([
  // Gray's own and its likely service names.
  "www", "api", "app", "console", "dashboard", "login", "signin", "signup", "auth", "oauth", "sso", "account", "accounts",
  "admin", "status", "docs", "help", "support", "billing", "pay", "payments", "wallet", "gray", "usefallback", "fallback",
  "provider", "providers", "relay", "relays", "tunnel", "rendezvous", "lane", "lanes", "cdn", "static", "assets", "blog",
  "security", "trust",
  // Mail role names (RFC 2142) and discovery names.
  "mail", "email", "smtp", "imap", "pop", "pop3", "mx", "webmail", "autodiscover", "autoconfig", "postmaster", "hostmaster",
  "webmaster", "abuse", "noc",
  // Network services found by name.
  "wpad", "isatap", "ns", "ns1", "ns2", "dns", "localhost",
]);
const RESERVED_LABEL_SET = new Set(TUNNEL_RESERVED_LABELS);

/** Whether no relay may hold `label` under the shared zone (`TUNNEL_RESERVED_LABELS`). */
export function tunnelLabelReserved(label: string): boolean {
  return RESERVED_LABEL_SET.has(label);
}

/**
 * Whether `relayId`'s tunnel name would be a reserved label: the console refuses such a relay id at registration
 * (`lane_stack_relay_id_reserved`) and publishes no tunnel registration for one, so the rendezvous refuses its login. A
 * derived label (`x-` and hex) never is.
 */
export function relayIdReserved(relayId: string): boolean {
  const label = tunnelLabel(relayId);
  return label !== null && tunnelLabelReserved(label);
}

/**
 * A relays zone: a lower-case DNS name of at least two LDH labels, short enough that every name under it fits
 * (253 octets with a 63-octet label in front, RFC 1035 §2.3.4).
 */
export function isTunnelZone(zone: string): boolean {
  if (zone.length < 3 || zone.length > 253 - 64) return false;
  const labels = zone.split(".");
  return labels.length >= 2 && labels.every((label) => LDH_LABEL.test(label));
}

/** The relay's name, `<label>.<zone>`; null for a relay id with no label or a zone that is none. */
export function tunnelName(relayId: string, zone: string): string | null {
  const label = tunnelLabel(relayId);
  return label === null || !isTunnelZone(zone) ? null : `${label}.${zone}`;
}

/** The first line of the signed login: what the signature is for, so it can be read as nothing else. */
export const TUNNEL_LOGIN_DOMAIN = "gray-tunnel-login/v1";
/**
 * The longest a login may be valid for. The tunnel client sends the same login again on each reconnect, and
 * gray-assistant starts it afresh with a new login once a reconnect is refused; ten minutes keeps a short network break
 * a reconnect, while a login copied out of the rendezvous's memory or logs claims the name for that long at most.
 */
export const TUNNEL_LOGIN_MAX_LIFETIME_MS = 10 * 60_000;
/** How far ahead of the rendezvous's clock `issued_ms` may be (the agent status allows five minutes; this is tighter). */
export const TUNNEL_LOGIN_MAX_FUTURE_MS = 60_000;

/**
 * The login, as the tunnel client's metadata carries it (frp `metadatas`: a map of strings, sent with the login and
 * kept with the session): one member per field, so nothing in it needs quoting in the client's config.
 */
export const TUNNEL_LOGIN_METAS = {
  relayId: "gray_relay_id",
  name: "gray_name",
  issuedMs: "gray_issued_ms",
  expiresMs: "gray_expires_ms",
  nonce: "gray_nonce",
  signature: "gray_signature",
} as const;

export interface TunnelLogin {
  readonly relay_id: string;
  /** The name the relay claims, `<label>.<zone>`. */
  readonly name: string;
  readonly issued_ms: number;
  readonly expires_ms: number;
  /** 16 random bytes in hex, so no two logins are the same bytes. */
  readonly nonce: string;
}

const msSchema = z.string().regex(/^(0|[1-9][0-9]{0,15})$/).transform(Number);
const metasSchema = z.object({
  [TUNNEL_LOGIN_METAS.relayId]: z.string().regex(LANE_RELAY_ID_PATTERN),
  [TUNNEL_LOGIN_METAS.name]: z.string().min(1).max(253).regex(/^[a-z0-9.-]+$/),
  [TUNNEL_LOGIN_METAS.issuedMs]: msSchema,
  [TUNNEL_LOGIN_METAS.expiresMs]: msSchema,
  [TUNNEL_LOGIN_METAS.nonce]: z.string().regex(/^[0-9a-f]{32}$/),
  [TUNNEL_LOGIN_METAS.signature]: z.string().regex(/^[0-9a-f]{128}$/),
});

/** The bytes the relay signs: the domain and each field on a line of its own, integers in decimal. No field holds a newline. */
export function tunnelLoginMessage(login: TunnelLogin): Uint8Array {
  return utf8Bytes([TUNNEL_LOGIN_DOMAIN, login.relay_id, login.name, String(login.issued_ms), String(login.expires_ms), login.nonce].join("\n"));
}

/** The client's metadata for a login and its signature (128 hex). */
export function tunnelLoginMetas(login: TunnelLogin, signatureHex: string): Record<string, string> {
  return {
    [TUNNEL_LOGIN_METAS.relayId]: login.relay_id,
    [TUNNEL_LOGIN_METAS.name]: login.name,
    [TUNNEL_LOGIN_METAS.issuedMs]: String(login.issued_ms),
    [TUNNEL_LOGIN_METAS.expiresMs]: String(login.expires_ms),
    [TUNNEL_LOGIN_METAS.nonce]: login.nonce,
    [TUNNEL_LOGIN_METAS.signature]: signatureHex,
  };
}

/** Why a login is refused; each is one word the rendezvous returns and logs, never a value from the login. */
export const TUNNEL_LOGIN_REFUSALS = ["malformed", "unknown_relay", "name_mismatch", "not_yet_valid", "expired", "lifetime", "signature"] as const;
export type TunnelLoginRefusal = (typeof TUNNEL_LOGIN_REFUSALS)[number];

export type TunnelLoginVerdict =
  | { readonly ok: true; readonly relayId: string; readonly label: string; readonly name: string }
  | { readonly ok: false; readonly code: TunnelLoginRefusal };

/** The login's relay id, for the caller that looks up the key before it verifies; null for metadata that is no login. */
export function tunnelLoginRelayId(metas: unknown): string | null {
  const parsed = metasSchema.safeParse(metas);
  return parsed.success ? parsed.data[TUNNEL_LOGIN_METAS.relayId] : null;
}

/**
 * Verify a login against the relay's Ed25519 key (its stack endpoints' lane record, `signing_public_key`, 64 hex),
 * the rendezvous's zone and clock. The relay may claim exactly `tunnelName(relay_id, zone)`; `publicKeyHex` null is a
 * relay the registry does not have.
 */
export async function verifyTunnelLogin(
  metas: unknown,
  options: { readonly publicKeyHex: string | null; readonly zone: string; readonly nowMs: number },
): Promise<TunnelLoginVerdict> {
  const parsed = metasSchema.safeParse(metas);
  if (!parsed.success) return { ok: false, code: "malformed" };
  const login: TunnelLogin = {
    relay_id: parsed.data[TUNNEL_LOGIN_METAS.relayId],
    name: parsed.data[TUNNEL_LOGIN_METAS.name],
    issued_ms: parsed.data[TUNNEL_LOGIN_METAS.issuedMs],
    expires_ms: parsed.data[TUNNEL_LOGIN_METAS.expiresMs],
    nonce: parsed.data[TUNNEL_LOGIN_METAS.nonce],
  };
  if (options.publicKeyHex === null) return { ok: false, code: "unknown_relay" };
  const label = tunnelLabel(login.relay_id);
  const name = tunnelName(login.relay_id, options.zone);
  if (label === null || name === null || login.name !== name) return { ok: false, code: "name_mismatch" };
  if (login.expires_ms <= login.issued_ms || login.expires_ms - login.issued_ms > TUNNEL_LOGIN_MAX_LIFETIME_MS) return { ok: false, code: "lifetime" };
  if (login.issued_ms > options.nowMs + TUNNEL_LOGIN_MAX_FUTURE_MS) return { ok: false, code: "not_yet_valid" };
  if (login.expires_ms <= options.nowMs) return { ok: false, code: "expired" };
  const valid = await ed25519VerifyHex(options.publicKeyHex, tunnelLoginMessage(login), parsed.data[TUNNEL_LOGIN_METAS.signature]).catch(() => false);
  if (!valid) return { ok: false, code: "signature" };
  return { ok: true, relayId: login.relay_id, label, name };
}

/** What the console publishes for one relay at `GET /v1/lane-stack/relays/{relay_id}/tunnel`: public values only. */
export const tunnelRegistrationSchema = z
  .object({
    relay_id: z.string().regex(LANE_RELAY_ID_PATTERN),
    label: z.string().regex(LDH_LABEL),
    signing_public_key: z.string().regex(/^[0-9a-f]{64}$/),
  })
  .strict();
export type TunnelRegistration = z.infer<typeof tunnelRegistrationSchema>;

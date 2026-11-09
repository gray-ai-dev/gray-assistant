/**
 * A per-account egress proxy as a source declares it. The daemon seals it with the account's
 * credential, and egress in the VM sends every vendor call of the account through it
 * (deploy/tee/egress/stack_relay.go); an account without one leaves from the VM's own address.
 * Credentials in a proxy URL are secrets,
 * so no message from this module ever contains a URL, a username or a password: a refusal names a
 * fixed member path or "proxy_url".
 *
 * A parsed value is field by field, not a URL string. The metadata half is `{type, host, port,
 * username}`; the password is returned separately and only reaches `SourceAdapter.credential()`
 * (K4-1), never `SourceAccount`. For CLIProxyAPI's `proxy_url` the platform `URL` does the parsing,
 * and a URL that would need a guess (a path or query, a SOCKS URL with no port, a password with no
 * username) is refused as ambiguous instead of silently taking one reading.
 */
import { z } from "zod";
import { isValidEgressCredential, isValidEgressHost } from "@gray/relay-connector";
import type { SourceEgress } from "../../source/types.ts";
import { RelayKitError } from "../../errors.ts";
import { MAX_URL_LENGTH } from "./limits.ts";

/** The proxy schemes the lane accepts. */
export const EGRESS_TYPES = ["http", "https", "socks5", "socks5h"] as const;

const HOST = /^[^\s/@]+$/;

/**
 * The object form, before normalization; `port` is a bigint when it came from `parseStrict`.
 *
 * Credentials are bounded by the connector's own E2 rule (255 UTF-8 bytes, no C0/DEL), so a source
 * value is always one the sealed egress member accepts (F2 D15).
 */
export const sourceEgressSchema = z
  .object({
    type: z.enum(EGRESS_TYPES),
    host: z.string().min(1).max(255).regex(HOST),
    port: z.union([z.number().int().min(1).max(65_535), z.bigint().min(1n).max(65_535n)]),
    username: z.string().refine(isValidEgressCredential, "username").optional(),
    password: z.string().refine(isValidEgressCredential, "password").optional(),
  })
  .strict();

type EgressInput = z.infer<typeof sourceEgressSchema>;

function normalizeHost(host: string): string {
  const trimmed = host.trim().toLowerCase();
  if (trimmed.startsWith("[") && trimmed.endsWith("]")) return trimmed.slice(1, -1);
  return trimmed;
}

/** The two halves of a declared proxy: what may be listed, and the one secret. */
export interface ParsedEgress {
  readonly egress: SourceEgress;
  readonly password?: string;
}

function normalize(input: EgressInput, detail: string): ParsedEgress {
  const host = normalizeHost(input.host);
  if (host.length === 0 || !HOST.test(host) || !isValidEgressHost(host)) throw new RelayKitError("source_shape_changed", detail);
  const username = input.username === "" || input.username === undefined ? undefined : input.username;
  const password = input.password === "" || input.password === undefined ? undefined : input.password;
  if (password !== undefined && username === undefined) {
    // A password with no username has no defined wire form; refuse instead of guessing.
    throw new RelayKitError("source_shape_changed", detail);
  }
  return {
    egress: {
      type: input.type,
      host,
      port: typeof input.port === "bigint" ? Number(input.port) : input.port,
      ...(username === undefined ? {} : { username }),
    },
    ...(password === undefined ? {} : { password }),
  };
}

/** Validate an object-form egress; the detail is a member path and never holds the value. */
export function parseEgressValue(value: unknown, detail: string): ParsedEgress {
  const parsed = sourceEgressSchema.safeParse(value);
  if (!parsed.success) throw new RelayKitError("source_shape_changed", detail);
  return normalize(parsed.data, detail);
}

function decodeCredential(text: string, detail: string): string | undefined {
  if (text === "") return undefined;
  let decoded: string;
  try {
    decoded = decodeURIComponent(text);
  } catch {
    throw new RelayKitError("source_shape_changed", detail);
  }
  if (!isValidEgressCredential(decoded)) throw new RelayKitError("source_shape_changed", detail);
  return decoded;
}

/**
 * Parse one `proxy_url` as CLIProxyAPI stores it in an auth file. The reading is field by field;
 * an explicit port is required for SOCKS because neither RFC 1928 nor the URL parser supplies a
 * default one.
 */
export function parseEgressUrl(raw: string, detail = "proxy_url"): ParsedEgress {
  if (raw.length === 0 || raw.length > MAX_URL_LENGTH) throw new RelayKitError("source_shape_changed", detail);
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new RelayKitError("source_shape_changed", detail);
  }
  const type = url.protocol.endsWith(":") ? url.protocol.slice(0, -1) : url.protocol;
  if (!(EGRESS_TYPES as readonly string[]).includes(type)) throw new RelayKitError("source_shape_changed", detail);
  if (url.search !== "" || url.hash !== "") throw new RelayKitError("source_shape_changed", detail);
  if (url.pathname !== "" && url.pathname !== "/") throw new RelayKitError("source_shape_changed", detail);
  const host = normalizeHost(url.hostname);
  if (host.length === 0 || !HOST.test(host)) throw new RelayKitError("source_shape_changed", detail);
  let port: number;
  if (url.port === "") {
    if (type === "http") port = 80;
    else if (type === "https") port = 443;
    else throw new RelayKitError("source_shape_changed", detail);
  } else {
    port = Number(url.port);
    if (!Number.isInteger(port) || port < 1 || port > 65_535) throw new RelayKitError("source_shape_changed", detail);
  }
  const username = decodeCredential(url.username, detail);
  const password = decodeCredential(url.password, detail);
  if (password !== undefined && username === undefined) throw new RelayKitError("source_shape_changed", detail);
  return {
    egress: {
      type: type as SourceEgress["type"],
      host,
      port,
      ...(username === undefined ? {} : { username }),
    },
    ...(password === undefined ? {} : { password }),
  };
}

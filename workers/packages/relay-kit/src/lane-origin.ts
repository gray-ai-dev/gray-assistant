/**
 * The two forms of a lane origin (docs/design/relay-outbound-only.md §5).
 *
 * - **Direct:** `https://host[:port]`, today's form. gray-assistant dials the host and checks its certificate with
 *   WebPKI, then pins the SPKI the verified report names.
 * - **Tunnel:** `https://<entry>/v1/peer/tunnel/<relay>`. A relay-stack VM that takes no inbound connection is
 *   reached through Gray's entry: gray-assistant opens the entry's WebSocket route
 *   `wss://<entry>/v1/peer/tunnel/<relay>` and runs TLS inside it, ending in the VM. The VM's certificate is
 *   self-signed, so no WebPKI check applies to it: the SPKI bound by the VM's attestation is the only check.
 *
 * A request URL is the origin followed by the lane path (`${origin}${path}`), as the daemon builds it, so a tunnel
 * request URL is `https://<entry>/v1/peer/tunnel/<relay>/v1/aci/...`; `tunnelRequestOf` splits it again.
 *
 * Pure: the daemon (which also runs in workerd) and the Node transport share it.
 */
import { STACK_RELAY_ID_PATTERN } from "@gray/lane-verify";

/** The entry's tunnel route; an origin whose path starts with it uses the tunnel transport. */
export const PEER_TUNNEL_PATH = "/v1/peer/tunnel/";

/** A parsed tunnel origin. */
export interface TunnelOrigin {
  /** The normalized origin, `https://<entry>/v1/peer/tunnel/<relay>`. */
  readonly origin: string;
  /** The entry's own origin, `https://<entry>`: the outer TLS is checked with WebPKI for its host. */
  readonly entry: string;
  /** The relay whose VM the tunnel reaches; the VM's attested identity must name the same relay. */
  readonly relayId: string;
}

/** A request URL split into the tunnel it goes through and the request the VM sees. */
export interface TunnelRequest extends TunnelOrigin {
  /** The inner request's path and query, as the VM's lane sees it (`/v1/aci/attestation?nonce=…`). */
  readonly path: string;
}

/** True for a relay id the tunnel route can name: the stack identity's `relay_id` pattern, without `.`/`..`. */
export function isTunnelRelayId(value: string): boolean {
  return STACK_RELAY_ID_PATTERN.test(value) && value !== "." && value !== "..";
}

/**
 * The tunnel form of a URL already parsed and checked as https without credentials, or null for a direct origin.
 * Throws on a path under the tunnel route that names no valid relay or carries more than the relay.
 */
export function tunnelOriginFromUrl(url: URL): TunnelOrigin | null {
  if (!url.pathname.startsWith(PEER_TUNNEL_PATH)) return null;
  const rest = url.pathname.slice(PEER_TUNNEL_PATH.length).replace(/\/$/u, "");
  if (rest.includes("/")) throw new Error("a tunnel origin names one relay and nothing after it");
  const relayId = decodeSegment(rest);
  if (relayId === null || !isTunnelRelayId(relayId)) throw new Error("a tunnel origin must name a relay id");
  return { origin: `${url.origin}${PEER_TUNNEL_PATH}${relayId}`, entry: url.origin, relayId };
}

/** The tunnel form of a normalized origin string, or null for a direct origin (or text that is not a URL). */
export function tunnelOriginOf(origin: string): TunnelOrigin | null {
  let url: URL;
  try {
    url = new URL(origin);
  } catch {
    return null;
  }
  try {
    return tunnelOriginFromUrl(url);
  } catch {
    return null;
  }
}

/**
 * Split a request URL built as `${tunnel origin}${path}`. Null when the URL is not under the tunnel route (a direct
 * request). Throws when it is under the route but names no relay.
 */
export function tunnelRequestOf(url: URL): TunnelRequest | null {
  if (!url.pathname.startsWith(PEER_TUNNEL_PATH)) return null;
  const rest = url.pathname.slice(PEER_TUNNEL_PATH.length);
  const slash = rest.indexOf("/");
  const segment = slash === -1 ? rest : rest.slice(0, slash);
  const relayId = decodeSegment(segment);
  if (relayId === null || !isTunnelRelayId(relayId)) throw new Error("the tunnel URL names no relay id");
  const inner = slash === -1 ? "/" : rest.slice(slash);
  return { origin: `${url.origin}${PEER_TUNNEL_PATH}${relayId}`, entry: url.origin, relayId, path: `${inner}${url.search}` };
}

function decodeSegment(segment: string): string | null {
  try {
    return decodeURIComponent(segment);
  } catch {
    return null;
  }
}

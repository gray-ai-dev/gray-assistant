/**
 * The relay's own alert channel (the config's `alerts.webhook`): a URL the relay chose, never Gray's. An alert about
 * Gray (a certificate for the relay's name it did not obtain, `./tunnel/ct.ts`) must not depend on Gray to arrive.
 *
 * - `json`: `{"alert": "<word>", "relay_id", "name", "detail": {...}, "at_ms"}`.
 * - `slack`: `{"text": "<one paragraph>"}`, which Slack's incoming webhooks take and Mattermost, Rocket.Chat and
 *   Discord's `/slack` endpoint do too.
 *
 * One POST with a 10 s timeout; a 2xx is delivered, anything else is retried by the caller on its next poll. The
 * URL is a secret of the relay's (it can post to its channel), so it is never logged.
 */
import { toJsonString, type JsonObject } from "@gray/json";
import type { AlertsConfig } from "../daemon/config.ts";
import type { CtFinding } from "./tunnel/ct.ts";

export const ALERT_TIMEOUT_MS = 10_000;

export interface RelayAlert {
  readonly alert: "ct_foreign_certificate";
  readonly relayId: string;
  readonly name: string;
  readonly detail: JsonObject;
  /** One paragraph for a chat channel. */
  readonly text: string;
  readonly atMs: number;
}

export function foreignCertificateAlert(relayId: string, name: string, finding: CtFinding, atMs: number): RelayAlert {
  const notAfter = Number.isFinite(finding.notAfterMs) ? new Date(finding.notAfterMs).toISOString() : "unknown";
  return {
    alert: "ct_foreign_certificate",
    relayId,
    name,
    atMs,
    detail: {
      source: finding.source,
      id: finding.id,
      cert_sha256: finding.certSha256,
      pubkey_sha256: finding.pubkeySha256,
      dns_names: [...finding.dnsNames],
      issuer: finding.issuer,
      not_after: notAfter,
    },
    text:
      `gray-assistant ${relayId}: a certificate for ${name} exists whose key this relay never served (${finding.issuer}, ` +
      `key SHA-256 ${finding.pubkeySha256}, valid until ${notAfter}, seen in CT by ${finding.source}). Someone who can ` +
      `route ${name} (Gray's rendezvous, or whoever holds its DNS) may be intercepting the relay's page. Stop using ` +
      `the page through the tunnel, check the certificate, and run \`gray-assistant tunnel ack ${finding.certSha256 ?? finding.pubkeySha256}\` once it is explained.`,
  };
}

export function alertBody(alert: RelayAlert, format: "json" | "slack"): string {
  if (format === "slack") return toJsonString({ text: alert.text });
  return toJsonString({ alert: alert.alert, relay_id: alert.relayId, name: alert.name, detail: alert.detail, at_ms: BigInt(alert.atMs) });
}

/** Send one alert to the relay's channel; true when it took it, false (never a throw) when it did not or there is none. */
export async function sendAlert(config: AlertsConfig | null, alert: RelayAlert, fetchImpl: (url: string, init: RequestInit) => Promise<Response> = (url, init) => fetch(url, init)): Promise<boolean> {
  const webhook = config?.webhook ?? null;
  if (webhook === null) return false;
  try {
    const response = await fetchImpl(webhook.url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: alertBody(alert, webhook.format),
      redirect: "error",
      signal: AbortSignal.timeout(ALERT_TIMEOUT_MS),
    });
    await response.body?.cancel().catch(() => undefined);
    return response.status >= 200 && response.status < 300;
  } catch {
    return false;
  }
}

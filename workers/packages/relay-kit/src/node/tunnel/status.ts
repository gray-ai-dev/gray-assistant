/**
 * The tunnel's part of the status snapshot (`status.json`'s `tunnel`), which `gray-assistant status`, `doctor`,
 * `gray-assistant tunnel status` and the local page read: the tunnel's word, the name, the certificate the terminator
 * serves, and the CT monitor's verdict with its findings. Public values only (names, hashes, times, words).
 */
import type { JsonObject } from "@gray/json";
import type { CtView } from "./ct.ts";
import type { TunnelView } from "./supervisor.ts";

export function tunnelStatusValue(view: TunnelView, ct: CtView | null): JsonObject {
  return {
    state: view.state,
    name: view.name,
    origin: view.origin,
    server: view.server,
    since_ms: view.sinceMs,
    client_restarts: view.clientRestarts,
    terminator_restarts: view.terminatorRestarts,
    certificate: {
      state: view.certificate.state,
      spki_sha256: view.certificate.spkiSha256,
      not_after_ms: view.certificate.notAfterMs,
      issuer: view.certificate.issuer,
      checked_ms: view.certificate.checkedMs,
    },
    ct:
      ct === null
        ? null
        : {
            state: ct.state,
            checked_ms: ct.checkedMs,
            sources: Object.fromEntries(Object.entries(ct.sources).map(([source, s]) => [source, s === undefined ? null : { ok: s.ok, at_ms: s.atMs, error: s.error }])),
            findings: ct.findings.map((f) => ({
              source: f.source,
              id: f.id,
              cert_sha256: f.certSha256,
              pubkey_sha256: f.pubkeySha256,
              dns_names: [...f.dnsNames],
              issuer: f.issuer,
              not_before_ms: Number.isFinite(f.notBeforeMs) ? f.notBeforeMs : null,
              not_after_ms: Number.isFinite(f.notAfterMs) ? f.notAfterMs : null,
              found_ms: f.foundMs,
              alerted_ms: f.alertedMs,
            })),
          },
  };
}

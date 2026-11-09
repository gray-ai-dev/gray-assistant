/**
 * The two programs the tunnel runs (docs/relay-tunnel.md), and the configuration `run` writes for each:
 *
 * - frpc 0.71.1 (the tunnel client, fatedier/frp): one control connection to the rendezvous over TLS that it verifies
 *   (`transport.tls.trustedCaFile`, without which frpc skips verification: pkg/transport/tls.go), the login's signed
 *   metadata, and one `https` proxy whose connections it hands to the terminator unopened. The custom first byte stays
 *   on, so frps can tell its clients from the relays' visitors on the one port 443.
 * - Caddy 2.11.7 (the TLS terminator and ACME client, caddyserver/caddy): the name's certificate by TLS-ALPN-01
 *   through the tunnel (the CA's validation arrives as one more TLS connection to the name), stored with its key in
 *   the state volume, renewed by Caddy; the HTTP-01 challenge and HTTP redirects are off, so Caddy opens no port but
 *   127.0.0.1:<tls_port>. It proxies every request to the agent's own listener. Its admin API is off: the file is the
 *   whole configuration.
 *
 * Both files are JSON (frp reads a `.json` config as JSON: pkg/config/load.go), written whole with mode 0600.
 */
import { rootCertificates } from "node:tls";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { RENDEZVOUS_FRP_TOKEN } from "@gray/control/tunnel";
import type { TunnelConfig } from "../../daemon/config.ts";
import { writeAtomicPrivateFile } from "../daemon/atomic-file.ts";

/** The proxy's name in frpc's config; frps prefixes it with the session's user (the relay's label). */
export const TUNNEL_PROXY_NAME = "relay";

export interface TunnelPaths {
  readonly frpcConfig: string;
  readonly caddyConfig: string;
  /** The trust anchors frpc verifies the rendezvous with. */
  readonly serverRoots: string;
  /** Caddy's storage: the ACME account, the name's key and certificate. */
  readonly caddyStorage: string;
  readonly ctState: string;
  readonly ctAcks: string;
  readonly ownKeys: string;
}

export function tunnelPaths(config: TunnelConfig): TunnelPaths {
  return {
    frpcConfig: join(config.dataDir, "frpc.json"),
    caddyConfig: join(config.dataDir, "caddy.json"),
    serverRoots: join(config.dataDir, "rendezvous-roots.pem"),
    caddyStorage: join(config.dataDir, "caddy"),
    ctState: join(config.dataDir, "ct.json"),
    ctAcks: join(config.dataDir, "ct-acks.json"),
    ownKeys: join(config.dataDir, "own-keys.json"),
  };
}

/** The rendezvous's trust anchors: the configured file, or the roots Node itself trusts (Mozilla's, as `fetch` uses). */
export function serverRootsPem(config: TunnelConfig): string {
  return config.serverCaFile === null ? `${rootCertificates.join("\n")}\n` : readFileSync(config.serverCaFile, "utf8");
}

/** frpc's configuration for one start, with this start's signed login as its metadata. */
export function frpcConfigValue(options: {
  readonly config: TunnelConfig;
  readonly label: string;
  readonly paths: TunnelPaths;
  readonly metas: Readonly<Record<string, string>>;
  readonly adminPassword: string;
}): Record<string, unknown> {
  const { config } = options;
  return {
    ...(config.dnsServer === null ? {} : { dnsServer: config.dnsServer }),
    serverAddr: config.server.host,
    serverPort: config.server.port,
    // A refused first login ends the process, so `run` starts it again with a fresh login (supervisor.ts).
    loginFailExit: true,
    // frps's plugin replaces it with the label it verified; this is only what frps logs before that.
    user: options.label,
    // warn: frpc logs every admin API request at info, and `run` reads that API every two seconds; the tunnel's own
    // state changes are the agent's `tunnel_state` lines.
    log: { to: "console", level: "warn", disablePrintColor: true },
    auth: { method: "token", token: RENDEZVOUS_FRP_TOKEN },
    transport: {
      protocol: "tcp",
      dialServerTimeout: 10,
      tls: { enable: true, disableCustomTLSFirstByte: false, serverName: config.server.host, trustedCaFile: options.paths.serverRoots },
    },
    webServer: { addr: "127.0.0.1", port: config.adminPort, user: "gray-assistant", password: options.adminPassword },
    metadatas: { ...options.metas },
    proxies: [{ name: TUNNEL_PROXY_NAME, type: "https", subdomain: options.label, localIP: "127.0.0.1", localPort: config.tlsPort }],
  };
}

/** Caddy's configuration: the name's certificate by TLS-ALPN-01, and every request to the agent's listener. */
export function caddyConfigValue(options: { readonly config: TunnelConfig; readonly paths: TunnelPaths; readonly upstream: { readonly host: string; readonly port: number } }): Record<string, unknown> {
  const { config } = options;
  const issuer: Record<string, unknown> = {
    module: "acme",
    ca: config.acme.directory,
    challenges: { http: { disabled: true }, "tls-alpn": { alternate_port: config.tlsPort } },
  };
  if (config.acme.email !== null) issuer.email = config.acme.email;
  if (config.acme.caRootFile !== null) issuer.trusted_roots_pem_files = [config.acme.caRootFile];
  const upstreamHost = options.upstream.host === "0.0.0.0" || options.upstream.host === "::" ? "127.0.0.1" : options.upstream.host;
  return {
    admin: { disabled: true, config: { persist: false } },
    logging: { logs: { default: { level: "INFO", writer: { output: "stderr" }, encoder: { format: "json" } } } },
    storage: { module: "file_system", root: options.paths.caddyStorage },
    apps: {
      http: {
        https_port: config.tlsPort,
        servers: {
          relay: {
            listen: [`127.0.0.1:${config.tlsPort}`],
            // TCP only: the tunnel carries no UDP, so HTTP/3 would only open a UDP socket nothing reaches.
            protocols: ["h1", "h2"],
            routes: [
              {
                match: [{ host: [config.name] }],
                handle: [
                  {
                    handler: "reverse_proxy",
                    upstreams: [{ dial: `${upstreamHost.includes(":") ? `[${upstreamHost}]` : upstreamHost}:${options.upstream.port}` }],
                    // The scheduler's answers are signed over their exact bytes; nothing is buffered or rewritten.
                    flush_interval: -1,
                  },
                ],
              },
            ],
            tls_connection_policies: [{ match: { sni: [config.name] } }],
            automatic_https: { disable_redirects: true },
          },
        },
      },
      tls: {
        // Managed whether or not a route names it: Caddy obtains, renews and serves the name's certificate.
        certificates: { automate: [config.name] },
        automation: {
          policies: [{ subjects: [config.name], issuers: [issuer], key_type: "p256" }],
        },
      },
    },
  };
}

/** Write the files a start needs: the roots and Caddy's once, frpc's on every start of the client (its login changes). */
export function writeTunnelFiles(options: {
  readonly config: TunnelConfig;
  readonly paths: TunnelPaths;
  readonly frpc: Record<string, unknown> | null;
  readonly caddy: Record<string, unknown> | null;
}): void {
  if (options.caddy !== null) {
    writeAtomicPrivateFile(options.paths.serverRoots, serverRootsPem(options.config));
    writeAtomicPrivateFile(options.paths.caddyConfig, `${JSON.stringify(options.caddy, null, 2)}\n`);
  }
  if (options.frpc !== null) writeAtomicPrivateFile(options.paths.frpcConfig, `${JSON.stringify(options.frpc, null, 2)}\n`);
}

/**
 * What `gray-assistant init` writes, as pure text: the config skeleton (JSONC, every key documented and
 * every default shown), one registration document per official vendor endpoint, and the nginx and
 * Caddy snippets that terminate TLS in front of the plain-HTTP scheduler (design v2 §A.10, K4).
 *
 * The Node side (`src/node/init.ts`) adds the relay key and the signed default allow-all policy
 * bundle; everything a golden test compares is here so it runs in workerd too.
 *
 * The placeholders are deliberate: Gray assigns the relay id and publishes the lane origin, its
 * release-signing key and the scheduler hostname. `doctor` refuses a config that still carries them,
 * so a relay cannot mistake the skeleton for a registration.
 *
 * `init --pair` (S57) writes `pairedConfigText` instead: Gray's answer fills every value it has, the flags the registry
 * user and its token's expiry (`--registry-user`, `--registry-expires-at`, which the apply's pairing command carries),
 * and only what the relay alone has and did not give (those two, the image when the panel had none) stays a placeholder.
 * It also records the releases Gray's signed list names at that moment as `releases.accepted_at_pairing`: joining is
 * the relay's choice to trust them, so its first boot does not wait `delay_days` (every later release still does).
 * It writes no `ui` section (relay standard v1.7): the relay's own page stays off on the public origin until the relay
 * turns it on (`"ui": {"public": true}`, GUIDE §12). `--registry-expires-at` is optional: without it the config has no
 * `stack.registry.expires_at` and the token has no known expiry (a pull the registry refuses is then the signal).
 */
import type { JsonObject } from "@gray/json";

/** The placeholder `init` writes when `--relay-id` is not given; `doctor` refuses it. */
export const RELAY_ID_PLACEHOLDER = "REPLACE-WITH-GRAY-RELAY-ID";
/** The placeholder scheduler URL; the operator replaces it with the TLS-terminated name. */
export const SCHEDULER_URL_PLACEHOLDER = "https://scheduler.example";
/** The lane origin placeholder (Gray gives the real one in the registration document). */
export const LANE_ORIGIN_PLACEHOLDER = "https://lane.example";
/** The release-list URL placeholder (same host as the lane by default). */
export const RELEASE_LIST_PLACEHOLDER = "https://lane.example/releases.json";
/** The pinned release key placeholder; 64 zeros cannot verify anything and `run`/`doctor` refuse it. */
export const RELEASE_PUBLIC_KEY_PLACEHOLDER = "0".repeat(64);
/** The lane instance's dstack app id placeholder (40 zeros); `run`/`doctor` refuse it. */
export const APP_ID_PLACEHOLDER = "0".repeat(40);
/** The KMS CA public key placeholder: the P-256 SPKI prefix and a zero point; `run`/`doctor` refuse it. */
export const KMS_CA_PUBKEY_PLACEHOLDER = `3059301306072a8648ce3d020106082a8648ce3d03010703420004${"0".repeat(128)}`;

/**
 * What `init` prints about the values Gray must publish. `init` keeps writing the placeholders (the
 * workspace is still reviewable and offline), but `run` and `doctor` refuse them, so the note is the
 * operator's next step rather than a surprise at startup. `members` are the dotted config keys that
 * still hold a placeholder (empty when the operator supplied real values on the command line).
 */
export function initPlaceholderNote(members: readonly string[]): string | null {
  if (members.length === 0) return null;
  return `placeholder written: ${members.join(", ")}; run and doctor refuse the init value until Gray's registration values replace it`;
}

/** The files `init` writes, relative to the workspace directory. */
export const INIT_FILES = {
  config: "gray-assistant.jsonc",
  key: "relay-key.json",
  policyBundle: "policy.bundle.json",
  accounts: "accounts.json",
  nginx: "proxy/nginx.conf",
  caddy: "proxy/Caddyfile",
  registrationDir: "registration",
} as const;

/** One official vendor endpoint and the protocols Gray's lane serves on it. */
export interface VendorEndpoint {
  readonly name: string;
  readonly vendor: "anthropic" | "openai" | "chatgpt";
  readonly baseUrl: string;
  readonly protocols: readonly string[];
  readonly nativePaths: readonly string[];
}

/** The official endpoints the lane serves (the early scope the owner fixed). */
export const VENDOR_ENDPOINTS: readonly VendorEndpoint[] = [
  {
    name: "anthropic",
    vendor: "anthropic",
    baseUrl: "https://api.anthropic.com/v1/",
    protocols: ["anthropic_messages"],
    nativePaths: ["/v1/messages"],
  },
  {
    name: "openai",
    vendor: "openai",
    baseUrl: "https://api.openai.com/v1/",
    protocols: ["open_ai_chat", "open_ai_responses"],
    nativePaths: ["/v1/chat/completions", "/v1/responses"],
  },
  {
    name: "chatgpt-codex",
    vendor: "chatgpt",
    baseUrl: "https://chatgpt.com/backend-api/codex/",
    protocols: ["open_ai_responses"],
    nativePaths: ["/backend-api/codex/responses"],
  },
];

/** What the config skeleton and registration documents are generated from. */
export interface InitDocumentOptions {
  readonly relayId: string;
  readonly schedulerUrl: string;
  readonly laneOrigin: string;
  readonly releaseListUrl: string;
  readonly releasePublicKey: string;
  /** D137: Gray's freshness public key; the line is written only when given. */
  readonly releaseFreshnessPublicKey?: string;
  /** The lane instance's dstack app id; the zero placeholder when absent. */
  readonly appId?: string;
  /** The node KMS's `ca_pubkey`; the zero-point placeholder when absent. */
  readonly kmsCaPubkey?: string;
  /** 64 lower-case hex; the relay key's public key (also the scheduler key in v1). */
  readonly relayPublicKey: string;
}

/** The config skeleton, with comments: every key the daemon reads, and each default it applies. */
export function initConfigText(options: InitDocumentOptions): string {
  return `{
  // ---- identity ----------------------------------------------------------------------------
  // Gray assigns this id at registration; it is also the key id every scheduler answer is signed
  // under (the relay key file's own key_id is local metadata and never reaches the wire).
  "relay_id": ${JSON.stringify(options.relayId)},

  // The Ed25519 key file init wrote: 0600, no symlink, no group/other bits. Back it up: losing it
  // means registering again with a new relay id (key rotation is a new relay id in v1).
  "key": "./relay-key.json",

  // The signed policy bundle uploaded before any credential on every boot. init writes the
  // default allow-all module here; replace it with a bundle signed by this relay's key to add rules.
  // A relay-stack app (stack.lane_origin) runs no policy module and is sent no bundle: a relay whose
  // only lane origin is its stack app may delete this key and the file.
  "policy_bundle": "./policy.bundle.json",

  // ---- the lane ----------------------------------------------------------------------------
  "lane": {
    // The lane replica origin(s) Gray publishes (https, no path). v1 assumes one boot per origin.
    "origins": [${JSON.stringify(options.laneOrigin)}],
    // Gray publishes the release list; it is signed, never read from an unsigned endpoint.
    "release_list": ${JSON.stringify(options.releaseListUrl)},
    // Gray's release-signing key, pinned here. Init writes zeros: replace it before starting
    // (run and doctor refuse the placeholder).
    "release_public_key": ${JSON.stringify(options.releasePublicKey)},
${options.releaseFreshnessPublicKey === undefined ? "" : `    // Gray's freshness key (D137): a list that carries expires_at stays current past a day while the
    // freshness document Gray publishes beside it (.freshness.json) counts.
    "release_freshness_public_key": ${JSON.stringify(options.releaseFreshnessPublicKey)},
`}    // The dstack instance each origin must be: credentials are sealed only to a lane whose
    // quote-bound event log reports this app id and a key provider "kms" with this CA public key.
    // Gray publishes both with the origin. Init writes zeros: run and doctor refuse them.
    "instances": {
      ${JSON.stringify(options.laneOrigin)}: {
        "app_id": ${JSON.stringify(options.appId ?? APP_ID_PLACEHOLDER)},
        "kms_ca_pubkey": ${JSON.stringify(options.kmsCaPubkey ?? KMS_CA_PUBKEY_PLACEHOLDER)}
      }
    },
    // Refuse a list older than this (seconds), so a withheld withdrawal is noticed. Default 86400.
    "release_list_max_age": 86400
  },

  // A release is accepted automatically after this many days counted from the relay's own first
  // sight (never from a time Gray publishes). Use "manual" to require releases accept <id>.
  "releases": { "accept": "auto-after-delay", "delay_days": 7 },

  // ---- scheduler ---------------------------------------------------------------------------
  "scheduler": {
    // Plain HTTP on the compose network; TLS is terminated by your proxy (see proxy/).
    "listen": { "host": "0.0.0.0", "port": 8080 },
    // The TLS-terminated origin registered with Gray; the TEE calls this. No path, query or fragment.
    "public_url": ${JSON.stringify(options.schedulerUrl)}
    // Optional: a 0600 file holding the bearer token for POST /v1/admin/reset.
    // "admin_token_file": "./admin-token"
  },

  // ---- accounts ----------------------------------------------------------------------------
  // file | http | cliproxyapi. file reads accounts.json beside this file (0600: it holds tokens).
  "source": {
    "kind": "file",
    "path": "./accounts.json"
  },

  // ---- tunables (defaults shown; every bound is in the package's IMPLEMENTATION_NOTES.md) ----
  "lease_lifetime": 3600,        // seconds a sealed bundle stays valid
  "renew_fraction": 0.5,         // renew after this fraction of the lease
  "healthz_poll": 5,             // seconds between /healthz boot checks
  "source_poll": 30,             // seconds between source polls
  "inflight_ttl": 600,           // seconds a pick lease lives without a report
  "affinity_ttl": 3600,          // seconds an idle conversation stays on one account (1-720 minutes)
  "report_max_age": 3600,        // seconds a saved attestation may be used to seal
  "release_poll": 300,           // seconds between release-list fetches
  "tick_ms": 1000,               // supervisor round interval, milliseconds
  "cooldowns": { "rate_limited_seconds": 60, "overloaded_seconds": 30 },
  "pccs_url": null,              // an Intel PCCS URL, or null for Intel PCS
  "replay_cap": 100000,          // signed scheduler nonces remembered per window
  // "affinity_cap": 64,          // conversation bindings kept in memory; default 4 x the pool size
  "state_file": "./state.json",  // atomic-rename state; only the agent writes it
  "status_file": "./status.json" // status snapshot \`gray-assistant status\` reads; control.json sits beside state_file
}
`;
}

/** The lane record repeated in every registration document (the console's endpoint shape). */
export function laneEndpointRecord(options: InitDocumentOptions): JsonObject {
  return {
    relay_id: options.relayId,
    signing_public_key: options.relayPublicKey,
    scheduler_url: options.schedulerUrl,
    scheduler_public_key: options.relayPublicKey,
  };
}

/**
 * One registration document per vendor endpoint. They all carry the same lane record, because Gray
 * stores the relay once per endpoint; editing one and not the others is a registration mistake the
 * notes warn about. The endpoint's `key_id` rule and the egress note are stated on every document
 * so a reader of one file needs no other file.
 */
export function registrationDocuments(options: InitDocumentOptions): ReadonlyArray<{ readonly name: string; readonly fileName: string; readonly value: JsonObject }> {
  return VENDOR_ENDPOINTS.map((endpoint) => ({
    name: endpoint.name,
    fileName: `${INIT_FILES.registrationDir}/${endpoint.name}.json`,
    value: {
      schema: "gray-relay-registration/1",
      vendor: endpoint.vendor,
      base_url: endpoint.baseUrl,
      protocols: [...endpoint.protocols],
      native_paths: [...endpoint.nativePaths],
      endpoint: laneEndpointRecord(options),
      key_id_rule:
        "key_id = relay_id: the scheduler signs every answer under the relay id below, and the TEE pins that id. The relay-key.json file's key_id is local metadata only and is never sent.",
      keys_note:
        "signing_public_key and scheduler_public_key are the same Ed25519 key in v1; splitting them is not supported. Register the relay id once; changing the key means a new relay id.",
      egress_note:
        "An account whose source declares a proxy has every vendor call made through that proxy: egress in the CVM sends each call of the account through it. An account without one leaves from the CVM's own address. Gray and the relay never see customer content.",
      registration_steps: [
        "Paste this endpoint record into the Gray console's provider registration for this vendor.",
        "Register the same relay id and lane record for every vendor endpoint at the same time; a partial edit leaves the lane inconsistent.",
        "Keep relay-key.json 0600 and backed up; the key file is the relay's identity.",
      ],
    },
  }));
}

// ---- init --pair (docs/confidential-lane-supply-implementation.md S57) -------------------------

/** What only the relay has, which `init --pair` cannot know: `run` refuses these and `doctor` names them. */
export const REGISTRY_USERNAME_PLACEHOLDER = "REPLACE-WITH-REGISTRY-USER";
/** The Unix epoch: a token expiry no real registry token has. `init --pair` before v1.7 wrote it; `run` refuses it. */
export const REGISTRY_EXPIRES_AT_PLACEHOLDER = "1970-01-01T00:00:00Z";
/** `stack.registry.username`'s rule (daemon/config.ts), which `init --pair --registry-user` checks before pairing. */
export const REGISTRY_USERNAME_PATTERN = /^[\x21-\x7e]{1,128}$/;

/** An instant at second precision in UTC (`YYYY-MM-DDTHH:MM:SSZ`), the form the config's instants take; null otherwise. */
export function utcSecondsMs(value: string): number | null {
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(value)) return null;
  const ms = Date.parse(value);
  return Number.isFinite(ms) && new Date(ms).toISOString() === `${value.slice(0, -1)}.000Z` ? ms : null;
}
/** The registry host when Gray's answer names neither a registry nor an image. */
export const REGISTRY_HOST_PLACEHOLDER = "registry.example";
/** The token service's origin when Gray's answer names neither a token URL nor a tunnel. */
export const TOKEN_URL_PLACEHOLDER = "https://token.example";
/** A relay image under `registry` with a digest of zeros, which no image has. */
export function relayImagePlaceholder(registry: string): string {
  return `${registry}/replace-with-your-image@sha256:${"0".repeat(64)}`;
}
/** Whether `image` is `relayImagePlaceholder`'s (any registry). */
export function isRelayImagePlaceholder(image: string): boolean {
  return image.endsWith(`/replace-with-your-image@sha256:${"0".repeat(64)}`);
}

/** The container paths the host install and compose mount (deploy/relay/host/compose.host.yaml): the kit and the state volume. */
export const KIT_MOUNT = "/run/secrets";
export const STATE_MOUNT = "/var/lib/gray-assistant";
/** The host install's default `--listen` (deploy/relay/host/install.sh), the agent's scheduler listener. */
export const PAIRED_LISTEN = Object.freeze({ host: "127.0.0.1", port: 18080 });

/** One hash `init --pair` accepts: a compose release or an OS image of Gray's list, and the name the comment gives it. */
export interface PairingAcceptedHash {
  readonly hash: string;
  readonly kind: "release" | "os_image";
  /** The release's tag (or commit) or the OS image's version, for the config's comment and the CLI's lines. */
  readonly name: string;
}

/** The values `pairedConfigText` writes: Gray's answer, resolved, and the pairing's facts. */
export interface PairedConfigOptions {
  readonly relayId: string;
  /** Gray's release list and keys, or null when Gray publishes none (init's placeholders then). */
  readonly release: { readonly list: string; readonly publicKey: string; readonly freshnessPublicKey: string | null } | null;
  readonly reportOrigin: string;
  /** Written only when it is not the tunnel's origin (the config's default). */
  readonly tokenUrl: string | null;
  readonly tunnel: { readonly server: string; readonly zone: string } | null;
  readonly relayImage: string;
  readonly registryHost: string;
  /**
   * The pull token's user and expiry (`--registry-user`, `--registry-expires-at`); null: the user's placeholder. A null
   * `expiresAt` (no `--registry-expires-at`) writes no `expires_at`: a token with no known expiry.
   */
  readonly registryLogin: { readonly username: string; readonly expiresAt: string | null } | null;
  readonly pairing: { readonly gray: string; readonly fingerprint: string; readonly pairedAt: string };
  /** The releases of Gray's verified list at pairing (`releases.accepted_at_pairing`); none when it was not read. */
  readonly acceptedAtPairing: readonly PairingAcceptedHash[];
}

/**
 * A tag or version from Gray's list as the config's comment and the CLI print it: printable ASCII only and at most 64
 * characters, so no name can end the comment line and add config text.
 */
export function printableReleaseName(name: string): string {
  return name.replace(/[^\x20-\x7e]/gu, "?").slice(0, 64);
}

/** The `releases` member: with the pairing's acceptances, one hash a line with its name. */
function pairedReleasesText(accepted: readonly PairingAcceptedHash[]): string {
  if (accepted.length === 0) {
    return `  // A release is accepted this many days after this relay first saw it; "manual" to accept each one yourself.
  "releases": { "accept": "auto-after-delay", "delay_days": 7 },`;
  }
  const lines = accepted.map((entry, index) => `      ${JSON.stringify(entry.hash)}${index === accepted.length - 1 ? "" : ","} // ${entry.kind === "release" ? "release" : "OS image"} ${printableReleaseName(entry.name)}`);
  return `  // A release is accepted this many days after this relay first saw it; "manual" to accept each one yourself.
  // accepted_at_pairing: what Gray's signed list named when this relay paired, which joining trusts. The agent accepts
  // each once, when it first sees it in the list, and records it in control.json; later releases wait delay_days.
  "releases": {
    "accept": "auto-after-delay",
    "delay_days": 7,
    "accepted_at_pairing": [
${lines.join("\n")}
    ]
  },`;
}

/**
 * The config `init --pair` writes: every value Gray answered in place, the container paths, and what only the relay
 * has as placeholders. No `policy_bundle` (a stack-only relay runs none, S23) and no `lane.origins`: the lane's origin
 * and instance come from Gray after Deploy (`stack.instance`, docs/relay-stack-provisioner.md P12).
 */
export function pairedConfigText(options: PairedConfigOptions): string {
  const j = (value: unknown): string => JSON.stringify(value);
  const release = options.release ?? { list: RELEASE_LIST_PLACEHOLDER, publicKey: RELEASE_PUBLIC_KEY_PLACEHOLDER, freshnessPublicKey: null };
  return `{
  // Written by gray-assistant init --pair from Gray's answer at ${options.pairing.pairedAt}; doctor names the source.
  "relay_id": ${j(options.relayId)},
  // The relay key (0600). Gray holds only its public half; back the file up.
  "key": ${j(`${KIT_MOUNT}/relay-key.json`)},

  // Gray's signed release list and its keys. The lane's origin and instance come from Gray after Deploy.
  "lane": {
    "release_list": ${j(release.list)},
    "release_public_key": ${j(release.publicKey)},
${release.freshnessPublicKey === null ? "" : `    "release_freshness_public_key": ${j(release.freshnessPublicKey)},\n`}    "release_list_max_age": 86400
  },

${pairedReleasesText(options.acceptedAtPairing)}

  // The agent's listener; the tunnel delivers the relay's public name to it.
  "scheduler": { "listen": { "host": ${j(PAIRED_LISTEN.host)}, "port": ${PAIRED_LISTEN.port} } },

  // Your accounts; the relay's own page (gray-assistant ui) adds them here.
  "source": { "kind": "file", "path": ${j(`${STATE_MOUNT}/accounts.json`)} },

  "state_file": ${j(`${STATE_MOUNT}/state.json`)},
  "status_file": ${j(`${STATE_MOUNT}/status.json`)},

  "stack": {
    // The lane's values come from Gray once the VM is deployed.
    "instance": "gray",
    // Your image, pinned by digest: the only one the VM is told to run.
    "relay_images": [${j(options.relayImage)}],
    // The read-only pull token the VM gets once its quote checks out: ${
      options.registryLogin === null
        ? `put the token in password_file and fill the
    // user; add "expires_at" (YYYY-MM-DDTHH:MM:SSZ) when the token has an expiry.`
        : `the token is password_file; change the user
    // (and "expires_at", YYYY-MM-DDTHH:MM:SSZ, when the token has an expiry) with the token.`
    }
    "registry": {
      "host": ${j(options.registryHost)},
      "username": ${j(options.registryLogin?.username ?? REGISTRY_USERNAME_PLACEHOLDER)},
      "password_file": ${j(`${KIT_MOUNT}/registry-password`)}${options.registryLogin?.expiresAt ? `,
      "expires_at": ${j(options.registryLogin.expiresAt)}` : ""}
    },
    "issue_log": ${j(`${STATE_MOUNT}/pull-tokens.jsonl`)},
${options.tokenUrl === null ? "" : `    "token_url": ${j(options.tokenUrl)},\n`}    "report_origin": ${j(options.reportOrigin)}
  },
${options.tunnel === null ? "" : `
  // Gray's rendezvous: the relay's public name without a public address.
  "tunnel": { "server": ${j(options.tunnel.server)}, "zone": ${j(options.tunnel.zone)} },
`}
  // The relay's own page stays off on the public origin; ui.public set to true turns it on (passkeys only, GUIDE §12).

  "pairing": { "gray": ${j(options.pairing.gray)}, "fingerprint": ${j(options.pairing.fingerprint)}, "paired_at": ${j(options.pairing.pairedAt)} }
}
`;
}

/** The compose file `init --pair` writes beside the config when it runs from the published image (`$GRAY_ASSISTANT_IMAGE`). */
export const PAIRED_COMPOSE_FILE = "compose.yaml";

/** The compose project and network of a paired relay's kit: one per relay, so several relays share a host. */
export function pairedComposeName(relayId: string): string {
  return `gray-assistant-${relayId}`;
}

/**
 * The kit's own compose file: the agent of deploy/relay/compose.yaml with the host install's mounts
 * (deploy/relay/host/compose.host.yaml), so the kit directory runs as it is with `docker compose up -d`. `image` is the
 * image `init` ran from, as its build named it; JSON quoting keeps it one YAML scalar. The project, its volume and its
 * network are named after the relay (`pairedComposeName`; a Gray relay ID is lower-case letters, digits and hyphens,
 * a valid compose project name): the network takes the project's name (`COMPOSE_PROJECT_NAME`, which compose sets
 * for interpolation from `name:`, `-p` or the environment), so a project started under another name keeps its network
 * beside it, and the relay's own software joins it by that name.
 */
export function pairedComposeText(image: string, relayId: string): string {
  const name = pairedComposeName(relayId);
  return `# gray-assistant's agent, written by \`gray-assistant init --pair\`. Start it from this directory: docker compose up -d
#
# The directory is the kit: mounted read-only at ${KIT_MOUNT} (the paths gray-assistant.jsonc names), its config where the
# image's command reads it. Every kit file is owned by 10001:10001 (the agent's uid) with mode 0600 or 0400, as
# \`init\` wrote it; add registry-password the same way. The agent's state is the relay-state volume.
#
# Change a config member with the agent's own writer, not an editor (e.g. the login proxy):
#   docker compose run --rm --no-deps -v "$PWD:/work" agent config set --config /work/gray-assistant.jsonc source.logins.proxy http://proxy.example:3128
#   docker compose up -d --force-recreate agent
# Add to this file (another network, TZ, ...) in compose.override.yaml beside it, which docker compose merges; this
# file is rewritten by the next init --pair --force, the override is not.
#
# The project is named after the relay, so several relays on one host do not share a container, volume or network.
name: ${JSON.stringify(name)}

services:
  agent:
    image: ${JSON.stringify(image)}
    restart: unless-stopped
    read_only: true
    user: "10001:10001"
    # Core dumps can contain a credential; no swap keeps the relay's secrets out of a swap file.
    ulimits:
      core: 0
    mem_limit: 512m
    memswap_limit: 512m
    pids_limit: 256
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true
    tmpfs:
      - /tmp:size=64m,mode=1777,noexec,nosuid,nodev
    environment:
      GRAY_ASSISTANT_CONFIG: /etc/gray-assistant/gray-assistant.jsonc
    logging:
      driver: local
    volumes:
      - ./${INIT_FILES.config}:/etc/gray-assistant/gray-assistant.jsonc:ro
      - .:${KIT_MOUNT}:ro
      - relay-state:${STATE_MOUNT}
    networks:
      - relay
    # No published port: with the config's tunnel section the agent connects out to Gray's rendezvous.

networks:
  relay:
    # Named after the compose project (the name above, or the one docker compose -p or COMPOSE_PROJECT_NAME gives),
    # so the relay's own software (a CLIProxyAPI service, an http source) joins it by that name with
    # \`external: true\` and the config's source.url names that service.
    name: "\${COMPOSE_PROJECT_NAME}"

volumes:
  relay-state:
`;
}

/** nginx: TLS termination and a byte-transparent reverse proxy to the agent's plain HTTP port. */
export function initNginxSnippet(options: InitDocumentOptions): string {
  const host = new URL(options.schedulerUrl).hostname;
  return `# gray-assistant: nginx TLS termination in front of the agent's plain-HTTP scheduler.
# Put the certificate and key where the paths below point, then include this file from nginx.conf's
# http block. The agent listens on the compose network; nothing on the host exposes port 8080.
upstream gray_assistant {
    server agent:8080;
    keepalive 16;
}

server {
    listen 443 ssl;
    http2 on;
    server_name ${host};

    ssl_certificate     /etc/nginx/tls/fullchain.pem;
    ssl_certificate_key /etc/nginx/tls/key.pem;
    ssl_protocols       TLSv1.2 TLSv1.3;

    # The scheduler request path is small, but a report batch can be a few MiB. Never buffer the
    # body: the signature covers the exact bytes, and buffering must not rewrite them.
    client_max_body_size 8m;
    proxy_request_buffering off;
    proxy_buffering off;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header Connection "";

    location / {
        proxy_pass http://gray_assistant;
        proxy_read_timeout 30s;
    }
}
`;
}

/** Caddy: the same termination, for operators who already run Caddy or want its ACME client. */
export function initCaddySnippet(options: InitDocumentOptions): string {
  const host = new URL(options.schedulerUrl).hostname;
  return `# gray-assistant: Caddy terminates TLS and proxies every byte unchanged to the agent.
# Replace the tls line with \`tls <account-email>\` to let Caddy's ACME client issue the certificate
# (DNS-01 or HTTP-01 as your zone allows); the agent itself contains no TLS code.
${host} {
    tls /etc/caddy/tls/fullchain.pem /etc/caddy/tls/key.pem

    reverse_proxy agent:8080 {
        # Flush as the agent writes: a signed answer must not wait for a buffer.
        flush_interval -1
        # Keep the request body byte for byte; the signature is over those bytes.
        transport http {
            read_buffer 0
        }
    }
}
`;
}

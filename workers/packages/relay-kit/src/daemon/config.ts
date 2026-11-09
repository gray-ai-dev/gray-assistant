/**
 * The daemon's configuration: one zod schema for every field the supervisor reads, with a bounded
 * default for each tunable (critique minor 1). The source section is deliberately opaque here —
 * K3 owns its adapter schema and K4 validates it before constructing the adapter — so this parser
 * preserves it untouched and refuses only a missing section.
 *
 * Units are the ones the operator sees in the JSON: metric times (`lease_lifetime`,
 * `healthz_poll`, `source_poll`, `inflight_ttl`, `report_max_age`, `release_poll`) are seconds;
 * `tick_ms` and the config-derived millisecond fields are milliseconds. `renew_fraction` is a
 * fraction of the lease, not a duration.
 *
 * ```jsonc
 * {"relay_id":"relay-1","key":"/run/secrets/relay-key.json",
 *  "policy_bundle":"/etc/gray-assistant/policy.bundle.json",
 *  "lane":{"origins":["https://lane.example"],
 *          "instances":{"https://lane.example":{"app_id":"<dstack app id, 40 hex>",
 *                                                "kms_ca_pubkey":"<the node KMS's ca_pubkey, 182 hex>"}},
 *          "release_list":"https://gray.example/releases.json",
 *          "release_public_key":"<Gray's pinned Ed25519 key, 64 hex>","release_list_max_age":86400,
 *          "release_freshness_public_key":"<Gray's freshness key, 64 hex; optional, D137>",
 *          "release_freshness":"https://gray.example/releases.freshness.json"},
 *  "releases":{"accept":"auto-after-delay","delay_days":7},
 *  "scheduler":{"listen":{"host":"0.0.0.0","port":8080},
 *               "public_url":"https://scheduler.relay.example"},
 *  "ui":{"listen":{"port":7470},"public":false,"origin":"https://relay.example"},
 *  "source":{...},
 *  "lease_lifetime":3600,"renew_fraction":0.5,"healthz_poll":5,"source_poll":30,
 *  "inflight_ttl":600,"affinity_ttl":3600,"report_max_age":3600,"release_poll":300,"tick_ms":1000,
 *  "cooldowns":{"rate_limited_seconds":60,"overloaded_seconds":30},
 *  "pccs_url":null,"replay_cap":100000,"state_file":"/var/lib/gray-assistant/state.json",
 *  "status_file":"/var/lib/gray-assistant/status.json",
 *  "stack":{"lane_origin":"https://lane.example/v1/peer/tunnel/acme","token_url":"https://scheduler.relay.example",
 *           "relay_images":["registry.relay.example/acme/new-api@sha256:<64 hex>"],
 *           "current_image":"registry.relay.example/acme/new-api@sha256:<64 hex>",
 *           "registry":{"host":"registry.relay.example","username":"gray-pull",
 *                       "password_file":"/run/secrets/registry-password","expires_at":"2027-01-01T00:00:00Z"},
 *           "issue_log":"/var/lib/gray-assistant/pull-tokens.jsonl",
 *           "report_origin":"https://api.gray.example"}}
 * ```
 *
 * `stack` (plan S9–S13, S11a, S11b) is optional: without it the agent serves no pull-token routes.
 *
 * `stack.instance` (docs/relay-stack-provisioner.md §9, P12) says where the stack app's origin and binding come from:
 * `"config"` (the default, and the only reading of a config without the member) is `stack.lane_origin` with its
 * `lane.instances` entry, copied by hand; `"gray"` (what `init` writes) takes them from Gray's answer to the agent
 * status once the VM's own quote proves them, so `stack.lane_origin` is left out, and `lane.origins`/`lane.instances`
 * are left out or name only other lanes. The adopted instance is runtime state in control.json (`stack_instance`).
 *
 * `ui` is optional. `ui.listen.port`: `gray-assistant run` also serves the local page (`gray-assistant ui`) on 127.0.0.1 at that
 * port; it binds the loopback address only, so there is no host member. `ui.public: true` (off by default): `run` also
 * serves the page under `/ui/` on the relay's own public origin, where only passkeys enrolled with `gray-assistant ui enroll`
 * sign in: `ui.origin` when set (an https origin the relay's proxy routes to the agent), else the relay tunnel's origin
 * while it is up, else `stack.token_url`'s. It is an admin surface on the internet; it needs `ui.origin` or `stack`.
 *
 * `tunnel` (docs/relay-tunnel.md) is optional: with it `run` keeps an outbound connection to Gray's rendezvous
 * (`tunnel.server`) and serves the agent's listener at `https://<label>.<tunnel.zone>` (`@gray/control/tunnel`), with a
 * certificate it obtains and renews itself; the relay needs no public address. `stack.token_url` then defaults to
 * that origin. `alerts` is where the relay's own alerts go (a webhook it chooses), never through Gray:
 *
 * ```jsonc
 * "tunnel": {"server": "tunnel.gray.example:443", "zone": "relays.gray.example",
 *            "acme": {"directory": "https://acme-v02.api.letsencrypt.org/directory"},
 *            "ct": {"poll": 3600}},
 * "alerts": {"webhook": {"url": "https://hooks.relay.example/gray", "format": "slack"}}
 * ```
 *
 * `lane.release_freshness_public_key` (D137) is optional: with it a list that carries `expires_at` stays
 * current past `release_list_max_age` while Gray's freshness document for its exact bytes counts. The
 * document's URL is `lane.release_freshness`, by default the list's URL with `.json` replaced by
 * `.freshness.json`. Without the key the 24 h rule is exactly as before.
 *
 * `pairing` (S57) is optional and only informs: `init --pair` writes where the values came from,
 * `{"gray": "<Gray's API origin>", "fingerprint": "SHA256:…", "paired_at": "YYYY-MM-DDTHH:MM:SSZ"}`, and `doctor` names it.
 *
 * `releases.accepted_at_pairing` (optional) is what `init --pair` writes after it verified Gray's signed list: the
 * compose hashes and OS image hashes the list named when the relay paired. Joining is the relay's choice to trust
 * them, so the agent accepts each one once, as `releases accept` would, when it first sees it in the list
 * (`acceptPairingReleases`); every later release waits `delay_days` as before.
 */
import { isTunnelZone, TUNNEL_LOGIN_MAX_LIFETIME_MS, tunnelName } from "@gray/control/tunnel";
import { isObject } from "@gray/json";
import { isStackRelayImage, releaseFreshnessLocation } from "@gray/lane-verify";
import { MAX_CREDENTIAL_LEASE_SECONDS, RESOURCE_ID } from "@gray/relay-connector";
import { z } from "zod";
import { RelayKitError } from "../errors.ts";
import {
  APP_ID_PLACEHOLDER,
  isRelayImagePlaceholder,
  KMS_CA_PUBKEY_PLACEHOLDER,
  REGISTRY_EXPIRES_AT_PLACEHOLDER,
  REGISTRY_HOST_PLACEHOLDER,
  REGISTRY_USERNAME_PATTERN,
  REGISTRY_USERNAME_PLACEHOLDER,
  RELEASE_LIST_PLACEHOLDER,
  TOKEN_URL_PLACEHOLDER,
  utcSecondsMs,
} from "../init.ts";
import { APP_ID_PATTERN, KMS_CA_PUBKEY_PATTERN, type LaneBinding } from "../lane-binding.ts";
import { DEFAULT_AFFINITY_TTL_MS, MAX_AFFINITY_CAP, MAX_AFFINITY_TTL_MS, MIN_AFFINITY_TTL_MS } from "../scheduler/policy.ts";
import { MAX_REPLAY_CAP, MIN_REPLAY_CAP } from "../scheduler/replay.ts";
import { normalizeHttpsOrigin } from "../verified-report.ts";
import { tunnelOriginOf } from "../lane-origin.ts";

/** P12: `stack.instance`, where the stack app's origin and binding come from; a config without it reads `config`. */
export const STACK_INSTANCE_SOURCES = ["gray", "config"] as const;
export type StackInstanceSource = (typeof STACK_INSTANCE_SOURCES)[number];

/** The release acceptance modes (design v2 §A.7): the default is automatic after the delay. */
export const RELEASE_ACCEPT_MODES = ["auto-after-delay", "manual"] as const;
/** How many hashes `releases.accepted_at_pairing` holds at most; a signed list names a few. */
export const MAX_PAIRING_ACCEPTANCES = 256;
export type ReleaseAcceptMode = (typeof RELEASE_ACCEPT_MODES)[number];

/** The parsed configuration: camelCase internally, snake_case on disk. */
export interface RelayDaemonConfig {
  readonly relayId: string;
  readonly keyPath: string;
  readonly lane: {
    readonly origins: readonly string[];
    /**
     * Plan S12: the dstack instance each origin must be (app id and KMS CA public key), keyed by the
     * normalized origin. Every origin has exactly one entry; the config refuses to load otherwise.
     */
    readonly instances: ReadonlyMap<string, LaneBinding>;
    readonly releaseList: string;
    /** Gray's release-signing key (K4-6), pinned in the config; the list is signed by it. */
    readonly releasePublicKey: Uint8Array;
    readonly releaseListMaxAgeSeconds: number;
    /** D137: Gray's freshness key and the document's URL, or null for the list's own 24 h rule only. */
    readonly releaseFreshness: { readonly publicKey: Uint8Array; readonly url: string } | null;
  };
  /**
   * The signed policy bundle `run` loads and uploads before credentials, on every lane origin but a
   * relay-stack one (`stack.lane_origin`), which runs no policy module (S23). Null only when the
   * config names no other origin; `policyOrigins` says which origins upload it.
   */
  readonly policyBundlePath: string | null;
  /** The plain-HTTP scheduler listener and its public (TLS-terminated) URL, when configured (the tunnel's origin by default). */
  readonly scheduler: {
    readonly listen: { readonly host: string; readonly port: number };
    readonly publicUrl: string | null;
    readonly adminTokenFile: string | null;
  };
  /** `acceptedAtPairing`: the hashes Gray's list named when `init --pair` ran, accepted once each; empty otherwise. */
  readonly releases: { readonly accept: ReleaseAcceptMode; readonly delayDays: number; readonly acceptedAtPairing: readonly string[] };
  /** K3's source section, kept exactly as the operator wrote it; K4 validates it. */
  readonly source: unknown;
  readonly leaseLifetimeSeconds: number;
  readonly renewFraction: number;
  readonly healthzPollMs: number;
  readonly sourcePollMs: number;
  readonly inflightTtlMs: number;
  /** How long an idle conversation stays on one account; `affinity_ttl` in seconds. */
  readonly affinityTtlMs: number;
  /** The affinity map cap, or null for the derived `max(1, accounts x 4)`. */
  readonly affinityCap: number | null;
  readonly reportMaxAgeSeconds: number;
  readonly releasePollMs: number;
  readonly tickMs: number;
  readonly cooldowns: { readonly rateLimitedMs: number; readonly overloadedMs: number };
  readonly pccsUrl: string | null;
  readonly replayCap: number;
  readonly stateFile: string;
  /** Where `run` publishes its status snapshot; defaults beside the state file. */
  readonly statusFile: string;
  /** The pull-token service of a relay-stack lane (S9–S13); null when the config has no `stack`. */
  readonly stack: StackConfig | null;
  /**
   * The local page `run` serves beside the agent: on 127.0.0.1 at `port` (`ui.listen`, null without one), and with
   * `public` under `/ui/` on `stack.token_url`'s origin with passkey sign-in. Null when the config has no `ui`.
   */
  readonly ui: { readonly port: number | null; readonly public: boolean; readonly origin: string | null } | null;
  /** The relay tunnel (docs/relay-tunnel.md); null when the config has no `tunnel`. */
  readonly tunnel: TunnelConfig | null;
  /** Where the relay's own alerts go; null when the config names no channel. */
  readonly alerts: AlertsConfig | null;
  /**
   * S57: where `init --pair` got the config's values: Gray's API origin, the paired key's fingerprint and when Gray
   * paired it. `doctor` names it; nothing else reads it. Null for a config written by hand or by plain `init`.
   */
  readonly pairing: { readonly gray: string; readonly fingerprint: string; readonly pairedAt: string } | null;
}

/** The relay tunnel: Gray's rendezvous, the relay's name under the relays zone, and how the name gets its certificate. */
export interface TunnelConfig {
  /** frps's control endpoint, `host:port` (the rendezvous shares 443 between its clients and the relays' names). */
  readonly server: { readonly host: string; readonly port: number };
  readonly zone: string;
  /** `<label>.<zone>` (`@gray/control/tunnel` tunnelName). */
  readonly name: string;
  /** `https://<name>`, the agent's public origin through the tunnel. */
  readonly origin: string;
  /** A PEM file of trust anchors for the rendezvous's own certificate; null: the roots Node trusts (a test CA otherwise). */
  readonly serverCaFile: string | null;
  /** The DNS server frpc resolves the rendezvous with (`host:port`, frp's `dnsServer`); null: the system's. */
  readonly dnsServer: string | null;
  readonly acme: {
    readonly directory: string;
    readonly email: string | null;
    /** A PEM file of trust anchors for the ACME directory's own HTTPS (a test CA such as Pebble); null for public CAs. */
    readonly caRootFile: string | null;
  };
  /** The tunnel client and the TLS terminator; the image bundles both at these paths. */
  readonly frpcPath: string;
  readonly caddyPath: string;
  /** The terminator's port on 127.0.0.1, where the tunnel delivers the name's TLS connections. */
  readonly tlsPort: number;
  /** The tunnel client's local admin API port on 127.0.0.1, which `run` reads the proxy's state from. */
  readonly adminPort: number;
  /** The terminator's storage (the name's private key and certificate) and the generated files; under the state directory. */
  readonly dataDir: string;
  /** How long a signed login is valid (`@gray/control/tunnel` caps it at ten minutes). */
  readonly loginLifetimeMs: number;
  readonly ct: {
    readonly pollMs: number;
    readonly sources: readonly ("certspotter" | "crtsh")[];
    /** A 0600 file with a Cert Spotter API key; null: unauthenticated queries (a limited number an hour). */
    readonly certspotterKeyFile: string | null;
    readonly certspotterUrl: string;
    readonly crtshUrl: string;
  };
}

/** The relay's own alert channel. `format`: `json` (Gray's document) or `slack` (`{"text": …}`, Slack-compatible). */
export interface AlertsConfig {
  readonly webhook: { readonly url: string; readonly format: "json" | "slack" } | null;
}

/**
 * The relay's side of a relay-stack lane: which lane origin is the stack app, what its pre-launch
 * may present, and the registry credential a boot that passes S11 receives.
 */
export interface StackConfig {
  /**
   * P12: where the stack app's origin and binding come from: `config` (`lane_origin` and its `lane.instances` entry)
   * or `gray` (the instance the daemon adopted from Gray's answer, once a boot's quote proved it).
   */
  readonly instanceSource: StackInstanceSource;
  /** The `lane.origins` entry that is the stack app; its `lane.instances` binding is S11's app id and KMS. Null with `gray`. */
  readonly laneOrigin: string | null;
  readonly instance: LaneBinding | null;
  /**
   * The pull-token service's https origin; must equal the compose's `x-gray-relay.token_url`. Defaults to the tunnel's
   * origin when the config has a `tunnel`.
   */
  readonly tokenUrl: string;
  /**
   * The relay's own images (`<registry host>/<repo>@sha256:<64 hex>`, S51): the only ones the token service names
   * and credential intake seals to (S54).
   */
  readonly relayImages: readonly string[];
  /**
   * S51: the image a boot gets when control.json names none (`gray-assistant stack rollout` writes one there): the
   * config's `current_image`, or the only entry of `relay_images`.
   */
  readonly currentImage: string;
  /** S11a: when set, the release entry's `stack.pre_launch_sha256` must be exactly this. */
  readonly preLaunchSha256: string | null;
  readonly registry: {
    /** `x-gray-relay.registry`: the host[:port] every relay image lives under. */
    readonly host: string;
    readonly username: string;
    /** A 0600 file holding the read-only registry token (S13); read when the agent starts. */
    readonly passwordFile: string;
    /**
     * The token's own expiry as `YYYY-MM-DDTHH:MM:SSZ`; the envelope carries it and nothing is issued after it. Null
     * (relay standard v1.7: `expires_at` left out) for a token with no known expiry: the envelope carries null, every
     * boot gets the token, and a pull the registry refuses is the signal.
     */
    readonly expiresAt: string | null;
    readonly expiresAtMs: number | null;
  };
  /** The append-only record of every issue (S13); defaults beside the state file. */
  readonly issueLog: string;
  /** Gray's public API origin; every issue is reported to its `/v1/lane-stack/pull-token-issues` (S13). */
  readonly reportOrigin: string;
}

const pathSchema = z
  .string()
  .min(1)
  .max(4096)
  .refine((value) => !value.includes("\u0000"), "a path holds a NUL");

const secondsSchema = z.number().int().min(1).max(86_400);
const optionalSeconds = (fallback: number, min: number, max: number) => z.number().int().min(min).max(max).optional().transform((value) => value ?? fallback);

const originSchema = z.string().max(2048).transform((value, ctx) => {
  try {
    return normalizeHttpsOrigin(value);
  } catch {
    ctx.addIssue({ code: "custom", message: "an https origin" });
    return z.NEVER;
  }
});

const urlSchema = z.string().max(4096).refine((value) => {
  try {
    const url = new URL(value);
    return url.protocol === "https:" || url.protocol === "http:";
  } catch {
    return false;
  }
}, "an http(s) URL");

/** Loopback hosts, in the forms `new URL().hostname` returns (IPv6 keeps its brackets). */
const LOOPBACK_HOSTS = new Set(["127.0.0.1", "::1", "[::1]", "localhost"]);

/**
 * The signed release list is https, or http for a loopback host only (the in-process test servers
 * and a same-host relay). R27: a network attacker can replay a captured still-fresh signed list over
 * plain http; the signature keeps the content honest, but only a loopback peer is trusted to be the
 * relay's own process. `pccs_url` keeps the wider `urlSchema`.
 */
const releaseListUrlSchema = z.string().max(4096).refine((value) => {
  try {
    const url = new URL(value);
    return url.protocol === "https:" || (url.protocol === "http:" && LOOPBACK_HOSTS.has(url.hostname));
  } catch {
    return false;
  }
}, "an https URL (http is allowed only for 127.0.0.1, ::1 or localhost)");

const publicKeySchema = z.string().regex(/^[0-9a-f]{64}$/);

const instanceSchema = z
  .object({
    app_id: z.string().regex(APP_ID_PATTERN, "the dstack app id, 40 lower-case hex"),
    kms_ca_pubkey: z.string().regex(KMS_CA_PUBKEY_PATTERN, "the node KMS's ca_pubkey, 182 lower-case hex (P-256 SPKI)"),
  })
  .strict();

const laneSchema = z
  .object({
    // Optional only with `stack.instance: "gray"`, whose stack app comes from Gray (`parseRelayDaemonConfig`).
    origins: z.array(originSchema).max(16).optional(),
    // S12: no default and no unchecked mode; `parseRelayDaemonConfig` names a missing entry.
    instances: z.record(z.string().max(2048), instanceSchema).optional(),
    release_list: releaseListUrlSchema,
    // K4-6: Gray signs the release list and the SDK config pins the key. There is no unpinned mode.
    release_public_key: publicKeySchema,
    release_list_max_age: optionalSeconds(86_400, 60, 604_800),
    // D137: the online freshness role. Optional; the URL defaults beside the list.
    release_freshness_public_key: publicKeySchema.optional(),
    release_freshness: releaseListUrlSchema.optional(),
  })
  .strict();

const listenSchema = z
  .object({
    host: z.string().regex(/^[A-Za-z0-9.:[\]-]{1,255}$/),
    // 0 is the test-only ephemeral port; the shipped config uses 8080.
    port: z.number().int().min(0).max(65_535),
  })
  .strict();

/** `ui.listen`: the local page's port (it binds 127.0.0.1 only, so the config names no host); `ui.public`: see above. */
const uiSchema = z
  .object({
    listen: z
      .object({
        // 0 is the test-only ephemeral port, as for the scheduler.
        port: z.number().int().min(0).max(65_535),
      })
      .strict()
      .optional(),
    public: z.boolean().optional(),
    // An https origin, no path: the address the relay's proxy serves the agent on.
    origin: z.string().max(2048).refine((value) => {
      try {
        const url = new URL(value);
        return url.protocol === "https:" && url.origin === value;
      } catch {
        return false;
      }
    }, "an https origin (no path or trailing slash)").optional(),
  })
  .strict();

const schedulerSchema = z
  .object({
    listen: listenSchema.optional().transform((value) => value ?? { host: "127.0.0.1", port: 8080 }),
    // D23: the registration document carries this as the lane record scheduler_url, which Gray
    // stores as an https origin only. Refusing a path here keeps the config and the registration
    // from disagreeing after a reload.
    public_url: z.string().max(2048).refine((value) => {
      if (/\s/.test(value)) return false;
      try {
        const url = new URL(value);
        return (
          url.protocol === "https:" &&
          url.username === "" &&
          url.password === "" &&
          url.search === "" &&
          url.hash === "" &&
          url.pathname === "/" &&
          url.href === `${url.origin}/`
        );
      } catch {
        return false;
      }
    }, "an https origin (no path, query or fragment)").optional(),
    admin_token_file: pathSchema.optional(),
  })
  .strict();

const releasesSchema = z
  .object({
    accept: z.enum(RELEASE_ACCEPT_MODES).optional().transform((value) => value ?? "auto-after-delay"),
    delay_days: z.number().int().min(0).max(365).optional().transform((value) => value ?? 7),
    accepted_at_pairing: z
      .array(z.string().regex(/^[0-9a-f]{64}$/))
      .max(MAX_PAIRING_ACCEPTANCES)
      .refine((hashes) => new Set(hashes).size === hashes.length, "no hash twice")
      .optional()
      .transform((value) => value ?? []),
  })
  .strict();

const cooldownsSchema = z
  .object({ rate_limited_seconds: secondsSchema.optional(), overloaded_seconds: secondsSchema.optional() })
  .strict();

const sha256HexSchema = z.string().regex(/^[0-9a-f]{64}$/, "64 lower-case hex");

/**
 * S6/S9: the token service as an https origin, exactly as the compose's `x-gray-relay.token_url`
 * writes it (`app-compose.mjs --relay-token-url`: no path, no trailing slash); pre-launch appends
 * `/v1/pull-token/…` and its `curl --proto =https` refuses anything else.
 */
const tokenUrlSchema = z.string().max(2048).refine((value) => {
  try {
    const url = new URL(value);
    return url.protocol === "https:" && url.origin === value;
  } catch {
    return false;
  }
}, "an https origin (no path or trailing slash)");

/** S6: `x-gray-relay.registry`, the host[:port] pre-launch logs in to (its own pattern). */
const registryHostSchema = z.string().max(253).regex(/^[A-Za-z0-9.-]+(:[0-9]+)?$/, "a registry host[:port]");

/** S51: a relay image, `<registry host[:port]>/<repository>@sha256:<64 hex>` (@gray/lane-verify's own test). */
const pinnedImageSchema = z.string().refine((value) => isStackRelayImage(value), "<registry host>/<repository>@sha256:<64 hex>");

/** An instant at second precision in UTC, the form the envelope carries. */
const utcSecondsSchema = z.string().refine((value) => utcSecondsMs(value) !== null, "YYYY-MM-DDTHH:MM:SSZ");

const stackSchema = z
  .object({
    instance: z.enum(STACK_INSTANCE_SOURCES).optional(),
    // Required with `instance: "config"`, refused with `"gray"` (`stackConfigOf`).
    lane_origin: originSchema.optional(),
    // Optional with a `tunnel`: its origin is the default.
    token_url: tokenUrlSchema.optional(),
    relay_images: z.array(pinnedImageSchema).min(1).max(16),
    current_image: pinnedImageSchema.optional(),
    pre_launch_sha256: sha256HexSchema.optional(),
    registry: z
      .object({
        host: registryHostSchema,
        username: z.string().regex(REGISTRY_USERNAME_PATTERN, "1-128 printable characters, no space"),
        password_file: pathSchema,
        expires_at: utcSecondsSchema.optional(),
      })
      .strict(),
    issue_log: pathSchema.optional(),
    // S13: Gray's public API origin. https, or http only for a loopback host (the tests, R27's rule).
    report_origin: z.string().max(2048).refine((value) => {
      try {
        const url = new URL(value);
        return url.origin === value && (url.protocol === "https:" || (url.protocol === "http:" && LOOPBACK_HOSTS.has(url.hostname)));
      } catch {
        return false;
      }
    }, "an https origin (no path or trailing slash)"),
  })
  .strict();

/** `host:port` of the rendezvous: a DNS name (or an IP for a test) and a port. */
const serverSchema = z.string().max(300).transform((value, ctx) => {
  const match = /^([A-Za-z0-9.-]{1,253}|\[[0-9a-fA-F:]{2,45}\]):([0-9]{1,5})$/.exec(value);
  const port = match === null ? NaN : Number(match[2]);
  if (match === null || !Number.isInteger(port) || port < 1 || port > 65_535) {
    ctx.addIssue({ code: "custom", message: "host:port" });
    return z.NEVER;
  }
  return { host: (match[1] as string).replace(/^\[|\]$/g, ""), port };
});

const httpsUrlSchema = z.string().max(2048).refine((value) => {
  try {
    const url = new URL(value);
    return url.protocol === "https:" && url.username === "" && url.password === "";
  } catch {
    return false;
  }
}, "an https URL");

/** The CT sources `run` asks (docs/relay-tunnel.md "Detection"): SSLMate's Cert Spotter API and Sectigo's crt.sh. */
export const CT_SOURCES = ["certspotter", "crtsh"] as const;

const tunnelSchema = z
  .object({
    server: serverSchema,
    zone: z.string().refine(isTunnelZone, "a lower-case DNS name of two or more labels"),
    server_ca: pathSchema.optional(),
    dns_server: z.string().regex(/^[0-9.]{7,15}:[0-9]{1,5}$/, "an IPv4 host:port").optional(),
    acme: z
      .object({
        // Let's Encrypt's production directory (https://letsencrypt.org/docs/acme-protocol-updates/).
        directory: httpsUrlSchema.optional(),
        email: z.string().max(254).regex(/^[^\s@]+@[^\s@]+$/).optional(),
        ca_root: pathSchema.optional(),
      })
      .strict()
      .optional(),
    frpc: pathSchema.optional(),
    caddy: pathSchema.optional(),
    tls_port: z.number().int().min(1024).max(65_535).optional(),
    admin_port: z.number().int().min(1024).max(65_535).optional(),
    data_dir: pathSchema.optional(),
    login_lifetime: z.number().int().min(60).max(TUNNEL_LOGIN_MAX_LIFETIME_MS / 1000).optional(),
    ct: z
      .object({
        // An hour: a foreign certificate is found within about an hour of the aggregators indexing it; CT logs
        // themselves promise inclusion within 24 h (RFC 6962 §3, the maximum merge delay).
        poll: z.number().int().min(300).max(86_400).optional(),
        sources: z.array(z.enum(CT_SOURCES)).min(1).max(2).optional(),
        certspotter_api_key_file: pathSchema.optional(),
        certspotter_url: httpsUrlSchema.optional(),
        crtsh_url: httpsUrlSchema.optional(),
      })
      .strict()
      .optional(),
  })
  .strict();

const alertsSchema = z
  .object({
    webhook: z.object({ url: httpsUrlSchema, format: z.enum(["json", "slack"]).optional() }).strict().optional(),
  })
  .strict();

/** S57: `init --pair`'s facts (`@gray/control/stack-pairing`'s fingerprint form). */
const pairingSchema = z
  .object({
    gray: z.string().max(2048).refine((value) => {
      try {
        const url = new URL(value);
        return url.origin === value && (url.protocol === "https:" || url.protocol === "http:");
      } catch {
        return false;
      }
    }, "an http(s) origin (no path or trailing slash)"),
    fingerprint: z.string().regex(/^SHA256:[A-Za-z0-9+/]{43}$/, "SHA256: and 43 base64 characters"),
    paired_at: utcSecondsSchema,
  })
  .strict();

const configSchema = z
  .object({
    relay_id: z.string().regex(RESOURCE_ID),
    key: pathSchema,
    // S23: optional for a relay whose only lane origin is its relay-stack app (`parseRelayDaemonConfig`).
    policy_bundle: pathSchema.optional(),
    lane: laneSchema,
    scheduler: schedulerSchema.optional().transform((value) => value ?? { listen: { host: "127.0.0.1", port: 8080 } }),
    source: z.unknown(),
    releases: releasesSchema.optional().transform((value) => value ?? { accept: "auto-after-delay" as const, delay_days: 7, accepted_at_pairing: [] }),
    // D35: the lane's longest credential lease is the upper bound, so a sealed bundle the daemon
    // builds is always one the TEE accepts (`checkBundleFreshness`).
    lease_lifetime: optionalSeconds(3600, 60, Number(MAX_CREDENTIAL_LEASE_SECONDS)),
    renew_fraction: z.number().min(0.05).max(0.95).optional().transform((value) => value ?? 0.5),
    healthz_poll: optionalSeconds(5, 1, 300),
    source_poll: optionalSeconds(30, 1, 3600),
    inflight_ttl: optionalSeconds(600, 1, 86_400),
    affinity_ttl: optionalSeconds(DEFAULT_AFFINITY_TTL_MS / 1000, MIN_AFFINITY_TTL_MS / 1000, MAX_AFFINITY_TTL_MS / 1000),
    affinity_cap: z.number().int().min(1).max(MAX_AFFINITY_CAP).optional().transform((value) => value ?? null),
    report_max_age: optionalSeconds(3600, 60, 86_400),
    release_poll: optionalSeconds(300, 30, 86_400),
    tick_ms: z.number().int().min(100).max(60_000).optional().transform((value) => value ?? 1000),
    cooldowns: cooldownsSchema.optional().transform((value) => value ?? {}),
    pccs_url: urlSchema.nullable().optional().transform((value) => value ?? null),
    replay_cap: z.number().int().min(MIN_REPLAY_CAP).max(MAX_REPLAY_CAP).optional().transform((value) => value ?? 100_000),
    state_file: pathSchema,
    status_file: pathSchema.optional(),
    stack: stackSchema.optional(),
    ui: uiSchema.optional(),
    tunnel: tunnelSchema.optional(),
    alerts: alertsSchema.optional(),
    pairing: pairingSchema.optional(),
  })
  .strict();

/** One config member `run`/`doctor` refuse while it is not the value Gray published. */
export interface ReleasePinningProblem {
  /** The dotted member path, exactly as the config file spells it. */
  readonly member: string;
  /** One plain sentence the operator sees; it names the member to fill and never echoes a value. */
  readonly message: string;
}

/** Whether a release-list URL is still the skeleton's `lane.example` value. */
export function isPlaceholderReleaseListUrl(value: string): boolean {
  if (value === RELEASE_LIST_PLACEHOLDER) return true;
  try {
    const host = new URL(value).hostname;
    return host === "lane.example" || host.endsWith(".lane.example");
  } catch {
    return true;
  }
}

/** A key of all zeros cannot verify anything; it is the init placeholder. */
export function isZeroReleasePublicKey(key: Uint8Array): boolean {
  return key.length > 0 && key.every((byte) => byte === 0);
}

/**
 * K5-1: `run` and `doctor` refuse a config that still carries the init placeholders for the two
 * values Gray must publish. One message names the exact member(s) to fill; `init` keeps writing the
 * placeholders and says so. `doctor` turns this into its one `release_key` FAIL line; `run` turns it
 * into a usage refusal before it reads a key file, binds a port or fetches anything.
 *
 * S12 adds `lane.instances`: once both release values are filled, an entry that still holds init's
 * zero app id or zero-point KMS key is refused the same way (an attestation could never pass it).
 */
export function releasePinningProblem(config: RelayDaemonConfig): ReleasePinningProblem | null {
  const list = isPlaceholderReleaseListUrl(config.lane.releaseList);
  const key = isZeroReleasePublicKey(config.lane.releasePublicKey);
  if (list && key) {
    return {
      member: "lane.release_list, lane.release_public_key",
      message: "lane.release_list and lane.release_public_key are still the init placeholders: fill them with the signed release-list URL and release-signing key Gray publishes",
    };
  }
  if (list) {
    return {
      member: "lane.release_list",
      message: "lane.release_list is still the init placeholder: fill it with the signed release-list URL Gray publishes",
    };
  }
  if (key) {
    return {
      member: "lane.release_public_key",
      message: "lane.release_public_key is still the init placeholder (64 zeros): fill it with Gray's published release-signing key (64 lower-case hex)",
    };
  }
  for (const instance of config.lane.instances.values()) {
    if (instance.appId === APP_ID_PLACEHOLDER || instance.kmsCaPubkey === KMS_CA_PUBKEY_PLACEHOLDER) {
      return {
        member: "lane.instances",
        message: "lane.instances still holds the init placeholder (zeros): fill each origin's app_id and kms_ca_pubkey with the values Gray publishes",
      };
    }
  }
  return null;
}

/**
 * S57: the `stack` members `init --pair` leaves for the relay, while they still hold its placeholders: the registry
 * user and its token's expiry, and the image, registry host and token URL when Gray's answer had none. `run` refuses
 * the config with the message, and `doctor` names it, as for the release placeholders.
 */
export function stackPlaceholderProblem(config: Pick<RelayDaemonConfig, "stack">): ReleasePinningProblem | null {
  const stack = config.stack;
  if (stack === null) return null;
  const members: string[] = [];
  if (stack.relayImages.some(isRelayImagePlaceholder)) members.push("stack.relay_images");
  if (stack.registry.host === REGISTRY_HOST_PLACEHOLDER) members.push("stack.registry.host");
  if (stack.registry.username === REGISTRY_USERNAME_PLACEHOLDER) members.push("stack.registry.username");
  // An expiry is optional (v1.7); the placeholder an older `init --pair` wrote is still refused, so it is filled or removed.
  if (stack.registry.expiresAt === REGISTRY_EXPIRES_AT_PLACEHOLDER) members.push("stack.registry.expires_at");
  if (stack.tokenUrl === TOKEN_URL_PLACEHOLDER) members.push("stack.token_url");
  if (members.length === 0) return null;
  return {
    member: members.join(", "),
    message: `${members.join(", ")} ${members.length === 1 ? "is" : "are"} still the init placeholder: fill ${members.length === 1 ? "it" : "them"} with your own values (the registry's read-only pull token user and its expiry, or no expires_at for a token without one, your image pinned by digest)`,
  };
}

/** What a config without the S12 instance expectations is told; it names members, never values. */
const MISSING_INSTANCES =
  "lane.instances must give every lane origin the dstack app_id and the KMS ca_pubkey Gray publishes for it (credentials are sealed only to that instance)";

/** Parse one daemon config value. Refusals name the member path and never echo a value. */
export function parseRelayDaemonConfig(value: unknown): RelayDaemonConfig {
  if (isObject(value as never)) {
    const lane = (value as { lane?: unknown }).lane;
    if (isObject(lane as never)) {
      const releaseList = (lane as { release_list?: unknown }).release_list;
      if (releaseList === undefined || releaseList === null || releaseList === "") {
        throw new RelayKitError("usage", "invalid daemon config: lane.release_list is not set; fill it with the signed release-list URL Gray publishes");
      }
      const instances = (lane as { instances?: unknown }).instances;
      // P12: with `stack.instance: "gray"` the stack app's entry comes from Gray, so a stack-only config has none.
      const stack = (value as { stack?: unknown }).stack;
      const fromGray = isObject(stack as never) && (stack as { instance?: unknown }).instance === "gray";
      if ((instances === undefined && !fromGray) || instances === null) {
        throw new RelayKitError("usage", `invalid daemon config: ${MISSING_INSTANCES}`);
      }
    }
  }
  const parsed = configSchema.safeParse(value);
  if (!parsed.success) {
    const issue = parsed.error.issues[0];
    const path = issue === undefined || issue.path.length === 0 ? "(root)" : issue.path.map(String).join(".");
    throw new RelayKitError("usage", `invalid daemon config: ${path}`);
  }
  if (parsed.data.source === undefined) throw new RelayKitError("usage", "invalid daemon config: source");
  // Without the stack app from Gray the config names at least one lane origin, as before P12.
  const laneOrigins = parsed.data.lane.origins ?? [];
  if (laneOrigins.length === 0 && parsed.data.stack?.instance !== "gray") throw new RelayKitError("usage", "invalid daemon config: lane.origins");
  const origins: string[] = [];
  for (const origin of laneOrigins) {
    if (origins.includes(origin)) throw new RelayKitError("usage", "invalid daemon config: lane.origins has a duplicate");
    origins.push(origin);
  }
  const instances = new Map<string, LaneBinding>();
  for (const [key, entry] of Object.entries(parsed.data.lane.instances ?? {})) {
    let origin: string;
    try {
      origin = normalizeHttpsOrigin(key);
    } catch {
      throw new RelayKitError("usage", "invalid daemon config: lane.instances has a key that is not an https origin");
    }
    if (instances.has(origin)) throw new RelayKitError("usage", "invalid daemon config: lane.instances names one origin twice");
    if (!origins.includes(origin)) throw new RelayKitError("usage", "invalid daemon config: lane.instances names an origin that lane.origins does not list");
    instances.set(origin, { appId: entry.app_id, kmsCaPubkey: entry.kms_ca_pubkey });
  }
  for (let index = 0; index < origins.length; index += 1) {
    if (!instances.has(origins[index] as string)) {
      throw new RelayKitError("usage", `invalid daemon config: lane.instances has no entry for lane.origins[${index}]; ${MISSING_INSTANCES}`);
    }
  }
  const releasePublicKey = hexBytes(parsed.data.lane.release_public_key);
  if (releasePublicKey === null) throw new RelayKitError("usage", "invalid daemon config: lane.release_public_key");
  const releaseFreshness = releaseFreshnessOf(parsed.data.lane, releasePublicKey);
  const tunnel = parsed.data.tunnel === undefined ? null : tunnelConfigOf(parsed.data.tunnel, parsed.data.relay_id, parsed.data.state_file);
  // The agent, Caddy, frpc's admin API and the local page all listen on 127.0.0.1 beside each other (0 is the tests' free port).
  const listenPort = parsed.data.scheduler.listen.port;
  if (tunnel !== null && listenPort !== 0 && (listenPort === tunnel.tlsPort || listenPort === tunnel.adminPort)) {
    throw new RelayKitError("usage", "invalid daemon config: scheduler.listen's port is also tunnel.tls_port or tunnel.admin_port; each needs its own port");
  }
  const uiPort = parsed.data.ui?.listen?.port;
  if (tunnel !== null && uiPort !== undefined && uiPort !== 0 && (uiPort === tunnel.tlsPort || uiPort === tunnel.adminPort)) {
    throw new RelayKitError("usage", "invalid daemon config: ui.listen's port is also tunnel.tls_port or tunnel.admin_port; each needs its own port");
  }
  const stack = parsed.data.stack === undefined ? null : stackConfigOf(parsed.data.stack, instances, parsed.data.state_file, tunnel);
  for (const origin of origins) {
    // docs/design/relay-outbound-only.md §5: `https://<entry>/v1/peer/tunnel/<relay>` reaches this relay's stack VM
    // through Gray's entry. It names this relay, and it is the stack app's origin: a default-layout lane is never
    // behind it.
    const tunnelOrigin = tunnelOriginOf(origin);
    if (tunnelOrigin === null) continue;
    if (tunnelOrigin.relayId !== parsed.data.relay_id) {
      throw new RelayKitError("usage", "invalid daemon config: a lane origin through Gray's entry (/v1/peer/tunnel/<relay>) must name this config's relay_id");
    }
    if (stack?.laneOrigin !== origin) {
      throw new RelayKitError("usage", "invalid daemon config: a lane origin through Gray's entry (/v1/peer/tunnel/<relay>) reaches only the relay-stack VM: it must be stack.lane_origin");
    }
  }
  if (parsed.data.ui?.public === true && stack === null && tunnel === null && parsed.data.ui.origin === undefined) {
    throw new RelayKitError("usage", "invalid daemon config: ui.public needs an origin to serve the page on: ui.origin, the tunnel section's, or the stack section's token_url");
  }
  if (parsed.data.policy_bundle === undefined && origins.some((origin) => origin !== stack?.laneOrigin)) {
    throw new RelayKitError(
      "usage",
      "invalid daemon config: policy_bundle is required: every lane origin but a relay-stack one (stack.lane_origin, which runs no policy module) installs the relay's policy before its credentials",
    );
  }
  return {
    relayId: parsed.data.relay_id,
    keyPath: parsed.data.key,
    policyBundlePath: parsed.data.policy_bundle ?? null,
    lane: {
      origins,
      instances,
      releaseList: parsed.data.lane.release_list,
      releasePublicKey,
      releaseListMaxAgeSeconds: parsed.data.lane.release_list_max_age,
      releaseFreshness,
    },
    scheduler: {
      listen: parsed.data.scheduler.listen,
      // With the tunnel its origin is the agent's public origin, the scheduler's included.
      publicUrl: parsed.data.scheduler.public_url ?? tunnel?.origin ?? null,
      adminTokenFile: parsed.data.scheduler.admin_token_file ?? null,
    },
    releases: { accept: parsed.data.releases.accept, delayDays: parsed.data.releases.delay_days, acceptedAtPairing: parsed.data.releases.accepted_at_pairing },
    source: parsed.data.source,
    leaseLifetimeSeconds: parsed.data.lease_lifetime,
    renewFraction: parsed.data.renew_fraction,
    healthzPollMs: parsed.data.healthz_poll * 1000,
    sourcePollMs: parsed.data.source_poll * 1000,
    inflightTtlMs: parsed.data.inflight_ttl * 1000,
    affinityTtlMs: parsed.data.affinity_ttl * 1000,
    affinityCap: parsed.data.affinity_cap,
    reportMaxAgeSeconds: parsed.data.report_max_age,
    releasePollMs: parsed.data.release_poll * 1000,
    tickMs: parsed.data.tick_ms,
    cooldowns: {
      rateLimitedMs: (parsed.data.cooldowns.rate_limited_seconds ?? 60) * 1000,
      overloadedMs: (parsed.data.cooldowns.overloaded_seconds ?? 30) * 1000,
    },
    pccsUrl: parsed.data.pccs_url,
    replayCap: parsed.data.replay_cap,
    stateFile: parsed.data.state_file,
    statusFile: parsed.data.status_file ?? `${parsed.data.state_file}.status.json`,
    stack,
    ui: parsed.data.ui === undefined ? null : { port: parsed.data.ui.listen?.port ?? null, public: parsed.data.ui.public ?? false, origin: parsed.data.ui.origin ?? null },
    tunnel,
    alerts: parsed.data.alerts === undefined ? null : { webhook: parsed.data.alerts.webhook === undefined ? null : { url: parsed.data.alerts.webhook.url, format: parsed.data.alerts.webhook.format ?? "json" } },
    pairing: parsed.data.pairing === undefined ? null : { gray: parsed.data.pairing.gray, fingerprint: parsed.data.pairing.fingerprint, pairedAt: parsed.data.pairing.paired_at },
  };
}

/**
 * The lane origins that install the relay's policy bundle before credentials: every one but the
 * relay-stack app's (S23: the lane routes a stack relay's requests through its container, and runs no
 * WASM policy module for it; the lane does not even list a stack relay for the policy route).
 */
export function policyOrigins(config: Pick<RelayDaemonConfig, "lane" | "stack">): readonly string[] {
  return config.lane.origins.filter((origin) => origin !== config.stack?.laneOrigin);
}

/**
 * The refusal of a plain https `stack.lane_origin` (kit 1.1.0, docs/design/relay-outbound-only.md section 5): a
 * relay-stack VM is reached only through Gray's entry.
 */
export const STACK_LANE_ORIGIN_TUNNEL_RULE =
  "invalid daemon config: stack.lane_origin is Gray's entry tunnel route, https://<entry>/v1/peer/tunnel/<relay_id>: since kit 1.1.0 a relay-stack VM takes no inbound connection, so a plain https origin does not reach it";

/** The `stack` section's cross-member rules; refusals name members, never values. */
function stackConfigOf(stack: z.infer<typeof stackSchema>, instances: ReadonlyMap<string, LaneBinding>, stateFile: string, tunnel: TunnelConfig | null): StackConfig {
  const instanceSource = stack.instance ?? "config";
  let instance: LaneBinding | null = null;
  if (instanceSource === "gray") {
    // P12: the stack app is the instance Gray names after a Deploy, adopted once its own quote proves it.
    if (stack.lane_origin !== undefined) {
      throw new RelayKitError(
        "usage",
        'invalid daemon config: stack.lane_origin is left out with stack.instance "gray": the stack app\'s origin comes from Gray after a Deploy; remove it, or set stack.instance to "config" to keep it and its lane.instances entry by hand',
      );
    }
  } else {
    if (stack.lane_origin === undefined) {
      throw new RelayKitError("usage", 'invalid daemon config: stack.lane_origin is required unless stack.instance is "gray" (the stack app\'s values from Gray)');
    }
    instance = instances.get(stack.lane_origin) ?? null;
    if (instance === null) throw new RelayKitError("usage", "invalid daemon config: stack.lane_origin is not one of lane.origins");
    // docs/design/relay-outbound-only.md section 5: a relay-stack VM takes no inbound connection, so its lane origin
    // is Gray's entry tunnel route; a plain https origin reaches no VM.
    if (tunnelOriginOf(stack.lane_origin) === null) throw new RelayKitError("usage", STACK_LANE_ORIGIN_TUNNEL_RULE);
  }
  // The compose policy requires the relay's image under `x-gray-relay.registry`, and pre-launch logs
  // in to exactly that host, so every pinned digest must live there.
  if (stack.relay_images.some((image) => !image.startsWith(`${stack.registry.host}/`))) {
    throw new RelayKitError("usage", "invalid daemon config: stack.relay_images must all be under stack.registry.host");
  }
  if (new Set(stack.relay_images).size !== stack.relay_images.length) throw new RelayKitError("usage", "invalid daemon config: stack.relay_images has a duplicate");
  // S51: with one image it is the current one; with more, the operator names it (control.json may later name another).
  if (stack.current_image === undefined && stack.relay_images.length > 1) {
    throw new RelayKitError("usage", "invalid daemon config: stack.current_image must name one of stack.relay_images when the list has more than one");
  }
  const currentImage = stack.current_image ?? (stack.relay_images[0] as string);
  if (!stack.relay_images.includes(currentImage)) throw new RelayKitError("usage", "invalid daemon config: stack.current_image is not one of stack.relay_images");
  const tokenUrl = stack.token_url ?? tunnel?.origin;
  if (tokenUrl === undefined) throw new RelayKitError("usage", "invalid daemon config: stack.token_url is required without a tunnel section (the tunnel's origin is its default)");
  return {
    instanceSource,
    laneOrigin: stack.lane_origin ?? null,
    instance,
    tokenUrl,
    relayImages: [...stack.relay_images],
    currentImage,
    preLaunchSha256: stack.pre_launch_sha256 ?? null,
    registry: {
      host: stack.registry.host,
      username: stack.registry.username,
      passwordFile: stack.registry.password_file,
      expiresAt: stack.registry.expires_at ?? null,
      expiresAtMs: stack.registry.expires_at === undefined ? null : Date.parse(stack.registry.expires_at),
    },
    issueLog: stack.issue_log ?? `${stateFile}.pull-tokens.jsonl`,
    reportOrigin: stack.report_origin,
  };
}

/** The defaults of the `tunnel` section, as the image lays it out (deploy/relay/Dockerfile bundles both programs). */
export const TUNNEL_DEFAULTS = Object.freeze({
  acmeDirectory: "https://acme-v02.api.letsencrypt.org/directory",
  frpcPath: "/usr/local/bin/frpc",
  caddyPath: "/usr/local/bin/caddy",
  tlsPort: 8443,
  adminPort: 7400,
  loginLifetimeSeconds: 300,
  ctPollSeconds: 3600,
  // https://sslmate.com/help/reference/ct_search_api_v1 and https://crt.sh/ (its JSON output and ?d=<id> download).
  certspotterUrl: "https://api.certspotter.com",
  crtshUrl: "https://crt.sh",
});

/** The `tunnel` section's cross-member rules; refusals name members, never values. */
function tunnelConfigOf(tunnel: z.infer<typeof tunnelSchema>, relayId: string, stateFile: string): TunnelConfig {
  const name = tunnelName(relayId, tunnel.zone);
  if (name === null) throw new RelayKitError("usage", "invalid daemon config: relay_id has no tunnel name under tunnel.zone");
  const tlsPort = tunnel.tls_port ?? TUNNEL_DEFAULTS.tlsPort;
  const adminPort = tunnel.admin_port ?? TUNNEL_DEFAULTS.adminPort;
  if (tlsPort === adminPort) throw new RelayKitError("usage", "invalid daemon config: tunnel.tls_port and tunnel.admin_port are one port");
  const stateDirectory = stateFile.replace(/\/[^/]*$/u, "") || ".";
  return {
    server: tunnel.server,
    zone: tunnel.zone,
    name,
    origin: `https://${name}`,
    serverCaFile: tunnel.server_ca ?? null,
    dnsServer: tunnel.dns_server ?? null,
    acme: { directory: tunnel.acme?.directory ?? TUNNEL_DEFAULTS.acmeDirectory, email: tunnel.acme?.email ?? null, caRootFile: tunnel.acme?.ca_root ?? null },
    frpcPath: tunnel.frpc ?? TUNNEL_DEFAULTS.frpcPath,
    caddyPath: tunnel.caddy ?? TUNNEL_DEFAULTS.caddyPath,
    tlsPort,
    adminPort,
    dataDir: tunnel.data_dir ?? `${stateDirectory}/tunnel`,
    loginLifetimeMs: (tunnel.login_lifetime ?? TUNNEL_DEFAULTS.loginLifetimeSeconds) * 1000,
    ct: {
      pollMs: (tunnel.ct?.poll ?? TUNNEL_DEFAULTS.ctPollSeconds) * 1000,
      sources: [...new Set(tunnel.ct?.sources ?? CT_SOURCES)],
      certspotterKeyFile: tunnel.ct?.certspotter_api_key_file ?? null,
      certspotterUrl: (tunnel.ct?.certspotter_url ?? TUNNEL_DEFAULTS.certspotterUrl).replace(/\/+$/u, ""),
      crtshUrl: (tunnel.ct?.crtsh_url ?? TUNNEL_DEFAULTS.crtshUrl).replace(/\/+$/u, ""),
    },
  };
}

/**
 * D137: the freshness role's key and URL. The URL alone is refused (it would verify nothing), and so is a
 * key equal to the release key or of zeros: the online role must have its own key (D134).
 */
function releaseFreshnessOf(
  lane: { readonly release_list: string; readonly release_freshness_public_key?: string | undefined; readonly release_freshness?: string | undefined },
  releasePublicKey: Uint8Array,
): { readonly publicKey: Uint8Array; readonly url: string } | null {
  if (lane.release_freshness_public_key === undefined) {
    if (lane.release_freshness !== undefined) {
      throw new RelayKitError("usage", "invalid daemon config: lane.release_freshness needs lane.release_freshness_public_key, the freshness key Gray publishes");
    }
    return null;
  }
  const publicKey = hexBytes(lane.release_freshness_public_key);
  if (publicKey === null || isZeroReleasePublicKey(publicKey)) throw new RelayKitError("usage", "invalid daemon config: lane.release_freshness_public_key");
  if (publicKey.every((byte, index) => byte === releasePublicKey[index])) {
    throw new RelayKitError("usage", "invalid daemon config: lane.release_freshness_public_key is the release key; Gray's freshness key is a key of its own");
  }
  return { publicKey, url: lane.release_freshness ?? releaseFreshnessLocation(lane.release_list) };
}

/** Parse a 64-hex public key; null for anything else (the caller names the member, never a value). */
function hexBytes(text: string): Uint8Array | null {
  if (!/^[0-9a-f]{64}$/.test(text)) return null;
  const out = new Uint8Array(32);
  for (let index = 0; index < 32; index += 1) out[index] = Number.parseInt(text.slice(index * 2, index * 2 + 2), 16);
  return out;
}

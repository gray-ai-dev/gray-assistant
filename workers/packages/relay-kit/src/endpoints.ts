/**
 * Every path and API version this tool speaks, in one file.
 *
 * The lane's intake endpoints are **placeholders**: the gateway side of the confidential lane is not
 * wired yet, so the two POST paths below are this package's proposal for the routes the TEE will
 * expose. They are defined once so a change is one edit, and the README says they are not deployed.
 * The scheduler paths are not placeholders: they are the ones `@gray/relay-connector`'s
 * `SchedulerClient` already calls.
 */

/**
 * Stamped by the published image's build (deploy/relay/image/bundle.mjs, esbuild `define`): the kit version of the
 * commit (deploy/relay/kit/VERSION) and the commit, `1.0.7+0123456789ab`. Undefined everywhere else.
 */
declare const __GRAY_ASSISTANT_VERSION__: string | undefined;

/**
 * The version the CLI prints (`--version`), sends as its user agent and reports to Gray (pairing's and the status
 * report's `agent_version`): the stamp of the published image, `0.0.0` in a build from a checkout.
 */
export const RELAY_KIT_VERSION: string = typeof __GRAY_ASSISTANT_VERSION__ === "string" ? __GRAY_ASSISTANT_VERSION__ : "0.0.0";

/** The lane-side paths (placeholder until the gateway wires the intake). */
export const LANE_ENDPOINTS = Object.freeze({
  /** `GET /v1/aci/attestation?nonce=<64 hex>`: the ACI report the lane serves (PAG's route). */
  attestation: "/v1/aci/attestation",
  /** `POST`: one signed policy bundle, JSON (see `POLICY_BUNDLE_API_VERSION`). */
  policyBundle: "/v1/aci/relay-policy/bundle",
  /** `POST`: one sealed credential message (full bundle or single-account update). */
  credentials: "/v1/aci/relay-credentials",
} as const);

/** The reference scheduler's paths, as `@gray/relay-connector`'s scheduler client calls them. */
export const SCHEDULER_ENDPOINTS = Object.freeze({
  pick: "/v1/pick",
  report: "/v1/report",
  lease: "/v1/lease",
  /** This package's own operator endpoint; not part of the TEE protocol. */
  adminReset: "/v1/admin/reset",
  /**
   * The doctor's proxy echo self-test: it answers the signed headers and the body hash it received,
   * so a relay can prove its TLS terminator forwards both byte for byte. No state, no secrets.
   */
  doctorEcho: "/v1/doctor/echo",
} as const);

/** The policy bundle document this CLI writes. */
export const POLICY_BUNDLE_API_VERSION = "gray.relay-kit/relay-policy-bundle/1";

/** The verified-attestation file this CLI writes and every sealing command requires. */
export const VERIFIED_REPORT_API_VERSION = "gray.relay-kit/verified-report/1";

/** The relay's Ed25519 key file. */
export const RELAY_KEY_API_VERSION = "gray.relay-kit/relay-key/1";

/** The reference scheduler's configuration file. */
export const SCHEDULER_CONFIG_API_VERSION = "gray.relay-kit/scheduler-config/1";

/** The name `keygen` gives the key file inside `--out`. */
export const RELAY_KEY_FILE_NAME = "relay-key.json";

/** The file `attest` writes when `--out` is not given. */
export const DEFAULT_VERIFIED_REPORT_FILE = "verified-report.json";

/**
 * The default age a verified report may have when a sealing command uses it. One hour is long
 * enough that a relay can attest once and seal the day's bundles, and short enough that a release
 * the operator revoked is not attested for long; the README tells operators to attest immediately
 * before sealing when the release list moves quickly. `--max-report-age` overrides it.
 */
export const DEFAULT_MAX_REPORT_AGE_SECONDS = 3600;

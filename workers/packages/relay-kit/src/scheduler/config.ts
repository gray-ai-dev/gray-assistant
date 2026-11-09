/**
 * The reference scheduler's configuration file, and nothing but its shape: paths are kept as the
 * strings the operator wrote (the Node loader resolves them relative to the file), and the parser
 * refuses an unknown member, an out-of-range weight and a duplicate account id before a socket is
 * opened.
 *
 * ```json
 * {"api_version":"gray.relay-kit/scheduler-config/1",
 *  "listen":{"host":"127.0.0.1","port":8443},
 *  "relay_id":"relay-1","relay_key":"relay-key.json",
 *  "attestation_report":"verified-report.json",
 *  "tls":{"cert_file":"cert.pem","key_file":"key.pem"},
 *  "accounts":[{"account_id":"acc-1","vendor":"anthropic","models":["claude-sonnet-4-5"],
 *               "weight":1,"max_concurrency":4}],
 *  "inflight_ttl_ms":600000,"replay_cap":100000,
 *  "affinity_ttl":3600,"affinity_cap":100000}
 * ```
 *
 * `admin_token` is optional: without it the reset route is not served at all. It is a secret, so no
 * error message in this module ever includes it.
 */
import { RESOURCE_ID, VENDORS, type Vendor } from "@gray/relay-connector";
import { z } from "zod";
import { SCHEDULER_CONFIG_API_VERSION } from "../endpoints.ts";
import { RelayKitError } from "../errors.ts";
import {
  DEFAULT_AFFINITY_TTL_MS,
  DEFAULT_INFLIGHT_TTL_MS,
  MAX_AFFINITY_CAP,
  MAX_AFFINITY_TTL_MS,
  MAX_INFLIGHT_TTL_MS,
  MIN_AFFINITY_TTL_MS,
  MIN_INFLIGHT_TTL_MS,
  type SchedulerAccount,
} from "./policy.ts";
import { DEFAULT_REPLAY_CAP, MAX_REPLAY_CAP, MIN_REPLAY_CAP } from "./replay.ts";

/** The model-id shape the scheduler wire accepts (`@gray/relay-connector`'s `modelSchema`). */
const MODEL = /^[\u0021-\u007e]{1,256}$/;
const MAX_ACCOUNTS = 10_000;

/** One account the operator declares: metadata only, matched by the sealed bundle's account map. */
export interface SchedulerAccountConfig extends SchedulerAccount {}

/** The listen address; port 0 asks the OS for an ephemeral one (tests). */
export interface SchedulerListenConfig {
  readonly host: string;
  readonly port: number;
}

/** The TLS certificate and key files the server presents to the TEE. */
export interface SchedulerTlsConfig {
  readonly certFile: string;
  readonly keyFile: string;
}

/** The whole configuration, as the pure parser returns it. */
export interface SchedulerConfig {
  readonly listen: SchedulerListenConfig;
  readonly relayId: string;
  readonly relayKeyPath: string;
  readonly attestationReportPath: string;
  readonly tls: SchedulerTlsConfig;
  readonly maxReportAgeSeconds: number;
  readonly leaseTtlSeconds: number;
  readonly maxSkewMs: number;
  readonly busyRetryMs: number;
  readonly rateLimitedMs: number;
  readonly overloadedMs: number;
  /** How long one pick's in-flight slot is held without a report (lease expiry). */
  readonly inflightTtlMs: number;
  /** The one shared nonce window's cap. */
  readonly replayCap: number;
  /** How long an idle affinity binding lasts; `affinity_ttl` in seconds. */
  readonly affinityTtlMs: number;
  /** The affinity map cap, or null for the derived `max(1, accounts x 4)`. */
  readonly affinityCap: number | null;
  readonly accounts: readonly SchedulerAccountConfig[];
  readonly adminToken: string | null;
}

const pathSchema = z.string().min(1).max(4096).refine((value) => !value.includes("\u0000"), "a path holds a NUL");
const secondsSchema = z.number().int().min(1).max(86_400);
const msSchema = z.number().int().min(1).max(86_400_000);

/**
 * The widest clock skew a signed scheduler request may carry: one hour. The nonce replay window is
 * sized at 2 × max_skew_ms, so a larger allowance only grows memory, not a gap a replay can slip
 * through — but beyond an hour the window stops being a clock correction and becomes a standing
 * replay risk, so the config refuses it.
 */
const MAX_SKEW_BOUND_MS = 3_600_000;
const skewMsSchema = z.number().int().min(1).max(MAX_SKEW_BOUND_MS);

/** The in-flight lease and the replay cap: validated config values, not handler constants. */
const inflightTtlMsSchema = z.number().int().min(MIN_INFLIGHT_TTL_MS).max(MAX_INFLIGHT_TTL_MS);
const replayCapSchema = z.number().int().min(MIN_REPLAY_CAP).max(MAX_REPLAY_CAP);
/** `affinity_ttl` is seconds; the E3 range is 1-720 minutes. */
const affinityTtlSchema = z.number().int().min(MIN_AFFINITY_TTL_MS / 1000).max(MAX_AFFINITY_TTL_MS / 1000);
const affinityCapSchema = z.number().int().min(1).max(MAX_AFFINITY_CAP);

const listenSchema = z
  .object({
    host: z.string().min(1).max(255).refine((value) => !/[\s/]/.test(value), "a host holds no whitespace or slash"),
    port: z.number().int().min(0).max(65_535),
  })
  .strict();

const tlsSchema = z.object({ cert_file: pathSchema, key_file: pathSchema }).strict();

const accountSchema = z
  .object({
    account_id: z.string().regex(RESOURCE_ID),
    vendor: z.enum(VENDORS),
    models: z.array(z.string().regex(MODEL)).min(1).max(256),
    weight: z.number().int().min(1).max(1_000_000).optional(),
    max_concurrency: z.number().int().min(1).max(10_000).optional(),
  })
  .strict();

const cooldownSchema = z
  .object({ rate_limited_seconds: secondsSchema.optional(), overloaded_seconds: secondsSchema.optional() })
  .strict();

const configSchema = z
  .object({
    api_version: z.literal(SCHEDULER_CONFIG_API_VERSION),
    listen: listenSchema,
    relay_id: z.string().regex(RESOURCE_ID),
    relay_key: pathSchema,
    attestation_report: pathSchema,
    tls: tlsSchema,
    accounts: z.array(accountSchema).min(1).max(MAX_ACCOUNTS),
    max_report_age_seconds: secondsSchema.optional(),
    lease_ttl_seconds: secondsSchema.optional(),
    max_skew_ms: skewMsSchema.optional(),
    busy_retry_ms: msSchema.optional(),
    inflight_ttl_ms: inflightTtlMsSchema.optional(),
    replay_cap: replayCapSchema.optional(),
    affinity_ttl: affinityTtlSchema.optional(),
    affinity_cap: affinityCapSchema.optional(),
    cooldowns: cooldownSchema.optional(),
    admin_token: z.string().regex(/^[\x21-\x7e]{16,512}$/).optional(),
  })
  .strict();

/** Parse the scheduler configuration. Refusals name a member path, never a value (the token included). */
export function parseSchedulerConfig(value: unknown): SchedulerConfig {
  const parsed = configSchema.safeParse(value);
  if (!parsed.success) {
    const issue = parsed.error.issues[0];
    const path = issue === undefined ? "" : issue.path.map(String).join(".");
    throw new RelayKitError("invalid_scheduler_config", path === "" ? "(root)" : path);
  }
  const ids = new Set<string>();
  const accounts: SchedulerAccountConfig[] = parsed.data.accounts.map((account, index) => {
    if (ids.has(account.account_id)) throw new RelayKitError("invalid_scheduler_config", `accounts.${index}.account_id`);
    ids.add(account.account_id);
    return {
      accountId: account.account_id,
      vendor: account.vendor as Vendor,
      models: [...account.models],
      weight: BigInt(account.weight ?? 1),
      maxConcurrency: BigInt(account.max_concurrency ?? 1),
    };
  });
  return {
    listen: { host: parsed.data.listen.host, port: parsed.data.listen.port },
    relayId: parsed.data.relay_id,
    relayKeyPath: parsed.data.relay_key,
    attestationReportPath: parsed.data.attestation_report,
    tls: { certFile: parsed.data.tls.cert_file, keyFile: parsed.data.tls.key_file },
    maxReportAgeSeconds: parsed.data.max_report_age_seconds ?? 3600,
    leaseTtlSeconds: parsed.data.lease_ttl_seconds ?? 60,
    maxSkewMs: parsed.data.max_skew_ms ?? 60_000,
    busyRetryMs: parsed.data.busy_retry_ms ?? 250,
    rateLimitedMs: (parsed.data.cooldowns?.rate_limited_seconds ?? 60) * 1000,
    overloadedMs: (parsed.data.cooldowns?.overloaded_seconds ?? 30) * 1000,
    inflightTtlMs: parsed.data.inflight_ttl_ms ?? DEFAULT_INFLIGHT_TTL_MS,
    replayCap: parsed.data.replay_cap ?? DEFAULT_REPLAY_CAP,
    affinityTtlMs: (parsed.data.affinity_ttl ?? DEFAULT_AFFINITY_TTL_MS / 1000) * 1000,
    affinityCap: parsed.data.affinity_cap ?? null,
    accounts,
    adminToken: parsed.data.admin_token ?? null,
  };
}

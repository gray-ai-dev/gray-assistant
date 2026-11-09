/**
 * The saved attestation verification every sealing command requires.
 *
 * `gray-assistant attest` fetches the lane's ACI report over TLS, records the SPKI it saw, runs
 * `@gray/lane-verify`'s full check (fresh nonce, DCAP quote, dstack event log, release list, TLS key)
 * and writes this file. A sealing command will not run without one, and re-checks everything it can
 * without the network or the quote:
 *
 * - the report text is the exact text that was verified (`report_sha256` over its UTF-8 bytes);
 * - the ACI chain still recomputes (keyset digest, §3.2 statement, `report_data`, the nonce);
 * - every check that must pass did pass, and `ok` is true; a `pinned` record must carry both a
 *   measured compose hash and an OS image, while an unpinned record is refused unless the caller
 *   explicitly accepts it (`--accept-unpinned`);
 * - the instance is the expected one (plan S12): its `app-id` event is the app id and its
 *   `key-provider` event names the KMS CA key the record was attested against (`lane-binding.ts`),
 *   recomputed from the event log; a record without that expectation is refused;
 * - the keyset has not expired, and the verification is no older than `--max-report-age`;
 * - for the CLI's sealing commands (S11b), the OS image is a production image by the
 *   `sha256sum.txt`/`metadata.json` `attest` checked it with (kept in the record), or one the
 *   operator accepted there with `--accept-os-image`; a record without them is refused.
 *
 * The one thing it cannot redo is the DCAP appraisal, which needs Intel collateral and the original
 * quote. That is why the file is a verification record, not just a report: the quote result is what
 * `attest` established, and the freshness window bounds how long a relay may rely on it (see
 * IMPLEMENTATION_NOTES §“report freshness”).
 */
import { bytesToLowerHex, parseAttestationReportText, reportDataSlot, verifyReportBinding, type ReportBinding } from "@gray/attest";
import { get, isObject, parseStrict, toJsonString, type Json, type JsonObject } from "@gray/json";
import { sha256Hex } from "@gray/lane";
import {
  DSTACK_V1_ATTESTATION_FORMAT,
  decodeDstackV1AttestationHex,
  measurementsFromEvidence,
  type DstackV1Attestation,
} from "@gray/lane-verify";
import { isLowerHex, utf8Bytes } from "@gray/relay-connector";
import { z } from "zod";
import { VERIFIED_REPORT_API_VERSION } from "./endpoints.ts";
import { RelayKitError } from "./errors.ts";
import { PEER_TUNNEL_PATH, tunnelOriginFromUrl } from "./lane-origin.ts";
import { osImageDecisionWithoutRegistry } from "./daemon/releases.ts";
import { APP_ID_PATTERN, KMS_CA_PUBKEY_PATTERN, isLaneBinding, laneBindingChecks, type LaneBinding } from "./lane-binding.ts";

const U64_MAX = 0xffff_ffff_ffff_ffffn;

/** The checks this package insists passed before it will seal. `attest` always makes them pass. */
export const REQUIRED_PASSING_CHECKS = Object.freeze([
  "aci_binding",
  "nonce",
  "quote",
  "tee_type_tdx",
  "quote_report_data",
  "event_log",
  "rtmr3",
  "compose_hash_allowlist",
  "tls_spki",
  "app_id",
  "key_provider",
] as const);

/** The clock allowance on `verified_at` (a report cannot come from the future by more than this). */
export const MAX_VERIFIED_CLOCK_SKEW_SECONDS = 60n;

/** One check line, as `@gray/lane-verify` reports it. */
export interface ReportCheck {
  readonly id: string;
  readonly status: "pass" | "fail" | "skip";
  readonly detail: string;
}

/** The verification summary saved next to the report text. */
export interface ReportVerification {
  readonly ok: boolean;
  readonly pinned: boolean;
  readonly keysetDigest: string;
  readonly reportData: string;
  readonly composeHash: string | null;
  readonly osImageHash: string | null;
  readonly tlsSpkiSha256: string | null;
  readonly teeType: string | null;
  readonly checks: readonly ReportCheck[];
}

/** A saved verification, exactly as this package writes it. */
export interface VerifiedReportFile {
  readonly origin: string;
  readonly nonce: string;
  readonly verifiedAt: bigint;
  readonly reportSha256: string;
  readonly reportText: string;
  /**
   * The release-list hashes `attest` verified against (empty arrays when `--allow-unpinned` was
   * used). Re-checked on every use: the derived measurements must still be members, so an edited
   * record cannot widen what the release pinned. `undefined` only for records written before this
   * field existed, which are treated as unpinned.
   */
  readonly expectedComposeHashes?: readonly string[];
  readonly expectedOsImageHashes?: readonly string[];
  /**
   * The instance `attest` required (plan S12): the dstack app id and the KMS CA public key. Re-checked
   * against the report's event log on every use. `undefined` only for records written before this
   * field existed; `checkVerifiedReport` refuses those.
   */
  readonly expectedInstance?: LaneBinding;
  /**
   * S11b: the OS image `attest` judged, with the release list's texts for it (null when the list had
   * none) and whether the operator accepted it with `--accept-os-image`. Sealing re-runs the judgment
   * from these, without the list. `undefined` for a record without it (the daemon's, or an older one).
   */
  readonly osImage?: RecordedOsImage;
  readonly verification: ReportVerification;
}

/** S11b: the OS image a record was checked with. */
export interface RecordedOsImage {
  readonly hash: string;
  readonly sha256sumTxt: string | null;
  readonly metadataJson: string | null;
  readonly acceptedByOperator: boolean;
}

/** A structurally valid saved verification, before any cryptographic check. */
export function verifiedReportValue(file: VerifiedReportFile): JsonObject {
  return {
    api_version: VERIFIED_REPORT_API_VERSION,
    origin: file.origin,
    nonce: file.nonce,
    verified_at: file.verifiedAt,
    report_sha256: file.reportSha256,
    report_text: file.reportText,
    expected_compose_hashes: [...(file.expectedComposeHashes ?? [])],
    expected_os_image_hashes: [...(file.expectedOsImageHashes ?? [])],
    ...(file.expectedInstance === undefined
      ? {}
      : { expected_app_id: file.expectedInstance.appId, expected_kms_ca_pubkey: file.expectedInstance.kmsCaPubkey }),
    ...(file.osImage === undefined
      ? {}
      : {
          os_image: {
            os_image_hash: file.osImage.hash,
            sha256sum_txt: file.osImage.sha256sumTxt,
            metadata_json: file.osImage.metadataJson,
            accepted_by_operator: file.osImage.acceptedByOperator,
          },
        }),
    verification: {
      ok: file.verification.ok,
      pinned: file.verification.pinned,
      keyset_digest: file.verification.keysetDigest,
      report_data: file.verification.reportData,
      compose_hash: file.verification.composeHash,
      os_image_hash: file.verification.osImageHash,
      tls_spki_sha256: file.verification.tlsSpkiSha256,
      tee_type: file.verification.teeType,
      checks: file.verification.checks.map((check) => ({ id: check.id, status: check.status, detail: check.detail })),
    },
  };
}

const checkSchema = z
  .object({ id: z.string().min(1), status: z.enum(["pass", "fail", "skip"]), detail: z.string() })
  .strict();

const verificationSchema = z
  .object({
    ok: z.boolean(),
    pinned: z.boolean(),
    keyset_digest: z.string().regex(/^sha256:[0-9a-f]{64}$/),
    report_data: z.string().regex(/^[0-9a-f]{64}$/),
    compose_hash: z.string().regex(/^[0-9a-f]{64}$/).nullable(),
    os_image_hash: z.string().regex(/^[0-9a-f]{64}$/).nullable(),
    tls_spki_sha256: z.string().regex(/^[0-9a-f]{64}$/).nullable(),
    tee_type: z.string().nullable(),
    checks: z.array(checkSchema),
  })
  .strict();

const hashListSchema = z.array(z.string().regex(/^[0-9a-f]{64}$/));

const verifiedReportSchema = z
  .object({
    api_version: z.literal(VERIFIED_REPORT_API_VERSION),
    origin: z.string().min(1),
    nonce: z.string().regex(/^[0-9a-f]{64}$/),
    verified_at: z.union([z.bigint().min(0n).max(U64_MAX), z.number().int().min(0).max(Number.MAX_SAFE_INTEGER)]),
    report_sha256: z.string().regex(/^[0-9a-f]{64}$/),
    report_text: z.string().min(1),
    expected_compose_hashes: hashListSchema.optional(),
    expected_os_image_hashes: hashListSchema.optional(),
    expected_app_id: z.string().regex(APP_ID_PATTERN).optional(),
    expected_kms_ca_pubkey: z.string().regex(KMS_CA_PUBKEY_PATTERN).optional(),
    os_image: z
      .object({
        os_image_hash: z.string().regex(/^[0-9a-f]{64}$/),
        // A few KB each in practice; bounded so a record cannot carry an arbitrary blob.
        sha256sum_txt: z.string().max(65_536).nullable(),
        metadata_json: z.string().max(65_536).nullable(),
        accepted_by_operator: z.boolean(),
      })
      .strict()
      .optional(),
    verification: verificationSchema,
  })
  .strict();

/** Parse a saved verification's JSON value; no secret is ever in it, so its errors are safe. */
export function parseVerifiedReportValue(value: unknown): VerifiedReportFile {
  const parsed = verifiedReportSchema.safeParse(value);
  if (!parsed.success) throw new RelayKitError("invalid_verified_report");
  const v = parsed.data.verification;
  const appId = parsed.data.expected_app_id;
  const kmsCaPubkey = parsed.data.expected_kms_ca_pubkey;
  if ((appId === undefined) !== (kmsCaPubkey === undefined)) throw new RelayKitError("invalid_verified_report");
  return {
    origin: parsed.data.origin,
    nonce: parsed.data.nonce,
    verifiedAt: typeof parsed.data.verified_at === "bigint" ? parsed.data.verified_at : BigInt(parsed.data.verified_at),
    reportSha256: parsed.data.report_sha256,
    reportText: parsed.data.report_text,
    expectedComposeHashes: parsed.data.expected_compose_hashes,
    expectedOsImageHashes: parsed.data.expected_os_image_hashes,
    ...(appId === undefined || kmsCaPubkey === undefined ? {} : { expectedInstance: { appId, kmsCaPubkey } }),
    ...(parsed.data.os_image === undefined
      ? {}
      : {
          osImage: {
            hash: parsed.data.os_image.os_image_hash,
            sha256sumTxt: parsed.data.os_image.sha256sum_txt,
            metadataJson: parsed.data.os_image.metadata_json,
            acceptedByOperator: parsed.data.os_image.accepted_by_operator,
          },
        }),
    verification: {
      ok: v.ok,
      pinned: v.pinned,
      keysetDigest: v.keyset_digest,
      reportData: v.report_data,
      composeHash: v.compose_hash,
      osImageHash: v.os_image_hash,
      tlsSpkiSha256: v.tls_spki_sha256,
      teeType: v.tee_type,
      checks: v.checks,
    },
  };
}

/** What `attest` knows after `verifyAttestation` returns (the structural part of its result). */
export interface AttestationSummary {
  readonly ok: boolean;
  readonly pinned: boolean;
  readonly keysetDigest: string | null;
  readonly reportData: string | null;
  readonly composeHash: string | null;
  readonly osImageHash: string | null;
  readonly tlsSpkiSha256: string | null;
  readonly teeType: string | null;
  readonly checks: readonly ReportCheck[];
}

/** What `attest` writes once the lane verified. */
export interface BuildVerifiedReportInput {
  readonly origin: string;
  readonly nonce: string;
  /** Unix seconds of the verification (the CLI's `--now`). */
  readonly verifiedAt: bigint;
  readonly reportText: string;
  readonly verification: AttestationSummary;
  /** The release-list compose hashes the verification ran against (empty for `--allow-unpinned`). */
  readonly expectedComposeHashes?: readonly string[];
  /** The release-list OS image hashes the verification ran against. */
  readonly expectedOsImageHashes?: readonly string[];
  /** The instance the lane origin must be; its `app_id` and `key_provider` checks must be in `verification`. */
  readonly expectedInstance: LaneBinding;
  /**
   * The operator's explicit acceptance of a report the release list did not fully pin
   * (`--accept-unpinned`, or `--accept-os-unpinned` for a compose-only list). Without it this
   * function refuses to turn an unpinned verification into a record a sealing command would trust.
   */
  readonly acceptedUnpinned?: boolean;
  /** S11b: the OS image the caller judged (`attest`), kept so sealing can judge it again. */
  readonly osImage?: RecordedOsImage;
}

/**
 * Build the saved record from the verification result, refusing an unpinned or failed run and a
 * report text that does not bind to the nonce. The record is what every later command re-checks.
 */
export function buildVerifiedReport(input: BuildVerifiedReportInput): VerifiedReportFile {
  normalizeHttpsOrigin(input.origin);
  if (!/^[0-9a-f]{64}$/.test(input.nonce)) throw new RelayKitError("invalid_verified_report", "nonce");
  if (input.verifiedAt < 0n || input.verifiedAt > U64_MAX) throw new RelayKitError("invalid_verified_report", "verified_at");
  const v = input.verification;
  if (v.ok !== true) throw new RelayKitError("report_unverified", "the verification failed");
  if (v.teeType !== "tdx") throw new RelayKitError("report_unverified", "the report and quote are not TDX");
  if (v.tlsSpkiSha256 === null) throw new RelayKitError("report_unverified", "no TLS SPKI was observed");
  if (v.pinned === true) {
    if (v.composeHash === null) throw new RelayKitError("report_unverified", "no measured compose hash was pinned");
    if (v.osImageHash === null) throw new RelayKitError("report_unverified", "no OS image was pinned");
  } else if (input.acceptedUnpinned !== true) {
    throw new RelayKitError(
      "report_unpinned",
      "the release list did not pin the compose hash and OS image; pass --accept-unpinned to accept it",
    );
  }
  if (!isLaneBinding(input.expectedInstance)) throw new RelayKitError("invalid_verified_report", "the expected app id or KMS CA public key");
  if (v.keysetDigest === null || v.reportData === null) throw new RelayKitError("invalid_verified_report", "the keyset digest or report data is missing");
  if (!/^sha256:[0-9a-f]{64}$/.test(v.keysetDigest) || !isLowerHex(v.reportData, 32)) throw new RelayKitError("invalid_verified_report");
  if (v.tlsSpkiSha256 !== null && !isLowerHex(v.tlsSpkiSha256, 32)) throw new RelayKitError("invalid_verified_report", "tls_spki_sha256");
  if (v.composeHash !== null && !isLowerHex(v.composeHash, 32)) throw new RelayKitError("invalid_verified_report", "compose_hash");
  if (v.osImageHash !== null && !isLowerHex(v.osImageHash, 32)) throw new RelayKitError("invalid_verified_report", "os_image_hash");
  const reportSha256 = sha256Hex(utf8Bytes(input.reportText));
  const checked = checkReportText(input.reportText, input.nonce, v.keysetDigest, v.reportData);
  if (!checked.ok) throw new RelayKitError("invalid_verified_report", checked.detail);
  return {
    origin: normalizeHttpsOrigin(input.origin),
    nonce: input.nonce,
    verifiedAt: input.verifiedAt,
    reportSha256,
    reportText: input.reportText,
    expectedComposeHashes: input.expectedComposeHashes ?? [],
    expectedOsImageHashes: input.expectedOsImageHashes ?? [],
    expectedInstance: { appId: input.expectedInstance.appId, kmsCaPubkey: input.expectedInstance.kmsCaPubkey },
    ...(input.osImage === undefined ? {} : { osImage: { ...input.osImage } }),
    verification: {
      ok: true,
      pinned: v.pinned === true,
      keysetDigest: v.keysetDigest,
      reportData: v.reportData,
      composeHash: v.composeHash,
      osImageHash: v.osImageHash,
      tlsSpkiSha256: v.tlsSpkiSha256,
      teeType: v.teeType,
      checks: v.checks.map((check) => ({ id: check.id, status: check.status, detail: check.detail })),
    },
  };
}

/** What a verified report check returns when it passes: the report and the binding it recomputed. */
export interface CheckedVerifiedReport {
  readonly file: VerifiedReportFile;
  /** The report as `@gray/attest` parsed it (bigint integers), which is what sealing takes. */
  readonly report: Json;
  readonly binding: ReportBinding;
}

export interface CheckVerifiedReportOptions {
  /** The verifier's clock in Unix seconds. */
  readonly nowSecs: bigint;
  /** The greatest age the caller accepts; the CLI's `--max-report-age`, default one hour. */
  readonly maxAgeSeconds: bigint;
  /** When given, the report must be from exactly this lane origin. */
  readonly origin?: string;
  /**
   * Accept a record whose release list did not pin both measurements. Defaults to false: a sealing
   * command or the scheduler refuses to trust an unpinned record unless the operator says so.
   */
  readonly acceptUnpinned?: boolean;
  /**
   * When given, the instance the record was attested against must be exactly this one (the daemon
   * passes its config's entry for the origin, so an edited record cannot change what it expects).
   */
  readonly expectedInstance?: LaneBinding;
  /**
   * S11b for the CLI's sealing commands, which have no release registry: the record's OS image must be
   * production by the texts it carries, or accepted by the operator at `attest`; a verified dev image
   * is refused either way, and a record that carries no OS image judgment is refused. The daemon
   * leaves it unset: its registry decides before it seals.
   */
  readonly requireProductionOsImage?: boolean;
}

/**
 * Re-check a saved verification: freshness, the exact report text, the ACI binding, the checks that
 * must have passed, and the keyset's expiry. Throws a `RelayKitError` on any refusal. On success it
 * returns the parsed report value, which sealing must use (its integers are `bigint`).
 */
export function checkVerifiedReport(file: VerifiedReportFile, options: CheckVerifiedReportOptions): CheckedVerifiedReport {
  normalizeHttpsOrigin(file.origin);
  if (options.origin !== undefined) {
    const wanted = normalizeHttpsOrigin(options.origin);
    if (wanted !== file.origin) throw new RelayKitError("report_origin_mismatch", `${wanted} is not ${file.origin}`);
  }
  if (options.maxAgeSeconds <= 0n) throw new RelayKitError("usage", "--max-report-age must be positive");
  if (options.nowSecs + MAX_VERIFIED_CLOCK_SKEW_SECONDS < file.verifiedAt) {
    throw new RelayKitError("report_stale", "the verification is from the future");
  }
  if (options.nowSecs >= file.verifiedAt) {
    const age = options.nowSecs - file.verifiedAt;
    if (age > options.maxAgeSeconds) {
      throw new RelayKitError("report_stale", `the verification is ${age} seconds old, over the ${options.maxAgeSeconds} allowed`);
    }
  }
  if (file.verification.ok !== true) throw new RelayKitError("report_unverified");
  if (file.verification.teeType !== "tdx") throw new RelayKitError("report_unverified", "the report and quote are not TDX");
  if (file.verification.tlsSpkiSha256 === null) throw new RelayKitError("report_unverified", "no TLS SPKI was observed");
  if (file.verification.pinned !== true && options.acceptUnpinned !== true) {
    throw new RelayKitError(
      "report_unpinned",
      "the release list did not pin the compose hash and OS image; pass --accept-unpinned to accept it",
    );
  }
  if (file.verification.pinned === true) {
    if (file.verification.composeHash === null) throw new RelayKitError("report_unverified", "no measured compose hash was pinned");
    if (file.verification.osImageHash === null) throw new RelayKitError("report_unverified", "no OS image was pinned");
  }
  if (file.expectedInstance === undefined) {
    throw new RelayKitError("report_unverified", "the record names no expected app id and KMS CA public key; run attest again");
  }
  if (
    options.expectedInstance !== undefined &&
    (options.expectedInstance.appId !== file.expectedInstance.appId || options.expectedInstance.kmsCaPubkey !== file.expectedInstance.kmsCaPubkey)
  ) {
    throw new RelayKitError("report_unverified", "the record was attested against another app id or KMS CA public key than this lane origin's");
  }
  if (sha256Hex(utf8Bytes(file.reportText)) !== file.reportSha256) {
    throw new RelayKitError("report_tampered", "the report text does not hash to report_sha256");
  }
  const checked = checkReportText(file.reportText, file.nonce, file.verification.keysetDigest, file.verification.reportData);
  if (!checked.ok) throw new RelayKitError("report_tampered", checked.detail);
  for (const required of REQUIRED_PASSING_CHECKS) {
    const check = file.verification.checks.find((entry) => entry.id === required);
    if (check === undefined) throw new RelayKitError("report_unverified", `the verification has no ${required} check`);
    if (check.status === "pass") continue;
    // An explicitly accepted unpinned record may only skip the pinning check itself; every
    // cryptographic check above still has to pass.
    if (options.acceptUnpinned === true && file.verification.pinned !== true && required === "compose_hash_allowlist" && check.status === "skip") continue;
    throw new RelayKitError("report_unverified", `${required} did not pass`);
  }
  if (file.verification.checks.some((check) => check.status === "fail")) {
    throw new RelayKitError("report_unverified", "the verification has a failed check");
  }
  // Never trust the record's derived fields: recompute the checkable verdict from `report_text`
  // plus the recorded release list, and require the saved fields to be a faithful cache of it.
  const derived = rederiveVerification(checked.report, file);
  if (file.verification.composeHash !== derived.composeHash) {
    throw new RelayKitError("report_tampered", "the record's compose_hash does not match the report's event log");
  }
  if (file.verification.osImageHash !== derived.osImageHash) {
    throw new RelayKitError("report_tampered", "the record's os_image_hash does not match the report's event log");
  }
  if (file.verification.pinned !== derived.pinned) {
    throw new RelayKitError("report_tampered", "the record's pinned claim does not match the report and release list");
  }
  requireChecks(derived.checks, "the recomputed verification");
  // The saved `checks` are a cache: every deterministic check the file claims must match the
  // re-derived status (an extra "pass" or an edited outcome is a tamper). Checks that need the
  // quote or the network (DCAP, TCB, keyset expiry) are not recomputable and are covered by the
  // required-pass/no-fail rules above.
  const derivedById = new Map(derived.checks.map((check) => [check.id, check.status]));
  if (file.verification.checks.some((check) => derivedById.has(check.id) && derivedById.get(check.id) !== check.status)) {
    throw new RelayKitError("report_tampered", "the record's checks do not match the verification recomputed from report_text");
  }
  if (checked.binding.keyset.not_after <= options.nowSecs) {
    throw new RelayKitError("report_stale", "the keyset has expired");
  }
  if (options.requireProductionOsImage === true) checkRecordedOsImage(file);
  return { file, report: checked.report, binding: checked.binding };
}

/**
 * S11b on a saved record (`requireProductionOsImage`). A record whose verification bound no OS image
 * was accepted OS-unpinned by its operator, so there is nothing to judge. Otherwise the record must
 * carry the image `attest` judged, be about the image the report binds, and pass the same rule again.
 */
function checkRecordedOsImage(file: VerifiedReportFile): void {
  const bound = file.verification.osImageHash;
  if (bound === null) return;
  const recorded = file.osImage;
  if (recorded === undefined) {
    throw new RelayKitError("report_unverified", "the record does not carry its OS image's sha256sum.txt and metadata.json (S11b); run attest again");
  }
  if (recorded.hash !== bound) throw new RelayKitError("report_tampered", "the record's OS image is not the one its report binds");
  const decision = osImageDecisionWithoutRegistry(
    { os_image_hash: recorded.hash, sha256sum_txt: recorded.sha256sumTxt, metadata_json: recorded.metadataJson },
    recorded.acceptedByOperator ? [recorded.hash] : [],
  );
  if (!decision.ok) {
    throw new RelayKitError(
      "report_unverified",
      decision.code === "os_image_dev"
        ? `os_image_dev: OS image ${bound} is a dstack dev image by its own metadata.json`
        : `os_image_unverified: OS image ${bound} is not proven a production image and was not accepted with --accept-os-image; run attest again`,
    );
  }
}

/** Require every check to pass (or be an allowed skip), with no fails. */
function requireChecks(checks: readonly ReportCheck[], what: string): void {
  const failed = checks.find((check) => check.status === "fail");
  if (failed !== undefined) {
    // The details are measurements and expectations from the record, never a secret.
    throw new RelayKitError("report_unverified", `${what} has a failed check: ${failed.id}: ${failed.detail}`);
  }
}

interface DerivedVerification {
  readonly pinned: boolean;
  readonly composeHash: string | null;
  readonly osImageHash: string | null;
  /** The deterministic `verifyAttestation` transcript, re-derived from `report_text`. */
  readonly checks: readonly ReportCheck[];
}

/**
 * Recompute everything `checkVerifiedReport` can verify without the DCAP quote: the evidence
 * resolution (dstack v1 decode included), the event-log replay and its compose/OS image
 * measurements, and the allowlist/`app_compose`/`vm_config` consistency checks `verifyAttestation`
 * runs deterministically, and the `app_id`/`key_provider` checks against the record's expected
 * instance. `pinned` follows from the derived checks: a release list that did not pin
 * both measurements cannot produce a pinned record, and an edited allowlist that stops matching is
 * a fail.
 */
function rederiveVerification(report: Json, file: VerifiedReportFile): DerivedVerification {
  const expectedCompose = file.expectedComposeHashes ?? [];
  const expectedOsImage = file.expectedOsImageHashes ?? [];
  const checks: ReportCheck[] = [];
  const result = (partial: Partial<DerivedVerification> = {}): DerivedVerification => ({
    pinned: false,
    composeHash: null,
    osImageHash: null,
    checks,
    ...partial,
  });

  const attestation = isObject(report) && isObject(report.attestation) ? report.attestation : null;
  const evidence = attestation !== null && isObject(attestation.evidence) ? attestation.evidence : null;
  if (attestation === null || evidence === null) return result();
  const effective = resolveRecordEvidence(report, evidence, checks);
  if (effective === null) return result();

  const measured = measurementsFromEvidence(effective);
  if (!measured.ok) {
    for (const problem of measured.problems) checks.push({ id: "event_log", status: "fail", detail: `${problem.code}: ${problem.message}` });
    return result();
  }
  const dstack = measured.measurements;
  checks.push({ id: "event_log", status: "pass", detail: `${dstack.events.length} events parsed` });
  checks.push({ id: "rtmr3", status: "pass", detail: bytesToLowerHex(dstack.rtmr3) });

  checkRecordAppCompose(effective, dstack.composeHash, checks);
  checkRecordAllowlist("compose_hash_allowlist", dstack.composeHash, expectedCompose, "the release list", checks);

  // The OS image the record claims: the quote-bound source (an `os-image-hash` event) wins; the
  // `vm_config` claim only counts when the release list binds it to the quote's measurements —
  // that binding needs the quote itself, so it is cross-checked against the recorded checks below.
  let bound = dstack.osImageHash;
  if (bound !== null) checks.push({ id: "os_image_bound", status: "pass", detail: `${bound} is bound by the RTMR3 event log` });
  const claimed = recordVmConfigOsImageHash(effective);
  if (claimed !== null && bound !== null && claimed !== bound) {
    checks.push({ id: "os_image_hash", status: "fail", detail: `vm_config carries ${claimed}, the quote-bound value is ${bound}` });
  }
  if (bound === null && claimed !== null) {
    if (expectedOsImage.includes(claimed)) {
      const boundByMeasurements = file.verification.checks.some(
        (check) => check.id === "os_image_measurements" && check.status === "pass" && check.detail.includes(claimed),
      );
      const boundByVerifier = file.verification.checks.some(
        (check) => check.id === "os_image_bound" && check.status === "pass" && check.detail.includes(claimed),
      );
      if (boundByMeasurements || boundByVerifier) {
        bound = claimed;
        checks.push({
          id: "os_image_bound",
          status: "pass",
          detail: `${claimed} is bound by ${boundByVerifier ? "the quote verifier" : "the quote's MRTD/RTMR0-2 via osImageMeasurements"}`,
        });
      } else {
        checks.push({ id: "os_image_hash", status: "fail", detail: `vm_config carries os_image_hash ${claimed}, but no check binds it to the quote` });
      }
    } else {
      checks.push({ id: "os_image_hash", status: "fail", detail: `vm_config carries ${claimed}, which the release list does not pin` });
    }
  }
  if (expectedOsImage.length === 0) {
    checks.push({ id: "os_image_hash_allowlist", status: "skip", detail: "no OS image allowlist supplied; the OS image is not pinned" });
  } else if (bound !== null) {
    checkRecordAllowlist("os_image_hash_allowlist", bound, expectedOsImage, "the OS image allowlist", checks);
  } else {
    checks.push({ id: "os_image_hash", status: "fail", detail: "OS image pinning was requested, but the evidence carries no OS image hash bound to the quote" });
  }

  const failed = checks.some((check) => check.status === "fail");
  const pinned =
    !failed &&
    expectedCompose.length > 0 &&
    expectedOsImage.length > 0 &&
    checks.some((check) => check.id === "compose_hash_allowlist" && check.status === "pass") &&
    checks.some((check) => check.id === "os_image_hash_allowlist" && check.status === "pass");
  // The instance checks come after `pinned`, which is about the release list only; a failure here
  // fails the recomputed verification instead.
  if (file.expectedInstance !== undefined) {
    for (const check of laneBindingChecks(dstack, file.expectedInstance)) checks.push(check);
  }
  return result({ pinned, composeHash: dstack.composeHash, osImageHash: pinned ? bound : null });
}

/**
 * The evidence the policy reads, mirroring `verifyAttestation`'s `resolveEvidence`: for the dstack
 * v1 format the event log, `vm_config` and `report_data` echo are decoded out of the MessagePack
 * attestation in `evidence.quote` so the log the file displays cannot differ from the log the quote
 * bound. The echo check uses the ACI `report_data` slot the binding already recomputed.
 */
function resolveRecordEvidence(report: Json, evidence: JsonObject, checks: ReportCheck[]): JsonObject | null {
  const format = get(evidence, "attestation_format");
  if (format === undefined) return evidence;
  if (format !== DSTACK_V1_ATTESTATION_FORMAT) {
    checks.push({ id: "attestation_format", status: "fail", detail: `evidence.attestation_format is not ${JSON.stringify(DSTACK_V1_ATTESTATION_FORMAT)}` });
    return null;
  }
  const text = get(evidence, "quote");
  const decoded = typeof text === "string" ? decodeDstackV1AttestationHex(text) : null;
  if (decoded === null || !decoded.ok) {
    checks.push({ id: "attestation_v1", status: "fail", detail: "evidence.quote is not a decodable dstack v1 attestation" });
    return null;
  }
  const attestation: DstackV1Attestation = decoded.attestation;
  const reportData = bytesToLowerHex(attestation.report_data);
  const slot = reportDataSlotOf(fileReportData(report));
  if (slot === null || reportData !== bytesToLowerHex(slot)) {
    checks.push({ id: "attestation_v1_report_data", status: "fail", detail: `the attestation echoes ${reportData}, not this report's report_data slot` });
    return null;
  }
  checks.push({ id: "attestation_v1_report_data", status: "pass", detail: reportData });
  return {
    ...evidence,
    quote: bytesToLowerHex(attestation.quote),
    event_log: toJsonString(
      attestation.event_log.map((event) => ({
        imr: BigInt(event.imr),
        event_type: BigInt(event.event_type),
        digest: event.digest,
        event: event.event,
        event_payload: event.event_payload,
      })) as unknown as Json,
    ),
    ...(attestation.config === null ? {} : { vm_config: attestation.config }),
  };
}

/** The report's ACI `report_data` field as bytes, for the v1 echo comparison. */
function fileReportData(report: Json): string | null {
  // ACI §4.1 puts the 32-byte statement digest at `attestation.report_data`. Reports served by the
  // lane have no top-level member of that name, so reading one there would silently find nothing.
  const attestation = get(report, "attestation");
  const value = get(attestation, "report_data");
  return typeof value === "string" ? value : null;
}

function reportDataSlotOf(hex: string | null): Uint8Array | null {
  if (hex === null) return null;
  const bytes = hexToBytes(hex);
  if (bytes === null) return null;
  return reportDataSlot(bytes);
}

function hexToBytes(text: string): Uint8Array | null {
  const clean = text.startsWith("0x") || text.startsWith("0X") ? text.slice(2) : text;
  if (clean.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(clean)) return null;
  const out = new Uint8Array(clean.length / 2);
  for (let index = 0; index < out.length; index += 1) out[index] = Number.parseInt(clean.slice(index * 2, index * 2 + 2), 16);
  return out;
}

function checkRecordAppCompose(evidence: JsonObject, composeHash: string, checks: ReportCheck[]): void {
  const appCompose = get(evidence, "app_compose");
  if (typeof appCompose !== "string") return;
  const actual = sha256Hex(utf8Bytes(appCompose));
  checks.push(
    actual === composeHash
      ? { id: "app_compose", status: "pass", detail: `SHA-256(app_compose) = ${actual}` }
      : { id: "app_compose", status: "fail", detail: `SHA-256(app_compose) = ${actual}, measured compose-hash = ${composeHash}` },
  );
}

function checkRecordAllowlist(id: string, actual: string, expected: readonly string[], label: string, checks: ReportCheck[]): void {
  if (expected.length === 0) {
    checks.push({ id, status: "skip", detail: `no ${label} supplied; not pinned` });
    return;
  }
  checks.push(
    expected.includes(actual)
      ? { id, status: "pass", detail: `${actual} is in ${label}` }
      : { id, status: "fail", detail: `${actual} is not in ${label}` },
  );
}

function recordVmConfigOsImageHash(evidence: JsonObject): string | null {
  const vmConfig = get(evidence, "vm_config");
  let value: Json | undefined = vmConfig;
  if (typeof vmConfig === "string") {
    try {
      value = parseStrict(vmConfig) as Json;
    } catch {
      return null;
    }
  }
  if (!isObject(value)) return null;
  for (const member of ["os_image_hash", "osImageHash"]) {
    const candidate = get(value, member);
    if (typeof candidate === "string" && isLowerHex(candidate.toLowerCase(), 32)) return candidate.toLowerCase();
  }
  return null;
}

/** The ACI half of the check, shared by build and load. */
function checkReportText(
  text: string,
  nonce: string,
  keysetDigest: string,
  reportData: string,
): { readonly ok: true; readonly report: Json; readonly binding: ReportBinding } | { readonly ok: false; readonly detail: string } {
  const parsed = parseAttestationReportText(text);
  if (!parsed.ok) return { ok: false, detail: "the report text is not an ACI report" };
  const binding = verifyReportBinding(parsed.value, nonce);
  if (!binding.ok || binding.binding === null) return { ok: false, detail: "the ACI binding does not hold" };
  if (binding.binding.keyset_digest !== keysetDigest) return { ok: false, detail: "the keyset digest differs from the verified one" };
  if (bytesToLowerHex(binding.binding.report_data) !== reportData) return { ok: false, detail: "the report data differs from the verified one" };
  return { ok: true, report: parsed.value, binding: binding.binding };
}

/**
 * A lane origin: `https://host[:port]`, no credentials, path, query or fragment; or a tunnel origin
 * `https://<entry>/v1/peer/tunnel/<relay>` (`lane-origin.ts`), whose only path is the entry's tunnel route.
 */
export function normalizeHttpsOrigin(text: string): string {
  let url: URL;
  try {
    url = new URL(text);
  } catch {
    throw new RelayKitError("usage", `not a URL: ${text}`);
  }
  if (url.protocol !== "https:") throw new RelayKitError("usage", "the lane origin must be https");
  if (url.username !== "" || url.password !== "") throw new RelayKitError("usage", "the lane origin must not carry credentials");
  if (url.search !== "" || url.hash !== "") throw new RelayKitError("usage", "the lane origin must not carry a query or fragment");
  let tunnel;
  try {
    tunnel = tunnelOriginFromUrl(url);
  } catch (error) {
    throw new RelayKitError("usage", `the lane origin's tunnel path is invalid: ${error instanceof Error ? error.message : "not a relay id"}`);
  }
  if (tunnel !== null) return tunnel.origin;
  if (url.pathname !== "/" && url.pathname !== "") throw new RelayKitError("usage", `the lane origin must not carry a path other than ${PEER_TUNNEL_PATH}<relay>`);
  return url.origin;
}

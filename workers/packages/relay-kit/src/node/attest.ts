/**
 * `gray-assistant attest`'s two external pieces: fetching the lane's ACI report over TLS and choosing the
 * quote verifier. The verification itself is `@gray/lane-verify`'s `verifyAttestation`, unchanged,
 * plus the relay's own `app_id` and `key_provider` checks on the instance it reports (plan S12).
 */
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { parseAttestationReportText } from "@gray/attest";
import {
  readReleaseListText,
  verifyAttestation,
  type AttestationVerification,
  type QuoteVerifier,
  type ReleaseList,
} from "@gray/lane-verify";
import { DEFAULT_MAX_REPORT_AGE_SECONDS, LANE_ENDPOINTS, RELAY_KIT_VERSION } from "../endpoints.ts";
import { RelayKitError } from "../errors.ts";
import { osImageDecisionWithoutRegistry } from "../daemon/releases.ts";
import { isLaneBinding, laneBindingChecks, type LaneBinding } from "../lane-binding.ts";
import { tunnelOriginOf } from "../lane-origin.ts";
import { buildVerifiedReport, checkVerifiedReport, type RecordedOsImage, type ReportCheck, type VerifiedReportFile } from "../verified-report.ts";
import { readFileText } from "./files.ts";
import { httpsRequestOnce } from "./https.ts";

/** The largest report this tool will read; a dstack report with its event log fits well below. */
export const MAX_REPORT_BYTES = 8 * 1024 * 1024;

/** A fetched report: its exact text and the TLS SPKI the client observed. */
export interface FetchedAttestation {
  readonly text: string;
  readonly spkiSha256: string;
}

/** Fetch `GET /v1/aci/attestation?nonce=…` from a normalized `https://host[:port]` or tunnel origin. */
export async function fetchAttestationReport(origin: string, nonce: string, ca: string | undefined, keyset?: string): Promise<FetchedAttestation> {
  // `${origin}${path}`, as the daemon builds its URLs: a tunnel origin keeps its route path.
  const url = new URL(`${origin}${LANE_ENDPOINTS.attestation}`);
  url.searchParams.set("nonce", nonce);
  const response = await httpsRequestOnce({
    url: url.toString(),
    method: "GET",
    headers: { accept: "application/json", "user-agent": `gray-assistant/${RELAY_KIT_VERSION}` },
    ...(ca === undefined ? {} : { ca }),
    // Through Gray's entry, the boot the caller names (docs/design/relay-zero-downtime.md); none: the entry's newest.
    ...(keyset === undefined ? {} : { tunnelKeyset: keyset }),
    timeoutMs: 20_000,
    maxResponseBytes: MAX_REPORT_BYTES,
  });
  if (response.status !== 200) throw new RelayKitError("attestation_failed", `${origin} answered ${response.status}`);
  if (response.spkiSha256 === null) throw new RelayKitError("attestation_failed", "the lane presented no TLS certificate");
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(response.body);
  } catch {
    throw new RelayKitError("attestation_failed", "the report is not UTF-8");
  }
  return { text, spkiSha256: response.spkiSha256 };
}

/**
 * Read the signed release list a customer pins, through `@gray/lane-verify`'s one reader: the
 * envelope's signature and `issued_at` freshness are checked against the pinned public key and the
 * caller's clock. The relay CLI never reads an unsigned list (K5-2). With `freshness` (D138) a list past
 * its own day stays current while its freshness document counts, as in the agent.
 */
export async function loadReleaseList(
  path: string,
  publicKey: Uint8Array,
  nowSecs: bigint,
  freshness: { readonly path: string; readonly publicKey: Uint8Array } | null = null,
): Promise<ReleaseList> {
  const text = readFileText(path, "release list", 4 * 1024 * 1024);
  const document = freshness === null ? null : readFileText(freshness.path, "freshness document", 64 * 1024);
  const read = await readReleaseListText(text, {
    publicKey,
    now: nowSecs,
    requireSignature: true,
    ...(freshness === null ? {} : { freshness: { publicKey: freshness.publicKey, text: document } }),
  });
  if (!read.ok) {
    const staleness = read.staleness === undefined ? "" : ` (${read.staleness})`;
    throw new RelayKitError("usage", `invalid release list ${path}: ${read.code}${staleness}: ${read.message}`);
  }
  return read.list;
}

/**
 * The quote verifier: the real `@phala/dcap-qvl` adapter by default (with a collateral cache,
 * `collateral-cache.ts`), or a test module named by
 * `--verifier-module` (the same seam `gray-lane-verify` offers). A module without a `quoteVerifier`
 * function is a usage error, never a silent fallback to "verified".
 */
export async function loadQuoteVerifier(options: { verifierModule?: string; pccs?: string }): Promise<QuoteVerifier> {
  if (options.verifierModule === undefined) {
    const { dcapQuoteVerifier } = await import("@gray/lane-verify/dcap");
    const { createCollateralCache } = await import("./collateral-cache.ts");
    // One collateral cache per verifier: the agent loads one and shares it between credential intake
    // and the pull-token service, so both draw on the same PCS/PCCS answers.
    const collateral = createCollateralCache();
    return dcapQuoteVerifier({ ...(options.pccs === undefined ? {} : { pccsUrl: options.pccs }), fetchCollateral: collateral.fetch });
  }
  let imported: { readonly quoteVerifier?: unknown };
  try {
    imported = (await import(pathToFileURL(resolve(options.verifierModule)).href)) as { readonly quoteVerifier?: unknown };
  } catch {
    throw new RelayKitError("usage", `cannot load the quote verifier module ${options.verifierModule}`);
  }
  if (typeof imported.quoteVerifier !== "function") {
    throw new RelayKitError("usage", `${options.verifierModule} does not export a quoteVerifier function`);
  }
  return imported.quoteVerifier as QuoteVerifier;
}

/** What the library `attestLane` needs; the CLI fills this from its flags. */
export interface AttestLaneOptions {
  /** A normalized `https://host[:port]` or tunnel origin, as `normalizeHttpsOrigin` returns it. */
  readonly origin: string;
  /** The release list to pin against; null means the caller explicitly passed no list. */
  readonly release: ReleaseList | null;
  readonly allowUnpinned: boolean;
  readonly acceptUnpinned: boolean;
  readonly acceptOsUnpinned: boolean;
  /** 32 bytes as 64 lower-case hex; fresh per call in production. */
  readonly nonce: string;
  /** The verifier's clock in Unix seconds, and the record's `verified_at`. */
  readonly nowSecs: bigint;
  /** How old a record may be when it is used to seal; also the immediate self-check's bound. */
  readonly maxReportAgeSeconds?: number;
  /** A private CA for the lane's certificate. */
  readonly ca?: string;
  /** The DCAP adapter, or a test module's function. */
  readonly quoteVerifier: QuoteVerifier;
  /** The dstack app id and KMS CA public key this origin must report; there is no unchecked mode. */
  /** Through Gray's entry, the boot to attest (its keyset digest, 64 hex); absent: the entry's newest boot. */
  readonly keyset?: string;
  readonly expectedInstance: LaneBinding;
  /**
   * P2d/P4b: accept a phase-2 boot in the empty slot (`@gray/lane-verify` `allowEmptySlot`). Only the relay's own
   * delivery (`deliver`) sets it: an empty slot serves nothing, so nothing else may be sent to it.
   */
  readonly allowEmptySlot?: boolean;
  /**
   * S11b for a caller with no release registry (`gray-assistant attest`): the boot's OS image must be
   * production by its own texts in the release list, or one of `acceptedOsImages`; a verified dev
   * image is refused either way. The daemon leaves it out: its registry decides (first sight, delay,
   * accept, veto) before it seals.
   */
  readonly osImageAcceptance?: { readonly acceptedOsImages: readonly string[] };
}

/** The pinning policy both the CLI and `@gray/lane-verify`'s CLI apply, in one place. */
export function attestationVerdict(
  verification: { readonly composePinned: boolean; readonly osPinned: boolean },
  pins: { readonly allowPath: string | null; readonly allowUnpinned: boolean; readonly acceptUnpinned: boolean; readonly acceptOsUnpinned: boolean },
): { readonly accepted: boolean; readonly verdict: string } {
  if (pins.allowPath === null) {
    if (!pins.allowUnpinned) return { accepted: false, verdict: "FAIL (UNPINNED)" };
    if (!pins.acceptUnpinned) return { accepted: false, verdict: "UNPINNED" };
    return { accepted: true, verdict: "PASS (UNPINNED)" };
  }
  if (!verification.composePinned) return { accepted: false, verdict: "FAIL (UNPINNED)" };
  if (!verification.osPinned) return { accepted: pins.acceptOsUnpinned, verdict: "PASS (OS UNPINNED)" };
  return { accepted: true, verdict: "PASS" };
}

/** A verified report, ready to write or to seal with. */
export interface VerifiedLane {
  readonly origin: string;
  readonly nonce: string;
  readonly reportText: string;
  readonly spkiSha256: string;
  readonly verification: AttestationVerification;
  readonly verdict: string;
  readonly file: VerifiedReportFile;
}

/** The three ways `attestLane` can decline to produce a record, with enough detail to print why. */
export type AttestLaneResult =
  | ({ readonly ok: true; readonly stage: "verified" } & VerifiedLane)
  | {
      readonly ok: false;
      readonly stage: "report";
      readonly origin: string;
      readonly nonce: string;
    }
  | {
      readonly ok: false;
      readonly stage: "verification";
      readonly origin: string;
      readonly nonce: string;
      readonly reportText: string;
      readonly spkiSha256: string;
      readonly verification: AttestationVerification;
    }
  | {
      readonly ok: false;
      readonly stage: "pinning";
      readonly origin: string;
      readonly nonce: string;
      readonly reportText: string;
      readonly spkiSha256: string;
      readonly verification: AttestationVerification;
      readonly verdict: string;
    };

/**
 * Fetch, verify and pin one lane, then build the saved record and self-check it. This is the whole
 * body of `gray-assistant attest` minus printing and writing: a daemon calls the same function, gets the
 * `VerifiedReportFile`, and passes it to `checkVerifiedReport` with its own sealing policy.
 *
 * A network, TLS or non-UTF-8 failure throws `RelayKitError` (as the CLI's command wrapper expects);
 * a lane that answered but did not verify is a normal `ok: false` result, so the caller can print
 * the checks that failed.
 */
export async function attestLane(options: AttestLaneOptions): Promise<AttestLaneResult> {
  // Checked before anything is fetched: a caller that passes no expectation (or a malformed one) is a
  // usage error, not a TypeError halfway through, and never an attestation without the S12 checks.
  if (!isLaneBinding(options.expectedInstance)) {
    throw new RelayKitError(
      "usage",
      "attestLane needs expectedInstance: the lane's dstack app id (40 lower-case hex) and the node KMS's ca_pubkey (182 lower-case hex)",
    );
  }
  const fetched = await fetchAttestationReport(options.origin, options.nonce, options.ca, tunnelOriginOf(options.origin) === null ? undefined : options.keyset);
  const parsed = parseAttestationReportText(fetched.text);
  if (!parsed.ok) {
    return { ok: false, stage: "report", origin: options.origin, nonce: options.nonce };
  }
  const verified = await verifyAttestation(parsed.value, {
    nonce: options.nonce,
    expectedComposeHashes: options.release?.composeHashes ?? [],
    expectedOsImageHashes: options.release?.osImageHashes ?? [],
    ...(options.release === null ? {} : { osImageMeasurements: options.release.osImageMeasurements }),
    tlsSpkiSha256: fetched.spkiSha256,
    // Through Gray's entry the client connected to the entry's name, which no VM identity names: the relay check is
    // the caller's (the daemon's "the identity's relay is this relay"), not the TLS domain's.
    ...(tunnelOriginOf(options.origin) === null ? { host: new URL(options.origin).hostname } : {}),
    nowSecs: options.nowSecs,
    quoteVerifier: options.quoteVerifier,
    ...(options.allowEmptySlot === true ? { allowEmptySlot: true } : {}),
  });
  // The instance checks join the transcript, so a mismatch fails the verification like any other
  // check and the CLI prints it with the rest.
  const instanceChecks = [...laneBindingChecks(verified, options.expectedInstance), ...osImageChecks(verified.osImageHash, options)];
  const verification: AttestationVerification = {
    ...verified,
    ok: verified.ok && instanceChecks.every((check) => check.status !== "fail"),
    checks: [...verified.checks, ...instanceChecks],
  };
  if (!verification.ok) {
    return {
      ok: false,
      stage: "verification",
      origin: options.origin,
      nonce: options.nonce,
      reportText: fetched.text,
      spkiSha256: fetched.spkiSha256,
      verification,
    };
  }
  const verdict = attestationVerdict(verification, {
    allowPath: options.release === null ? null : "release-list",
    allowUnpinned: options.allowUnpinned,
    acceptUnpinned: options.acceptUnpinned,
    acceptOsUnpinned: options.acceptOsUnpinned,
  });
  if (!verdict.accepted) {
    return {
      ok: false,
      stage: "pinning",
      origin: options.origin,
      nonce: options.nonce,
      reportText: fetched.text,
      spkiSha256: fetched.spkiSha256,
      verification,
      verdict: verdict.verdict,
    };
  }
  const file = buildVerifiedReport({
    origin: options.origin,
    nonce: options.nonce,
    verifiedAt: options.nowSecs,
    reportText: fetched.text,
    verification,
    expectedComposeHashes: options.release?.composeHashes ?? [],
    expectedOsImageHashes: options.release?.osImageHashes ?? [],
    expectedInstance: options.expectedInstance,
    acceptedUnpinned: verification.pinned !== true,
    ...osImageRecord(verification.osImageHash, options),
  });
  // The verdict above already applied the caller's pinning policy. This self-check then proves the
  // record we are about to return is internally consistent: every deterministic check, the report
  // hash, the ACI binding and the keyset expiry. `acceptUnpinned: true` only skips the record's
  // "both measurements pinned" flag, which the verdict decided explicitly; a caller that later seals
  // still calls `checkVerifiedReport` with its own policy.
  checkVerifiedReport(file, {
    nowSecs: options.nowSecs,
    maxAgeSeconds: BigInt(options.maxReportAgeSeconds ?? DEFAULT_MAX_REPORT_AGE_SECONDS),
    acceptUnpinned: true,
  });
  return {
    ok: true,
    stage: "verified",
    origin: options.origin,
    nonce: options.nonce,
    reportText: fetched.text,
    spkiSha256: fetched.spkiSha256,
    verification,
    verdict: verdict.verdict,
    file,
  };
}

/**
 * The `os_image_production` line (S11b) when the caller asked for it: the release list entry of the OS
 * image the quote bound. Nothing when the caller has a registry, when there is no list, or when the
 * verification bound no OS image (that already fails or was accepted as OS-unpinned).
 */
function osImageChecks(osImageHash: string | null, options: AttestLaneOptions): readonly ReportCheck[] {
  if (options.osImageAcceptance === undefined || options.release === null || osImageHash === null) return [];
  const entry = options.release.osImages.find((image) => image.os_image_hash === osImageHash);
  if (entry === undefined) return [];
  const decision = osImageDecisionWithoutRegistry(entry, options.osImageAcceptance.acceptedOsImages);
  if (decision.ok) {
    const named = options.osImageAcceptance.acceptedOsImages.includes(osImageHash);
    return [{ id: "os_image_production", status: "pass", detail: `${osImageHash} ${named ? "accepted by --accept-os-image" : "is a production image by its sha256sum.txt and metadata.json"}` }];
  }
  const why = decision.code === "os_image_dev" ? "is a dstack dev image by its own metadata.json; it is never accepted" : "does not prove itself a production image; pass --accept-os-image to accept it on your own judgment";
  return [{ id: "os_image_production", status: "fail", detail: `${decision.code}: ${osImageHash} ${why}` }];
}

/**
 * S11b: what the record keeps of the OS image judgment (`os_image_production`), so a sealing command
 * can repeat it without the list: the entry's texts and whether the operator named the image.
 */
function osImageRecord(osImageHash: string | null, options: AttestLaneOptions): { readonly osImage?: RecordedOsImage } {
  if (options.osImageAcceptance === undefined || options.release === null || osImageHash === null) return {};
  const entry = options.release.osImages.find((image) => image.os_image_hash === osImageHash);
  if (entry === undefined) return {};
  return {
    osImage: {
      hash: osImageHash,
      sha256sumTxt: entry.sha256sum_txt,
      metadataJson: entry.metadata_json,
      acceptedByOperator: options.osImageAcceptance.acceptedOsImages.includes(osImageHash),
    },
  };
}

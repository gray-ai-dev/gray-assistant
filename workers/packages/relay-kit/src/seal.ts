/**
 * The sealing half of `gray-assistant credentials …`, as a library the CLI and a daemon share.
 *
 * A signed credential payload is sealed once per verified replica: the connector's intake key is
 * per replica and per boot, so the same bytes become one HPKE envelope per report. These functions
 * take reports that have already passed `checkVerifiedReport` (the CLI's `--report` loading does
 * that, and `attestLane` returns the checked record) and never read a file or a clock. That keeps
 * them pure: they run in Node and workerd, and a test can hold them to the connector's own
 * `applySealed` without a filesystem.
 *
 * The version rules and the credential classes stay the other package's; this module only chooses
 * which report each envelope is sealed to and validates the ciphertext it produced with the TEE's
 * parser.
 */
import {
  parseSealedCredential,
  sealCredentialBundle,
  sealCredentialRevoke,
  sealCredentialUpdate,
  type CredentialBundle,
  type CredentialRevoke,
  type CredentialUpdate,
} from "@gray/relay-connector";
import type { Json, JsonObject } from "@gray/json";
import { RelayKitError } from "./errors.ts";
import type { CheckedVerifiedReport } from "./verified-report.ts";

/** One envelope sealed to one replica, with the intake key it names. */
export interface SealedForReplica {
  readonly report: CheckedVerifiedReport;
  readonly intakeKeyId: string;
  readonly keysetDigest: string;
  readonly envelope: JsonObject;
}

/** What every sealing call needs: the same signed payload, the relay's seed and one clock. */
export interface SealOptions {
  /** The reports of every replica the relay serves; each gets its own envelope. */
  readonly reports: readonly CheckedVerifiedReport[];
  /** The 32-byte Ed25519 seed of the relay's registered key. */
  readonly signingKey: Uint8Array;
  /** Unix seconds used for the connector's freshness checks. */
  readonly nowSecs: bigint;
}

/** Seal a full credential bundle to every replica. */
export async function sealCredentialBundleForReplicas(options: SealOptions & { readonly bundle: CredentialBundle }): Promise<readonly SealedForReplica[]> {
  return sealForReports(options, (report) =>
    sealCredentialBundle(report.report, options.signingKey, options.bundle, {
      nonce: report.file.nonce,
      quoteVerified: true,
      nowSecs: options.nowSecs,
    }),
  );
}

/** Seal one refreshed token to every replica. */
export async function sealCredentialUpdateForReplicas(options: SealOptions & { readonly update: CredentialUpdate }): Promise<readonly SealedForReplica[]> {
  return sealForReports(options, (report) =>
    sealCredentialUpdate(report.report, options.signingKey, options.update, {
      nonce: report.file.nonce,
      quoteVerified: true,
      nowSecs: options.nowSecs,
    }),
  );
}

/** Seal one account or whole-relay revocation to every replica. */
export async function sealCredentialRevokeForReplicas(options: SealOptions & { readonly revoke: CredentialRevoke }): Promise<readonly SealedForReplica[]> {
  return sealForReports(options, (report) =>
    sealCredentialRevoke(report.report, options.signingKey, options.revoke, {
      nonce: report.file.nonce,
      quoteVerified: true,
      nowSecs: options.nowSecs,
    }),
  );
}

async function sealForReports(
  options: SealOptions,
  seal: (report: CheckedVerifiedReport) => Promise<JsonObject>,
): Promise<readonly SealedForReplica[]> {
  if (options.reports.length === 0) throw new RelayKitError("usage", "missing --report");
  const origins = new Set<string>();
  for (const report of options.reports) {
    if (origins.has(report.file.origin)) throw new RelayKitError("duplicate_replica", report.file.origin);
    origins.add(report.file.origin);
  }
  const out: SealedForReplica[] = [];
  for (const report of options.reports) {
    const envelope = await seal(report);
    const parsed = parseSealedCredential(envelope as Json);
    out.push({ report, intakeKeyId: parsed.keyId, keysetDigest: parsed.keysetDigest, envelope });
  }
  return out;
}
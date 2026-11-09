/**
 * The status snapshot `gray-assistant run` writes and `gray-assistant status` reads. It is a public view of
 * the daemon (`DaemonStatus` + `DaemonHealth`), never a credential: no token, no account secret, no
 * header. It exists because `status` is a second process and the supervisor's replica state is
 * deliberately in memory (design v2 §A.2); the file is the one bridge.
 *
 * Written atomically (fresh 0600 file, fsync, rename, directory fsync) so a reader never sees a torn
 * document. A missing file means "not running", not an error.
 */
import { closeSync, fsyncSync, mkdirSync, openSync, readFileSync, renameSync, unlinkSync, writeSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { dirname, resolve } from "node:path";
import { parsePlain, toJsonString, type JsonObject } from "@gray/json";
import type { DaemonHealth, DaemonStatus } from "../../daemon/types.ts";
import type { AgentStatusReportState } from "./agent-status-report.ts";

/**
 * The snapshot's API version, so a later shape can be refused rather than misread. Members added since (a replica's
 * `last_push_at_ms` and `sealed_accounts`, a parked account's `source_id`, `agent_status` and its `instance`, `ui_page`)
 * are additions a reader of version 1 skips.
 */
export const DAEMON_STATUS_API_VERSION = 1;

export interface DaemonStatusSnapshot {
  readonly apiVersion: number;
  readonly writtenAtMs: number;
  readonly health: DaemonHealth;
  readonly status: DaemonStatus;
  /** What the agent last reported to Gray (S45); null or absent without a `stack` section. */
  readonly agentStatus?: AgentStatusReportState | null;
  /**
   * Where the relay's own page answers now (`gray-assistant ui enroll` builds its link from it): `public`/`tunnel` with the
   * origin, `loopback` with the port; null or absent while the agent serves none.
   */
  readonly uiPage?: { readonly mode: "loopback" | "public" | "tunnel"; readonly origin: string | null; readonly port: number | null } | null;
  /** The relay tunnel and its CT monitor (`../tunnel/status.ts`); null or absent without a `tunnel` section. */
  readonly tunnel?: JsonObject | null;
}

/** The JSON value of one snapshot. */
export function daemonStatusValue(snapshot: DaemonStatusSnapshot): JsonObject {
  return {
    api_version: snapshot.apiVersion,
    written_at_ms: snapshot.writtenAtMs,
    health: {
      ready: snapshot.health.ready,
      reasons: [...snapshot.health.reasons],
      at_ms: snapshot.health.atMs,
    },
    status: {
      relay_id: snapshot.status.relayId,
      started: snapshot.status.started,
      paused: snapshot.status.paused,
      last_version: snapshot.status.lastVersion,
      clock_skew_ms: snapshot.status.clockSkewMs,
      clock_skew_at_ms: snapshot.status.clockSkewAtMs,
      source: {
        healthy: snapshot.status.source.healthy,
        last_poll_at_ms: snapshot.status.source.lastPollAtMs,
        accounts: snapshot.status.source.accounts,
      },
      replicas: snapshot.status.replicas.map((replica) => ({
        origin: replica.origin,
        phase: replica.phase,
        keyset_digest: replica.keysetDigest,
        policy_version: replica.policyVersion,
        credential_version: replica.credentialVersion,
        lease_expires_at_ms: replica.leaseExpiresAtMs,
        lease_remaining_ms: replica.leaseRemainingMs,
        accounts: replica.accounts,
        reasons: [...replica.reasons],
        last_error: replica.lastError,
        next_attempt_at_ms: replica.nextAttemptAtMs,
        sealed_account_ids: replica.sealedAccountIds === null ? null : [...replica.sealedAccountIds],
        refused_account_ids: replica.refusedAccountIds === null ? null : [...replica.refusedAccountIds],
        digest_changes: replica.digestChanges,
        retiring: replica.retiring,
        retire_after_ms: replica.retireAfterMs,
        scheduler_api_version: replica.schedulerApiVersion,
        last_push_at_ms: replica.lastPushAtMs,
        relay_image: replica.relayImage,
        sealed_accounts: replica.sealedAccounts.map((account) => ({ source_id: account.sourceId, version: account.version, at_ms: account.atMs })),
      })),
      // docs/design/relay-zero-downtime.md: an image rollout's second relay-stack replica, while there is one.
      stack_secondary:
        snapshot.status.stackSecondary === undefined || snapshot.status.stackSecondary === null
          ? null
          : {
              role: snapshot.status.stackSecondary.role,
              origin: snapshot.status.stackSecondary.origin,
              app_id: snapshot.status.stackSecondary.appId,
              phase: snapshot.status.stackSecondary.phase,
              keyset_digest: snapshot.status.stackSecondary.keysetDigest,
              relay_image: snapshot.status.stackSecondary.relayImage,
              lease_expires_at_ms: snapshot.status.stackSecondary.leaseExpiresAtMs,
              last_error: snapshot.status.stackSecondary.lastError,
            },
      parked: snapshot.status.parked.map((account) => ({ account_id: account.accountId, source_id: account.sourceId ?? null, vendor: account.vendor, reason: account.reason })),
      releases: snapshot.status.releases.map((release) => ({
        compose_hash: release.composeHash,
        git_commit: release.gitCommit,
        first_seen_ms: release.firstSeenMs,
        acceptable_at_ms: release.acceptableAtMs,
        acceptable: release.acceptable,
        accepted: release.accepted,
        accepted_at_ms: release.acceptedAtMs,
        accepted_at_pairing: release.acceptedAtPairing,
        rejected: release.rejected,
      })),
      os_images: snapshot.status.osImages.map((image) => ({
        os_image_hash: image.osImageHash,
        first_seen_ms: image.firstSeenMs,
        acceptable_at_ms: image.acceptableAtMs,
        acceptable: image.acceptable,
        refusal: image.refusal,
        accepted: image.accepted,
        accepted_at_ms: image.acceptedAtMs,
        accepted_at_pairing: image.acceptedAtPairing,
        rejected: image.rejected,
        provenance: image.provenance,
        is_dev: image.isDev,
        version: image.version,
      })),
      release_list: {
        url: snapshot.status.releaseList.url,
        freshness_url: snapshot.status.releaseList.freshnessUrl,
        issued_at_ms: snapshot.status.releaseList.issuedAtMs,
        expires_at_ms: snapshot.status.releaseList.expiresAtMs,
        current_until_ms: snapshot.status.releaseList.currentUntilMs,
        current_by: snapshot.status.releaseList.currentBy,
        freshness: snapshot.status.releaseList.freshness,
        freshness_issued_at_ms: snapshot.status.releaseList.freshnessIssuedAtMs,
        freshness_expires_at_ms: snapshot.status.releaseList.freshnessExpiresAtMs,
        last_error: snapshot.status.releaseList.lastError,
        staleness: snapshot.status.releaseList.staleness,
      },
      alerts: snapshot.status.alerts.map((alert) => ({ at_ms: alert.atMs, event: alert.event, detail: alert.detail })),
      // S53: what the token service names now; the replica's relay_image is what its boot runs.
      stack: snapshot.status.stack === null ? null : { current_image: snapshot.status.stack.current, previous_image: snapshot.status.stack.previous },
    },
    agent_status: agentStatusValue(snapshot.agentStatus ?? null),
    ui_page: snapshot.uiPage == null ? null : { mode: snapshot.uiPage.mode, origin: snapshot.uiPage.origin, port: snapshot.uiPage.port === null ? null : BigInt(snapshot.uiPage.port) },
    tunnel: snapshot.tunnel ?? null,
  };
}

/** The agent status report's state as the snapshot holds it (`gray-assistant status`, `doctor`). */
function agentStatusValue(state: AgentStatusReportState | null): JsonObject | null {
  if (state === null) return null;
  return {
    last_issued_ms: state.lastIssuedMs,
    last_accepted_at_ms: state.lastAcceptedAtMs,
    recorded: state.recorded,
    last_failure: state.lastFailure === null ? null : { status: state.lastFailure.status, code: state.lastFailure.code, at_ms: state.lastFailure.atMs },
    pending: state.pending,
    next_attempt_at_ms: state.nextAttemptAtMs,
    // P12: the lane instance Gray's last answer named, as it named it (doctor compares it with the adopted one).
    instance:
      state.instance == null
        ? null
        : { app_id: state.instance.app_id, lane_origin: state.instance.lane_origin, kms_ca_pubkey: state.instance.kms_ca_pubkey, deployment: state.instance.deployment },
  };
}

/** Write one snapshot atomically. The directory is created; the file is 0600. */
export function writeDaemonStatusFile(path: string, snapshot: DaemonStatusSnapshot): void {
  const target = resolve(path);
  const directory = dirname(target);
  mkdirSync(directory, { recursive: true });
  const temporary = `${target}.tmp-${process.pid}-${randomBytes(8).toString("hex")}`;
  let fd: number | null = null;
  try {
    fd = openSync(temporary, "wx", 0o600);
    writeSync(fd, `${toJsonString(daemonStatusValue(snapshot))}\n`, null, "utf8");
    fsyncSync(fd);
    closeSync(fd);
    fd = null;
    renameSync(temporary, target);
    const dirFd = openSync(directory, "r");
    try {
      fsyncSync(dirFd);
    } finally {
      closeSync(dirFd);
    }
  } catch (error) {
    if (fd !== null) {
      try {
        closeSync(fd);
      } catch {
        // The write already failed.
      }
    }
    try {
      unlinkSync(temporary);
    } catch {
      // There may be no temporary file.
    }
    throw error;
  }
}

/** Read a snapshot, or null when it is missing or unreadable. Never throws on bad JSON. */
export function readDaemonStatusFile(path: string): JsonObject | null {
  let text: string;
  try {
    text = readFileSync(resolve(path), "utf8");
  } catch {
    return null;
  }
  try {
    const value = parsePlain(text);
    return typeof value === "object" && value !== null && !Array.isArray(value) ? (value as JsonObject) : null;
  } catch {
    return null;
  }
}

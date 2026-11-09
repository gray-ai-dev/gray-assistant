import type { Credential, Vendor } from "@gray/relay-connector";

/**
 * Where the relay daemon reads the relay's accounts from (relay SDK design v2 §A.8): the relay's own
 * software through one adapter per kind. The daemon (`gray-assistant run`) depends only on this file; each
 * adapter lives in its own file under `src/node/source/` and implements `SourceAdapter`.
 *
 * Two rules every adapter keeps:
 *
 * - Metadata and secrets are separate calls. `list` returns metadata only and is called on every poll;
 *   `credential` returns one secret and is called only when the daemon seals or pushes that account.
 *   Change detection is by `changeMark`, never by reading or hashing the secret on every poll.
 * - The daemon never refreshes a token. A source that refreshes lazily (only when its own software
 *   serves the account) says so in `refresh`, and the daemon alerts when a sealed credential passes its
 *   expiry without a new `changeMark` (design v2 §A.8, critique R13).
 */

/** The source kinds of v1 (design v2 §A.8). */
export const SOURCE_KINDS = ["file", "http", "cliproxyapi"] as const;
export type SourceKind = (typeof SOURCE_KINDS)[number];

/** An account's health as the relay's software states it. */
export type SourceAccountStatus = "active" | "limited" | "banned" | "disabled";

/**
 * A per-account egress proxy as the source declares it (design v3 addendum E2). The password is not
 * here: metadata is listed on every poll and may be logged by a supervised process, so the secret
 * half of a proxy credential is returned only by `credential()` (K4-1). The daemon passes the whole
 * value into the sealed bundle once `@gray/relay-connector` accepts the `egress` member.
 */
export interface SourceEgress {
  readonly type: "http" | "https" | "socks5" | "socks5h";
  readonly host: string;
  readonly port: number;
  readonly username?: string;
}

/** One secret read: the account credential and, separately, the proxy password when one is declared. */
export interface SourceCredential {
  readonly credential: Credential;
  /** The egress proxy's password, only when the source declares one and it has a username. */
  readonly egressPassword?: string;
}

/** One account's metadata (never its secret). */
export interface SourceAccount {
  /** The software's own id for the account, as it is; the daemon derives the lane account id from it. */
  readonly sourceId: string;
  readonly vendor: Vendor;
  readonly credentialType: Credential["type"];
  /** Exact public model ids, or `"*"` for every model of the vendor (the default when the source has no list). */
  readonly models: readonly string[] | "*";
  readonly weight: bigint;
  readonly maxConcurrency: bigint;
  readonly status: SourceAccountStatus;
  /** Unix ms until which a `limited` account stays out of the picks, when the source knows it. */
  readonly limitedUntilMs?: number;
  /** Unix ms at which the account's current secret expires, when the source knows it. */
  readonly credentialExpiresAtMs?: number;
  /**
   * Opaque; changes whenever the secret or anything the daemon seals for the account changes (the
   * source's `updated_at`, last refresh time, token expiry, or a version counter). Equal marks mean
   * "nothing to push".
   */
  readonly changeMark: string;
  readonly egress?: SourceEgress;
  /**
   * The relay login (`gray-assistant login codex --name <login>`) the account's credential comes from, when the source
   * names one (the `file` source's `oauth_login` credential). A name, never a token; the agent status reports it.
   */
  readonly login?: string;
}

/** How the source's software refreshes subscription tokens (critique R13). */
export type SourceRefresh = "proactive" | "lazy" | "unknown";

/** One poll's result. */
export interface SourceSnapshot {
  readonly accounts: readonly SourceAccount[];
  readonly refresh: SourceRefresh;
  /** Accounts the source lists with a vendor this gray-assistant does not serve yet (`http`); left out of `accounts`. */
  readonly skipped?: readonly SourceSkippedAccount[];
}

/** One account left out of a snapshot because its vendor is not one of this release's lane vendors. */
export interface SourceSkippedAccount {
  readonly sourceId: string;
  /** The vendor name as the source wrote it (a closed lower-case word, never a secret). */
  readonly vendor: string;
}

/** What `probe` found: the software and whether a secret can be read without a person present. */
export interface SourceProbe {
  readonly software: string;
  readonly version: string | null;
  readonly credentialReadable: boolean;
}

/**
 * One adapter. Every method honours `signal` (the daemon's deadline) and throws a `RelayKitError` with a
 * closed code on failure; no method logs, and no error message contains a secret or a source token.
 */
export interface SourceAdapter {
  readonly kind: SourceKind;
  probe(signal: AbortSignal): Promise<SourceProbe>;
  list(signal: AbortSignal): Promise<SourceSnapshot>;
  credential(sourceId: string, signal: AbortSignal): Promise<SourceCredential>;
  /**
   * The account interface's optional third route (`PUT …/accounts/{id}/credential`, standard "Account source"): write
   * back a token egress refreshed inside the VM for a `refresh: "gray"` account. Absent: the source takes none.
   */
  writeCredential?(sourceId: string, credential: Credential, signal: AbortSignal): Promise<void>;
}

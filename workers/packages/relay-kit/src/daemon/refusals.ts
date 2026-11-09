/**
 * The refusal table (design v2 §A.5, critique R10, review M3): every closed code the lane can answer
 * for an upload, keyed by (route, message kind, code), with the action the supervisor takes and
 * whether the action may succeed on a retry without operator input.
 *
 * Two rules make the table honest:
 *
 * - The policy route's statuses differ from the credential route's: a missing relay is 403 with
 *   `unknown_relay`, while every credential refusal is 400 with a code. The table knows both.
 * - A replay is not automatically an error: an upload that timed out after the TEE applied it is
 *   refused `bundle_replay` on the retry. `decideRefusal` treats a replay of a retried message as
 *   success (the version is the TEE's), while a first-attempt replay with an intact ledger is the
 *   `second_writer` signal.
 */

/** The two upload routes the supervisor uses. */
export type RefusalRoute = "credentials" | "policy";

/** The message the route carried; a policy bundle has its own kind. */
export type RefusalMessageKind = "bundle" | "update" | "revoke" | "policy";

/** What the supervisor does next. */
export type RefusalAction =
  | "installed"
  | "reattest"
  | "reseal"
  | "full_bundle"
  | "refilter"
  | "retry"
  | "version_probe"
  | "second_writer"
  | "relay_unknown"
  | "terminal";

/** One row. `transient` is true only when a retry can succeed with no operator action. */
export interface RefusalRow {
  readonly route: RefusalRoute;
  readonly kind: RefusalMessageKind;
  readonly code: string;
  readonly action: RefusalAction;
  readonly transient: boolean;
  /** A fixed operator sentence; never contains a value from the request. */
  readonly message: string;
}

/** Every row the daemon knows, in one array so a test can walk all of them. */
export const REFUSAL_TABLE: readonly RefusalRow[] = Object.freeze([
  // The boot changed under the message: every kind, both routes.
  { route: "credentials", kind: "bundle", code: "unknown_intake_key", action: "reattest", transient: true, message: "the lane boot changed (unknown intake key)" },
  { route: "credentials", kind: "update", code: "unknown_intake_key", action: "reattest", transient: true, message: "the lane boot changed (unknown intake key)" },
  { route: "credentials", kind: "revoke", code: "unknown_intake_key", action: "reattest", transient: true, message: "the lane boot changed (unknown intake key)" },
  { route: "credentials", kind: "bundle", code: "attestation_mismatch", action: "reattest", transient: true, message: "the lane boot changed (attestation mismatch)" },
  { route: "credentials", kind: "update", code: "attestation_mismatch", action: "reattest", transient: true, message: "the lane boot changed (attestation mismatch)" },
  { route: "credentials", kind: "revoke", code: "attestation_mismatch", action: "reattest", transient: true, message: "the lane boot changed (attestation mismatch)" },
  { route: "credentials", kind: "bundle", code: "bundle_replay", action: "installed", transient: true, message: "the version is already installed" },
  { route: "credentials", kind: "update", code: "bundle_replay", action: "installed", transient: true, message: "the version is already installed" },
  { route: "credentials", kind: "revoke", code: "bundle_replay", action: "installed", transient: true, message: "the version is already installed" },
  { route: "credentials", kind: "bundle", code: "bundle_rollback", action: "version_probe", transient: true, message: "the lane remembers a higher version" },
  { route: "credentials", kind: "update", code: "bundle_rollback", action: "version_probe", transient: true, message: "the lane remembers a higher version" },
  { route: "credentials", kind: "revoke", code: "bundle_rollback", action: "version_probe", transient: true, message: "the lane remembers a higher version" },
  { route: "credentials", kind: "bundle", code: "bundle_expired", action: "reseal", transient: true, message: "the bundle's lease expired before intake" },
  { route: "credentials", kind: "update", code: "bundle_expired", action: "full_bundle", transient: true, message: "the replica's lease expired; a full bundle renews it" },
  { route: "credentials", kind: "revoke", code: "bundle_expired", action: "retry", transient: true, message: "the replica's lease expired; the revoke is still valid" },
  { route: "credentials", kind: "bundle", code: "bundle_not_yet_valid", action: "retry", transient: true, message: "the bundle's issued_at is ahead of the lane clock" },
  { route: "credentials", kind: "update", code: "bundle_not_yet_valid", action: "retry", transient: true, message: "the lane clock is behind the relay clock" },
  { route: "credentials", kind: "revoke", code: "bundle_not_yet_valid", action: "retry", transient: true, message: "the lane clock is behind the relay clock" },
  { route: "credentials", kind: "bundle", code: "unknown_relay", action: "relay_unknown", transient: true, message: "the lane does not list this relay (so far)" },
  { route: "credentials", kind: "update", code: "unknown_relay", action: "relay_unknown", transient: true, message: "the lane does not list this relay (so far)" },
  { route: "credentials", kind: "revoke", code: "unknown_relay", action: "relay_unknown", transient: true, message: "the lane does not list this relay (so far)" },
  // A partial update can no longer reach its account: renew the whole pool.
  { route: "credentials", kind: "update", code: "unknown_account", action: "full_bundle", transient: true, message: "the replica never received this account; a full bundle adds it" },
  // A revoke of an account the replica no longer holds has already succeeded.
  { route: "credentials", kind: "revoke", code: "unknown_account", action: "installed", transient: true, message: "the account is already gone from the replica" },
  { route: "credentials", kind: "bundle", code: "unknown_account", action: "full_bundle", transient: true, message: "the replica's account map is stale; a full bundle replaces it" },
  { route: "credentials", kind: "update", code: "invalid_credential", action: "full_bundle", transient: true, message: "the refreshed credential was refused; rebuild the bundle" },
  { route: "credentials", kind: "bundle", code: "invalid_credential", action: "refilter", transient: true, message: "one account's credential was refused; park it and reseal" },
  { route: "credentials", kind: "bundle", code: "invalid_bundle", action: "refilter", transient: true, message: "the bundle shape was refused; rebuild after parking the offending account" },
  // Local bugs, wrong keys and impossible documents: retrying cannot help.
  { route: "credentials", kind: "bundle", code: "bad_relay_signature", action: "terminal", transient: false, message: "the lane refused the relay's signature; check the registered key" },
  { route: "credentials", kind: "update", code: "bad_relay_signature", action: "terminal", transient: false, message: "the lane refused the relay's signature; check the registered key" },
  { route: "credentials", kind: "revoke", code: "bad_relay_signature", action: "terminal", transient: false, message: "the lane refused the relay's signature; check the registered key" },
  { route: "credentials", kind: "bundle", code: "duplicate_account", action: "terminal", transient: false, message: "the lane holds this account for another relay" },
  { route: "credentials", kind: "bundle", code: "invalid_envelope", action: "terminal", transient: false, message: "the lane could not read the envelope" },
  { route: "credentials", kind: "update", code: "invalid_envelope", action: "terminal", transient: false, message: "the lane could not read the envelope" },
  { route: "credentials", kind: "revoke", code: "invalid_envelope", action: "terminal", transient: false, message: "the lane could not read the envelope" },
  { route: "credentials", kind: "bundle", code: "decryption_failed", action: "terminal", transient: false, message: "the lane could not open the envelope" },
  { route: "credentials", kind: "update", code: "decryption_failed", action: "terminal", transient: false, message: "the lane could not open the envelope" },
  { route: "credentials", kind: "revoke", code: "decryption_failed", action: "terminal", transient: false, message: "the lane could not open the envelope" },
  { route: "credentials", kind: "bundle", code: "invalid_plaintext", action: "terminal", transient: false, message: "the lane could not parse the signed payload" },
  { route: "credentials", kind: "update", code: "invalid_plaintext", action: "terminal", transient: false, message: "the lane could not parse the signed payload" },
  { route: "credentials", kind: "revoke", code: "invalid_plaintext", action: "terminal", transient: false, message: "the lane could not parse the signed payload" },
  // Policy: the bundle's version is fixed, so a replay is the store's own idempotence and a rollback
  // is another writer with a newer policy (or a stale bundle the operator must replace).
  { route: "policy", kind: "policy", code: "unknown_relay", action: "relay_unknown", transient: true, message: "the lane does not list this relay (so far)" },
  { route: "policy", kind: "policy", code: "version_replay", action: "installed", transient: true, message: "this policy version is already installed" },
  { route: "policy", kind: "policy", code: "version_rollback", action: "second_writer", transient: false, message: "the lane has a newer policy version than this bundle" },
  { route: "policy", kind: "policy", code: "relay_key_invalid", action: "terminal", transient: false, message: "the lane's registry holds an unusable relay key" },
  { route: "policy", kind: "policy", code: "invalid_policy_bundle", action: "terminal", transient: false, message: "the lane refused the signed policy bundle" },
  { route: "policy", kind: "policy", code: "invalid_body", action: "terminal", transient: false, message: "the lane could not read the policy body" },
  { route: "policy", kind: "policy", code: "body_too_large", action: "terminal", transient: false, message: "the policy bundle is over the lane's cap" },
  { route: "policy", kind: "policy", code: "not_found", action: "terminal", transient: false, message: "the lane does not serve the policy route" },
  { route: "policy", kind: "policy", code: "method_not_allowed", action: "terminal", transient: false, message: "the lane refused the method" },
  { route: "credentials", kind: "bundle", code: "body_too_large", action: "terminal", transient: false, message: "the credential bundle is over the lane's cap" },
  { route: "credentials", kind: "bundle", code: "invalid_body", action: "terminal", transient: false, message: "the lane could not read the credential body" },
  { route: "credentials", kind: "bundle", code: "not_found", action: "terminal", transient: false, message: "the lane does not serve the credential route" },
  { route: "credentials", kind: "bundle", code: "method_not_allowed", action: "terminal", transient: false, message: "the lane refused the method" },
]);

/** The terminal row for a code the daemon has never seen: fail closed, never retry blindly. */
const FALLBACK: RefusalRow = {
  route: "credentials",
  kind: "bundle",
  code: "unknown",
  action: "terminal",
  transient: false,
  message: "the lane refused the message with an unhandled code",
};

/** The table row for one (route, kind, code); an unknown code falls back to terminal. */
export function refusalRowFor(route: RefusalRoute, kind: RefusalMessageKind, code: string): RefusalRow {
  for (const row of REFUSAL_TABLE) {
    if (row.route === route && row.kind === kind && row.code === code) return row;
  }
  return { ...FALLBACK, route, kind, code };
}

/** What one refusal means with the message's attempt count and the ledger's state. */
export interface RefusalContext {
  readonly route: RefusalRoute;
  readonly kind: RefusalMessageKind;
  readonly code: string;
  /** 1-based attempt of the message that was refused (1 = the first send). */
  readonly attempt: number;
  readonly ledgerIntact: boolean;
  /**
   * The HTTP status of the refusal, when the daemon knows it. R06: an unknown code on 5xx or 429
   * is transient (the lane or a proxy is briefly unavailable), while an unknown 4xx code is
   * terminal; the status is not part of the code so it is carried beside it.
   */
  readonly httpStatus?: number;
}

export interface RefusalDecision {
  readonly action: RefusalAction;
  readonly transient: boolean;
  readonly message: string;
  readonly row: RefusalRow;
}

/**
 * Resolve one refusal. The special cases are the version rules: a replay after a retry is success,
 * a first-attempt replay with an intact file is a second writer, and a rollback with a lost file is
 * the upward probe. Everything else is the table's row.
 */
export function decideRefusal(context: RefusalContext): RefusalDecision {
  const row = refusalRowFor(context.route, context.kind, context.code);
  if (context.code === "bundle_replay") {
    // R18: the daemon never resends a version, so a replay is not proof of installation. With the
    // file lost it is the TEE holding a higher version than this process can name (probe upward);
    // with the file intact it is a second writer, exactly like a rollback. Attempts are irrelevant.
    if (!context.ledgerIntact) return { action: "version_probe", transient: true, message: row.message, row };
    return { action: "second_writer", transient: false, message: "a replay with an intact state file suggests a second writer", row };
  }
  if (context.code === "version_replay") {
    // The policy version is fixed, so a replay is the policy store's own idempotence.
    if (context.route === "policy") return { action: "installed", transient: true, message: row.message, row };
    if (!context.ledgerIntact) return { action: "version_probe", transient: true, message: row.message, row };
    return { action: "second_writer", transient: false, message: "a policy replay on the credential route suggests a second writer", row };
  }
  if (context.code === "bundle_rollback" || context.code === "version_rollback") {
    if (context.route === "policy") return { action: "second_writer", transient: false, message: row.message, row };
    if (!context.ledgerIntact) return { action: "version_probe", transient: true, message: row.message, row };
    return { action: "second_writer", transient: false, message: "a rollback with an intact state file suggests a second writer", row };
  }
  // R06: a code the table does not know is transient only when the HTTP status itself says the
  // lane (or a proxy in front of it) was briefly unavailable. An unknown 4xx stays terminal.
  const known = REFUSAL_TABLE.some((entry) => entry.route === context.route && entry.kind === context.kind && entry.code === context.code);
  if (!known && context.httpStatus !== undefined && (context.httpStatus >= 500 || context.httpStatus === 429)) {
    return { action: "retry", transient: true, message: "the lane answered a transient HTTP status with an unhandled code", row };
  }
  return { action: row.action, transient: row.transient, message: row.message, row };
}

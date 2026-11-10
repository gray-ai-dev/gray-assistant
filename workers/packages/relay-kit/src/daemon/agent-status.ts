/**
 * The agent status gray-assistant posts to Gray's console (docs/confidential-lane-supply-implementation.md S45): what the
 * relay's own machine knows and the VM cannot see. The VM reports what it serves (`stack.report`); only the agent
 * knows whether its Codex logins still refresh and how far it sealed each replica, which the panel's "needs
 * re-login" list reads.
 *
 *     {"status": {"relay_id", "issued_ms", "agent_version",
 *                 "logins": [{"login", "vendor": "chatgpt_codex", "state", "failed", "access_expires_at_s",
 *                             "refreshed_at_s", "next_refresh_at_s", "failures", "account_ids"}],
 *                 "replicas": [{"origin", "stack", "phase", "credential_version", "lease_expires_at_ms",
 *                               "sealed_account_ids", "last_push_ms", "last_error"}],
 *                 "parked": [{"account_id", "reason"}],
 *                 "sources": [{"account_id", "vendor", "credential_type", "login"}] | null,
 *                 "ui_mode": "loopback|public|tunnel", "ui_port": 7470,   // while the page runs; the port for loopback
 *                 "tunnel": "connected",              // only with the config's tunnel section
 *                 "boot": {"code", "held", "first_ms", "last_ms", "count", "compose_hash"} | null,
 *                 "accepted_compose": ["<64 hex>", …] | null},
 *      "signature": "<128 hex>"}
 *
 * The schema and the signed message are the console's (`@gray/control/stack-agent`), so a status this builds is one
 * the console takes: the relay key's Ed25519 over `gray-relay-agent-status/v1\n` || JCS(status), the construction of
 * the signed release status (`release-status.ts`). Pure (no `node:`): the Node reporter
 * (`../node/daemon/agent-status-report.ts`) reads the logins and posts.
 *
 * Nothing here is a secret: login names, token times and failure words, origins, versions, the panel's account ids and
 * closed reasons. Account ids are named only when they are the panel's (`STACK_ID_PATTERN`); a parked account the
 * source names otherwise (a derived id, another source's own words) is left out, as the panel could not name it.
 *
 * `sources` (2026-10-29) is what the credential source lists at the daemon's last poll, for the panel's "adopt N
 * accounts": per account its vendor, its credential type and the relay login it comes from, as the source's
 * metadata states them (the daemon's `list`, never `credential`). Null while the source cannot be read.
 *
 * `boot` (S58) is the token service's latest refusal of a booting VM (`PullTokenBoot`), null once a token was issued
 * after it, so the panel can say why a boot waits or stopped.
 *
 * `accepted_compose` (relay standard v1.7 item 9) is the compose hashes of Gray's signed release list this relay lets boot
 * now (the daemon's release registry: accepted explicitly or after `delay_days`, not rejected), sorted, null before the
 * agent read its first list. Gray's provisioner boots only a release whose hash the latest status lists, so a VM is
 * never made, and its certificate never ordered, for a release the token service would hold.
 *
 * Panel ids (S59): every account id the status names (`sources`, logins', parked) goes through `panelId`, the daemon's
 * `panelAccountId`: the source's own id when it is a panel id, else the plain alias the relay's host gave it
 * (`anthropic-1`, account-aliases.ts). A source id that is an e-mail address never leaves the host.
 */
import { bytesToLowerHex, ed25519Sign } from "@gray/attest";
import { STACK_ID_PATTERN } from "@gray/control";
import {
  STACK_AGENT_ACCEPTED_COMPOSE_MAX,
  STACK_AGENT_ACCOUNT_IDS_MAX,
  STACK_AGENT_CREDENTIAL_TYPES,
  STACK_AGENT_LOGIN_NAME,
  STACK_AGENT_LOGINS_MAX,
  STACK_AGENT_PARKED_MAX,
  STACK_AGENT_REPLICA_PHASES,
  STACK_AGENT_REPLICAS_MAX,
  STACK_AGENT_SOURCE_VENDORS,
  STACK_AGENT_SOURCES_MAX,
  STACK_AGENT_STATUS_MAX_BYTES,
  STACK_AGENT_UI_PORT_MAX,
  STACK_AGENT_UI_PORT_MIN,
  STACK_AGENT_WORD,
  stackAgentStatusMessage,
  type StackAgentLoginState,
  type StackAgentUiMode,
} from "@gray/control/stack-agent";
import type { TunnelState } from "@gray/control/tunnel";
import { isObject, toJsonString, type JsonObject } from "@gray/json";
import type { Vendor } from "@gray/relay-connector";
import type { PullTokenBoot } from "./pull-token.ts";
import type { DaemonParkedAccount, DaemonReplicaStatus, DaemonSourceAccount } from "./types.ts";

export const AGENT_STATUS_PATH = "/v1/lane-stack/agent-status";

/** The word a replica's last error or a park reason is reported as when it is not a closed lower-case word. */
export const AGENT_STATUS_UNRECOGNIZED = "unrecognized";

/** One login as the agent sees it; the Node side reads the record (`loginAgentView`, ../node/login/record.ts). */
export interface AgentLogin {
  readonly login: string;
  readonly state: StackAgentLoginState;
  readonly failed: string | null;
  readonly accessExpiresAtS: number | null;
  readonly refreshedAtS: number | null;
  readonly nextRefreshAtS: number | null;
  readonly failures: number | null;
  /** The accounts of `accounts.json` that name this login. */
  readonly accountIds: readonly string[];
}

export interface AgentStatusInput {
  readonly relayId: string;
  readonly issuedMs: number;
  readonly agentVersion: string;
  /** `stack.lane_origin`: the replica whose lane holds credentials under the panel's account ids. */
  readonly stackOrigin: string;
  readonly logins: readonly AgentLogin[];
  readonly replicas: readonly DaemonReplicaStatus[];
  readonly parked: readonly DaemonParkedAccount[];
  /** The daemon's `status().sources`: the source's accounts, or null when it cannot be read. */
  readonly sources: readonly DaemonSourceAccount[] | null;
  /**
   * Where the relay's own page runs, null or absent while it runs nowhere: `loopback` with its port on 127.0.0.1
   * (`gray-assistant ui`, `ui.listen`), `public` on the relay's own origin, `tunnel` on the relay tunnel's.
   */
  readonly ui?: { readonly mode: "loopback"; readonly port: number } | { readonly mode: Exclude<StackAgentUiMode, "loopback"> } | null;
  /** The relay tunnel's word (`@gray/control/tunnel`); null or absent without a `tunnel` section. */
  readonly tunnel?: TunnelState | null;
  /** S58: the token service's latest refusal (`PullTokenService.boot()`); absent without a token service. */
  readonly boot?: PullTokenBoot | null;
  /**
   * S59: the id the panel knows a source account by (the daemon's `panelAccountId`), or null when it has none yet.
   * Absent: the source id itself when it is a panel id (`STACK_ID_PATTERN`).
   */
  readonly panelId?: (vendor: Vendor, sourceId: string) => string | null;
  /**
   * v1.7 item 9: the compose hashes the release registry lets boot now (`acceptedComposeHashes`); null before the first
   * release list; absent: the member is left out (an agent without a release registry).
   */
  readonly acceptedCompose?: readonly string[] | null;
}

const int = (value: number | null): bigint | null => (value === null ? null : BigInt(Math.trunc(value)));
const word = (value: string): string => (STACK_AGENT_WORD.test(value) ? value : AGENT_STATUS_UNRECOGNIZED);
const panelIds = (ids: readonly string[]): string[] => [...new Set(ids.filter((id) => STACK_ID_PATTERN.test(id)))].sort().slice(0, STACK_AGENT_ACCOUNT_IDS_MAX);
const byText = (left: string, right: string): number => (left < right ? -1 : left > right ? 1 : 0);

/**
 * The status the console keeps, at most S45's counts and its 256 KiB with room for the envelope: when a relay has so
 * many logins, parked and source accounts that it would not fit, parked accounts go first, then source accounts, then
 * logins, from the end of their order (`trimmed` says how many).
 */
export function agentStatusDocument(input: AgentStatusInput): { readonly status: JsonObject; readonly trimmed: number } {
  const panelId = input.panelId ?? ((_vendor: Vendor, sourceId: string) => (STACK_ID_PATTERN.test(sourceId) ? sourceId : null));
  const panelIdsOf = (vendor: Vendor, ids: readonly string[]): string[] => panelIds(ids.map((id) => panelId(vendor, id)).filter((id): id is string => id !== null));
  const logins = [...input.logins]
    .sort((left, right) => byText(left.login, right.login))
    .slice(0, STACK_AGENT_LOGINS_MAX)
    .map((l) => ({
      login: l.login,
      vendor: "chatgpt_codex",
      state: l.state,
      failed: l.state === "failed" ? l.failed : null,
      access_expires_at_s: int(l.accessExpiresAtS),
      refreshed_at_s: int(l.refreshedAtS),
      next_refresh_at_s: int(l.nextRefreshAtS),
      failures: int(l.failures),
      account_ids: panelIdsOf("chatgpt_codex", l.accountIds),
    }));
  const phases: readonly string[] = STACK_AGENT_REPLICA_PHASES;
  const replicas = [...input.replicas]
    .sort((left, right) => byText(left.origin, right.origin))
    .slice(0, STACK_AGENT_REPLICAS_MAX)
    .map((r) => ({
      origin: r.origin,
      stack: r.origin === input.stackOrigin,
      phase: phases.includes(r.phase) ? r.phase : "unknown",
      credential_version: r.credentialVersion,
      lease_expires_at_ms: int(r.leaseExpiresAtMs),
      sealed_account_ids: r.sealedAccountIds === null ? null : panelIds(r.sealedAccountIds),
      last_push_ms: int(r.lastPushAtMs),
      last_error: r.lastError === null ? null : word(r.lastError),
    }));
  // A loopback port the console's schema would refuse is left out with its mode, rather than sent.
  const page = input.ui ?? null;
  const ui: JsonObject =
    page === null
      ? {}
      : page.mode !== "loopback"
        ? { ui_mode: page.mode }
        : Number.isInteger(page.port) && page.port >= STACK_AGENT_UI_PORT_MIN && page.port <= STACK_AGENT_UI_PORT_MAX
          ? { ui_mode: "loopback", ui_port: BigInt(page.port) }
          : {};
  const seen = new Set<string>();
  const parked: JsonObject[] = [];
  const parkedIds = input.parked
    .map((p) => ({ id: p.sourceId === undefined ? null : panelId(p.vendor, p.sourceId), reason: p.reason }))
    .sort((left, right) => byText(left.id ?? "", right.id ?? ""));
  for (const p of parkedIds) {
    if (p.id === null || !STACK_ID_PATTERN.test(p.id) || seen.has(p.id)) continue;
    seen.add(p.id);
    parked.push({ account_id: p.id, reason: word(p.reason) });
    if (parked.length === STACK_AGENT_PARKED_MAX) break;
  }
  const sources = input.sources === null ? null : sourceAccounts(input.sources, panelId);
  const boot: JsonObject = input.boot === undefined ? {} : { boot: input.boot === null ? null : bootValue(input.boot) };
  const acceptedCompose: JsonObject =
    input.acceptedCompose === undefined
      ? {}
      : { accepted_compose: input.acceptedCompose === null ? null : [...new Set(input.acceptedCompose.filter((h) => /^[0-9a-f]{64}$/.test(h)))].sort().slice(0, STACK_AGENT_ACCEPTED_COMPOSE_MAX) };
  const allSources = sources?.length ?? 0;
  const document = (keepLogins: number, keepParked: number, keepSources: number): JsonObject => ({
    relay_id: input.relayId,
    issued_ms: BigInt(Math.trunc(input.issuedMs)),
    agent_version: input.agentVersion,
    logins: logins.slice(0, keepLogins),
    replicas,
    parked: parked.slice(0, keepParked),
    sources: sources === null ? null : sources.slice(0, keepSources),
    ...ui,
    ...(input.tunnel === undefined || input.tunnel === null ? {} : { tunnel: input.tunnel }),
    ...boot,
    ...acceptedCompose,
  });
  // The envelope (`{"status":…,"signature":"<128 hex>"}`) is under 200 bytes; 1 KiB of room is plenty.
  const fits = (value: JsonObject): boolean => new TextEncoder().encode(toJsonString(value)).length <= STACK_AGENT_STATUS_MAX_BYTES - 1024;
  if (fits(document(logins.length, parked.length, allSources))) return { status: document(logins.length, parked.length, allSources), trimmed: 0 };
  // The largest count that fits, by halving (each list's entries are about the same size).
  const largest = (total: number, ok: (n: number) => boolean): number => {
    let low = 0;
    let high = total;
    while (low < high) {
      const middle = Math.ceil((low + high) / 2);
      if (ok(middle)) low = middle;
      else high = middle - 1;
    }
    return low;
  };
  // Each list is cut only once every list before it is empty.
  const keepParked = largest(parked.length, (n) => fits(document(logins.length, n, allSources)));
  const parkedFit = keepParked > 0 || fits(document(logins.length, 0, allSources));
  const keepSources = parkedFit ? allSources : largest(allSources, (n) => fits(document(logins.length, 0, n)));
  const sourcesFit = parkedFit || keepSources > 0 || fits(document(logins.length, 0, 0));
  const keepLogins = sourcesFit ? logins.length : largest(logins.length, (n) => fits(document(n, 0, 0)));
  return {
    status: document(keepLogins, keepParked, keepSources),
    trimmed: logins.length - keepLogins + parked.length - keepParked + allSources - keepSources,
  };
}

/**
 * The source's accounts as the status names them: panel ids only (others left out, as for parked accounts), once
 * each, in id order, at most `STACK_AGENT_SOURCES_MAX`. The console's lists are closed and the daemon's are the same (a
 * test holds them equal); should they part, a vendor the console does not know leaves its account out, and a credential
 * type or login it would not take is null, so the console never refuses the whole status for one account.
 */
function sourceAccounts(accounts: readonly DaemonSourceAccount[], panelId: (vendor: Vendor, sourceId: string) => string | null): JsonObject[] {
  const vendors: readonly string[] = STACK_AGENT_SOURCE_VENDORS;
  const types: readonly string[] = STACK_AGENT_CREDENTIAL_TYPES;
  const seen = new Set<string>();
  const out: JsonObject[] = [];
  const named = accounts.map((a) => ({ ...a, id: panelId(a.vendor, a.sourceId) })).sort((left, right) => byText(left.id ?? "", right.id ?? ""));
  for (const a of named) {
    if (a.id === null || !STACK_ID_PATTERN.test(a.id) || !vendors.includes(a.vendor) || seen.has(a.id)) continue;
    seen.add(a.id);
    out.push({
      account_id: a.id,
      vendor: a.vendor,
      credential_type: types.includes(a.credentialType) ? a.credentialType : null,
      login: a.login !== null && STACK_AGENT_LOGIN_NAME.test(a.login) ? a.login : null,
    });
    if (out.length === STACK_AGENT_SOURCES_MAX) break;
  }
  return out;
}

/** S58's `boot` as the console's schema takes it: integers as JSON integers, the count within its bound. */
function bootValue(boot: PullTokenBoot): JsonObject {
  return {
    code: boot.code,
    held: boot.held,
    first_ms: BigInt(Math.trunc(boot.firstMs)),
    last_ms: BigInt(Math.trunc(Math.max(boot.firstMs, boot.lastMs))),
    count: BigInt(Math.max(1, Math.trunc(boot.count))),
    compose_hash: boot.composeHash,
  };
}

/** The members of a status that are times: a status that differs from the last one only in them is not a change. */
const TIMES: Readonly<Record<string, readonly string[]>> = {
  status: ["issued_ms"],
  logins: ["access_expires_at_s", "refreshed_at_s", "next_refresh_at_s"],
  replicas: ["lease_expires_at_ms", "last_push_ms"],
};

function withoutTimes(item: unknown, members: readonly string[]): unknown {
  return Object.fromEntries(Object.entries(item as JsonObject).filter(([key]) => !members.includes(key)));
}

/** The status without its times, as text: two statuses with one key differ in something but a time (S45's "change"). */
export function agentStatusChangeKey(status: JsonObject): string {
  const top = withoutTimes(status, TIMES.status as readonly string[]) as JsonObject;
  return toJsonString({
    ...top,
    logins: (status["logins"] as JsonObject[]).map((l) => withoutTimes(l, TIMES.logins as readonly string[])),
    replicas: (status["replicas"] as JsonObject[]).map((r) => withoutTimes(r, TIMES.replicas as readonly string[])),
  } as JsonObject);
}

/** The report body: the status and the relay key's signature over `stackAgentStatusMessage(status)`. */
export async function signAgentStatus(status: JsonObject, seed: Uint8Array): Promise<JsonObject> {
  return { status, signature: bytesToLowerHex(await ed25519Sign(seed, stackAgentStatusMessage(status))) };
}

/**
 * The answer's `refresh_gray`: the panel's account ids whose Token refresh is `gray` (egress refreshes them in the VM),
 * whose relay login gray-assistant hands to the VM. Null when the answer has none (an older console) or it is not a
 * list of panel ids.
 */
export function refreshGrayOf(answer: unknown): ReadonlySet<string> | null {
  const value = isObject(answer as never) ? (answer as Record<string, unknown>)["refresh_gray"] : undefined;
  if (!Array.isArray(value) || !value.every((id) => typeof id === "string" && STACK_ID_PATTERN.test(id))) return null;
  return new Set(value as string[]);
}

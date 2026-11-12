import { jcsBytes } from "@gray/attest";
import type { Json } from "@gray/json";
import { EGRESS_TYPES } from "@gray/relay-connector/egress";
import { z } from "zod";
import { STACK_ID_PATTERN, STACK_VENDORS } from "./stack.ts";
import { TOKEN_SERVICE_CODES } from "./stack-provision-words.ts";
import { TUNNEL_STATES } from "./tunnel.ts";

/**
 * gray-assistant's agent status (docs/confidential-lane-supply-implementation.md S45): what the relay's own agent knows
 * and the VM cannot see, how far it sealed each replica, posted to the console's public
 * `POST /v1/lane-stack/agent-status` as `{"status": {...}, "signature": "<128 hex>"}`. The signature is the relay
 * key's Ed25519 (its stack endpoints' lane record, `signing_public_key`) over `gray-relay-agent-status/v1\n` ||
 * JCS(status), the construction of relay-kit's signed release status (`release-status.ts`). Nothing here is a
 * secret: origins, versions, account ids and closed reasons.
 *
 * `ui_mode` says where gray-assistant's own page runs (where a key is typed on the relay's side, never on Gray's page), and
 * is absent while it runs nowhere: `loopback` on the relay machine's 127.0.0.1 at `ui_port` (`gray-assistant ui`, or
 * `ui.listen` beside the agent; the panel links to `http://127.0.0.1:<ui_port>/ui/…`), `public` on the relay's own
 * HTTPS origin (its `stack.token_url`, or the `ui.origin` its proxy serves), `tunnel` on the relay tunnel's
 * `https://<relay-id>.<relays zone>`. `ui_port` comes with `loopback` only. A closed word and a port, never an origin or
 * a path: the panel builds each address from what Gray already knows, and the status carries no free text.
 *
 * `tunnel` is present only for an agent that keeps the relay tunnel (docs/relay-tunnel.md, the config's `tunnel`
 * section): `connected` while the rendezvous holds its name, `down` otherwise, so the panel can say whether the relay's
 * public origin (`https://<label>.<zone>`, `@gray/control/tunnel`) answers and link to its page.
 *
 * Every word is closed (S33 rule 1): the replica phases (relay-kit's daemon
 * `REPLICA_PHASES`; its test holds the two lists equal), and the error and park reasons as lower-case words. Ids are
 * the panel's account id rule. The console keeps the newest status per relay (0032 `lane_stack_agent_status`).
 *
 * `sources` (2026-10-29, optional: an agent before it stays valid) lists the accounts the agent's credential source
 * holds, by panel id, so the panel can offer to adopt those it does not have: vendor and credential type only, never a
 * credential. Null when the agent cannot read its source (unknown, unlike `[]`, a source listing none).
 *
 * `boot` (2026-10-29, optional: an agent before it sends none) is what the relay's token service last answered a booting
 * VM: the refusal code (`TOKEN_SERVICE_CODES`), whether it held the boot (a 5xx or 429, which pre-launch waits out, so
 * the boot goes on once the relay fixes it) or refused it, when it first and last answered so, and how often; the
 * compose hash the refused boot ran when the code is about a release (so the panel can name the release to accept).
 * Null once a token was issued after it. Gray reads it as the reason a boot waits or stopped, beside the serial
 * console's line (docs/relay-stack-provisioner.md P8b).
 *
 * `accepted_compose` (relay standard v1.7 item 9, optional: an agent before it sends none) is the compose hashes of
 * Gray's signed release list the relay's release registry lets boot now (accepted, explicitly or after its delay, and
 * not rejected), sorted, at most STACK_AGENT_ACCEPTED_COMPOSE_MAX. Null while the agent has read no release list yet
 * (it cannot say). The provisioner boots only a release profile whose compose hash the relay's latest status lists
 * (docs/relay-standard-v1.7.md section 6); absent or null, nothing is accepted.
 *
 * A subpath export (`@gray/control/stack-agent`), not part of the package's index: the message needs `@gray/attest`'s
 * JCS, which the other importers of `@gray/control` (gray-jobs, the snapshot) would otherwise bundle for nothing.
 */

/** A replica's step in the agent's supervisor (relay-kit daemon `REPLICA_PHASES`). */
export const STACK_AGENT_REPLICA_PHASES = ["unknown", "attesting", "release_pending", "policy", "credentials", "serving", "failed", "withdrawn"] as const;

/** The bounds of one status: parked and source accounts as a relay's accounts (1000), replicas as `lane.origins` (16). */
export const STACK_AGENT_REPLICAS_MAX = 16;
export const STACK_AGENT_PARKED_MAX = 1000;
export const STACK_AGENT_SOURCES_MAX = 1000;
/** Compose hashes one status lists as accepted: a signed release list names a few (relay-kit `MAX_PAIRING_ACCEPTANCES`). */
export const STACK_AGENT_ACCEPTED_COMPOSE_MAX = 256;
/** Account ids one replica lists: a bundle's accounts (@gray/relay-connector `MAX_ACCOUNTS_PER_BUNDLE`). */
export const STACK_AGENT_ACCOUNT_IDS_MAX = 1000;
/** Where gray-assistant's own page runs (above). */
export const STACK_AGENT_UI_MODES = ["loopback", "public", "tunnel"] as const;
export type StackAgentUiMode = (typeof STACK_AGENT_UI_MODES)[number];
/** The local page's ports: unprivileged ones (gray-assistant binds 127.0.0.1 as its own user); 7470 by default. */
export const STACK_AGENT_UI_PORT_MIN = 1024;
export const STACK_AGENT_UI_PORT_MAX = 65_535;
/** The largest report body the console reads (S45). */
export const STACK_AGENT_STATUS_MAX_BYTES = 256 * 1024;

/** How far ahead of the console's clock `issued_ms` may be, and how old a status may be (S45). */
export const STACK_AGENT_STATUS_MAX_FUTURE_MS = 5 * 60_000;
export const STACK_AGENT_STATUS_MAX_AGE_MS = 60 * 60_000;

/** A closed lower-case word: a replica's last error, a parked account's reason. */
export const STACK_AGENT_WORD = /^[a-z0-9_]{1,64}$/;

/** A source account's vendor and credential type (@gray/relay-connector `VENDORS`, `CREDENTIAL_TYPES`): every stack vendor. */
export const STACK_AGENT_SOURCE_VENDORS = STACK_VENDORS;
export const STACK_AGENT_CREDENTIAL_TYPES = ["api_key", "oauth_access_token"] as const;

const u64 = z.number().int().min(0).max(Number.MAX_SAFE_INTEGER);
const accountId = z.string().regex(STACK_ID_PATTERN);
const accountIds = z.array(accountId).max(STACK_AGENT_ACCOUNT_IDS_MAX);
const word = z.string().regex(STACK_AGENT_WORD);

const replicaSchema = z
  .object({
    origin: z.string().min(1).max(2048).regex(/^[!-~]+$/),
    stack: z.boolean(),
    phase: z.enum(STACK_AGENT_REPLICA_PHASES),
    credential_version: z.string().regex(/^(0|[1-9][0-9]{0,19})$/).nullable(),
    lease_expires_at_ms: u64.nullable(),
    sealed_account_ids: accountIds.nullable(),
    last_push_ms: u64.nullable(),
    last_error: word.nullable(),
  })
  .strict();

const parkedSchema = z.object({ account_id: accountId, reason: word }).strict();

/** The token service's latest refusal of a booting VM (above, `boot`). */
const bootSchema = z
  .object({
    code: z.enum(TOKEN_SERVICE_CODES),
    held: z.boolean(),
    first_ms: u64,
    last_ms: u64,
    count: z.number().int().min(1).max(1_000_000_000),
    compose_hash: z.string().regex(/^[0-9a-f]{64}$/).nullable(),
  })
  .strict()
  .refine((b) => b.first_ms <= b.last_ms, { message: "first_ms is not after last_ms", path: ["first_ms"] });
export type StackAgentBoot = z.infer<typeof bootSchema>;

/**
 * A source account's proxy (`sources[].proxy`): what the lane compares of a panel proxy with the sealed egress member.
 * The host is checked as a panel proxy's is by the console, per account, so one host it would refuse does not refuse
 * the whole status.
 */
const sourceProxySchema = z
  .object({
    type: z.enum(EGRESS_TYPES),
    host: z.string().min(1).max(255).regex(/^[!-~]+$/),
    port: z.number().int().min(1).max(65535),
  })
  .strict();
export type StackAgentSourceProxy = z.infer<typeof sourceProxySchema>;

/** One account the agent's source lists. `credential_type` null when the source does not say. */
const sourceSchema = z
  .object({
    account_id: accountId,
    vendor: z.enum(STACK_AGENT_SOURCE_VENDORS),
    credential_type: z.enum(STACK_AGENT_CREDENTIAL_TYPES).nullable(),
    // The proxy the source declares for the account (its type, host and port; the user name and password stay on the
    // relay's machine and in the VM), null for none. Absent from an older gray-assistant, and for an account whose
    // proxy it would not seal: the console then leaves the account's proxy as it is (`syncSourceProxies`).
    proxy: sourceProxySchema.nullable().optional(),
    // Retired (gray-assistant before 1.4 names the relay login of an `oauth_login` account): taken, never read, and
    // dropped before the status is kept (`withoutRetiredAgentFields`).
    login: z.string().max(64).nullable().optional(),
  })
  .strict();

function unique<T>(items: readonly T[], key: (item: T) => string): boolean {
  return new Set(items.map(key)).size === items.length;
}

/** S45's status document, integers as JS numbers (the console reads the body with `@gray/json` and converts them). */
export const stackAgentStatusSchema = z
  .object({
    relay_id: z.string().regex(STACK_ID_PATTERN),
    issued_ms: u64,
    agent_version: z.string().regex(/^[0-9A-Za-z.+-]{1,64}$/),
    replicas: z.array(replicaSchema).max(STACK_AGENT_REPLICAS_MAX),
    parked: z.array(parkedSchema).max(STACK_AGENT_PARKED_MAX),
    // Retired: gray-assistant before 1.4 reports the Codex logins it refreshed on the relay's machine. Gray refreshes
    // nothing now (docs/design/relay-sign-in-in-vm.md), so the list is taken, never read, and dropped before the status
    // is kept (`withoutRetiredAgentFields`); bounded as it was (a relay's accounts).
    logins: z.array(z.unknown()).max(STACK_AGENT_SOURCES_MAX).optional(),
    // docs/relay-stack-provisioner.md P10: when the read-only registry token gray-assistant hands out ends (its config's
    // `stack.registry.expires_at`), so Gray can tell the relay 14 days before; absent from agents that do not report it.
    registry: z.object({ expires_at_s: u64.nullable() }).strict().optional(),
    sources: z.array(sourceSchema).max(STACK_AGENT_SOURCES_MAX).nullable().optional(),
    // Optional: an agent before the local page sends neither, and neither while the page is off.
    ui_mode: z.enum(STACK_AGENT_UI_MODES).optional(),
    ui_port: z.number().int().min(STACK_AGENT_UI_PORT_MIN).max(STACK_AGENT_UI_PORT_MAX).optional(),
    // Optional: an agent without the relay tunnel (or before it) sends none.
    tunnel: z.enum(TUNNEL_STATES).optional(),
    // Optional: an agent before it sends none; null once a token was issued after the latest refusal.
    boot: bootSchema.nullable().optional(),
    // Optional: an agent before v1.7 sends none; null while the agent has read no release list.
    accepted_compose: z
      .array(z.string().regex(/^[0-9a-f]{64}$/))
      .max(STACK_AGENT_ACCEPTED_COMPOSE_MAX)
      .nullable()
      .optional(),
  })
  .strict()
  .superRefine((s, ctx) => {
    if (s.accepted_compose && !unique(s.accepted_compose, (h) => h)) ctx.addIssue({ code: "custom", path: ["accepted_compose"], message: "a compose hash is listed twice" });
    if ((s.ui_mode === "loopback") !== (s.ui_port !== undefined)) ctx.addIssue({ code: "custom", path: ["ui_port"], message: "ui_port comes with ui_mode loopback, and only with it" });
    if (!unique(s.replicas, (r) => r.origin)) ctx.addIssue({ code: "custom", path: ["replicas"], message: "an origin is listed twice" });
    if (!unique(s.parked, (p) => p.account_id)) ctx.addIssue({ code: "custom", path: ["parked"], message: "an account is listed twice" });
    if (s.sources && !unique(s.sources, (a) => a.account_id)) ctx.addIssue({ code: "custom", path: ["sources"], message: "an account is listed twice" });
  });
export type StackAgentStatus = z.infer<typeof stackAgentStatusSchema>;

/**
 * The status without the members an older gray-assistant still sends and Gray no longer reads (`logins`, a source
 * account's `login`), for the console to keep. The signature is checked over the status as sent, before this.
 */
export function withoutRetiredAgentFields(status: Json): Json {
  if (status === null || typeof status !== "object" || Array.isArray(status)) return status;
  const { logins: _logins, ...rest } = status as { readonly [key: string]: Json };
  const sources = rest["sources"];
  if (!Array.isArray(sources)) return rest;
  return {
    ...rest,
    sources: sources.map((source) => {
      if (source === null || typeof source !== "object" || Array.isArray(source)) return source;
      const { login: _login, ...kept } = source as { readonly [key: string]: Json };
      return kept;
    }),
  };
}

/** The report body: the status and the relay key's signature over `stackAgentStatusMessage(status)`, 128 lower-case hex. */
export const stackAgentStatusReportSchema = z.object({ status: stackAgentStatusSchema, signature: z.string().regex(/^[0-9a-f]{128}$/) }).strict();

/** The first line of the signed message: what the signature is for, so it can be read as nothing else. */
export const STACK_AGENT_STATUS_DOMAIN = "gray-relay-agent-status/v1";

/**
 * The bytes the relay signs: the domain line, then the JCS of the status as JSON (integers as JSON integers, `@gray/json`
 * bigints). Throws (`@gray/attest` `JcsError`) for a value outside JCS's integer subset; a status the schema takes is
 * never one.
 */
export function stackAgentStatusMessage(status: Json): Uint8Array {
  const body = jcsBytes(status);
  const prefix = new TextEncoder().encode(`${STACK_AGENT_STATUS_DOMAIN}\n`);
  const message = new Uint8Array(prefix.length + body.length);
  message.set(prefix, 0);
  message.set(body, prefix.length);
  return message;
}

// The relay stack panel (/provider/stack): the console's /provider/lane-stacks operations
// (workers/console/src/lane-stack/contract.ts; docs/confidential-lane-supply-implementation.md sections 8 and 9 E),
// the words for their values, and the forms' conversions to the bodies the API takes. A relay runs its own software
// as a private image in Gray's confidential VM; this panel holds what the VM serves it, never a secret (S29). Pure data
// and functions, so `node --test` loads it directly.
import { endpointProtocolLabel } from './endpoint-protocols.ts';
import { COMPATIBLE_VENDORS, compatibleRows, type CompatibleVendor } from './lane-vendors.ts';
import type { Status } from './provider-status.ts';

export type StackVendor = 'anthropic' | 'openai' | 'chatgpt_codex' | CompatibleVendor;
export const STACK_VENDORS: readonly StackVendor[] = ['anthropic', 'openai', 'chatgpt_codex', ...COMPATIBLE_VENDORS.map(v => v.id)];
export const VENDOR_LABEL: Readonly<Record<StackVendor, string>> = { anthropic: 'Anthropic', openai: 'OpenAI', chatgpt_codex: 'ChatGPT Codex', ...compatibleRows(v => v.name) };
export const vendorLabel = (vendor: string | null) => vendor && vendor in VENDOR_LABEL ? VENDOR_LABEL[vendor as StackVendor] : vendor ?? 'Unknown vendor';

export type StackWindow = { seconds: number; max_requests: number; max_tokens: number };
/** `expires_ms` is null when the relay set no expiry for its registry token (relay standard v1.7). */
export type StackIssue = { issue_id: string; issued_ms: number; expires_ms: number | null; compose_hash: string; quote_sha256: string; received_ms: number };
/** A restart of the relay's app it asked for (S53): after `gray-assistant stack rollout`, `rollback` or `restart`. */
export type StackRestartRequest = {
  request_id: string; relay_id: string; app_id: string; reason: 'rollout' | 'rollback' | 'restart'; image: string | null;
  issued_ms: number; received_ms: number; status: 'pending' | 'done' | 'failed' | 'superseded'; settled_ms: number | null; detail: string | null;
};
/** What the panel reads of the relay's health: the VM's latest report, with the image this boot runs (S55). */
export type StackVmHealth = { vm: { reported_ms: number; relay_image: string | null } | null };
export type StackRelay = {
  relay_id: string; token_url: string | null; registry: string | null; image: string | null;
  settings: Record<string, unknown>;
  /** Who inserts the relay's appended texts (relay standard v1.7): its container, or Gray's entry in the VM. */
  appends_by: AppendsBy;
  /** Egress's upkeep of each account (`own_calls`): how often it reads rate limits and lists models. */
  own_calls: OwnCalls;
  /**
   * The lane instance's values Gray publishes for the relay's lane.instances (S12): its dstack app ID, origin and node
   * KMS CA key. Null until Gray fills them; the panel shows them and never edits them.
   */
  app_id: string | null; lane_origin: string | null; kms_ca_pubkey: string | null;
  /** Why the lane is not served the configuration as it stands (two routes for one protocol and model, more appended
   *  texts than one request carries); null when it is. */
  config_problem: string | null;
  /** The configuration's version: it grows with every change of what the lane is served, and is each write's precondition. */
  version: number;
  created_ms: number; updated_ms: number;
  /** The workspace's endpoints whose lane record names this relay with mode stack. */
  endpoints: { id: string; name: string; enabled: boolean; vendor: StackVendor | null }[];
  last_pull_token_issue: StackIssue | null;
  /**
   * The first part of the configuration the lane lacks to serve the relay, or `ready` (the console computes it, so the
   * list and the relay's page agree); relay-stack-state.ts laneState adds the gateway's view of the routes.
   */
  lane_state?: 'config_refused' | 'no_endpoint' | 'endpoints_disabled' | 'no_models' | 'no_accounts' | 'accounts_paused' | 'no_account_for_models' | 'ready';
  /** How gray-assistant is paired with this record (S57, relay-stack-pairing.ts); absent from consoles before pairing. */
  pairing?: StackPairing;
  /**
   * 2 when the relay paired with a contract of its own on Base (docs/design/relay-no-always-on-host.md 13.11 P5b): its
   * releases are decided there, on the Releases tab. 1, or absent from consoles before it, otherwise.
   */
  phase?: 1 | 2;
  /** The phase Gray runs the relay on now: a paired relay below it pairs gray-assistant again; absent from consoles before it. */
  phase_wanted?: 1 | 2;
  /**
   * When the registry token gray-assistant hands the VM ends (ms): `registry_expires_at` of the apply or the pairing, then
   * the date `deliver`, `accounts push` or `registry set` reports. Null when the relay set none; absent from consoles before it.
   */
  registry_expires_ms?: number | null;
  /**
   * Gray took the relay out of routing for a non-compliant change to a request or an answer
   * (docs/design/relay-ejection.md); null while it routes, absent from consoles before it.
   */
  ejection?: StackEjection | null;
  /**
   * Where Gray's notices reach the relay's people (the console's contact.ts): `reachable` once an alert e-mail address
   * is confirmed or a webhook is set, `pending` the address that waits for its code, `saved` the address kept
   * unverified where Gray sends no e-mail, `named` when the relay has any address or webhook. Absent from consoles
   * before it.
   */
  contact?: StackContact;
  /** The relay's messages in the console (Gray's notices, on the Messages tab) this member has not seen. Absent from consoles before it. */
  messages?: { unread: number };
};
export type StackContact = { reachable: boolean; pending: string | null; saved?: string | null; named: boolean };
/** An open ejection (`LaneStackEjection`): what the relay's software did, on which request and when; never a value. */
export type StackEjection = {
  violation_id: string;
  kind: 'request' | 'answer';
  code: 'stack_rewrite_refused' | 'stack_header_refused' | 'event_mismatch' | 'event_unrecorded' | 'event_hold_bound' | 'body_mismatch';
  /** The protected body member (`/model`) or the header a request violation named; null for an answer. */
  field: string | null;
  /** Gray's request id (x-request-id) it was found on, or null. */
  request_id: string | null;
  /** When the VM found it, to the minute. */
  at_minute_ms: number;
  ejected_ms: number;
  /** What the relay's software did, in the console's words. */
  reason: string;
  fix: string;
  /** Where the relay asks Gray to restore it (LANE_STACK_EJECTION_CONTACT), null while none is configured; absent from consoles before it. */
  contact?: { text: string; href: string } | null;
};
/** The title over an ejection, the same on Overview and in the alert (@gray/control RELAY_ALERT_WORDS.relay_ejected). */
export const EJECTION_TITLE = 'Gray took your deployment out of routing';
/** The reasons Gray refused a pairing attempt with one of the relay's codes (@gray/control/stack-pairing PAIR_REFUSALS). */
export type PairingRefusalReason = 'used' | 'expired' | 'replaced' | 'signature' | 'key_taken' | 'key_mismatch' | 'locked';
/** The relay record's `pairing`: the latest code (never its value), the key Gray holds, the latest refused attempt, and why no code can be made now. */
export type StackPairing = {
  /** `waiting`: a live code (unused, unexpired, not replaced) exists, even when a key is paired already. */
  state: 'unpaired' | 'waiting' | 'expired' | 'paired';
  code: { created_ms: number; expires_ms: number; used_ms: number | null; replaced_ms: number | null } | null;
  key: { public_key: string; fingerprint: string; source: 'pairing' | 'endpoints'; paired_ms: number | null; paired_from: string | null; agent_version: string | null } | null;
  refusal: { reason: PairingRefusalReason; at_ms: number; from: string | null } | null;
  blocked: { code: 'lane_stack_pairing_locked'; text: string } | null;
};
/** `POST …/pairing-codes`: the code, answered once, the command that pairs with it, and the pairing after it. */
export type PairingCodeAnswer = { code: string; expires_ms: number; command: string; pairing: StackPairing };
export type AccountStatus = 'active' | 'paused';
/** An account's stored client identity (S32a): headers, Anthropic betas and generated ids. Retired 2026-11-18: never sent to the VM. */
export type StackIdentity = { headers: Record<string, string>; betas: string[]; generated: string[] };
export type StackAccount = {
  account_id: string; vendor: StackVendor; labels: string[]; models: string[]; weight: number; max_concurrency: number;
  windows: StackWindow[]; status: AccountStatus; proxy_id: string | null; credential_version: number; created_ms: number; updated_ms: number;
  /** Set through the API (identity and identity_profile are retired: stored, never applied); a save from these pages sends them back as stored. */
  credential_type?: 'api_key' | 'oauth_access_token' | null; identity?: StackIdentity | null; identity_profile?: string | null;
  /** The account's group, a name for the relay's people (docs/design/relay-operator-page.md section 2): never in the lane configuration. */
  group: string | null;
};

// ---------------------------------------------------------------------------
// Account upkeep (docs/relay-changes-v2.md section 6): egress keeps each account up on its own schedule, from Gray's
// vendor table (deploy/tee/egress/vendor-ops-v1.json); the relay sets how often, never what runs. The container reads
// the results with GET $GRAY_EGRESS_URL/v1/relay/account-state.

/** The operations whose cadence the relay sets: reading the vendor's rate limits, and listing its models. */
export type OwnCallOp = 'limits' | 'models';
export const OWN_CALL_OPS: readonly OwnCallOp[] = ['limits', 'models'];
export const OWN_CALL_LABEL: Readonly<Record<OwnCallOp, string>> = { limits: 'Read rate limits', models: 'List models' };
/** The relay record's `own_calls`: per operation, seconds between egress's runs for each account; null Gray's default for the vendor, 0 off. */
export type OwnCalls = { every_seconds: Record<OwnCallOp, number | null> };
export const OWN_CALLS_DEFAULT: OwnCalls = { every_seconds: { limits: null, models: null } };
/** What the console takes besides 0: whole seconds within the widest bounds of the vendor table; egress then holds each vendor to its own. */
export const OWN_CALL_BOUNDS: Readonly<Record<OwnCallOp, { min: number; max: number }>> = { limits: { min: 60, max: 86_400 }, models: { min: 300, max: 86_400 } };
export type OwnCallCadence = { default: number; min: number; max: number };
export type StackCredential = 'api_key' | 'oauth_access_token';
const LOGIN_LIMITS: OwnCallCadence = { default: 300, min: 60, max: 3_600 }, KEY_LIMITS: OwnCallCadence = { default: 900, min: 300, max: 86_400 }, MODELS: OwnCallCadence = { default: 3_600, min: 300, max: 86_400 };
const KEY_MODELS = { api_key: { models: MODELS } }, KEY_BOTH = { api_key: { limits: KEY_LIMITS, models: MODELS } };
/** The vendor table's operations per vendor and credential type, with each cadence's default and bounds (vendor-ops-v1.json `every_seconds`). */
export const OWN_CALL_TABLE: Readonly<Record<StackVendor, Partial<Record<StackCredential, Partial<Record<OwnCallOp, OwnCallCadence>>>>>> = {
  anthropic: { api_key: { models: MODELS }, oauth_access_token: { limits: LOGIN_LIMITS } },
  openai: KEY_MODELS,
  chatgpt_codex: { oauth_access_token: { limits: LOGIN_LIMITS, models: MODELS } },
  gemini: KEY_MODELS, deepseek: KEY_BOTH, moonshot: KEY_BOTH, moonshot_cn: KEY_BOTH, zhipu: { api_key: {} }, zhipu_cn: { api_key: {} },
  minimax: KEY_MODELS, minimax_cn: KEY_MODELS, qwen: KEY_MODELS, qwen_cn: KEY_MODELS,
};
/** An account's credential type as egress keys the table: the declared one, else the vendor's only one; null when that is open. */
export function upkeepCredential(vendor: StackVendor, declared: StackCredential | null | undefined): StackCredential | null {
  if (declared) return declared;
  const types = Object.keys(OWN_CALL_TABLE[vendor] ?? {}) as StackCredential[];
  return types.length === 1 ? types[0] : null;
}
/**
 * What egress runs of one operation for an account (deploy/tee/egress/stack_ops.go): `none` when the vendor's table has
 * no such operation, `off` for 0, else every `seconds`: the relay's value held to the vendor's bounds (`held` when that
 * changed it) or the vendor's default. Null when the credential type decides it and is not declared.
 */
export type OwnCallRun = { kind: 'none' } | { kind: 'off' } | { kind: 'every'; seconds: number; from: 'default' | 'relay' | 'held' };
export function ownCallRun(vendor: StackVendor, declared: StackCredential | null | undefined, op: OwnCallOp, setting: number | null): OwnCallRun | null {
  const type = upkeepCredential(vendor, declared);
  if (type === null) return null;
  const cadence = OWN_CALL_TABLE[vendor]?.[type]?.[op];
  if (!cadence) return { kind: 'none' };
  if (setting === 0) return { kind: 'off' };
  if (setting === null) return { kind: 'every', seconds: cadence.default, from: 'default' };
  const seconds = Math.max(cadence.min, Math.min(setting, cadence.max));
  return { kind: 'every', seconds, from: seconds === setting ? 'relay' : 'held' };
}
export type ProxyType = 'http' | 'https' | 'socks5' | 'socks5h';
export const PROXY_TYPES: readonly ProxyType[] = ['http', 'https', 'socks5', 'socks5h'];
export const PROXY_TYPE_LABEL: Readonly<Record<ProxyType, string>> = { http: 'HTTP', https: 'HTTPS', socks5: 'SOCKS5', socks5h: 'SOCKS5h' };
/** A type as the form offers it: SOCKS5h says what the h is. */
export const PROXY_TYPE_OPTION: Readonly<Record<ProxyType, string>> = { ...PROXY_TYPE_LABEL, socks5h: 'SOCKS5h: the proxy resolves host names' };
/** `last_checks`: the newest answered connection check towards each vendor, newest first. */
export type StackProxy = { proxy_id: string; type: ProxyType; host: string; port: number; credential_version: number; created_ms: number; updated_ms: number; accounts: number; last_checks?: StackProxyCheck[] };
/**
 * A proxy connection check (`…/proxies/{id}/checks`): the lane in the relay's VM dials the proxy with its sealed
 * credential, tunnels to the vendor's API host and completes a TLS handshake, sending no request (@gray/lane-wire
 * `stack.proxy_checks`). `outcome` is null while it is pending; one the VM did not answer within
 * LANE_STACK_PROXY_CHECK_EXPIRY_MS of being queued (120 s by default, configurable) is `expired`, and another can be
 * asked for.
 */
export type StackProxyCheck = {
  check_id: string; proxy_id: string; vendor: StackVendor; state: 'pending' | 'answered' | 'expired'; requested_ms: number; requested_by: string;
  outcome: 'ok' | 'failed' | null; code: string | null; latency_ms: number | null; checked_ms: number | null; answered_ms: number | null;
};
export type StackRoute = { endpoint_id: string; endpoint_enabled: boolean; requested_model: string; upstream_model: string; vendor: StackVendor; protocol: string; visible: boolean };
export type AppendPosition = 'system_start' | 'system_end' | 'instructions_before' | 'instructions_after';
export type StackAppend = { append_id: string; position: AppendPosition; text: string; sha256: string; created_ms: number; updated_ms: number };
export type StackUsageRow = {
  /** With `bucket`: the start of the UTC hour or day the row covers. */
  bucket_ms?: number;
  account_id: string; model: string; requests: number; completed: number; success_rate: number | null;
  input_tokens: number; output_tokens: number; cache_read_tokens: number; cache_write_tokens: number;
  mean_duration_ms: number | null; mean_ttft_ms: number | null;
};
/** `bucket_ms` is the step of a read with `bucket` (an hour or a day), null without one. */
export type StackUsage = { from_ms: number; to_ms: number; bucket_ms?: number | null; rows: StackUsageRow[] };
export type StackConfigWindow = StackWindow & { used_requests: number; used_tokens: number };
/**
 * `GET …/config`: the configuration the lane would be served now, with each window's used counters (S31), and when
 * each window at a maximum frees if no request comes meanwhile (`limits`; null when the kept minutes cannot say).
 */
export type StackConfigAnswer = {
  relay_id: string; version: number; digest: string;
  config: { accounts: { id: string; windows: StackConfigWindow[] }[]; used_at_ms: number } | null;
  limits?: { account_id: string; seconds: number; frees_at_ms: number | null }[];
};
/** An entry of a relay's change history (`GET …/audit`). */
export type StackAuditEntry = { id: string; actor_user_id: string; action: string; target: string; details: Record<string, unknown> | null; created_ms: number };
/** The relay kit Gray published (RELAY_KIT_URL, RELAY_KIT_SHA256, RELAY_CONFORMANCE_IMAGE); null until it is. */
export type StackKit = { url: string; sha256: string; conformance_image: string | null };
/** `GET /provider/lane-stacks`: the workspace's relays, the kit and where the standard is (RELAY_STANDARD_URL). */
export type StackList = { relays: StackRelay[]; kit?: StackKit | null; standard_url?: string | null };

/**
 * What "Copy agent instructions" in Build your image copies: a prompt for the relay's coding agent (Claude Code, Codex,
 * …) to port the software in its current directory from the standard (Gray ships no ready-made port), following the
 * kit's AGENTS.md stages 1 to 3 (port, conformance,
 * push), and to report the pushed image by digest, which the operator pins in Pin your image. AGENTS.md has the rest.
 * With a provider setup code (`setup`), the agent claims it first and then sets the relay up on Gray itself through
 * relay-stack.md (register, pair, pin, models, prices, VM), so one paste covers the whole flow.
 */
export function buildInstructions(kit: StackKit, standardUrl: string | null, setup?: { code: string; until: string; guideUrl: string } | null): string {
  if (setup) {
    return [
      'Port the software in the current directory to Gray\'s integration standard, as a private Docker image that runs in Gray\'s confidential VM, then set it up on Gray.',
      '',
      `1. First claim the one-time provider setup code ${setup.code} (valid until ${setup.until}, single use) as ${setup.guideUrl} step 1 says, before anything else.`,
      `2. Download Gray's kit from ${kit.url} into a new directory outside this repository. Check that its SHA-256 is ${kit.sha256} (sha256sum, or shasum -a 256 on macOS) and stop if it is not. Then unpack it there.`,
      `3. Read the kit's AGENTS.md (deploy/relay/kit/AGENTS.md in the unpacked kit)${standardUrl ? ` and the standard it points to, ${standardUrl}` : ''}. Follow its stages 1 to 3 on the software here: port it to the standard yourself, pass Gray's conformance tool${kit.conformance_image ? ` (the image ${kit.conformance_image}, where AGENTS.md says gray-conformance)` : ''}, and push the image to my private registry.`,
      '4. Never send a credential, token or key anywhere, never put one in the image, and never print one. If pushing needs a registry login, log in with docker login --password-stdin from the registry-password file without reading it, or ask me to log in.',
      `5. When conformance passes on the pushed image, follow ${setup.guideUrl} from step 3: ask me for the deployment's name, an e-mail address Gray may write to about this deployment (release proposals, the traffic window, VM and account problems go there; if Gray sends it a 6-digit code, ask me for it and apply it) and how long a Gray release should wait for my veto (its release delay); draft the model table (Gray model ID, vendor, the vendor's name, price) from the models and prices this software already has configured, read-only, with the guide's relay-models.json for Gray's model IDs and reference prices, and show me the whole table to confirm once (I may change all prices at once or drop rows) before you apply it; then register the deployment, pin the image by digest, pair gray-assistant on my machine, connect gray-assistant to this software's accounts, add the models and prices I confirmed, ask Gray for the VM, and wait for Gray. Every time you read the guide's status, read its messages first and tell me what Gray says in them (a release to approve, a Deploy I can make now, a problem); once you told me, mark them seen as the guide says, so you do not tell me the same ones again. If the deployment already exists on Gray, the guide's status says what it needs (an older pairing pairs gray-assistant again). If you may write only in one directory, point HOME at a directory inside it first. Never ask me for an account key.`,
    ].join('\n');
  }
  return [
    'Port the software in the current directory to Gray\'s integration standard, as a private Docker image that runs in Gray\'s confidential VM.',
    '',
    `1. Download Gray's kit from ${kit.url} into a new directory outside this repository. Check that its SHA-256 is ${kit.sha256} (sha256sum, or shasum -a 256 on macOS) and stop if it is not. Then unpack it there.`,
    `2. Read the kit's AGENTS.md (deploy/relay/kit/AGENTS.md in the unpacked kit)${standardUrl ? ` and the standard it points to, ${standardUrl}` : ''}. Follow its stages 1 to 3 on the software here: port it to the standard yourself, pass Gray's conformance tool${kit.conformance_image ? ` (the image ${kit.conformance_image}, where AGENTS.md says gray-conformance)` : ''}, and push the image to my private registry.`,
    '3. Never send a credential, token or key anywhere, never put one in the image, and never print one. If pushing needs a registry login, log in with docker login --password-stdin from the registry-password file without reading it, or ask me to log in.',
    '4. When conformance passes on the pushed image, tell me its reference by digest (registry/path@sha256:...) and the conformance result. I paste the reference into "Pin your image" on Gray\'s console.',
  ].join('\n');
}

// ---------------------------------------------------------------------------
// Addresses and the write precondition

const BASE = '/provider/lane-stacks';
export const STACKS_PATH = BASE;
/** A relay's operation path under /api/v1: `stackPath('relay-1', 'accounts', 'acct')`. */
export const stackPath = (relayId: string, ...rest: string[]) => [BASE, ...[relayId, ...rest].map(encodeURIComponent)].join('/');
/** The panel's own address: `/provider/stack/<relay>/<tab>`. */
export const stackHref = (relayId?: string, tab?: string) => `/provider/stack${relayId ? `/${encodeURIComponent(relayId)}${tab && tab !== 'overview' ? `/${tab}` : ''}` : ''}`;
/**
 * A write's precondition: the relay's configuration version the edit started from, as an RFC 9110 entity tag (the
 * console's translation rules send theirs the same way). A write against a version that moved on is refused with 412.
 */
export const ifMatch = (version: number): Record<string, string> => ({ 'If-Match': `"${version}"` });
/** A write refused because the relay changed after the version it named was read (412 lane_stack_version_conflict). */
export const isStale = (error: unknown) => (error as { status?: unknown } | null)?.status === 412;
/** A relay deletion refused while an endpoint that uses the relay is enabled. */
export const RELAY_IN_USE = 'lane_stack_relay_in_use';
/** A registration refused because the relay ID's tunnel label reads as Gray's own or a mail or network service (S60). */
export const RELAY_ID_RESERVED = 'lane_stack_relay_id_reserved';
/** A registration refused because the workspace has a relay with this ID already (409). */
export const RELAY_EXISTS = 'lane_stack_relay_exists';
/** A relay ID's rule (@gray/control stack.ts): 1 to 128 of A-Z a-z 0-9 . _ : -. */
export const RELAY_ID = /^[A-Za-z0-9._:-]{1,128}$/;
/**
 * The relay ID a name gives: its letters and digits, accents dropped (Unicode NFKD), lower case, every other run as one
 * hyphen, at most 63 characters (one DNS label: the relay tunnel's name is the ID). '' when nothing is left.
 */
export function relayIdFrom(name: string): string {
  return name.normalize('NFKD').replace(/\p{M}/gu, '').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 63).replace(/-+$/, '');
}
/** `id`, or the first of `id-2`, `id-3`, … that `taken` does not hold. */
export function freeRelayId(id: string, taken: ReadonlySet<string>): string {
  if (!taken.has(id)) return id;
  for (let n = 2; ; n++) { const next = `${id.slice(0, 63 - String(n).length - 1)}-${n}`; if (!taken.has(next)) return next; }
}
/** Where anyone reads the texts a relay may append, on the model API's host (no session or key). */
export const publicAppendsUrl = (apiOrigin: string, relayId: string) => `${apiOrigin}/v1/lane-stack/relays/${encodeURIComponent(relayId)}/appends`;

// ---------------------------------------------------------------------------
// Words

export const STATUS_WORDS: Readonly<Record<AccountStatus, Status>> = { active: { label: 'Active', tone: 'success' }, paused: { label: 'Paused', tone: 'neutral' } };
export const POSITION_LABEL: Readonly<Record<AppendPosition, string>> = {
  system_start: 'Start of the system prompt',
  system_end: 'End of the system prompt',
  instructions_before: 'Before the instructions',
  instructions_after: 'After the instructions',
};
/** Which client APIs each position applies to (@gray/lane protocol.ts). */
export const POSITION_APIS: Readonly<Record<AppendPosition, string>> = {
  system_start: 'Anthropic Messages', system_end: 'Anthropic Messages',
  instructions_before: 'OpenAI Chat and Responses', instructions_after: 'OpenAI Chat and Responses',
};
export const APPEND_POSITIONS = Object.keys(POSITION_LABEL) as AppendPosition[];
/** An appended text's bound: everything one request may have appended (@gray/lane DEFAULT_MAX_TOTAL_BYTES). */
export const APPEND_MAX_BYTES = 8192;
/** S30: the relay's own settings are a JSON object of at most 64 KiB. */
export const SETTINGS_MAX_BYTES = 64 * 1024;
/** The longest limit window: 7 days, the subscriptions' weekly limits (@gray/control LANE_STACK_WINDOW_MAX_SECONDS). */
export const WINDOW_MAX_SECONDS = 7 * 86_400;

export const utf8Length = (text: string) => new TextEncoder().encode(text).length;
/** A credential version: 0 lets the lane take any sealed version. */
export const credentialText = (version: number) => version === 0 ? 'Any version' : `Version ${version}`;
/** The first 12 digits of a hash (after its `sha256:` when it names one), for a cell; the whole hash goes in its tooltip and copy button. */
export function shortHash(hash: string) {
  const prefix = hash.startsWith('sha256:') ? 'sha256:' : '', hex = hash.slice(prefix.length);
  return hex.length > 12 ? `${prefix}${hex.slice(0, 12)}…` : hash;
}
/** `repo@sha256:<64 hex>` as its repository and digest. */
export function imageParts(image: string): { repository: string; digest: string } {
  const at = image.lastIndexOf('@');
  return at < 0 ? { repository: image, digest: '' } : { repository: image.slice(0, at), digest: image.slice(at + 1) };
}
export const routeLabel = (route: Pick<StackRoute, 'protocol'>) => endpointProtocolLabel(route.protocol);

/**
 * A model the relay adds on Models (`PUT …/models`, workers/console/src/lane-stack/models.ts): the Gray model ID
 * customers call, the vendor's own name for it, and the vendor. Gray makes the vendor's stack endpoint and fills its
 * address, paths and protocols; the relay names none of them.
 */
export type ModelForm = { vendor: StackVendor; model: string; upstream: string };
export type StackModelAnswer = { endpoint_id: string; created: boolean; changed: boolean };
/** Whose catalog models each vendor serves: the Codex backend serves OpenAI's, an OpenAI-compatible vendor its own. */
export const VENDOR_PUBLISHER: Readonly<Record<StackVendor, string>> = { anthropic: 'anthropic', openai: 'openai', chatgpt_codex: 'openai', ...compatibleRows(v => v.publisher) };
/** The vendor's name suggested for a Gray model ID (vendor-model-name.ts, which the console's relay-models.json shares). */
export { stackServes, vendorModelName, vendorRetired } from './vendor-model-name.ts';
/** `PUT …/models`'s body; throws the sentence to show for a field left empty. */
export function modelInput(form: ModelForm): { vendor: StackVendor; requested_model: string; upstream_model: string } {
  const requested = form.model.trim(), upstream = form.upstream.trim();
  if (!requested) throw new Error('Choose the Gray model customers call.');
  if (!upstream) throw new Error('Give the vendor’s name for the model, the one your accounts call.');
  return { vendor: form.vendor, requested_model: requested, upstream_model: upstream };
}

const UNITS = [['day', 86_400], ['hour', 3600], ['minute', 60], ['second', 1]] as const;
/** A window's length in the largest unit that holds it whole: "5 hours", "7 days", "90 minutes". */
export function windowName(seconds: number) {
  const [unit, size] = UNITS.find(([, size]) => seconds % size === 0) ?? UNITS[3];
  const n = seconds / size;
  return `${n.toLocaleString('en-US')} ${unit}${n === 1 ? '' : 's'}`;
}
/** Why a proxy check failed, in words (@gray/lane-wire PROXY_CHECK_CODES). */
export const CHECK_FAILURE: Readonly<Record<string, string>> = {
  // The lane holds a proxy's credential only through a sealed account that uses the proxy.
  credential_missing: 'The lane has no credential for this proxy yet. Check it after an account that uses it has been sent with gray-assistant.',
  // A proxy at a private or internal address is refused at egress's dial and reads as this (deploy/tee/egress dial_guard.go).
  proxy_unreachable: 'The VM could not connect to the proxy. Use its public address: private and internal addresses (such as 10.x, 192.168.x, 127.x) are not allowed.',
  proxy_auth_failed: 'The proxy refused its user name and password.',
  proxy_refused: 'The proxy refused to open a tunnel to the vendor.',
  upstream_unreachable: 'The proxy could not reach the vendor.',
  tls_failed: 'The vendor’s TLS handshake failed or its certificate did not verify.',
  timeout: 'No answer in time.',
};
/** A check's state and what it found, in words. */
export function checkResult(check: Pick<StackProxyCheck, 'vendor' | 'state' | 'outcome' | 'code' | 'latency_ms'>): { status: Status; detail: string } {
  if (check.state === 'expired') return { status: { label: 'No answer', tone: 'warning' }, detail: 'Your VM did not answer in time. Is it running? Run the check again.' };
  if (check.outcome === null) return { status: { label: 'Pending', tone: 'info' }, detail: 'Waiting for your VM to run it.' };
  if (check.outcome === 'ok') return { status: { label: 'OK', tone: 'success' }, detail: `Reached ${VENDOR_LABEL[check.vendor]}${check.latency_ms == null ? '' : ` in ${check.latency_ms.toLocaleString('en-US')} ms`}.` };
  return { status: { label: 'Failed', tone: 'danger' }, detail: (check.code && CHECK_FAILURE[check.code]) ?? `The check failed (${check.code ?? 'no reason given'}).` };
}

/** A limit's use: "120 of 500", or "120 · no limit" for a maximum of 0. */
export const usedText = (used: number, max: number) => max === 0 ? `${used.toLocaleString('en-US')} · no limit` : `${used.toLocaleString('en-US')} of ${max.toLocaleString('en-US')}`;

// ---------------------------------------------------------------------------
// Form values → request bodies. Each conversion throws an Error whose message the form shows.

const ID_PATTERN = /^[A-Za-z0-9._:-]{1,128}$/;
const ID_RULE = '1 to 128 letters, digits and . _ : -';
function checkId(value: string, what: string) {
  if (!ID_PATTERN.test(value)) throw new Error(`${what}: use ${ID_RULE}.`);
  return value;
}
/** A whole number typed in a field ('' is `empty`), from `min`. */
function whole(text: string, what: string, { min = 0, max = Number.MAX_SAFE_INTEGER, empty }: { min?: number; max?: number; empty?: number } = {}) {
  const value = text.replace(/,/g, '').trim();
  if (value === '' && empty !== undefined) return empty;
  // A bound far beyond any real value (a u32) is not worth naming.
  const range = max <= 1_000_000 ? ` from ${min.toLocaleString('en-US')} to ${max.toLocaleString('en-US')}` : min > 0 ? ` from ${min}` : '';
  if (!/^\d+$/.test(value) || Number(value) < min || Number(value) > max) throw new Error(`${what} is a whole number${range}.`);
  return Number(value);
}
/** Comma-separated labels. */
export const labelList = (text: string) => text.split(',').map(label => label.trim()).filter(Boolean);
const optional = (text: string) => text.trim() === '' ? null : text.trim();

export type AccountInput = {
  vendor: StackVendor; labels: string[]; models: string[]; weight: number; max_concurrency: number;
  windows: StackWindow[]; status: AccountStatus; proxy_id: string | null; credential_version: number;
  credential_type: 'api_key' | 'oauth_access_token' | null; identity: StackIdentity | null; identity_profile: string | null;
};
/** What a save keeps of the stored account besides the form's fields: the API replaces an account whole. */
export type AccountKept = { credential_type: AccountInput['credential_type']; identity: StackIdentity | null; identity_profile: string | null };
export const keptOf = (a: StackAccount | undefined): AccountKept => ({ credential_type: a?.credential_type ?? null, identity: a?.identity ?? null, identity_profile: a?.identity_profile ?? null });
export type AccountForm = { id: string; vendor: StackVendor; models: string[]; labels: string; weight: string; concurrency: string; proxy: string; credentialVersion: string; status: AccountStatus };
export const blankAccount: AccountForm = { id: '', vendor: 'anthropic', models: [], labels: '', weight: '1', concurrency: '', proxy: '', credentialVersion: '0', status: 'active' };
export const accountForm = (a: StackAccount): AccountForm => ({
  id: a.account_id, vendor: a.vendor, models: [...a.models], labels: a.labels.join(', '), weight: String(a.weight), concurrency: String(a.max_concurrency),
  proxy: a.proxy_id ?? '', credentialVersion: String(a.credential_version), status: a.status,
});
/** An account's whole body: the API replaces an account whole, so a change of one part sends the rest as stored. */
export const accountBody = (a: StackAccount, change: Partial<AccountInput> = {}): AccountInput => ({
  vendor: a.vendor, labels: a.labels, models: a.models, weight: a.weight, max_concurrency: a.max_concurrency, windows: a.windows,
  status: a.status, proxy_id: a.proxy_id, credential_version: a.credential_version, ...keptOf(a), ...change,
});
/** The account form's body; `windows` are the account's as stored (they are edited under Limits), and so is `kept`. */
export function accountInput(form: AccountForm, windows: StackWindow[], kept: AccountKept = keptOf(undefined)): { id: string; input: AccountInput } {
  const id = checkId(form.id.trim(), 'Account ID');
  const labels = labelList(form.labels);
  if (!labels.every(label => ID_PATTERN.test(label)) || new Set(labels).size !== labels.length) throw new Error(`Labels: each is ${ID_RULE}, with no label twice.`);
  return {
    id,
    input: {
      vendor: form.vendor, labels, models: [...new Set(form.models)],
      weight: whole(form.weight, 'Weight', { min: 1, max: 4_294_967_295 }), max_concurrency: whole(form.concurrency, 'Concurrency', { min: 1, max: 4_294_967_295 }),
      windows, status: form.status, proxy_id: form.proxy || null, credential_version: whole(form.credentialVersion, 'Credential version', { empty: 0 }),
      ...kept,
    },
  };
}

export type WindowUnit = 'seconds' | 'minutes' | 'hours' | 'days';
export const WINDOW_UNITS: readonly WindowUnit[] = ['minutes', 'hours', 'days', 'seconds'];
const UNIT_SECONDS: Readonly<Record<WindowUnit, number>> = { seconds: 1, minutes: 60, hours: 3600, days: 86_400 };
export type WindowForm = { length: string; unit: WindowUnit; requests: string; tokens: string };
export const blankWindow: WindowForm = { length: '', unit: 'hours', requests: '', tokens: '' };
export function windowForm(w: StackWindow): WindowForm {
  const unit = (['days', 'hours', 'minutes', 'seconds'] as const).find(u => w.seconds % UNIT_SECONDS[u] === 0) ?? 'seconds';
  return { length: String(w.seconds / UNIT_SECONDS[unit]), unit, requests: w.max_requests ? String(w.max_requests) : '', tokens: w.max_tokens ? String(w.max_tokens) : '' };
}
/** A typed window's length in seconds, or null while it is not a whole number. */
export const windowSeconds = (form: Pick<WindowForm, 'length' | 'unit'>) => /^\d+$/.test(form.length.replace(/,/g, '').trim()) ? Number(form.length.replace(/,/g, '').trim()) * UNIT_SECONDS[form.unit] : null;
/** The windows typed: lengths from 1 second to 7 days, each length once; a blank maximum is none (0). */
export function windowsInput(forms: WindowForm[]): StackWindow[] {
  const windows = forms.map((form, index) => {
    const what = forms.length > 1 ? `Window ${index + 1}: ` : '';
    const seconds = whole(form.length, `${what}Length`, { min: 1 }) * UNIT_SECONDS[form.unit];
    if (seconds > WINDOW_MAX_SECONDS) throw new Error(`${what}A window is at most 7 days long.`);
    return { seconds, max_requests: whole(form.requests, `${what}Max requests`, { empty: 0 }), max_tokens: whole(form.tokens, `${what}Max tokens`, { empty: 0 }) };
  });
  if (new Set(windows.map(w => w.seconds)).size !== windows.length) throw new Error('Two windows have the same length; give each window its own length.');
  return windows;
}

export type ProxyInput = { type: ProxyType; host: string; port: number; credential_version: number };
export type ProxyForm = { id: string; type: ProxyType; host: string; port: string; credentialVersion: string };
export const blankProxy: ProxyForm = { id: '', type: 'socks5', host: '', port: '', credentialVersion: '0' };
export const proxyForm = (p: StackProxy): ProxyForm => ({ id: p.proxy_id, type: p.type, host: p.host, port: String(p.port), credentialVersion: String(p.credential_version) });
export function proxyInput(form: ProxyForm): { id: string; input: ProxyInput } {
  const id = checkId(form.id.trim(), 'Proxy ID'), host = form.host.trim();
  // The sidecar's own rule (@gray/relay-connector isValidEgressHost) is the server's; this catches a pasted URL.
  if (!host || /[\s/@[\]]/.test(host) || host.includes('://')) throw new Error('Host: a name or an IP address, without a scheme, user, port or path.');
  return { id, input: { type: form.type, host, port: whole(form.port, 'Port', { min: 1, max: 65_535 }), credential_version: whole(form.credentialVersion, 'Credential version', { empty: 0 }) } };
}

export type AppendInput = { position: AppendPosition; text: string };
export type AppendForm = { id: string; position: AppendPosition; text: string };
export const blankAppend: AppendForm = { id: '', position: 'system_end', text: '' };
export const appendForm = (a: StackAppend): AppendForm => ({ id: a.append_id, position: a.position, text: a.text });
export function appendInput(form: AppendForm): { id: string; input: AppendInput } {
  const id = checkId(form.id.trim(), 'Text ID');
  if (form.text === '') throw new Error('Write the text to append.');
  if (utf8Length(form.text) > APPEND_MAX_BYTES) throw new Error(`The text is ${utf8Length(form.text).toLocaleString('en-US')} bytes; the limit is ${APPEND_MAX_BYTES.toLocaleString('en-US')}.`);
  return { id, input: { position: form.position, text: form.text } };
}

export type AppendsBy = 'relay' | 'gray';
export const APPENDS_BY_LABEL: Record<AppendsBy, string> = { relay: 'Your software', gray: 'Gray, before your software' };

/** The relay's own record. The lane app ID, origin and KMS key are Gray's (set by Gray's operators), not in it. */
export type RelayInput = { token_url: string | null; registry: string | null; image: string | null; settings: Record<string, unknown>; appends_by: AppendsBy; own_calls: OwnCalls };
/** One operation's cadence as the form holds it: Gray's default, off, or every `seconds` the relay typed. */
export type OwnCallForm = { mode: 'default' | 'off' | 'every'; seconds: string };
export const ownCallForm = (value: number | null | undefined): OwnCallForm =>
  value === null || value === undefined ? { mode: 'default', seconds: '' } : value === 0 ? { mode: 'off', seconds: '' } : { mode: 'every', seconds: String(value) };
export type RelayForm = { relayId: string; tokenUrl: string; registry: string; image: string; settings: string; appendsBy: AppendsBy; ownCalls: Record<OwnCallOp, OwnCallForm> };
/** Days before a registry token's end that the panel warns, as the relay's alert does (console alerts.ts REGISTRY_WARN_DAYS). */
export const REGISTRY_WARN_DAYS = 14;
/**
 * The registry token's end as the panel shows it: null when the relay set none; `ended` once it is past (no boot gets the
 * token then), `soon` within REGISTRY_WARN_DAYS, else `ok`.
 */
export function registryExpiry(relay: Pick<StackRelay, 'registry_expires_ms'>, now: number): { ms: number; state: 'ok' | 'soon' | 'ended' } | null {
  const ms = relay.registry_expires_ms ?? null;
  if (ms === null) return null;
  return { ms, state: ms <= now ? 'ended' : ms - now < REGISTRY_WARN_DAYS * 86_400_000 ? 'soon' : 'ok' };
}
/** The command that seals a new registry token's login and reports its new end (phase 2, in the kit directory). */
export const REGISTRY_SET_COMMAND = 'docker compose run --rm --no-deps agent registry set';

export const blankRelay: RelayForm = { relayId: '', tokenUrl: '', registry: '', image: '', settings: '{}', appendsBy: 'relay', ownCalls: { limits: ownCallForm(null), models: ownCallForm(null) } };
export const relayForm = (r: StackRelay): RelayForm => ({
  relayId: r.relay_id, tokenUrl: r.token_url ?? '', registry: r.registry ?? '', image: r.image ?? '', settings: JSON.stringify(r.settings ?? {}, null, 2), appendsBy: r.appends_by ?? 'relay',
  ownCalls: { limits: ownCallForm(r.own_calls?.every_seconds.limits), models: ownCallForm(r.own_calls?.every_seconds.models) },
});
/** The form's cadences: null for Gray's default, 0 for off, else whole seconds within OWN_CALL_BOUNDS. */
export function ownCallsInput(form: Record<OwnCallOp, OwnCallForm>): OwnCalls {
  const one = (op: OwnCallOp) => {
    const { mode, seconds } = form[op];
    if (mode === 'default') return null;
    if (mode === 'off') return 0;
    const { min, max } = OWN_CALL_BOUNDS[op], value = seconds.replace(/,/g, '').trim();
    if (!/^\d+$/.test(value) || Number(value) < min || Number(value) > max) throw new Error(`${OWN_CALL_LABEL[op]} every: a whole number of seconds from ${min.toLocaleString('en-US')} to ${max.toLocaleString('en-US')}, or choose Off.`);
    return Number(value);
  };
  return { every_seconds: { limits: one('limits'), models: one('models') } };
}
/** The relay's own record; blank fields are not named yet (null). The server holds the exact rules (@gray/control stack.ts). */
export function relayInput(form: RelayForm): RelayInput {
  const token_url = optional(form.tokenUrl), registry = optional(form.registry), image = optional(form.image);
  if (token_url !== null && !/^https:\/\/[^/?#\s]+\/?$/.test(token_url)) throw new Error('Pull-token service: an https origin such as https://tokens.example.com, without a path, or leave it empty to use the tunnel.');
  if (registry !== null && /[/\s@]|:\/\//.test(registry)) throw new Error('Registry: a host name with an optional port, as docker login takes it, without a scheme or path.');
  if (image !== null && !/@sha256:[0-9a-f]{64}$/.test(image)) throw new Error('Image: pin it by digest, <repository>@sha256:<64 hex digits>.');
  let settings: unknown;
  try { settings = JSON.parse(form.settings.trim() || '{}'); } catch { throw new Error('Settings: not valid JSON.'); }
  if (!settings || typeof settings !== 'object' || Array.isArray(settings)) throw new Error('Settings: a JSON object, {…}.');
  if (utf8Length(JSON.stringify(settings)) > SETTINGS_MAX_BYTES) throw new Error('Settings: at most 64 KiB.');
  return { token_url, registry, image, settings: settings as Record<string, unknown>, appends_by: form.appendsBy, own_calls: ownCallsInput(form.ownCalls) };
}

// ---------------------------------------------------------------------------
// The lane's state

/** The upstream models the relay's routes call for `vendor`: the models an account of that vendor can list. */
export function upstreamModels(routes: readonly StackRoute[], vendor: StackVendor) {
  return [...new Set(routes.filter(route => route.vendor === vendor).map(route => route.upstream_model))].sort();
}
/** The active accounts that can serve a route: same vendor, and its upstream model in their list. */
export const servingAccounts = (route: StackRoute, accounts: readonly StackAccount[]) =>
  accounts.filter(a => a.status === 'active' && a.vendor === route.vendor && a.models.includes(route.upstream_model));

// ---------------------------------------------------------------------------
// Usage

/**
 * The usage ranges: the last hour, and calendar days in the reader's time zone (C9): today so far, yesterday, and the
 * last seven days with today so far. Each is compared with the span just before it of the same length, today with
 * yesterday up to the same time.
 */
export type UsageRange = '1h' | 'today' | 'yesterday' | '7d';
export const USAGE_RANGES: readonly { value: UsageRange; label: string }[] = [
  { value: '1h', label: 'Last hour' }, { value: 'today', label: 'Today' }, { value: 'yesterday', label: 'Yesterday' }, { value: '7d', label: 'Last 7 days' },
];
const HOUR = 3_600_000;
/** The reader's midnight `back` days before the day holding `now`. */
export function dayStart(now: number, back = 0) {
  const day = new Date(now);
  return new Date(day.getFullYear(), day.getMonth(), day.getDate() - back).getTime();
}
export type UsageSpan = {
  from: number; to: number;
  /** The span compared with: the same length just before (today: yesterday up to the same time). */
  previous: { from: number; to: number };
  /** The chart's step: hours over one day, the reader's days over seven, none over an hour. */
  bucket: 'hour' | 'day' | null;
  /** Whether the span ends now, in the middle of a day. */
  partial: boolean;
  /** "the last hour", "today so far", "yesterday", "the last 7 days". */
  period: string;
  /** "vs previous hour", "vs yesterday at this time". */
  versus: string;
};
export function usageSpan(range: UsageRange, now: number): UsageSpan {
  const today = dayStart(now), sinceMidnight = now - today;
  switch (range) {
    case '1h': return { from: now - HOUR, to: now, previous: { from: now - 2 * HOUR, to: now - HOUR }, bucket: null, partial: false, period: 'the last hour', versus: 'vs the hour before' };
    case 'today': return { from: today, to: now, previous: { from: dayStart(now, 1), to: dayStart(now, 1) + sinceMidnight }, bucket: 'hour', partial: true, period: 'today so far', versus: 'vs yesterday at this time' };
    case 'yesterday': return { from: dayStart(now, 1), to: today - 1, previous: { from: dayStart(now, 2), to: dayStart(now, 1) - 1 }, bucket: 'hour', partial: false, period: 'yesterday', versus: 'vs the day before' };
    case '7d': return { from: dayStart(now, 6), to: now, previous: { from: dayStart(now, 13), to: dayStart(now, 7) + sinceMidnight }, bucket: 'day', partial: true, period: 'the last 7 days', versus: 'vs the 7 days before' };
  }
}
/** The usage read of `[from, to]`, by hour with `bucket`. The server counts the minute that holds `to`, so a whole day
 *  ends a millisecond before the next midnight. */
export const usageTarget = (relayId: string, from: number, to: number, bucket?: 'hour') =>
  `${stackPath(relayId, 'usage')}?from_ms=${from}&to_ms=${to}${bucket ? `&bucket=${bucket}` : ''}`;
/** The seven days of the 7-day range, oldest first: each the reader's whole day, today up to now. */
export const usageDays = (now: number) => Array.from({ length: 7 }, (_, index) => ({ from: dayStart(now, 6 - index), to: index === 6 ? now : dayStart(now, 5 - index) - 1, today: index === 6 }));
/** Whether an answer covers the span asked for: the server starts at the oldest minute it keeps. */
export const coversSpan = (usage: StackUsage, from: number) => usage.from_ms <= from - (from % 60_000);
/** The reader's time zone as charts and ranges name it: "GMT+8". */
export function timeZoneLabel(now: number) {
  const offset = new Intl.DateTimeFormat('en-US', { timeZoneName: 'shortOffset' }).formatToParts(new Date(now)).find(part => part.type === 'timeZoneName')?.value;
  return !offset ? 'local time' : offset === 'GMT' || offset === 'GMT+0' ? 'UTC' : offset;
}

export type UsageTotals = { requests: number; completed: number; input: number; output: number; cacheRead: number; cacheWrite: number; durationMs: number | null };
/** Sums of rows; the mean duration is weighted by each row's completed requests, which its mean is over. */
export function usageTotals(rows: readonly StackUsageRow[]): UsageTotals {
  let requests = 0, completed = 0, input = 0, output = 0, cacheRead = 0, cacheWrite = 0, duration = 0, timed = 0;
  for (const row of rows) {
    requests += row.requests; completed += row.completed; input += row.input_tokens; output += row.output_tokens;
    cacheRead += row.cache_read_tokens; cacheWrite += row.cache_write_tokens;
    if (row.mean_duration_ms != null) { duration += row.mean_duration_ms * row.completed; timed += row.completed; }
  }
  return { requests, completed, input, output, cacheRead, cacheWrite, durationMs: timed ? duration / timed : null };
}
/** Rows summed per account or per model, most requests first. */
export function usageBy(rows: readonly StackUsageRow[], key: 'account_id' | 'model'): (UsageTotals & { key: string })[] {
  const groups = new Map<string, StackUsageRow[]>();
  for (const row of rows) groups.set(row[key], [...groups.get(row[key]) ?? [], row]);
  return [...groups].map(([name, list]) => ({ key: name, ...usageTotals(list) })).sort((a, b) => b.requests - a.requests || a.key.localeCompare(b.key));
}
/**
 * A duration as the request logs write one (request-logs.ts durationText): milliseconds under a second, seconds with
 * one decimal from there ("820 ms", "12.2 s"); "—" when nothing was measured.
 */
export function secondsText(ms: number | null | undefined) {
  if (ms == null || !Number.isFinite(ms)) return '—';
  return ms < 1000 ? `${Math.round(ms)} ms` : `${(ms / 1000).toLocaleString('en-US', { minimumFractionDigits: 1, maximumFractionDigits: 1 })} s`;
}

export type UsagePoint = { start_ms: number; requests: number; completed: number; input: number; output: number };
/**
 * One point per bucket of the answer's range, empty buckets included (the server leaves them out), each the sum of
 * its rows. Buckets are UTC hours from the one holding `from_ms`: the reader's hours wherever the offset is whole hours.
 */
export function usageSeries(usage: StackUsage): UsagePoint[] {
  const step = usage.bucket_ms;
  if (!step) return [];
  const sums = new Map<number, UsagePoint>();
  for (const row of usage.rows) {
    if (row.bucket_ms == null) continue;
    const point = sums.get(row.bucket_ms) ?? { start_ms: row.bucket_ms, requests: 0, completed: 0, input: 0, output: 0 };
    point.requests += row.requests; point.completed += row.completed; point.input += row.input_tokens; point.output += row.output_tokens;
    sums.set(row.bucket_ms, point);
  }
  const points: UsagePoint[] = [];
  for (let start = usage.from_ms - (usage.from_ms % step); start < usage.to_ms; start += step) points.push(sums.get(start) ?? { start_ms: start, requests: 0, completed: 0, input: 0, output: 0 });
  return points;
}

/** A rate as a percentage, "—" without requests. */
export const rateText = (part: number, whole: number) => whole ? new Intl.NumberFormat('en-US', { style: 'percent', maximumFractionDigits: 1 }).format(part / whole) : '—';
/** The change against an earlier figure, null when there is none to compare with. */
export const change = (now: number, before: number | undefined) => before == null || before === 0 ? null : (now - before) / before;

// ---------------------------------------------------------------------------
// Income (S61)

/**
 * One row of `GET …/income`: what the requests one account served with one model earned (in one UTC hour or day with
 * `bucket`), in micro-dollars, as Earnings classifies it: paid on chain, accrued (owed, not yet paid on chain) and
 * withheld (its charge did not reach the chain); requests without a supplier quote are counted apart and earn nothing.
 * `account_id` is null for income from before Gray recorded each request's account.
 */
export type StackIncomeRow = {
  bucket_ms?: number;
  account_id: string | null; model: string;
  paid_microusd: number; accrued_microusd: number; withheld_microusd: number; unquoted_requests: number;
};
/** The requests that arrived in `[from_ms, to_ms]`; `accounts_from_ms` is the stack's first request with a recorded account. */
export type StackIncome = { from_ms: number; to_ms: number; bucket_ms: number | null; accounts_from_ms: number | null; rows: StackIncomeRow[] };
/** The income read of `[from, to]` (both ends counted, as the usage read's spans give them), by hour with `bucket`. */
export const incomeTarget = (relayId: string, from: number, to: number, bucket?: 'hour') =>
  `${stackPath(relayId, 'income')}?from_ms=${from}&to_ms=${to}${bucket ? `&bucket=${bucket}` : ''}`;

export type IncomeTotals = { total: number; paid: number; accrued: number; withheld: number; unquoted: number };
const noIncome = (): IncomeTotals => ({ total: 0, paid: 0, accrued: 0, withheld: 0, unquoted: 0 });
function addIncome(sum: IncomeTotals, row: StackIncomeRow) {
  sum.paid += row.paid_microusd; sum.accrued += row.accrued_microusd; sum.withheld += row.withheld_microusd; sum.unquoted += row.unquoted_requests;
  sum.total = sum.paid + sum.accrued + sum.withheld;
  return sum;
}
/** Sums of rows; `total` is what the requests earned, paid or not. */
export const incomeTotals = (rows: readonly StackIncomeRow[]): IncomeTotals => rows.reduce(addIncome, noIncome());
/** Rows summed per account or per model, most income first; income with no recorded account last. */
export function incomeBy(rows: readonly StackIncomeRow[], key: 'account_id' | 'model'): (IncomeTotals & { key: string | null })[] {
  const groups = new Map<string | null, IncomeTotals>();
  for (const row of rows) groups.set(row[key], addIncome(groups.get(row[key]) ?? noIncome(), row));
  return [...groups].map(([name, sum]) => ({ key: name, ...sum }))
    .sort((a, b) => Number(a.key === null) - Number(b.key === null) || b.total - a.total || (a.key ?? '').localeCompare(b.key ?? ''));
}
/** A bucketed read's sums by the bucket's start. */
export function incomeByBucket(income: StackIncome): Map<number, IncomeTotals> {
  const sums = new Map<number, IncomeTotals>();
  for (const row of income.rows) if (row.bucket_ms != null) sums.set(row.bucket_ms, addIncome(sums.get(row.bucket_ms) ?? noIncome(), row));
  return sums;
}
/**
 * Where the split by account of an answer starts, when part of its income has no account: the stack's first request
 * with one (null when none has one yet). Undefined when every row names its account.
 */
export const accountsSplitFrom = (income: StackIncome): number | null | undefined => income.rows.some(row => row.account_id === null) ? income.accounts_from_ms : undefined;

// ---------------------------------------------------------------------------
// gray-assistant

/** Names in a sentence: "a", "a and b", "a, b and c". */
export const listText = (names: readonly string[]) => names.length < 2 ? names.join('') : `${names.slice(0, -1).join(', ')} and ${names.at(-1)}`;
/** What the commands need from Gray (the lane instance's values) and does not have yet, by name. */
export function missingInstance(relay: Pick<StackRelay, 'app_id' | 'lane_origin' | 'kms_ca_pubkey'>): string[] {
  return [[relay.lane_origin, 'lane origin'], [relay.app_id, 'app ID'], [relay.kms_ca_pubkey, 'KMS CA key']].filter(([value]) => value === null).map(([, name]) => name as string);
}
/** The token types a vendor's accounts take: an API key for OpenAI and the OpenAI-compatible vendors, an OAuth access token for ChatGPT Codex, either for Anthropic. */
const TOKEN_TYPE: Readonly<Record<StackVendor, string>> = { anthropic: '<api_key|oauth_access_token>', openai: 'api_key', chatgpt_codex: 'oauth_access_token', ...compatibleRows(() => 'api_key') };

/**
 * The commands that seal one account's credential to the lane's VM by hand, from the relay's own machine (gray-assistant's
 * agent does it by itself when it runs with the relay's stack section): gray-assistant verifies the lane's attestation
 * against Gray's published values, seals the token for that VM and uploads the sealed envelope. The instance values are
 * Gray's (null until published: `missingInstance` says which, and no command is given). The relay's own files stay
 * placeholders in angle brackets. No version: gray-assistant picks it (the time now, in ms) and prints it, and the panel
 * shows the version the VM reports it holds.
 */
export function pushTokenCommands({ relayId, accountId, vendor, laneOrigin, appId, kmsCaPubkey }: {
  relayId: string; accountId: string; vendor: StackVendor; laneOrigin: string; appId: string; kmsCaPubkey: string;
}) {
  return [
    '# On your own machine. The token file holds the secret; it never leaves this machine unsealed.',
    `gray-assistant attest ${laneOrigin} --allow <release-list.json> --release-key <release key> \\`,
    `  --app-id ${appId} --kms-ca-pubkey ${kmsCaPubkey} --out verified-report.json`,
    'gray-assistant credentials push-token --report verified-report.json \\',
    `  --relay-id ${relayId} --key relay-key.json \\`,
    `  --account ${accountId || '<account id>'} --vendor ${vendor} --type ${TOKEN_TYPE[vendor]} --token-file <token file> \\`,
    '  --out sealed-credential.json',
    `gray-assistant upload ${laneOrigin} sealed-credential.json --report verified-report.json`,
  ].join('\n');
}

/** A restart request's reason and status in the panel's words, with each status's badge tone. */
export const RESTART_REASONS: Record<StackRestartRequest['reason'], string> = { rollout: 'Rollout', rollback: 'Rollback', restart: 'Restart' };
export const RESTART_STATUSES: Record<StackRestartRequest['status'], { label: string; tone: 'info' | 'success' | 'danger' | 'neutral' }> = {
  pending: { label: 'Waiting for Gray', tone: 'info' },
  done: { label: 'Restarted', tone: 'success' },
  failed: { label: 'Failed', tone: 'danger' },
  superseded: { label: 'Superseded', tone: 'neutral' },
};

/**
 * The image the VM runs, from its latest report (S55): `none` before any report, `unreported` from a lane that does not
 * report its image yet, else the image and whether it is the one registered on the relay (the relay chooses its image
 * at boot, so the two can differ until the record is updated).
 */
export function runningImage(health: StackVmHealth | null | undefined, registered: string | null):
  | { kind: 'loading' } | { kind: 'none' } | { kind: 'unreported'; reportedMs: number }
  | { kind: 'image'; image: string; reportedMs: number; registered: boolean } {
  if (!health) return { kind: 'loading' };
  if (!health.vm) return { kind: 'none' };
  if (!health.vm.relay_image) return { kind: 'unreported', reportedMs: health.vm.reported_ms };
  return { kind: 'image', image: health.vm.relay_image, reportedMs: health.vm.reported_ms, registered: registered === health.vm.relay_image };
}

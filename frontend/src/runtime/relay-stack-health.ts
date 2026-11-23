// Account health in the relay stack panel (step 2, docs/confidential-lane-supply-implementation.md S33–S48): the shapes
// of the console's health operations (workers/console/src/lane-stack/health-contract.ts) and the pure functions that
// turn their closed words into the panel's sentences. The words are @gray/lane-wire's (stack-health.ts): every state,
// reason, attempt class, vendor code and window key the console may answer has a sentence here, so nothing reaches the
// page as a code. relay-stack-state.ts maps the server's one state per account onto the panel's state words.
// `node --test` loads this file directly.
import { relayPageOrigin } from './relay-page.ts';
import type { RelayDebugShare } from './debug-share.ts';
import {
  OWN_CALL_OPS, OWN_CALL_TABLE, ownCallRun, STACK_VENDORS, upkeepCredential, VENDOR_LABEL, vendorLabel,
  type OwnCallOp, type OwnCalls, type StackAccount, type StackCredential, type StackRelay, type StackRoute, type StackVendor,
} from './relay-stack.ts';

const MIN = 60_000, HOUR = 60 * MIN, DAY = 24 * HOUR;
const n = (value: number) => value.toLocaleString('en-US');
const plural = (count: number, one: string, many = `${one}s`) => `${n(count)} ${count === 1 ? one : many}`;
const lowerFirst = (text: string) => text.replace(/^./, c => c.toLowerCase());

// ---------------------------------------------------------------------------
// Shapes (health-contract.ts)

export const SERVER_STATES = ['not_served', 'waiting_credential', 'paused', 'held', 'at_limit', 'cooling', 'proxy_failing', 'credential_expiring', 'failing', 'serving'] as const;
export type ServerState = typeof SERVER_STATES[number];
export const ATTEMPT_CLASSES = [
  'ok', 'stream_error', 'vendor_reset', 'relay_closed', 'gray_ended', 'egress_limit', 'client_error', 'auth', 'forbidden', 'billing', 'restricted', 'window_exhausted', 'rate_limit',
  'overloaded', 'unavailable', 'vendor_5xx', 'challenge', 'connect', 'proxy', 'relay_refused', 'cooling', 'credential_unknown', 'container_fault',
  'relay_declined',
] as const;
export type AttemptClass = typeof ATTEMPT_CLASSES[number];
export type CoolingMode = 'off' | 'observe' | 'enforce';
export type CredentialType = 'api_key' | 'oauth_access_token';
export type WindowKey = 'unified' | '5h' | '7d' | '7d_oi' | 'primary' | 'secondary';

/** A cooling entry of the VM's report (S42): ends are whole minutes, `observed` ones refused nothing. */
export type CoolingEntry = {
  model: string | null; kind: 'cool' | 'hold'; until_minute_ms: number | null; rule_id: string; class: AttemptClass; vendor_code: string;
  set_minute_ms: number; gen: number; observed: boolean; clears: ('credential' | 'test')[]; cred_gen?: number;
};
/** A vendor rate-limit window as egress last read it from the vendor's headers (S36). */
export type WindowState = {
  key: WindowKey; window_minutes: number | null; used_percent: number | null; status: 'allowed' | 'allowed_warning' | 'rejected' | null;
  claim: string | null; resets_at_minute_ms: number | null; observed_minute_ms: number;
};
export type SealedCredential = { version: number; type: CredentialType; expires_at_s: number | null };
/** Why a token exchange inside the VM gave no token (egress's closed words). */
export type LoginCode = 'vendor_rejected' | 'invalid_answer' | 'proxy_failed' | 'connect_failed' | 'timeout' | 'egress_error';
/**
 * A subscription account's sign-in inside the VM (the report's `login`, docs/design/relay-sign-in-in-vm.md and
 * relay-in-cvm-login.md): the relay's software signs it in and refreshes it through egress. `requested`: a person is
 * signing it in now with `gray-assistant login`. Its times are whole hours.
 */
export type LoginReport = {
  by: 'relay'; state: 'signed_in' | 'needed' | 'requested'; failures: number;
  last: { outcome: 'ok' | 'failed'; code: LoginCode | null; hour_ms: number } | null; last_ok_hour_ms: number | null;
  /** Sealed to be signed in inside the VM (`sign_in` or a password); absent otherwise. */
  vm_sign_in?: true;
};
/**
 * Whether the panel treats the account as signed in inside the VM: sealed for it, or its last token exchange was a
 * sign-in there. A plain OAuth token the relay's software or Gray refreshes is not, even when egress reports its state.
 */
export function signsInInVm(login: LoginReport | null | undefined): login is LoginReport {
  return !!login && (login.vm_sign_in === true || login.last !== null);
}
export type ReportAccount = {
  account_id: string; served: 'served' | 'paused' | 'excluded'; reason: string | null; sealed: SealedCredential | null; proxy_id: string | null;
  in_flight_peak: { minute_ms: number; value: number } | null; cooling: CoolingEntry[]; windows: WindowState[];
  /** For a subscription account the relay's software signs in inside the VM; absent from a VM older than it. */
  login?: LoginReport | null;
};
export type VmReport = {
  reported_ms: number; seq: number;
  boot: { started_minute_ms: number; egress_started_minute_ms: number | null; lease_expires_at_s: number | null };
  config: { console_version: number | null; fetched_current: boolean; fetched_minute_ms: number | null; absent: 'unknown_relay' | 'stack_config_refused' | null };
  cooling: { mode: CoolingMode | null; digest: string | null };
  counters: { request_unknown: number; attempts_exceeded: number } | null;
  sealed_unnamed: number;
  routes_excluded: { protocol: string; requested_model: string; reason: 'route_unserved' | 'route_conflict' }[];
  appends_excluded: { append_id: string; reason: 'append_digest_mismatch' | 'appends_over_limit' }[];
};
export type AccountHealth = {
  account_id: string; vendor: StackVendor; status: 'active' | 'paused'; state: ServerState; reason: string; until_ms: number | null; model: string | null;
  as_of_ms: number | null; clear_gen: number; last_success_minute_ms: number | null; last_error: { class: AttemptClass; minute_ms: number } | null; report: ReportAccount | null;
};
/** `GET …/health`: one state per account, the VM's latest report (null before its first), the cooling served. */
export type StackHealth = {
  relay_id: string; as_of_ms: number; vm: VmReport | null;
  cooling: { mode: CoolingMode; version: number; digest: string; applied: boolean | null };
  accounts: AccountHealth[];
  /** The calls of the last hour and day by why they failed (relay-stack-calls.ts); absent from consoles before it. */
  calls?: import('./relay-stack-calls').StackCalls;
};
export type AttemptsRow = { bucket_ms?: number; account_id: string; proxy_id: string; model: string; class: AttemptClass; attempts: number; retried: number; retried_other: number };
export type StackAttempts = { from_ms: number; to_ms: number; bucket_ms: number | null; rows: AttemptsRow[] };
export type TraceAttempt = {
  n: number; account_id: string | null; proxy_id: string | null; class: AttemptClass; code: string | null; status: number | null; vendor_code: string | null;
  end: string | null; bytes: number | null; at_ms: number; first_byte_ms: number | null; ms: number | null;
};
/**
 * `GET …/traces/{request}`. `trace` is null when Gray kept no trace of the request's calls but its customer shared it
 * for debugging (`debug_share`, debug-share.ts); `debug_share` is null when they did not, and absent from a console that
 * does not record shares yet.
 */
export type StackTrace = {
  request_id: string; created_ms: number;
  trace: { relay_id: string; truncated: boolean; calls: { endpoint_id: string; upstream_model: string; at_ms: number; fault: { by: string; why: string } | null; attempts: TraceAttempt[] }[] } | null;
  debug_share?: RelayDebugShare | null;
};
export type CoolingRule = {
  id: string; vendors: StackVendor[]; credential: 'any' | CredentialType; status: number[]; codes: string[]; action: 'cool' | 'hold';
  until: 'fixed' | 'stated' | null; seconds: number | null; max_seconds: number | null; scope: 'account' | 'model'; clears: ('credential' | 'test')[];
};
export type WindowRule = { id: string; window: 'short' | 'long' | 'model'; at_percent: number; scope: 'account' | 'model' };
export type StackCooling = {
  mode: CoolingMode; defaults: 'gray-cooling-v2' | null; rules: CoolingRule[]; windows: WindowRule[]; version: number; digest: string; applied: boolean | null; presets: CoolingRule[];
  /** Gray's current defaults, whatever the relay runs: what "Use Gray's defaults" puts back. */
  gray_defaults: { rules: CoolingRule[]; windows: WindowRule[] };
};
export type TestProtocol = 'anthropic_messages' | 'open_ai_responses' | 'open_ai_chat';
export type StackTest = {
  test_id: string; account_id: string; model: string; protocol: TestProtocol; state: 'pending' | 'answered' | 'expired'; requested_ms: number; requested_by: string;
  outcome: 'ok' | 'failed' | null; code: string | null; status: number | null; class: AttemptClass | null; vendor_code: string | null;
  first_byte_ms: number | null; first_token_ms: number | null; total_ms: number | null; windows: WindowState[] | null; cleared: number | null; checked_ms: number | null; answered_ms: number | null;
};
export type TestSchedule = { mode: 'off' | 'held' | 'all'; every_minutes: number };
export type CredentialIssueKind = 'credential_expiring' | 'not_sealed' | 'credential_waiting' | 'not_in_source' | 'lease_expiring' | 'agent_silent';
export type CredentialIssue = { kind: CredentialIssueKind; account_ids: string[]; since_ms: number | null; detail: string | null; credential_version: number | null };
export type AgentReplica = {
  origin: string; stack: boolean; phase: string; credential_version: string | number | null; lease_expires_at_ms: number | null;
  sealed_account_ids: string[] | null; last_push_ms: number | null; last_error: string | null;
};
/** An account gray-assistant found in its credential source (no credential): what the panel can adopt. */
/** `proxy`: the proxy the source declares (type, host, port), null for none; absent from an older gray-assistant. */
export type AgentSource = { account_id: string; vendor: StackVendor; credential_type: CredentialType | null; proxy?: { type: string; host: string; port: number } | null };
export type AgentStatusBody = {
  relay_id: string; issued_ms: number; agent_version: string; replicas: AgentReplica[]; parked: { account_id: string; reason: string }[];
  /** Absent from agents before 2026-10-29; null when the agent could not read its source. */
  sources?: AgentSource[] | null;
  /** Where gray-assistant's own page runs (`gray-assistant ui`; absent while it runs nowhere): relay-page.ts makes the address. */
  ui_mode?: 'loopback' | 'public' | 'tunnel';
  /** The page's port on the relay's 127.0.0.1, with `loopback` only. */
  ui_port?: number;
  /** The page's public https origin (gray-assistant's `ui.origin`), with `public` only; absent from a kit before 1.7.0. */
  ui_origin?: string;
  /** The relay tunnel (docs/relay-tunnel.md): `connected` while the rendezvous holds the relay's name; absent without one. */
  tunnel?: 'connected' | 'down';
};
/** `GET …/agent-status`: the newest status gray-assistant's agent signed, null before its first. */
export type StackAgentStatus = {
  status: AgentStatusBody | null; issued_ms: number | null; received_ms: number | null;
  /** The relay's tunnel origin, https://<label>.<relays zone>, where this deployment runs a rendezvous; else null. */
  tunnel_origin?: string | null;
};
export type IdentityValue = { headers: Record<string, string>; betas: string[]; generated: string[] };
export type ApiTokenScope = 'read' | 'manage';
export type ApiToken = {
  token_id: string; name: string; scope: ApiTokenScope; token_prefix: string; created_by: string; created_ms: number;
  expires_ms: number | null; last_used_ms: number | null; revoked_ms: number | null;
};

// ---------------------------------------------------------------------------
// Times

/** The panel says "as of" past this (S46): the VM reports at least every minute. */
export const STALE_AFTER_MS = 3 * MIN;
/** Whether a state's report is old enough to say when it is from. */
export const isStaleReport = (asOf: number | null, now: number) => asOf !== null && now - asOf > STALE_AFTER_MS;
/** A span behind, in its largest whole unit: "just now", "4 min ago", "2 h ago", "3 d ago". */
export function agoText(ms: number, now: number) {
  const past = Math.max(0, now - ms);
  if (past < MIN) return 'just now';
  if (past < HOUR) return `${Math.round(past / MIN)} min ago`;
  if (past < DAY) return `${Math.round(past / HOUR)} h ago`;
  return `${Math.round(past / DAY)} d ago`;
}
/** A duration in its largest units: "5 s", "10 min", "1 h", "8 d", "1 h 30 min". */
export function durationText(seconds: number) {
  if (seconds < 60) return `${n(seconds)} s`;
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `${n(minutes)} min`;
  const hours = Math.floor(minutes / 60), rest = minutes % 60;
  if (hours < 48) return rest ? `${n(hours)} h ${rest} min` : `${n(hours)} h`;
  const days = Math.round(hours / 24);
  return `${n(days)} d`;
}
/** Milliseconds as a reader takes them: "320 ms", "1.4 s", "12 s". */
export const msText = (ms: number) => ms < 1000 ? `${n(Math.round(ms))} ms` : ms < 10_000 ? `${(ms / 1000).toFixed(1)} s` : `${n(Math.round(ms / 1000))} s`;

// ---------------------------------------------------------------------------
// Words

/** What an attempt's class means, as a phrase that completes "… failed:" or labels a breakdown row. */
export const CLASS_WORDS: Readonly<Record<AttemptClass, string>> = {
  ok: 'Completed', stream_error: 'Stream error', vendor_reset: 'Connection reset by the vendor', relay_closed: 'Closed by your container', gray_ended: 'Ended by Gray',
  egress_limit: 'Over Gray’s egress limit', client_error: 'Client error (4xx)', auth: 'Credential rejected (401)', forbidden: 'Forbidden (403)', billing: 'Billing problem',
  restricted: 'Account restricted', window_exhausted: 'Limit used up', rate_limit: 'Rate limited (429)', overloaded: 'Overloaded (529)', unavailable: 'Unavailable (503)',
  vendor_5xx: 'Vendor error (5xx)', challenge: 'Challenge page (IP or proxy check)', connect: 'Couldn’t connect', proxy: 'Proxy failed', relay_refused: 'Refused by Gray',
  cooling: 'Refused while cooling', credential_unknown: 'Unknown credential', container_fault: 'Container fault', relay_declined: 'Declined by your software',
};
/** The classes that are the vendor's or the network's failures (the console's FAILURE_CLASSES, state.ts). */
export const FAILURE_CLASSES: ReadonlySet<AttemptClass> = new Set<AttemptClass>(['stream_error', 'vendor_reset', 'auth', 'forbidden', 'billing', 'restricted', 'window_exhausted', 'rate_limit', 'overloaded', 'unavailable', 'vendor_5xx', 'challenge', 'connect', 'proxy']);
/** Vendor codes in words; one not listed reads as its words. */
const VENDOR_CODE_WORDS: Readonly<Record<string, string>> = {
  billing_error: 'billing error', insufficient_quota: 'quota used up', billing_not_active: 'billing not active', insufficient_balance: 'balance too low', credit_balance_too_low: 'credit balance too low',
  token_revoked: 'token revoked', token_invalidated: 'token invalidated', deactivated_workspace: 'workspace deactivated', usage_not_included: 'usage not included in the plan',
  account_state: 'account suspended', organization_disabled: 'organization disabled', identity_verification_required: 'identity verification required', detail_unauthorized: 'unauthorized',
  invalid_api_key: 'invalid API key', usage_limit_reached: 'usage limit reached', window_exhausted: 'window used up', model_window_exhausted: 'model window used up', html_challenge: 'challenge page',
  overloaded_error: 'overloaded', rate_limit_error: 'rate limited', rate_limit_exceeded: 'rate limit exceeded', authentication_error: 'authentication error', permission_error: 'permission error',
};
export const vendorCodeText = (code: string | null) => !code || code === 'other' ? null : VENDOR_CODE_WORDS[code] ?? code.replaceAll('_', ' ');

/** A vendor window's name: Codex windows by their length (S36: their primary/secondary names swap). */
export function windowLabel(w: Pick<WindowState, 'key' | 'window_minutes'>) {
  if (w.key === '5h') return '5-hour';
  if (w.key === '7d') return 'Weekly';
  if (w.key === '7d_oi') return 'Weekly (per model)';
  if (w.key === 'unified') return 'Overall';
  if (w.window_minutes === null) return w.key === 'primary' ? 'Primary' : 'Secondary';
  return w.window_minutes <= 360 ? '5-hour' : 'Weekly';
}
/** The windows worth a meter, tightest first: those with a share the vendor reported. */
export function vendorWindows(report: Pick<ReportAccount, 'windows'> | null): WindowState[] {
  return [...(report?.windows ?? [])].filter(w => w.used_percent !== null || w.status === 'rejected')
    .sort((a, b) => (b.status === 'rejected' ? 1000 : b.used_percent ?? 0) - (a.status === 'rejected' ? 1000 : a.used_percent ?? 0));
}

/** A sealed version reads as when gray-assistant sealed it: its versions are the wall clock in ms (relay-kit versions.ts). */
export const isClockVersion = (version: number) => version >= 1_000_000_000_000;
export function sealedVersionText(version: number, clock: (ms: number) => string) {
  return isClockVersion(version) ? `sealed ${clock(version)}` : `version ${n(version)}`;
}
export const CREDENTIAL_TYPE_WORDS: Readonly<Record<CredentialType, string>> = { api_key: 'API key', oauth_access_token: 'Account sign-in' };

// ---------------------------------------------------------------------------
// One account's state from the server (S46)

/** Held for these classes means the vendor refuses the account itself: the panel says "banned · replace". */
export const BANNED_CLASSES: ReadonlySet<string> = new Set(['forbidden', 'restricted', 'billing', 'auth']);
/**
 * The rule id of the hold the VM makes by itself, whatever the rules say: the vendor answered that a route's upstream
 * model does not exist (S38's fixed rule; egress `stackModelGoneRule`). The hold is that model's and a passing test ends it.
 */
export const MODEL_GONE_RULE = 'model_not_found';
/** The enforced entry an account's state is about: the one of the state's model, else the first; null without a report's entries. */
function stateEntry(h: Pick<AccountHealth, 'model' | 'report'>) {
  const entries: readonly CoolingEntry[] = h.report?.cooling ?? [];
  return entries.find(e => !e.observed && (e.model ?? null) === (h.model ?? null)) ?? entries.find(e => !e.observed) ?? null;
}

/**
 * Whether an account cools for a reason time does not end (one of `BANNED_CLASSES`): the console's alert reads the same
 * (alerts.ts `accountAlert`). Class `auth` is egress's word for a vendor's 401 to a call made with the account's
 * credential (a customer's request, an account test, egress's own limits or model-list call): Gray signs nothing in and
 * knows nothing of a sign-in, so no word here says a login was tried or rejected.
 */
export const credentialCooling = (h: Pick<AccountHealth, 'state' | 'reason'> | null | undefined): boolean => h?.state === 'cooling' && BANNED_CLASSES.has(h.reason);
/** Why an account cools, as a sentence without its full stop ("The vendor answered 401 to a call made with this account’s credential"). */
export const coolingWhy = (reason: string): string => COOLING_WORDS[reason] ?? HELD_WORDS[reason] ?? `The vendor answered ${lowerFirst(CLASS_WORDS[reason as AttemptClass] ?? reason.replaceAll('_', ' '))}`;
/** A cooling's reason in a few words ("Credential rejected (401)"). */
export const coolingShort = (reason: string): string => COOLING_SHORT[reason] ?? CLASS_WORDS[reason as AttemptClass] ?? reason.replaceAll('_', ' ');

/**
 * Where an account's credential is renewed, for what to do when the vendor refuses it: `sign_in`, the relay's software
 * signs it in inside the VM (`signsInInVm`); `source`, the account source holds it (an API key, or a token the source
 * renews); `unknown`, no report of the VM says. The console reads the same (failure-reasons.ts `credentialKindOf`).
 */
export type CredentialKind = 'sign_in' | 'source' | 'unknown';
export const credentialKind = (report: Pick<ReportAccount, 'sealed' | 'login'> | null | undefined): CredentialKind => signsInInVm(report?.login) ? 'sign_in' : report?.sealed ? 'source' : 'unknown';
/** What to do about a credential the vendor answered 401 to, by where it is renewed; the console's messages say the same. */
export const CREDENTIAL_SOURCE_FIX = 'Replace the credential in your account source, then run accounts push.';
export const credentialSignInFix = (accountId = ''): string => `Sign it in again (${signInCommand(accountId)}), or replace it in your account source, then run accounts push.`;
/** `below`: the sign-in command is shown in a code block under the sentence, so the sentence does not repeat it. */
export function credentialFix(kind: CredentialKind, accountId = '', command: 'inline' | 'below' = 'inline'): string {
  if (kind === 'source') return CREDENTIAL_SOURCE_FIX;
  if (kind === 'sign_in') return command === 'below' ? 'Sign it in again with the command below, or replace it in your account source, then run accounts push.' : credentialSignInFix(accountId);
  // Which of the two it is is not known: both, each for its kind of account.
  return `An API key: ${lowerFirst(CREDENTIAL_SOURCE_FIX)} An account that signs in: ${lowerFirst(credentialSignInFix(accountId))}`;
}
/** What to do about a refusal of one of `BANNED_CLASSES`: the credential for a 401, the account for the others. */
export const refusalFix = (reason: string, kind: CredentialKind, accountId = '', command: 'inline' | 'below' = 'inline'): string =>
  reason === 'auth' ? credentialFix(kind, accountId, command) : 'Replace the account, or test it once the vendor lets it work again.';

/**
 * The accounts an open alert names as refused over their credential (the console's `credential_cooling`), those of one
 * reason and one kind of credential together, each group with what to do:
 * "a, b: Credential rejected (401). Replace the credential in your account source, then run accounts push."
 */
export function refusedAccountsText(list: readonly { account_id?: unknown; reason?: unknown; credential?: unknown }[]): string {
  const groups = new Map<string, { reason: string; kind: CredentialKind; ids: string[] }>();
  for (const a of list) {
    const reason = String(a.reason ?? ''), kind: CredentialKind = a.credential === 'sign_in' || a.credential === 'source' ? a.credential : 'unknown';
    const group = groups.get(`${reason}\n${kind}`) ?? { reason, kind, ids: [] };
    group.ids.push(String(a.account_id ?? ''));
    groups.set(`${reason}\n${kind}`, group);
  }
  return [...groups.values()].map(g => `${g.ids.join(', ')}: ${coolingShort(g.reason)}. ${refusalFix(g.reason, g.kind, g.ids.length === 1 ? g.ids[0] : '')}`).join(' ');
}

export type ServerStateText = { label: string; reason: string };
/**
 * The panel's words for the console's state of an account: the label of its badge and the reason in one sentence.
 * `clock` writes a moment ("5:40 PM"), `failing` the account's failure share in its last hour when known.
 */
export function serverStateText(h: Pick<AccountHealth, 'state' | 'reason' | 'until_ms' | 'model' | 'report'> & { account_id?: string }, { clock, failing, modelName = id => id }: {
  clock: (ms: number) => string; failing?: { failures: number; counted: number; top: AttemptClass[] } | null; modelName?: (id: string) => string;
}): ServerStateText {
  const until = h.until_ms !== null ? clock(h.until_ms) : null;
  const on = h.model ? ` on ${modelName(h.model)}` : '';
  const entry = stateEntry(h);
  const code = vendorCodeText(entry?.vendor_code ?? null);
  switch (h.state) {
    case 'serving': return { label: 'Serving', reason: 'Taking requests.' };
    case 'paused': return { label: 'Paused', reason: 'You paused it; the lane gives it no request until you resume it.' };
    case 'not_served': return { label: 'Not served', reason: NOT_SERVED[h.reason] ?? 'The VM leaves it out of what it serves.' };
    case 'waiting_credential':
      return h.reason === 'credential_waiting' ? { label: 'Waiting for a new credential', reason: 'The VM holds an older credential than the one this account asks for. gray-assistant seals the new one when it has it.' }
        : h.reason === 'proxy_waiting' ? { label: 'Waiting for its proxy’s credential', reason: 'The VM holds an older credential for its proxy than the proxy asks for. gray-assistant seals the new one when it has it.' }
        : h.reason === 'login_waiting' ? { label: 'Waiting for its sign-in', reason: `${loginText(h.report?.login ?? null, clock)} The VM serves it once your software has signed it in.` }
        : { label: 'No credential yet', reason: 'The VM holds no credential for it. gray-assistant seals it once it runs, and again after each VM restart.' };
    case 'held': {
      // The vendor's own id of the model, as the vendor answered about it.
      if (entry?.rule_id === MODEL_GONE_RULE && h.model) return { label: 'Held', reason: `The vendor answered that the model ${h.model} does not exist${code ? `: ${code}` : ''}. Change the route’s upstream model to one the vendor serves, or test it once the vendor serves it again.` };
      const why = HELD_WORDS[h.reason] ?? `It is held after ${lowerFirst(CLASS_WORDS[h.reason as AttemptClass] ?? h.reason.replaceAll('_', ' '))}`;
      const fix = BANNED_CLASSES.has(h.reason) ? (h.reason === 'auth' ? ` ${credentialFix(credentialKind(h.report), h.account_id)} A passing test releases it.` : ' Replace the account, or test it once the vendor lets it work again.') : ' Clear it, or a passing test releases it.';
      return { label: BANNED_CLASSES.has(h.reason) ? 'Refused · replace' : 'Held', reason: `${why}${on}${code ? `: ${code}` : ''}.${fix}` };
    }
    case 'at_limit': {
      const window = h.report ? vendorWindows(h.report).find(w => w.status === 'rejected' || (w.used_percent ?? 0) >= 100) : undefined;
      const name = window ? `${lowerFirst(windowLabel(window))} ` : '';
      return {
        label: until ? `At limit · frees ${until}` : 'At limit',
        reason: `${h.reason === 'window_rejected' ? `The vendor refused it on its ${name}window` : `Its ${name}limit is used up`}${on}${until ? `; it takes requests again at ${until}` : ''}.`,
      };
    }
    case 'cooling': {
      const why = `${coolingWhy(h.reason)}${on}`;
      const label = until ? `Cooling until ${until}` : 'Cooling down';
      // A refusal over the credential does not end with the cooling: the lane's next call carries the same credential.
      if (BANNED_CLASSES.has(h.reason)) return { label, reason: `${why}. The lane rests it${until ? ` until ${until}` : ''} and then tries it again with the same credential. ${refusalFix(h.reason, credentialKind(h.report), h.account_id)}` };
      return { label, reason: `${why}; the lane rests it${until ? ` until ${until}` : ''} and then tries it again.` };
    }
    case 'proxy_failing': return { label: 'Proxy failing', reason: 'Its proxy failed every call in the last 15 minutes. Check the proxy, or move the account to another.' };
    case 'credential_expiring': {
      // Where the credential is renewed says what to do: an account the relay's software signs in inside the VM signs in
      // again there, one the source holds is replaced there (Roteo, kit 1.9.0: both were told to renew it in the source).
      const fix = credentialFix(credentialKind(h.report), h.account_id);
      return h.reason === 'credential_expired'
        ? { label: 'Credential expired', reason: `Its sealed credential has expired. ${fix}` }
        : { label: until ? `Credential expires ${until}` : 'Credential expiring', reason: `Its sealed credential expires${until ? ` at ${until}` : ' within a day'}. ${fix}` };
    }
    case 'failing': {
      const share = failing && failing.counted ? Math.round((failing.failures / failing.counted) * 100) : null;
      const top = failing?.top.length ? `, mostly ${failing.top.slice(0, 2).map(c => lowerFirst(CLASS_WORDS[c])).join(' and ')}` : '';
      return { label: share !== null ? `Failing ${share}%` : 'Failing', reason: share !== null ? `${plural(failing!.failures, 'call')} of ${n(failing!.counted)} in the last hour failed${top}.` : 'At least half of its calls in the last hour failed.' };
    }
  }
}
/**
 * The console's state of an account in a few words for its table row (at most about 60 characters): what happened and,
 * for what the relay fixes, the fix. The sentence (`serverStateText`) is the row's tooltip and the account sheet's.
 */
export function shortReason(h: Pick<AccountHealth, 'state' | 'reason' | 'model' | 'report' | 'last_success_minute_ms'>, { clock, failing, modelName = id => id }: {
  clock: (ms: number) => string; failing?: { failures: number; counted: number; top: AttemptClass[] } | null; modelName?: (id: string) => string;
}): string {
  const on = h.model ? ` on ${modelName(h.model)}` : '';
  switch (h.state) {
    case 'serving': return h.last_success_minute_ms !== null ? `Last completed call ${clock(h.last_success_minute_ms)}` : 'Taking requests';
    case 'paused': return 'No requests until you resume it';
    case 'not_served': return NOT_SERVED_SHORT[h.reason] ?? 'Left out by the VM';
    case 'waiting_credential': return h.reason === 'credential_waiting' ? 'The VM holds an older credential' : h.reason === 'proxy_waiting' ? 'The VM holds an older proxy credential'
      : h.reason === 'login_waiting' ? loginShort(h.report?.login ?? null, clock) : 'The VM has no credential yet';
    case 'held': return stateEntry(h)?.rule_id === MODEL_GONE_RULE && h.model ? `Model not found${on} · change or test` : h.reason === 'forbidden' ? `403${on} · replace or test` : h.reason === 'restricted' ? 'Restricted by the vendor · replace or test'
      : h.reason === 'billing' ? 'Refused over billing · replace or test' : h.reason === 'auth' ? `Credential rejected (401) · ${CREDENTIAL_SHORT_FIX[credentialKind(h.report)]}`
      : `${CLASS_WORDS[h.reason as AttemptClass] ?? h.reason.replaceAll('_', ' ')}${on} · clear or test`;
    case 'at_limit': {
      const window = h.report ? vendorWindows(h.report).find(w => w.status === 'rejected' || (w.used_percent ?? 0) >= 100) : undefined;
      return `${window ? windowLabel(window) : 'Its'} limit used up${on}`.replace(/^Its limit/, 'Limit');
    }
    case 'cooling': return `${coolingShort(h.reason)}${on}${BANNED_CLASSES.has(h.reason) ? ` · ${h.reason === 'auth' ? CREDENTIAL_SHORT_FIX[credentialKind(h.report)] : 'replace'}` : ''}`;
    case 'proxy_failing': return 'Every call failed at its proxy (15 min)';
    case 'credential_expiring': return `${h.reason === 'credential_expired' ? 'Expired' : 'Ends soon'} · ${CREDENTIAL_SHORT_FIX[credentialKind(h.report)]}`;
    case 'failing': return failing && failing.counted
      ? `${n(failing.failures)} of ${n(failing.counted)} calls failed in 1 h${failing.top[0] ? `, mostly ${lowerFirst(CLASS_WORDS[failing.top[0]])}` : ''}`
      : 'Half its calls failed in the last hour';
  }
}
/** Why a token exchange inside the VM gave no token, completing "The last sign-in failed: …". */
export const LOGIN_CODE_WORDS: Readonly<Record<LoginCode, string>> = {
  vendor_rejected: 'the vendor refused it', invalid_answer: 'the vendor’s answer held no usable token', proxy_failed: 'its proxy failed',
  connect_failed: 'Gray couldn’t reach the vendor', timeout: 'the vendor didn’t answer in time', egress_error: 'Gray’s egress failed',
};
const LOGIN_CODE_SHORT: Readonly<Record<LoginCode, string>> = {
  vendor_rejected: 'refused by the vendor', invalid_answer: 'no usable token', proxy_failed: 'proxy failed', connect_failed: 'couldn’t reach the vendor',
  timeout: 'no answer in time', egress_error: 'egress failed',
};
/**
 * A gray-assistant command as the relay runs it: on phase 2 nothing runs on the host, so each is a one-off container in
 * the kit directory (the kit's AGENTS.md, "Phase 2").
 */
export const kitRun = (command: string): string => `docker compose run --rm --no-deps agent ${command}`;
/**
 * A command that signs with the guardian key (`releases approve|reject|delay`, `pause`, `unpause`): `--config` names
 * the config where the kit's compose mounts the kit directory, because the config's `chain.guardian_key` is relative to
 * the config file and the default one (/etc/gray-assistant/) has no key beside it (@gray/control `kitGuardianRun`, the
 * same words).
 */
export const kitGuardianRun = (command: string): string => `${kitRun(command)} --config /run/secrets/gray-assistant.jsonc`;
/**
 * gray-assistant's step with a VM (its agent status's `phase`, a closed list: @gray/control STACK_AGENT_REPLICA_PHASES)
 * in the panel's words; the phase's own name is never shown.
 */
const SEALING_WORDS: Readonly<Record<string, string>> = {
  unknown: 'Not started yet', attesting: 'Checking the VM', release_pending: 'Waiting for your decision on a Gray release', policy: 'Preparing the VM',
  credentials: 'Sealing the credentials', serving: 'Sealed and serving', failed: 'Failed', withdrawn: 'Withdrawn from the VM',
};
export const sealingWords = (phase: string): string => SEALING_WORDS[phase] ?? 'Working';
/** `accounts push`: reads the source, tells Gray what it lists (and what it left out) and seals it to the VM. */
export const PUSH_COMMAND = kitRun('accounts push');
/** The command that signs an account in inside the VM (docs/design/relay-sign-in-in-vm.md §1), run in the kit directory. */
export function signInCommand(accountId: string): string {
  return kitRun(`login ${accountId.trim() || '<account ID>'}`);
}
/** The command that gives accounts one of the account file's proxies (docs/design/relay-operator-page.md section 6), run in the kit directory. */
export function proxyCommand(accountIds: readonly string[]): string {
  return kitRun(`accounts proxy ${accountIds.map(id => id.trim()).filter(Boolean).join(' ') || '<account ID>'} --proxy <proxy ID>`);
}
/** What tech starts on the relay's machine when gray-assistant's page does not open (the kit's compose service, section 7). */
export const PAGE_START_COMMAND = 'docker compose up -d page';
/** The last token exchange inside the VM in a sentence: its hour and how it went ("" when there was none). */
export function lastExchangeText(login: LoginReport, clock: (ms: number) => string): string {
  if (!login.last) return '';
  const at = `The last token exchange was in the hour starting ${clock(login.last.hour_ms)}`;
  if (login.last.outcome === 'ok') return ` ${at} and gave a token.`;
  return ` ${at} and failed${login.last.code ? `: ${LOGIN_CODE_WORDS[login.last.code]}` : ''}${login.failures > 1 ? ` (${n(login.failures)} in a row)` : ''}.`;
}
/**
 * A subscription account's sign-in as a sentence: "Your software signs it in inside the VM. Signed in. The last token
 * exchange was in the hour starting 5 PM and gave a token." The hours are the report's (the VM reports them to the hour).
 * With `accountId`, a needed sign-in names the command that does it.
 */
export function loginText(login: LoginReport | null, clock: (ms: number) => string, accountId?: string): string {
  const who = 'Your software signs it in inside the VM.';
  if (!login) return who;
  const last = lastExchangeText(login, clock);
  switch (login.state) {
    case 'signed_in': return `${who} Signed in.${last}`;
    case 'requested': return `${who} Signing in: someone ran login and the VM waits for the vendor’s approval.${last}`;
    case 'needed': return `${who} It needs a sign-in${login.last ? '' : ' and has had none yet'}${accountId ? `: run ${signInCommand(accountId)} in the kit directory` : ''}.${last}`;
  }
}
/** The same in a few words, for a row. */
export function loginShort(login: LoginReport | null, clock: (ms: number) => string): string {
  if (!login) return 'Signs in inside the VM';
  const failed = login.last?.outcome === 'failed' && login.last.code ? `: ${LOGIN_CODE_SHORT[login.last.code]}` : '';
  switch (login.state) {
    case 'signed_in': return login.last_ok_hour_ms !== null ? `Signed in inside the VM · ${clock(login.last_ok_hour_ms)}` : 'Signed in inside the VM';
    case 'requested': return 'Signing in now';
    case 'needed': return login.last?.outcome === 'failed' ? `Needs sign-in · last exchange failed${failed}` : 'Needs sign-in';
  }
}
const NOT_SERVED_SHORT: Readonly<Record<string, string>> = {
  vendor_mismatch: 'Sealed credential is another vendor’s', invalid_credential: 'Sealed credential can’t be used', proxy_unknown: 'Its proxy isn’t one of this deployment’s',
  proxy_mismatch: 'Sealed for another proxy', duplicate_credential: 'Same credential as another account', not_reported: 'Not in the VM’s last report', config_refused: 'Gray holds the configuration back',
};
/** The fix of a refused credential in a row's few words, by where it is renewed (`credentialKind`). */
const CREDENTIAL_SHORT_FIX: Readonly<Record<CredentialKind, string>> = { sign_in: 'sign it in again', source: 'replace it', unknown: 'replace or sign in again' };
const COOLING_SHORT: Readonly<Record<string, string>> = {
  rate_limit: 'Rate-limited (429)', overloaded: 'Vendor overloaded (529)', challenge: 'Challenge page from the vendor', auth: 'Credential rejected (401)', unavailable: 'Vendor unavailable (503)',
  vendor_5xx: 'Vendor error (5xx)', window_exhausted: 'Limit used up',
};

const NOT_SERVED: Readonly<Record<string, string>> = {
  vendor_mismatch: 'The credential gray-assistant sealed for it is another vendor’s. Check the account’s vendor or its source.',
  invalid_credential: 'Its sealed credential is of another type than the account declares, or the VM couldn’t open it. Seal it again.',
  proxy_unknown: 'Its proxy isn’t one of this deployment’s proxies. Choose another in the account’s settings.',
  proxy_mismatch: 'Its sealed credential names another proxy than the one it uses now. gray-assistant seals it again for the new proxy.',
  duplicate_credential: 'Another account sent the same credential. Give each account its own.',
  not_reported: 'The VM’s last report doesn’t list it yet. It does once the VM has taken the configuration that adds it.',
  config_refused: 'Gray holds this configuration back, so the VM serves none of it.',
};
const HELD_WORDS: Readonly<Record<string, string>> = {
  forbidden: 'The vendor refuses it with a 403', restricted: 'The vendor restricted the account', billing: 'The vendor refuses it over billing', auth: 'The vendor answered 401 to a call made with this account’s credential',
};
const COOLING_WORDS: Readonly<Record<string, string>> = {
  rate_limit: 'The vendor rate-limited it (429)', overloaded: 'The vendor was overloaded (529)', challenge: 'The vendor answered with a challenge page, an IP or proxy check',
  auth: 'The vendor answered 401 to a call made with this account’s credential', unavailable: 'The vendor was unavailable (503)', vendor_5xx: 'The vendor failed (5xx)', window_exhausted: 'Its limit is used up',
};

/** An account's failures in its last hour of attempts, for the `failing` sentence. */
export function failingOf(rows: readonly AttemptsRow[], accountId: string, now: number) {
  const byClass = new Map<AttemptClass, number>();
  for (const row of rows) if (row.account_id === accountId && (row.bucket_ms === undefined || row.bucket_ms >= now - HOUR - (now % HOUR))) byClass.set(row.class, (byClass.get(row.class) ?? 0) + row.attempts);
  let failures = 0;
  for (const [c, count] of byClass) if (FAILURE_CLASSES.has(c)) failures += count;
  const counted = failures + (byClass.get('ok') ?? 0);
  const top = [...byClass].filter(([c]) => FAILURE_CLASSES.has(c)).sort((a, b) => b[1] - a[1]).map(([c]) => c);
  return { failures, counted, top };
}

/** Attempts summed per class over rows (one account's or all), ok first then failures by size. */
export function attemptsByClass(rows: readonly AttemptsRow[], accountId?: string) {
  const out = new Map<AttemptClass, { attempts: number; retried: number; retried_other: number }>();
  for (const row of rows) {
    if (accountId !== undefined && row.account_id !== accountId) continue;
    const sum = out.get(row.class) ?? { attempts: 0, retried: 0, retried_other: 0 };
    sum.attempts += row.attempts; sum.retried += row.retried; sum.retried_other += row.retried_other;
    out.set(row.class, sum);
  }
  return [...out].map(([c, v]) => ({ class: c, ...v })).sort((a, b) => Number(b.class === 'ok') - Number(a.class === 'ok') || b.attempts - a.attempts);
}

// ---------------------------------------------------------------------------
// Cooling rules in words

const VENDOR_NAMES: Readonly<Record<StackVendor, string>> = VENDOR_LABEL;
/** The names of Gray's default rules and sub2api's presets in words; a relay's own rule reads as the name it gave it. */
const RULE_TITLES: Readonly<Record<string, string>> = {
  window_exhausted: 'Limit used up', model_window_exhausted: 'A model’s limit used up', billing: 'Billing problem', restricted: 'Account restricted', oauth_auth: 'Sign-in credential rejected (401)',
  key_auth: 'API key rejected (401)', challenge: 'Challenge page', forbidden: 'Forbidden', rate_limit: 'Rate limited', overloaded: 'Overloaded',
  [MODEL_GONE_RULE]: 'Model not found at the vendor',
  '529_60m': 'Overloaded: an hour per model', '429_10m': 'Rate limited: 10 minutes per model', '503_30m': 'Unavailable: 30 minutes per model',
};
export const ruleTitle = (id: string) => RULE_TITLES[id] ?? id;
/** What a rule matches, in words: "429 · window used up or usage limit reached · subscription logins". */
export function ruleMatchText(rule: CoolingRule) {
  const parts = [rule.status.join(', ')];
  if (rule.codes.length) parts.push(rule.codes.map(code => vendorCodeText(code) ?? code).join(' or '));
  if (rule.vendors.length) parts.push(rule.vendors.map(v => VENDOR_NAMES[v]).join(', '));
  if (rule.credential !== 'any') parts.push(rule.credential === 'api_key' ? 'API keys' : 'account sign-ins');
  return parts.join(' · ');
}
/** What a rule does, in words: "Holds the account until cleared", "Cools the model 10 min", "Cools the account until the vendor's reset (5 min if none, at most 1 h)". */
export function ruleActionText(rule: CoolingRule) {
  const what = rule.scope === 'model' ? 'the model on the account' : 'the account';
  if (rule.action === 'hold') return `Holds ${what} until it is cleared`;
  if (rule.until === 'stated') return `Cools ${what} until the vendor’s stated reset (${durationText(rule.seconds ?? 5)} if none, at most ${durationText(rule.max_seconds ?? rule.seconds ?? 5)})`;
  return `Cools ${what} for ${durationText(rule.seconds ?? 5)}`;
}
export function ruleClearsText(rule: CoolingRule) {
  const ways = [rule.clears.includes('test') && 'a passing test', rule.clears.includes('credential') && 'a new credential'].filter(Boolean) as string[];
  return ways.length ? `Also ends on ${ways.join(' or ')}.` : '';
}
/** The attempt classes a rule would match (an estimate: rules match statuses and codes, attempts keep their class). */
export function ruleClasses(rule: CoolingRule): AttemptClass[] {
  const codes = new Set(rule.codes);
  const out = new Set<AttemptClass>();
  if (codes.has('window_exhausted') || codes.has('usage_limit_reached') || codes.has('model_window_exhausted')) out.add('window_exhausted');
  if (['billing_error', 'insufficient_quota', 'billing_not_active', 'insufficient_balance', 'credit_balance_too_low'].some(c => codes.has(c))) out.add('billing');
  if (['token_revoked', 'token_invalidated', 'deactivated_workspace', 'usage_not_included', 'account_state', 'organization_disabled', 'identity_verification_required', 'detail_unauthorized'].some(c => codes.has(c))) out.add('restricted');
  if (codes.has('html_challenge')) out.add('challenge');
  if (!codes.size) {
    for (const status of rule.status) {
      if (status === 401) out.add('auth');
      else if (status === 403) out.add('forbidden');
      else if (status === 429) out.add('rate_limit');
      else if (status === 529) out.add('overloaded');
      else if (status === 503) out.add('unavailable');
      else if (status >= 500) out.add('vendor_5xx');
      else if (status >= 400) out.add('client_error');
    }
  }
  return [...out];
}
/**
 * What the rules would have cooled over the attempts read (observe mode's "what would have happened"): for each rule,
 * the accounts whose answers fell in a class the rule matches, first rule first, as the egress applies them.
 */
export function wouldCool(rules: readonly CoolingRule[], rows: readonly AttemptsRow[], accounts: readonly Pick<StackAccount, 'account_id' | 'vendor' | 'credential_type'>[]) {
  const byId = new Map(accounts.map(a => [a.account_id, a]));
  const taken = new Set<string>();
  const out: { rule: CoolingRule; accounts: string[]; attempts: number }[] = [];
  for (const rule of rules) {
    const classes = new Set(ruleClasses(rule));
    const hit = new Map<string, number>();
    for (const row of rows) {
      const account = byId.get(row.account_id);
      if (!account || !classes.has(row.class) || taken.has(`${row.account_id}\n${row.class}`)) continue;
      if (rule.vendors.length && !rule.vendors.includes(account.vendor)) continue;
      if (rule.credential !== 'any' && account.credential_type && account.credential_type !== rule.credential) continue;
      hit.set(row.account_id, (hit.get(row.account_id) ?? 0) + row.attempts);
    }
    for (const id of hit.keys()) for (const c of classes) taken.add(`${id}\n${c}`);
    if (hit.size) out.push({ rule, accounts: [...hit.keys()].sort(), attempts: [...hit.values()].reduce((a, b) => a + b, 0) });
  }
  return out;
}

// ---------------------------------------------------------------------------
// Account tests

const TEST_CODE_WORDS: Readonly<Record<string, string>> = {
  vendor_error: 'The vendor answered with an error', connect_failed: 'Couldn’t connect to the vendor', proxy_failed: 'The proxy failed', tls_failed: 'The TLS handshake failed',
  upstream_failed: 'The vendor closed the connection', stream_incomplete: 'The answer stopped before its end', timeout: 'No answer within 60 s', route_refused: 'Gray has no route for this model',
  header_refused: 'A registered header was refused', not_sealed: 'The VM holds no credential for it', credential_expired: 'Its sealed credential has expired',
  account_unknown: 'The VM doesn’t know the account yet', model_unknown: 'The model isn’t one the account serves',
};
/** The account's enforced rests that have not ended, the account-wide ones first, then by model: what the sheet lists. */
export function activeRests(report: Pick<ReportAccount, 'cooling'> | null | undefined, now: number): CoolingEntry[] {
  const key = (e: CoolingEntry) => `${e.model === null ? '0' : `1${e.model}`}\n${e.kind === 'hold' ? 0 : 1}`;
  return (report?.cooling ?? []).filter(e => !e.observed && (e.until_minute_ms === null || e.until_minute_ms > now))
    .sort((a, b) => (key(a) < key(b) ? -1 : key(a) > key(b) ? 1 : 0));
}

/**
 * The account's models as the Test picker offers them: those that rest on their own first (an enforced hold or cool of
 * that model), the held ones before the cooling ones (a hold does not end by itself), each with its rest, then the
 * others, each group in the account's order. The first
 * is the default, the console's own when a test names no model (health.ts `testModelOf`): a passing test ends the tested
 * model's rests and the account-wide ones, never another model's, so the model that rests is the one worth testing.
 */
export function testModels(models: readonly string[], report: Pick<ReportAccount, 'cooling'> | null | undefined, now: number): { model: string; rest: CoolingEntry | null }[] {
  const rests = new Map<string, CoolingEntry>();
  for (const e of activeRests(report, now)) if (e.model !== null && (!rests.has(e.model) || e.kind === 'hold')) rests.set(e.model, e);
  const resting = [...models.filter(m => rests.get(m)?.kind === 'hold'), ...models.filter(m => rests.get(m)?.kind === 'cool')].map(model => ({ model, rest: rests.get(model)! }));
  return [...resting, ...models.filter(m => !rests.has(m)).map(model => ({ model, rest: null }))];
}

/** A test's result in one line: "Passed · first token 640 ms · 1.9 s" or "Failed: Rate limited (429)". */
export function testResultText(t: StackTest): { label: string; tone: 'success' | 'danger' | 'neutral' | 'info'; detail: string } {
  if (t.state === 'pending') return { label: 'Testing…', tone: 'info', detail: 'Waiting for the VM to run it (it polls every few seconds).' };
  if (t.state === 'expired') return { label: 'No answer', tone: 'neutral', detail: 'The VM didn’t run the test within 2 minutes. Is it running?' };
  const times = [t.first_token_ms !== null && `first token ${msText(t.first_token_ms)}`, t.total_ms !== null && `${msText(t.total_ms)} in all`].filter(Boolean).join(' · ');
  if (t.outcome === 'ok') return { label: 'Passed', tone: 'success', detail: `${times || 'The vendor answered.'}${t.cleared ? ` · released ${plural(t.cleared, 'cooling')}` : ''}` };
  const why = t.class ? CLASS_WORDS[t.class] : t.code ? TEST_CODE_WORDS[t.code] ?? t.code.replaceAll('_', ' ') : 'It failed';
  const code = vendorCodeText(t.vendor_code);
  return { label: 'Failed', tone: 'danger', detail: `${why}${t.status ? ` · HTTP ${t.status}` : ''}${code ? ` · ${code}` : ''}` };
}
// ---------------------------------------------------------------------------
// Account upkeep: egress's own calls per account (relay-stack.ts OWN_CALL_TABLE), in words

const OWN_CALL_NOUN: Readonly<Record<OwnCallOp, { what: string; none: string }>> = {
  limits: { what: 'rate limits', none: 'no rate limits to read' },
  models: { what: 'models', none: 'no model list' },
};
const andList = (items: readonly string[]) => items.length <= 1 ? items.join('') : `${items.slice(0, -1).join(', ')} and ${items[items.length - 1]}`;
/** A vendor and credential type as the upkeep sentences name them: the type only for a vendor with two ("Anthropic logins"). */
function upkeepName(vendor: StackVendor, type: StackCredential) {
  return Object.keys(OWN_CALL_TABLE[vendor]).length > 1 ? `${VENDOR_LABEL[vendor]} ${type === 'api_key' ? 'API keys' : 'logins'}` : VENDOR_LABEL[vendor];
}
function upkeepRows(op: OwnCallOp) {
  return STACK_VENDORS.flatMap(vendor => (Object.entries(OWN_CALL_TABLE[vendor]) as [StackCredential, Partial<Record<OwnCallOp, { default: number; min: number; max: number }>>][])
    .map(([type, ops]) => ({ name: upkeepName(vendor, type), cadence: ops[op] ?? null })));
}
/** Gray's default cadence of one operation across the vendor table: "every 5 min for Anthropic logins and ChatGPT Codex, …". */
export function ownCallDefaultsText(op: OwnCallOp): string {
  const rows = upkeepRows(op), without = rows.filter(r => !r.cadence).map(r => r.name);
  const groups = new Map<number, string[]>();
  for (const r of rows) if (r.cadence) groups.set(r.cadence.default, [...groups.get(r.cadence.default) ?? [], r.name]);
  if (groups.size === 1 && without.length < rows.length - without.length) {
    const [seconds] = groups.keys();
    return `every ${durationText(seconds)} for every vendor but ${andList(without)}, which ${without.length === 1 ? 'has' : 'have'} ${OWN_CALL_NOUN[op].none}`;
  }
  return `${[...groups].map(([seconds, names]) => `every ${durationText(seconds)} for ${andList(names)}`).join(', ')}; other vendors have ${OWN_CALL_NOUN[op].none}`;
}
/** The relay's cadence of one operation, in words: Gray's default with what it is, off, or every n with the vendors whose bounds hold it. */
export function ownCallText(op: OwnCallOp, value: number | null): string {
  if (value === null) return `Gray’s default: ${ownCallDefaultsText(op)}`;
  if (value === 0) return `Off: egress reads no ${OWN_CALL_NOUN[op].what} for any account`;
  const held = new Map<number, string[]>();
  for (const r of upkeepRows(op)) {
    if (!r.cadence) continue;
    const seconds = Math.max(r.cadence.min, Math.min(value, r.cadence.max));
    if (seconds !== value) held.set(seconds, [...held.get(seconds) ?? [], r.name]);
  }
  const bounds = [...held].map(([seconds, names]) => `${andList(names)} every ${durationText(seconds)}, ${seconds < value ? 'their longest' : 'their shortest'}`);
  return `Every ${durationText(value)}${bounds.length ? `; ${bounds.join('; ')}` : ''}`;
}
/** What egress keeps up for one account, in words: "Rate limits every 5 min (Gray’s default) · models every 1 h (Gray’s default)". */
export function upkeepText(vendor: StackVendor, declared: StackCredential | null | undefined, own: OwnCalls): string {
  if (upkeepCredential(vendor, declared) === null) return 'Depends on the credential type: declare it in the account’s settings';
  const parts = OWN_CALL_OPS.flatMap(op => {
    const run = ownCallRun(vendor, declared, op, own.every_seconds[op]);
    if (!run || run.kind === 'none') return [];
    if (run.kind === 'off') return [`${OWN_CALL_NOUN[op].what} off`];
    return [`${OWN_CALL_NOUN[op].what} every ${durationText(run.seconds)}${run.from === 'default' ? ' (Gray’s default)' : run.from === 'held' ? ' (the vendor’s bound)' : ''}`];
  });
  return parts.length ? parts.join(' · ').replace(/^./, c => c.toUpperCase()) : 'Nothing: Gray’s vendor table has no upkeep for this vendor';
}

// ---------------------------------------------------------------------------
// Credentials: the "needs re-login" list (S45) with each kind's next step

export type NextStep = {
  title: string; detail: string; command: string | null; tone: 'danger' | 'warning';
  /** Where gray-assistant's own page does it, when the agent reports one: the step's primary action, the command its fallback. */
  open: { href: string; label: string } | null;
};
/** What the panel knows of the relay's machine to fill a step in: its relay and gray-assistant's own page. */
export type StepContext = { relayId: string; page: string | null };
/**
 * The context from gray-assistant's latest status: its own page's origin (relay-page.ts, from `ui_mode` and `ui_port`, and
 * the relay's tunnel origin the console names when it runs there) while the agent is connected. Commands name no `--config`: gray-assistant finds its config at its default location.
 */
export function stepContext(relay: Pick<StackRelay, 'relay_id' | 'token_url' | 'phase'>, agent: StackAgentStatus | null | undefined, now: number): StepContext {
  const status = agent?.status ?? null;
  const connected = agentState(agent, now, relay.phase).connected;
  return {
    relayId: relay.relay_id, page: connected ? relayPageOrigin(relay, status, agent?.tunnel_origin ?? null) : null,
  };
}
/** The exact next step of a re-login item, with the command to run on the relay's machine (the relay's own values filled in). */
export function nextStep(issue: CredentialIssue, { clock, accountsText, ctx, kindOf }: {
  clock: (ms: number) => string; accountsText: (ids: readonly string[]) => string; ctx?: StepContext;
  /** Where an account's credential is renewed (`credentialKind` of its report); absent: not known. */
  kindOf?: (accountId: string) => CredentialKind;
}): NextStep {
  const who = issue.account_ids.length ? accountsText(issue.account_ids) : null;
  // The page's own addresses (frontend/src/relay-ui/App.tsx): the accounts, the doctor's checks.
  const open = (path: (page: string) => string, label: string) => ctx?.page ? { href: path(ctx.page), label } : null;
  const accounts = (page: string) => `${page}/ui/accounts`;
  const checks = (page: string) => `${page}/ui/health`;
  switch (issue.kind) {
    case 'credential_expiring': {
      const title = `${who ?? 'A credential'}: credential ${issue.detail === 'expired' ? 'expired' : `expires ${issue.since_ms ? clock(issue.since_ms) : 'soon'}`}`;
      const tone = issue.detail === 'expired' ? 'danger' as const : 'warning' as const;
      // By where the credential is renewed: an account the relay's software signs in inside the VM signs in again there
      // (its command); one the source holds is replaced there, and accounts push seals the new one.
      const one = issue.account_ids.length === 1 ? issue.account_ids[0] : '';
      const kind = one && kindOf ? kindOf(one) : 'unknown';
      if (kind === 'sign_in') return { title, tone, open: null, command: signInCommand(one), detail: credentialFix(kind, one, 'below') };
      return { title, tone, open: open(accounts, 'Renew it on your machine'), command: PUSH_COMMAND, detail: credentialFix(kind, one) };
    }
    case 'not_sealed': return {
      title: `${who ?? 'An account'}: no credential since the VM started`, tone: 'danger', open: open(checks, 'Check it on your machine'),
      detail: `The VM ${issue.since_ms ? `started ${clock(issue.since_ms)}` : 'started'} and hasn’t received ${issue.account_ids.length === 1 ? 'its' : 'their'} credential. Run accounts push in the kit directory: it seals every account your source lists to the VM.`,
      command: PUSH_COMMAND,
    };
    case 'credential_waiting': return {
      title: `${who ?? 'An account'}: waiting for a newer credential`, tone: 'warning', open: null,
      detail: 'The panel asks for a newer credential than the VM holds. Put the new one in your account source and run accounts push; to use the one the VM holds, turn off “Require a newer credential” in the account’s settings.',
      command: PUSH_COMMAND,
    };
    // Gray adopts what the source lists and never removes an account by itself (console store.ts `syncFromSource`).
    case 'not_in_source': return {
      title: `${who ?? 'An account'}: no longer in your account source`, tone: 'warning', open: null,
      detail: `gray-assistant’s source doesn’t list ${issue.account_ids.length === 1 ? 'it' : 'them'} any more, so the VM gets no new credential for ${issue.account_ids.length === 1 ? 'it' : 'them'}. Gray keeps the account: add it back to the source and run accounts push, or delete it here if it’s gone for good.`,
      command: null,
    };
    // Listed only once gray-assistant's renewal is overdue (console state.ts `renewalOverdue`): a healthy lease never shows.
    // The same words as the relay's `lease_expiring` alert (console alerts.ts LEASE_OVERDUE_FIX, LEASE_EXPIRED_FIX).
    case 'lease_expiring': return {
      title: issue.detail === 'expired'
        ? `The VM’s credential lease ${issue.since_ms ? `ended ${clock(issue.since_ms)}` : 'has ended'} and hasn’t been renewed`
        : `The VM’s credential lease ${issue.since_ms ? `ends ${clock(issue.since_ms)}` : 'ends soon'} and hasn’t been renewed`,
      tone: issue.detail === 'expired' ? 'danger' : 'warning',
      open: open(checks, 'Check it on your machine'),
      // The command is in the item's code block (`command`): the sentence points at it instead of repeating it in prose.
      detail: (issue.detail === 'expired' ? LEASE_EXPIRED_FIX : LEASE_OVERDUE_FIX).replace(`run ${kitRun('doctor')}.`, 'run the command below.'),
      command: kitRun('doctor'),
    };
    case 'agent_silent': return {
      title: issue.since_ms ? 'gray-assistant stopped reporting' : 'gray-assistant hasn’t reported yet', tone: 'warning', open: null,
      detail: issue.since_ms ? `Its last status came ${clock(issue.since_ms)}. Gray sees your accounts again at the next accounts push; doctor says what stops it.` : 'Gray sees your accounts once gray-assistant reports them. Run accounts push in the kit directory.',
      command: issue.since_ms ? kitRun('doctor') : PUSH_COMMAND,
    };
  }
}

/**
 * The relay tunnel as the panel shows it (docs/relay-tunnel.md), from the agent's `tunnel` word and the origin the
 * console names: null for an agent without a tunnel, and on phase 2, where nothing keeps one open; unknown while the
 * agent is silent (its word is old).
 */
export function tunnelWords(agent: StackAgentStatus | null | undefined, now: number, phase?: 1 | 2): { label: string; tone: 'success' | 'danger' | 'neutral'; detail: string; origin: string | null } | null {
  const word = agent?.status?.tunnel;
  if (!agent || word === undefined || phase === 2) return null;
  const origin = agent.tunnel_origin ?? null;
  if (!agentState(agent, now).connected) return { label: 'Unknown', tone: 'neutral', origin, detail: 'gray-assistant stopped reporting, so its tunnel’s state is not known.' };
  if (word === 'connected') return { label: 'Connected', tone: 'success', origin, detail: 'Your deployment’s name answers through Gray’s rendezvous; your machine needs no public address.' };
  return { label: 'Down', tone: 'danger', origin, detail: 'Your deployment’s name does not answer, so a VM that starts now cannot reach your token service. gray-assistant tunnel status on your machine says why.' };
}

/**
 * Whether the agent counts as connected: it posted a status within the S45 silence bound (two 15-minute heartbeats).
 * On phase 2 nothing runs on the host: gray-assistant reports once per command (`deliver`, `accounts push`, a status with
 * no replica), so it is never connected and never silent. A host agent that still runs reports its replicas, as before.
 */
export const AGENT_SILENT_AFTER_MS = 30 * MIN;
export function agentState(agent: StackAgentStatus | null | undefined, now: number, phase?: 1 | 2): { label: string; tone: 'success' | 'warning' | 'neutral'; connected: boolean } {
  if (phase === 2 && !agent?.status?.replicas?.length) return { label: agent?.status && agent.received_ms !== null ? 'Runs per command' : 'Not reported yet', tone: 'neutral', connected: false };
  if (!agent?.status || agent.received_ms === null) return { label: 'Not connected', tone: 'neutral', connected: false };
  if (now - agent.received_ms > AGENT_SILENT_AFTER_MS) return { label: 'Silent', tone: 'warning', connected: false };
  return { label: 'Connected', tone: 'success', connected: true };
}

// ---------------------------------------------------------------------------
// Adoption: accounts gray-assistant found that the panel doesn't list

/** Gray's own proxies, the ones it made for an account source's proxy (console source-proxies.ts SOURCE_PROXY_PREFIX). */
export const isSourceProxy = (proxyId: string): boolean => proxyId.startsWith('source-');
/** Whether gray-assistant's source sets the account's proxy (its status names a `proxy` for it): the panel shows it read-only. */
export function proxyFromSource(agent: StackAgentStatus | null | undefined, accountId: string): boolean {
  const entry = agent?.status?.sources?.find(s => s.account_id === accountId);
  return entry !== undefined && entry.proxy !== undefined;
}

/** The accounts of the agent's source the panel lacks, in id order; null when the agent sent no source list. */
export function adoptable(agent: StackAgentStatus | null | undefined, accounts: readonly Pick<StackAccount, 'account_id'>[]): AgentSource[] | null {
  const sources = agent?.status?.sources;
  if (!sources) return null;
  const known = new Set(accounts.map(a => a.account_id));
  return sources.filter(s => !known.has(s.account_id)).sort((a, b) => a.account_id.localeCompare(b.account_id));
}
/** Whether the account is one gray-assistant's source lists: its credential and proxy come from there, so the panel pauses it but never deletes it. */
export function inSource(agent: StackAgentStatus | null | undefined, accountId: string): boolean {
  return agent?.status?.sources?.some(s => s.account_id === accountId) ?? false;
}

/** Why gray-assistant left an account out of its last push (the kit's closed park reasons), completing "<account>: …". */
export const PARK_WORDS: Readonly<Record<string, string>> = {
  invalid_credential_format: 'its credential isn’t in the form the vendor issues',
  unsupported_credential_type: 'Gray serves this vendor with no credential of this kind',
  invalid_egress_format: 'its proxy isn’t one Gray can use',
  credential_unreadable: 'gray-assistant couldn’t read its credential',
  missing_credential: 'the source holds no credential for it',
};
export const parkWords = (reason: string): string => PARK_WORDS[reason] ?? reason.replaceAll('_', ' ');

/**
 * An account the panel doesn't serve from the source yet, with its one fix: `parked`, left out of the last push for
 * `reason` (fix the source, then accounts push); `no_model`, adopted once its vendor has a model (add one to
 * relay-stack.json's models, then apply); `next_report`, adopted with gray-assistant's next report.
 */
export type WaitingAccount = { account_id: string; vendor: StackVendor | null; adopted: boolean } & ({ why: 'parked'; reason: string } | { why: 'no_model' | 'next_report' });
/**
 * The accounts waiting, parked first, each in id order: every account the last status left out, then the source's
 * accounts the panel lacks. A vendor has a model when an enabled stack endpoint maps one, as the console's adoption reads
 * it (store.ts `sourceSyncIn`). Null when the agent sent no source list.
 */
export function waitingAccounts(agent: StackAgentStatus | null | undefined, accounts: readonly Pick<StackAccount, 'account_id' | 'vendor'>[], routes: readonly Pick<StackRoute, 'vendor' | 'endpoint_enabled'>[]): WaitingAccount[] | null {
  const status = agent?.status;
  if (!status?.sources) return null;
  const known = new Map(accounts.map(a => [a.account_id, a.vendor]));
  const sources = new Map(status.sources.map(s => [s.account_id, s.vendor]));
  const byId = (a: { account_id: string }, b: { account_id: string }) => a.account_id.localeCompare(b.account_id);
  const parked = new Map((status.parked ?? []).map(p => [p.account_id, p.reason]));
  const left: WaitingAccount[] = [...parked].map(([account_id, reason]) => ({ account_id, vendor: sources.get(account_id) ?? known.get(account_id) ?? null, adopted: known.has(account_id), why: 'parked' as const, reason })).sort(byId);
  const modelled = new Set(routes.filter(r => r.endpoint_enabled).map(r => r.vendor));
  const waiting: WaitingAccount[] = (adoptable(agent, accounts) ?? []).filter(s => !parked.has(s.account_id))
    .map(s => ({ account_id: s.account_id, vendor: s.vendor, adopted: false, why: modelled.has(s.vendor) ? 'next_report' as const : 'no_model' as const }));
  return [...left, ...waiting];
}

// ---------------------------------------------------------------------------
// A new relay's onboarding checklist

export type ChecklistState = 'done' | 'current' | 'upcoming' | 'failed' | 'unknown';
/** Who moves a step on: the relay's coding agent (with the setup instructions the person copies once) or Gray. */
export type StepOwner = 'agent' | 'gray';
/** `command`: what the step's detail says to run, shown as code under it (copyable), never inside the sentence. */
export type ChecklistItem = { key: string; title: string; detail: string; state: ChecklistState; owner: StepOwner; command?: string };
/** `command` with `commandLead`, the words that introduce it: both only on the step to do now, where the command shows. */
type Step = { key: string; title: string; owner: StepOwner; done: boolean | null; failed?: string | null; doneText: string; todoText: string; command?: string; commandLead?: string };
/** The VM as the checklist reads it (the deployment): its state, why it failed, and the start-up step under way. */
/**
 * What to do about the VM's lease past its renewal: Overview's and Credentials' item and the Messages tab say the same as
 * the alert's e-mail (console alerts.ts LEASE_OVERDUE_FIX, LEASE_EXPIRED_FIX; relay-stack-health.test.mjs holds them).
 */
export const LEASE_OVERDUE_FIX = `gray-assistant normally renews it well before then. Past it the VM serves no account. On your machine, in gray-assistant’s kit directory, run ${kitRun('doctor')}.`;
export const LEASE_EXPIRED_FIX = `The VM serves no account until gray-assistant renews it. On your machine, in gray-assistant’s kit directory, run ${kitRun('doctor')}.`;

/** gray-assistant's version as it reported it; null for none, or 0.0.0 (what a kit built without a version stamp says). */
export const reportedVersion = (version: string | null | undefined): string | null => (version && version !== '0.0.0' ? version : null);
/** "gray-assistant 0.9.3", or "gray-assistant version not reported" rather than a misleading 0.0.0. */
export const grayRelayVersion = (version: string | null | undefined): string => {
  const v = reportedVersion(version);
  return v ? `gray-assistant ${v}` : 'gray-assistant version not reported';
};

/** The contact step's title, as the setup API's (provider-setup/relay-stack.ts CONTACT_TITLE). */
export const CONTACT_TITLE = 'Tell Gray where to reach you';
const CONTACT_TODO = 'Your agent asks you for an e-mail address, for Gray to reach you about new releases, your traffic window, and problems with your VM or accounts.';
/**
 * Overview's and the VM tab's notice while the relay has left no way to be reached: no confirmed address, no webhook
 * and no address saved where Gray sends no e-mail. What it is for, and the one thing to do on the Messages tab. Null
 * once it left one, or the console does not say.
 */
export function contactNotice(contact: StackRelay['contact'], canManage: boolean): { title: string; body: string; action: string } | null {
  if (!contact || contact.reachable || contact.saved) return null;
  if (contact.pending) {
    return { title: 'Confirm your address', body: `We sent a code to ${contact.pending}. ${canManage ? 'Enter it on the Messages tab to confirm the address.' : 'A member who manages this workspace’s services enters it on the Messages tab.'} Until then Gray’s notices are only your messages here, and nothing is sent to you.`, action: canManage ? 'Enter the code' : 'Open messages' };
  }
  const why = 'Gray needs an e-mail address for this deployment: its people write to it when a release, your traffic window, your VM or an account needs you.';
  return { title: 'Leave an address for Gray', body: `${why} ${canManage ? 'Add one on the Messages tab.' : 'A member who manages this workspace’s services can add one on the Messages tab.'}`, action: canManage ? 'Add an address' : 'Open messages' };
}
/** Overview's notice while Gray has messages this member has not read (the Messages tab lists them); null when there are none. */
export function messagesNotice(unread: number | undefined): { title: string; body: string; action: string } | null {
  if (!unread) return null;
  return { title: unread === 1 ? 'Gray has 1 new message for you' : `Gray has ${n(unread)} new messages for you`, body: 'A release to approve, a Deploy you can make, or a problem with your VM or accounts: Gray keeps its notices here. Your agent reads them too, in its setup status.', action: unread === 1 ? 'Read it' : 'Read them' };
}

/** The deploy step once Gray approved the relay's VM: Deploy can start (RelaySetup.tsx AgentProgress gives it its action). */
export const DEPLOY_APPROVED = 'Gray approved your VM. Your agent deploys it, or you press Deploy on the VM tab.';
/** The deploy step while Gray has yet to propose a release the relay can start on (`release_retired_unproposed`). */
export const DEPLOY_WAITS_FOR_GRAY = 'The release this deployment paired on can’t start new VMs any more, and Gray has to propose a newer one before you can Deploy. Gray’s operators have been told; there is nothing to do on your side.';
/** How the deploy step's words end once a release in effect on the contract makes Deploy possible (RelaySetup.tsx AgentProgress). */
export const DEPLOY_NOW = 'Deploy now, on the VM tab.';
/**
 * The wait for Gray's operators to decide the VM, on the Deploy step and the VM tab: who decides, about how long, and
 * that the relay is told (the console's `vm_decided` message), so nobody has to keep the page open.
 */
export const VM_DECISION_WAIT = 'Gray’s operators are deciding your VM, usually within a day; there is nothing to do until then. Gray leaves you a message when they decide (the Messages tab).';
/**
 * Whether the Deploy step is the one to do now and nothing holds it: Gray approved the VM, or the release a first
 * Deploy waited for is in effect. "Your part" then says so instead of "Done" (the page's header and the step do).
 */
export const deployStepReady = (steps: readonly Pick<ChecklistItem, 'key' | 'state' | 'detail'>[]): boolean =>
  steps.some(step => step.key === 'deploy' && step.state === 'current' && (step.detail === DEPLOY_APPROVED || step.detail.endsWith(DEPLOY_NOW)));
/** "Your part" while the Deploy step is ready. */
export const DEPLOY_READY_PART = 'One step is ready: Deploy your VM. Your agent does it at its next apply, or press Deploy on the VM tab.';
/** The same while the relay left no address: an agent's apply deploys only once it has one (the console's contact step). */
export const DEPLOY_READY_NO_ADDRESS_PART = 'One step is ready: Deploy your VM. Press Deploy on the VM tab; or first leave an address for Gray in the list below, and your agent deploys it at its next apply.';
/** "Your part" while Gray's operators decide the VM: the wait is hours, the agent's session need not last it. */
export const VM_WAIT_PART = 'Nothing to do now: Gray’s operators are deciding your VM, usually within a day, and Gray leaves you a message when they decide. Your agent’s session can end meanwhile; after the message, copy the instructions again and paste them into your agent, which goes on from there.';
/** The same while the relay still owes its address: what is the person's to do comes first, the wait after it. */
export const vmWaitOwedPart = (owed: string): string => `One thing is yours now: ${owed} in the list below; your agent’s Deploy waits for it. Meanwhile Gray’s operators are deciding your VM, usually within a day, and Gray leaves you a message when they decide.`;
/** "Your part" while the address is the one step that waits for the person and the setup is elsewhere: never "Done". */
export const addressPart = (owed: string): string => `One thing is yours: ${owed} in the list below. Your agent goes on with the other steps meanwhile.`;
/**
 * "Your part" for what waits for the person, null when nothing does ("Done", or a failed step's line): Deploy ready,
 * Gray's operators deciding the VM, each with the address when it is still owed; or the address alone. From the same steps
 * as the list below it, so the two never disagree on a page left open.
 */
export function deployPartLine(steps: readonly Pick<ChecklistItem, 'key' | 'state' | 'detail'>[]): string | null {
  const contact = steps.find(step => step.key === 'contact' && step.state === 'current');
  // What the address step asks of the person now: an address, or the code Gray sent to the one they gave.
  const owed = contact ? (contact.detail.startsWith('Enter the code') ? 'enter the code Gray sent to your address' : 'leave an address for Gray') : null;
  if (deployStepReady(steps)) return owed ? DEPLOY_READY_NO_ADDRESS_PART : DEPLOY_READY_PART;
  const waiting = steps.some(step => step.key === 'deploy' && step.state === 'current' && step.detail.endsWith(VM_DECISION_WAIT));
  if (waiting) return owed ? vmWaitOwedPart(owed) : VM_WAIT_PART;
  // Elsewhere in the setup with the address still owed: that step is the person's, so the card does not say "Done".
  return owed ? addressPart(owed) : null;
}
/** How the pair step's words begin when the pairing is made again for a release that can no longer be deployed (RelaySetup.tsx stepAction). */
export const PAIR_FOR_RELEASE = 'The Gray release this deployment paired on can no longer be deployed';
/** The deploy step while a release Gray proposed waits for the guardian (`release_retired_proposed`): what to do, in order. */
export const DEPLOY_APPROVE_FIRST = 'Approve Gray’s new release, then Deploy. The release you paired on can’t start new VMs any more; the VM tab has the command.';
export type ChecklistVm = {
  state: 'none' | 'deploying' | 'running' | 'failed' | 'restarting' | 'deleting' | 'deleted'; failure: string | null; step: string | null;
  /** Phase 2: the running VM came up in the empty slot (its boot logged prelaunch_empty_slot) and waits for `deliver`. */
  awaitingDelivery?: boolean;
  /** Phase 2: the VM restarts for the relay's `deliver` (a restart the relay signed, S53): the delivery is done. */
  delivered?: boolean;
  /** Deploy is refused until gray-assistant pairs again (`blocked.deploy.code` release_retired_pair_again): the pairing's release can no longer boot. */
  pairAgain?: boolean;
  /** Whether a VM exists (relay-stack-vm.ts vmExists): a Deploy that failed before the cloud made one left none. Absent: by the state. */
  exists?: boolean;
  /**
   * The pairing's release can no longer start VMs, and a first Deploy waits on a newer one: `approve`, Gray proposed it
   * and the guardian approves it (release_retired_proposed); `unproposed`, Gray has yet to propose it; `ready`, it is in
   * effect on the relay's contract and Deploy boots it (`deploy_ready`), `approved` when the guardian approved it.
   */
  release?: 'approve' | 'unproposed' | 'ready' | null;
  approved?: boolean;
  /** Gray's decision on the relay's VM (the deployment's quota): not asked, asked (and when), approved, refused. */
  quota?: { state: 'none' | 'requested' | 'approved' | 'refused'; requested_ms: number | null };
};
/**
 * The steps from a registered relay to served traffic, each green from a real signal. A step's detail is one short line:
 * what turned it green, what to do, or why it failed (the fix is where its action leads). One step is current: the
 * first not done, unless one failed, which is then the one to fix. `vm` is the VM tab's read of the deployment; without
 * it (a console before the provisioner, or the read failed) the VM's steps go by the relay record and the VM's reports.
 */
export function onboarding({ relay, accounts, health, agent, served, priced, now, clock = ms => new Date(ms).toLocaleString('en-US', { month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' }), later = {}, boot = null, vm = null, ready = false }: {
  relay: Pick<StackRelay, 'image' | 'registry' | 'token_url' | 'app_id' | 'lane_origin' | 'kms_ca_pubkey' | 'endpoints' | 'last_pull_token_issue' | 'pairing' | 'phase' | 'phase_wanted' | 'contact'> & { created_ms?: number; relay_id?: string };
  accounts: readonly StackAccount[] | null;
  health: StackHealth | null | undefined;
  agent: StackAgentStatus | null | undefined;
  /** Whether an account of the relay completed a customer's request (usage), null when unknown; a failed one does not count. */
  served: boolean | null;
  /** Whether any of its models has an approved price (the gateway's view), null when unknown. */
  priced: boolean | null;
  now: number;
  clock?: (ms: number) => string;
  /** The image the VM reports at boot, once that signal exists. */
  later?: { bootImage?: string | null };
  /** What holds the VM's boot or stopped it, in the token service's words (relay-stack-vm.ts bootReason, S58). */
  boot?: { title: string; fix: string } | null;
  vm?: ChecklistVm | null;
  /** The operator said the image is built (My image is ready, kept in this browser); Gray sees it only once it is pinned. */
  ready?: boolean;
}): ChecklistItem[] {
  // The image the VM booted: the one it reports at boot once that signal exists, else the digest the compose pins.
  const image = later.bootImage ?? relay.image;
  const digest = image?.match(/@sha256:([0-9a-f]{64})$/)?.[1]?.slice(0, 12) ?? null;
  const repository = image?.split('@')[0]?.split('/').pop() ?? null;
  const agentNow = agentState(agent, now, relay.phase);
  const listed = (accounts ?? []).filter(a => a.status === 'active' && a.models.length > 0);
  const models = [...new Set(relay.endpoints.filter(e => e.enabled).map(e => vendorLabel(e.vendor)))];
  // The listed accounts holding a sealed key (a paused one is not listed, so "3 of 2 sealed" never shows).
  const listedIds = new Set(listed.map(a => a.account_id));
  const holding = (health?.accounts ?? []).filter(a => a.report?.sealed && (listedIds.size === 0 || listedIds.has(a.account_id))).length;
  const refused = health?.vm?.config.absent === 'stack_config_refused';
  // A Deploy that failed before the cloud made a VM left none: its failure is the deploy step's, not the boot's.
  const hasVm = vm ? vm.exists ?? (vm.state !== 'none' && vm.state !== 'deleted') : relay.app_id !== null && relay.lane_origin !== null && relay.kms_ca_pubkey !== null;
  const deployFailed = !!vm && !hasVm && vm.state === 'failed';
  const booted = vm ? vm.state === 'running' : relay.last_pull_token_issue !== null || !!health?.vm;
  const silent = relay.phase !== 2 && agent?.status && !agentNow.connected && agent.received_ms ? `gray-assistant stopped reporting ${agoText(agent.received_ms, now)}; check it with gray-assistant doctor on your machine.` : null;
  // Pairing (S57) replaces connecting by hand: done once Gray holds the relay's key; a console without it, as before.
  const key = relay.pairing?.key ?? null;
  const version = agent?.status ? ` · ${grayRelayVersion(agent.status.agent_version)}` : '';
  const pairedAt = key?.paired_ms ? clock(key.paired_ms) : null;
  // Paired on phase 1 while Gray runs the relay on phase 2 (rehearsal of 2026-11-13): the pairing is made again, and
  // until then no boot of its VM connects; the provider setup API's pair step says the same (PAIR_AGAIN_TEXT).
  const pairAgain = key !== null && relay.phase !== 2 && relay.phase_wanted === 2;
  // Paired on a release that can no longer be deployed, with no contract on chain to approve a newer one on: the same step.
  const releaseAgain = key !== null && !pairAgain && vm?.pairAgain === true;
  const grayRelay: Step = relay.pairing ? {
    key: 'pair', title: 'Pair gray-assistant', owner: 'agent', done: key !== null && !pairAgain && !releaseAgain,
    failed: releaseAgain ? `${PAIR_FOR_RELEASE}, and no newer one can be approved before a first Deploy: pair gray-assistant again to take Gray’s current release. Nothing is lost: the deployment has no VM yet.` : pairAgain ? 'This deployment is still on phase 1, and Gray runs it on phase 2 now: its VM cannot connect until your agent pairs gray-assistant again (relay-stack.md §10). Delete the VM first if it has one.' : key ? silent : null,
    // A key the stack endpoints name came from the registration, unless a pairing gave it (its time says so): the
    // agent's first model copies the paired key to its endpoint, and the step must not change its words then.
    doneText: key?.source === 'endpoints' && !key.paired_ms ? 'With your registration’s key'
      : agentNow.connected || relay.phase === 2 ? `${pairedAt ?? 'Paired'}${version}` : `Paired${pairedAt ? ` ${pairedAt}` : ''} · start gray-assistant to connect it`,
    todoText: 'Your agent installs gray-assistant on your server and links it to Gray.',
  } : {
    key: 'agent', title: 'Connect gray-assistant', owner: 'agent', done: agentNow.connected, failed: silent,
    doneText: `Connected${version}`, todoText: 'Your agent runs gray-assistant on your machine with this deployment’s stack section.',
  };
  const starting = vm && (vm.state === 'deploying' || vm.state === 'restarting') ? vm.step : null;
  const steps: Step[] = [
    // The relay's coding agent does every step but Gray's from the instructions the person copies once
    // (/v1/setup/relay-stack.md, deploy/relay/kit/AGENTS.md); each step is the panel's by hand too. Gray sees the image
    // once it is pinned; until then the operator's own word that it is ready moves the steps on.
    { key: 'build', title: 'Build your image', owner: 'agent', done: relay.image !== null || ready,
      doneText: relay.image !== null ? 'Built and pinned' : 'You marked it ready. Gray sees it once the image is pinned.',
      todoText: 'Your agent adapts your software to Gray’s standard, builds an image and uploads it to your registry.' },
    { key: 'register', title: 'Name your deployment', owner: 'agent', done: true, doneText: [relay.relay_id, relay.created_ms ? clock(relay.created_ms) : 'Registered'].filter(Boolean).join(' · '), todoText: 'Your agent registers the deployment with Gray under the name you choose.' },
    // Where Gray's notices go (owner decision of 2026-11-14): done by a confirmed address or a webhook, as the setup
    // API's contact step (provider-setup/relay-stack.ts); unknown on a console that does not say. It comes right
    // after the relay's name, where the agent's apply asks for it (it queues no first Deploy without one), and it is
    // open beside the step the setup is at, never instead of it: by hand the steps open one at a time, and this one
    // must hold none of the others back (the pairing's card stays usable).
    { key: 'contact', title: CONTACT_TITLE, owner: 'agent', done: relay.contact ? relay.contact.reachable || !!relay.contact.saved : null,
      // Saved where Gray sends no e-mail: an address Gray's people use, not one notices are sent to.
      doneText: relay.contact?.reachable ? 'Gray’s notices reach you' : `${relay.contact?.saved ?? 'Your address'} is saved. Gray can’t send e-mail yet, so your notices are on the Messages tab.`,
      todoText: relay.contact?.pending ? `Enter the code we sent to ${relay.contact.pending}: on the Messages tab, or give it to your agent.` : CONTACT_TODO },
    grayRelay,
    { key: 'image', title: 'Pin your image', owner: 'agent', done: relay.image !== null && relay.registry !== null && relay.token_url !== null,
      doneText: digest ? `${repository} · sha256:${digest}` : `${repository ?? 'Your image'} · ${relay.registry ?? 'your registry'}`, todoText: 'Your agent tells Gray the exact image to run and the registry it comes from.' },
    // Deploy is the agent's apply once Gray approved the VM, or the VM tab's button (docs/relay-stack-provisioner.md P5);
    // gray-assistant takes the VM's values from Gray by itself (P12), so nothing is published for the relay to copy.
    // A first Deploy that waits on a newer release (the pairing's can no longer start VMs) says whose turn it is: the
    // guardian's approval, Gray's proposal, or Deploy itself once the release is in effect on the contract.
    { key: 'deploy', title: 'Deploy your VM', owner: vm?.release === 'unproposed' || (!vm?.release && !hasVm && vm?.quota?.state === 'requested') ? 'gray' : 'agent', done: hasVm, doneText: 'Gray made your VM',
      failed: vm?.release === 'approve' ? DEPLOY_APPROVE_FIRST
        : deployFailed && vm?.release !== 'unproposed' && vm?.release !== 'ready' && !releaseAgain ? `${vm?.failure ?? 'Deploy did not go through.'} The VM tab says what to do.` : null,
      // Gray's turn is no failure of the relay's: the step waits, tagged Gray.
      todoText: vm?.release === 'unproposed' ? DEPLOY_WAITS_FOR_GRAY : vm?.release === 'ready' ? `${vm.approved ? 'Your guardian approved Gray’s new release.' : 'Gray’s new release is in effect on your contract.'} ${DEPLOY_NOW}`
        // Whose turn it is by Gray's decision on the VM: nobody asked yet, Gray is deciding (since when), or Deploy can start.
        : vm?.quota?.state === 'requested' ? `${vm.quota.requested_ms ? `Asked ${agoText(vm.quota.requested_ms, now)}.` : 'Asked.'} ${VM_DECISION_WAIT}`
        : vm?.quota?.state === 'approved' ? DEPLOY_APPROVED
        : vm?.quota?.state === 'refused' ? 'Gray did not approve a VM for this deployment. The VM tab says why; ask Gray before asking again.'
        : 'Your agent asks Gray for a VM, or you ask on the VM tab. Once Gray approves, the agent deploys it.' },
    { key: 'boot', title: relay.phase === 1 ? 'The VM starts your image' : 'Gray starts your VM', owner: 'gray', done: booted && !refused && !boot,
      failed: refused ? 'The VM refused its configuration.' : boot ? boot.title : vm?.state === 'failed' && hasVm ? vm.failure ?? 'The VM didn’t start.' : null,
      doneText: relay.last_pull_token_issue ? `Started ${clock(relay.last_pull_token_issue.issued_ms)}` : 'Started',
      todoText: starting ?? (relay.phase === 1 ? 'Gray starts the VM. gray-assistant gives it access to download your image.' : 'Gray starts the VM. It waits, empty, until your image is delivered.') },
    // Phase 2: the first boot waits in the empty slot until the agent runs `deliver`, which restarts it with the image
    // (the setup API's `deliver` step, provider-setup/relay-stack.ts).
    // Its title names the image alone: the accounts it seals are listed by the next steps (Gray adopts what it reports).
    { key: 'deliver', title: 'Deliver your image', owner: 'agent', done: vm ? (vm.state === 'running' && !vm.awaitingDelivery) || (vm.state === 'restarting' && !!vm.delivered) : booted,
      doneText: vm?.state === 'restarting' ? 'Delivered. The VM is restarting with your image.' : 'Your image runs in the VM', command: vm?.awaitingDelivery ? kitRun('deliver') : undefined, commandLead: 'Your agent runs this in the kit directory:',
      todoText: vm?.awaitingDelivery ? 'The VM waits for its delivery.' : 'Your agent sends your image to the waiting VM, which restarts with it. The delivery also reports your accounts to Gray.' },
    // Gray makes a vendor's stack endpoint with the relay's first model of it (Models), so an enabled one means a model.
    { key: 'models', title: 'Add your models', owner: 'agent', done: models.length > 0, doneText: models.join(', '), todoText: 'Your agent lists the models your deployment serves on Gray.' },
    // The agent points gray-assistant's account source at the relay's own software (GUIDE §4) and adopts what it finds; the
    // keys go from there to gray-assistant and are sealed to the VM, never typed.
    { key: 'accounts', title: 'Add your accounts', owner: 'agent', done: listed.length > 0, doneText: plural(listed.length, 'account'), todoText: 'Gray lists the accounts gray-assistant reports from your software, at the delivery or at a later report.' },
    { key: 'credentials', title: 'Keys reach the VM', owner: 'agent', done: holding > 0, doneText: `${n(holding)} of ${n(listed.length || holding)} sealed`,
      command: kitRun('accounts push'), commandLead: 'The command your agent runs:',
      todoText: 'gray-assistant reads each account’s key from your software and sends it to the VM encrypted. Only the VM can read it.' },
    // A relay sets its own prices (a free market): each takes effect when the agent applies it, with no approval.
    { key: 'prices', title: 'Price your models', owner: 'agent', done: priced, doneText: 'In force', todoText: 'Your agent sets a price for each model. It takes effect at once, and customers can use the model.' },
    { key: 'served', title: 'First request served', owner: 'gray', done: served, doneText: 'An account completed a customer’s request', todoText: 'This turns green when an account completes a customer’s request. A failed request doesn’t count.' },
  ];
  const anyFailed = steps.some(step => step.failed);
  let current = anyFailed;
  return steps.map(({ done, failed, doneText, todoText, command, commandLead, ...step }) => {
    if (failed) return { ...step, state: 'failed' as const, detail: failed };
    if (done === null) return { ...step, state: 'unknown' as const, detail: todoText };
    // The address can be left at any moment: to do now beside the step the setup is at, taking nobody's turn.
    if (!done && step.key === 'contact') return { ...step, state: 'current' as const, detail: todoText };
    if (done) return { ...step, state: 'done' as const, detail: doneText };
    if (!current) { current = true; return { ...step, state: 'current' as const, detail: command && commandLead ? `${todoText} ${commandLead}` : todoText, ...(command ? { command } : {}) }; }
    return { ...step, state: 'upcoming' as const, detail: todoText };
  });
}

/**
 * The setup's steps before the relay exists, each with what it will need: the same steps and words as `onboarding`,
 * all to do, for a page that names the relay first.
 */
export function setupPreview(): ChecklistItem[] {
  const pairing = { state: 'unpaired', code: null, key: null, refusal: null, blocked: null } as const;
  return onboarding({ relay: { image: null, registry: null, token_url: null, app_id: null, lane_origin: null, kms_ca_pubkey: null, endpoints: [], last_pull_token_issue: null, pairing },
    accounts: [], health: null, agent: null, served: false, priced: false, now: 0 })
    .map(step => ({ ...step, state: 'upcoming' as const, detail: step.key === 'register' ? 'Your agent registers the deployment with Gray under the name you choose.' : step.detail }));
}

// ---------------------------------------------------------------------------
// A client identity an account still stores (retired 2026-11-18: never sent to the VM, console store.ts documentOf)

/** An identity with no header, beta or id: stored, it is none. */
export const isNoIdentity = (i: IdentityValue | null | undefined) => !!i && !Object.keys(i.headers).length && !i.betas.length && !i.generated.length;
/** What an account's details say it stores, read-only; the panel no longer sets either. */
/**
 * The client identity an account still stores (retired 2026-11-18, never applied), in a few words: its profile by the
 * name the relay gave it (as written), and its own; null when it stores none.
 */
export function storedIdentity(account: { identity?: IdentityValue | null; identity_profile?: string | null }): string | null {
  const own = !!account.identity && !isNoIdentity(account.identity);
  if (account.identity_profile) return `${account.identity_profile} profile${own ? ' and its own' : ''}`;
  return own ? 'Its own' : null;
}

/**
 * An account that signs in: every ChatGPT Codex account, and an Anthropic one without an API key. The vendor states
 * its usage windows on each answer, a call or a test (egress README "Windows (S36)": Anthropic's `unified` headers,
 * Codex's `x-codex-*`), so the panel has none to show before the first.
 */
export const signsIn = (account: { vendor: StackVendor; credential_type?: CredentialType | null }) =>
  account.vendor === 'chatgpt_codex' || (account.vendor === 'anthropic' && account.credential_type !== 'api_key');

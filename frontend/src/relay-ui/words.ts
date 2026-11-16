// The local page's words: vendor and credential names, states, times and the sentences for the server's closed
// refusal codes. Pure, so `words.test.mjs` reads each in Node.
import { COMPATIBLE_VENDORS, compatibleRows, isCompatibleVendor } from '../runtime/lane-vendors.ts';
import { serverStateText, shortReason, type AccountHealth } from '../runtime/relay-stack-health.ts';
import type { Account, AgentState, CredentialType, PanelAccount, PanelView, PastedCredentialType, Proxy, PushView, RelayInfo, Vendor } from './api';

export const VENDORS: readonly Vendor[] = ['anthropic', 'openai', 'chatgpt_codex', ...COMPATIBLE_VENDORS.map(v => v.id)];

export const VENDOR_LABEL: Record<Vendor, string> = { anthropic: 'Anthropic', openai: 'OpenAI', chatgpt_codex: 'ChatGPT Codex', ...compatibleRows(v => v.name) };

/** The credential kinds the form takes for each vendor, in the order it offers them; the first is the default. */
export const CREDENTIAL_CHOICES: Record<Vendor, readonly PastedCredentialType[]> = {
  anthropic: ['api_key', 'oauth_access_token'],
  openai: ['api_key'],
  chatgpt_codex: ['oauth_access_token'],
  ...compatibleRows(() => ['api_key'] as const),
};

export function credentialLabel(vendor: Vendor, type: CredentialType): string {
  if (type === 'sign_in') return 'Signs in inside the VM';
  if (type === 'password') return 'Password sign-in inside the VM';
  if (type === 'api_key') return 'API key';
  return vendor === 'anthropic' ? 'Sign-in token' : 'Access token';
}

/** What the key field expects, for its hint. */
export function keyHint(vendor: Vendor, type: CredentialType): string {
  if (vendor === 'anthropic' && type === 'api_key') return 'Starts with sk-ant-api03-.';
  if (vendor === 'anthropic') return 'A sign-in token: starts with sk-ant-oat01-.';
  if (vendor === 'openai') return 'Starts with sk- (a project key, sk-proj-, works too). Admin keys are refused.';
  if (isCompatibleVendor(vendor)) return `A ${VENDOR_LABEL[vendor]} pay-as-you-go API key for this region's host, not a coding-plan key.`;
  return 'An access token (a JWT). It can’t refresh itself.';
}

export type KeyKind = 'anthropic_api_key' | 'anthropic_subscription' | 'openai_api_key' | 'access_token' | 'admin_key' | 'vendor_api_key' | 'unknown';

/**
 * What a pasted key looks like, by its public prefix only, so the operator sees at once whether they pasted the right
 * kind. gray-assistant checks the whole format itself (the TEE's rule) when the form is sent; this is the hint.
 */
export function recognizeKey(value: string): { readonly kind: KeyKind; readonly label: string } | null {
  const key = value.trim();
  if (key === '') return null;
  if (/^sk-ant-admin/.test(key) || /^sk-admin-/.test(key)) return { kind: 'admin_key', label: 'Looks like an admin key, which is refused' };
  if (/^sk-ant-api\d\d-/.test(key)) return { kind: 'anthropic_api_key', label: 'Looks like an Anthropic API key' };
  if (/^sk-ant-oat\d\d-/.test(key)) return { kind: 'anthropic_subscription', label: 'Looks like a sign-in token' };
  if (key.startsWith('sk-')) return { kind: 'openai_api_key', label: 'Looks like an OpenAI API key' };
  if (key.split('.').length === 3 && key.length > 40) return { kind: 'access_token', label: 'Looks like an access token' };
  return { kind: 'unknown', label: 'Not a key format gray-assistant knows' };
}

/** The kind of key a vendor and credential type take. */
export function expectedKeyKind(vendor: Vendor, type: CredentialType): KeyKind {
  if (isCompatibleVendor(vendor)) return 'vendor_api_key';
  if (vendor === 'anthropic') return type === 'api_key' ? 'anthropic_api_key' : 'anthropic_subscription';
  if (vendor === 'openai') return 'openai_api_key';
  return 'access_token';
}

/**
 * Whether a pasted key looks like the kind the vendor takes. An OpenAI-compatible vendor's keys have no shape of their
 * own (`sk-…`, `AIza…`, `<id>.<secret>`, a JWT), so any key fits it but an admin key and Anthropic's.
 */
export function keyFits(vendor: Vendor, type: CredentialType, seen: { readonly kind: KeyKind } | null): boolean {
  if (seen === null) return true;
  const expected = expectedKeyKind(vendor, type);
  if (expected === 'vendor_api_key') return seen.kind !== 'admin_key' && seen.kind !== 'anthropic_api_key' && seen.kind !== 'anthropic_subscription';
  return seen.kind === expected;
}

/** A gray-assistant command line for this relay: `--config` only when gray-assistant would not find the config itself. */
export function relayCommand(relay: { config_path: string; config_default: boolean }, verb: string): string {
  return relay.config_default ? `gray-assistant ${verb}` : `gray-assistant ${verb} --config ${relay.config_path}`;
}

export const AGENT_WORDS: Record<AgentState, { label: string; tone: 'success' | 'warning' | 'danger' | 'neutral' }> = {
  running: { label: 'Running', tone: 'success' },
  stale: { label: 'Not reporting', tone: 'warning' },
  stopped: { label: 'Stopped', tone: 'danger' },
  not_running: { label: 'Not running', tone: 'neutral' },
};

/** Why the agent left an account out (its closed park reasons), in words. */
const PARK_REASONS: Record<string, string> = {
  not_selected: 'The config’s source.select leaves it out.',
  status: 'Its status in accounts.json is not active.',
  unsupported_credential_type: 'This vendor doesn’t take this kind of credential.',
  invalid_credential_format: 'The key isn’t in the vendor’s format. Replace it.',
  credential_unreadable: 'gray-assistant couldn’t read its key. Check accounts.json.',
  missing_credential: 'It has no key yet.',
  credential_expired: 'Its key has expired. Replace it.',
  credential_expired_unchanged: 'Its key expired and nothing replaced it.',
  invalid_egress_format: 'Its proxy isn’t one the lane accepts.',
};

/**
 * The CT monitor's alert (docs/relay-tunnel.md): Certificate Transparency logs show certificates for the relay's name
 * that gray-assistant did not obtain, so someone else may be able to answer on it. Null while there is none.
 */
export function ctAlertText(tunnel: RelayInfo['tunnel']): { title: string; detail: string } | null {
  if (tunnel?.ct?.state !== 'alert') return null;
  const n = tunnel.ct.findings;
  return {
    title: `${n === 1 ? 'A certificate' : `${n} certificates`} for ${tunnel.name} that gray-assistant did not obtain`,
    detail: 'Certificate Transparency logs show it, so someone else may be able to answer on your deployment’s name. gray-assistant tunnel status on your machine lists each one; once you have explained one, gray-assistant tunnel ack <sha256> clears it.',
  };
}

export function parkReason(reason: string | null): string {
  if (reason === null) return 'gray-assistant left it out.';
  return PARK_REASONS[reason] ?? `gray-assistant left it out (${reason.replaceAll('_', ' ')}).`;
}

/** The account's credential as one short phrase. */
export function credentialPhrase(account: Pick<Account, 'vendor' | 'credential_type'>): string {
  return credentialLabel(account.vendor, account.credential_type);
}

export function modelsPhrase(models: Account['models']): string {
  if (models === '*') return 'All models';
  if (models.length === 1) return models[0]!;
  return `${models[0]} and ${models.length - 1} more`;
}

/** The server's refusals, in the page's words. `field` refusals are said beside their field. */
const REFUSALS: Record<string, string> = {
  signed_out: 'You’re signed out of this page.',
  not_loopback: 'Open this page at 127.0.0.1 or localhost.',
  unreachable: 'gray-assistant doesn’t answer. Is gray-assistant ui still running?',
  csrf: 'This page is out of date. Reload it and try again.',
  cross_site: 'gray-assistant refused a request that didn’t come from this page.',
  source_read_only: 'accounts.json can’t be changed from here: its folder is read-only for gray-assistant.',
  source_not_file: 'Accounts come from your software, not from accounts.json.',
  source_unreadable: 'accounts.json can’t be read as it is. Fix it first.',
  refused_by_source: 'gray-assistant would refuse accounts.json with this change.',
  account_not_found: 'That account isn’t in accounts.json any more.',
  busy: 'Another gray-assistant command is changing the same file. Try again in a moment.',
  io: 'gray-assistant couldn’t read or write a file.',
  internal: 'Something went wrong in gray-assistant.',
  not_found: 'gray-assistant doesn’t know that request.',
  passkey_refused: 'gray-assistant didn’t accept that passkey.',
  enroll_link_invalid: 'This enrolment link has been used or has expired.',
  ceremony_expired: 'The passkey prompt took too long. Try again.',
  rate_limited: 'Too many tries. Wait a minute and try again.',
  not_available: 'This gray-assistant page can’t do that. Use the command on your machine.',
  sign_in_busy: 'Four sign-ins are under way already. Finish or cancel one first.',
  sign_in_no_input: 'This sign-in takes nothing now. If it ended, start it again.',
  sign_in_unknown: 'That sign-in ended. Start it again.',
  proxy_not_found: 'That proxy isn’t in the list any more.',
  proxy_in_use: 'Accounts still leave through this proxy. Move them to another first.',
};

export function refusalText(code: string, detail?: string | null): string {
  // A proxy in use names who uses it (their ids, at most ten).
  if (code === 'proxy_in_use' && detail) return `${detail.split(',').join(', ')} still ${detail.includes(',') ? 'leave' : 'leaves'} through this proxy. Move ${detail.includes(',') ? 'them' : 'it'} to another first.`;
  const text = REFUSALS[code] ?? `gray-assistant refused it (${code.replaceAll('_', ' ')}).`;
  return detail ? `${text} (${detail})` : text;
}

/** A refusal of the page's server in words: what its field means when it names one, else its code's sentence. */
export function refusalWords(refusal: { code: string; field: string | null; detail: string | null } | null): string {
  if (!refusal) return refusalText('internal');
  return refusal.field ? fieldError(refusal.field, refusal.code, refusal.detail) : refusalText(refusal.code, refusal.detail);
}

/** Which pasted line a refusal is about: the server names it by its place (`keys.2`, `proxies.0`), counted from zero. */
function lineOf(detail: string | null | undefined): number | null {
  const match = /^[a-z_]+\.(\d+)$/.exec(detail ?? '');
  return match ? Number(match[1]) + 1 : null;
}

/** A refusal said beside one field of a form; `detail` names the pasted line it is about, when the server does. */
export function fieldError(field: string, code: string, detail?: string | null): string {
  const line = lineOf(detail);
  if (field === 'account_id') return code === 'taken' ? 'An account with this ID exists already.' : 'Use 1–128 letters, digits and . _ : - (no spaces).';
  if (field === 'credential') {
    if (code === 'format') return 'This isn’t in the format this vendor uses for this kind of key.';
    if (code === 'type_vendor') return 'This vendor doesn’t take this kind of credential.';
    return 'Paste the key.';
  }
  if (field === 'keys') {
    const which = line === null ? 'A key here' : `Key ${line}`;
    if (code === 'format') return `${which} isn’t in the format this vendor uses. Nothing was added.`;
    if (code === 'duplicate') return `${which} is here twice. Nothing was added.`;
    if (code === 'taken') return `${which} belongs to an account of this vendor already. Nothing was added.`;
    return 'Paste the keys, one a line.';
  }
  if (field === 'id_prefix') return 'Use letters, digits and . _ : - (no spaces), or leave it empty.';
  if (field === 'group') return 'A group’s name is at most 64 characters, on one line.';
  if (field === 'models') return 'Give model IDs separated by commas, or leave it empty for all models.';
  if (field === 'proxy') {
    if (code === 'unknown') return 'That proxy isn’t in the list any more.';
    return `${line === null ? 'This' : `Line ${line}`} isn’t a proxy address: scheme://user:password@host:port, with http, https, socks5 or socks5h. Nothing was added.`;
  }
  if (field === 'proxy_id') {
    if (code === 'proxy_in_use') return refusalText(code, detail);
    return code === 'taken' ? 'Another proxy has this ID.' : 'That proxy isn’t in the list any more.';
  }
  if (field === 'account_ids') return 'One of these accounts isn’t in accounts.json any more.';
  if (field === 'vendor') return code === 'no_sign_in' ? 'This vendor has no account sign-in. Add its API key instead.' : code === 'no_api_key' ? 'This vendor takes no API key. Add it with account sign-in.' : 'gray-assistant doesn’t know this vendor.';
  if (field === 'text') return 'Paste the code, or the whole address the browser ended on.';
  if (field === 'code') return 'That code didn’t work: it was used, it expired, or a character is missing.';
  return 'Check this value.';
}

// ---------------------------------------------------------------------------------------------------------------------
// Accounts, proxies and the push

/** An account that signs in inside the VM (a subscription), not one whose key is pasted. */
export function signsIn(type: CredentialType): boolean {
  return type === 'sign_in' || type === 'password';
}

/** The vendors a subscription is signed in for, and those an API key is pasted for. */
export const SUBSCRIPTION_VENDORS: readonly Vendor[] = ['anthropic', 'chatgpt_codex'];
export const KEY_VENDORS: readonly Vendor[] = VENDORS.filter(vendor => CREDENTIAL_CHOICES[vendor].includes('api_key'));

/** The account's kind in a word or two: "Account sign-in", "API key", "Sign-in token". */
export function kindPhrase(account: Pick<Account, 'vendor' | 'credential_type'>): string {
  return signsIn(account.credential_type) ? 'Account sign-in' : credentialLabel(account.vendor, account.credential_type);
}

/** A proxy's address without its user name or password: "socks5://203.0.113.9:1080". */
export function proxyAddress(proxy: { type: string; host: string; port: number }): string {
  return `${proxy.type}://${proxy.host.includes(':') ? `[${proxy.host}]` : proxy.host}:${proxy.port}`;
}

/** A proxy as one option of a picker: its id, then its address. */
export function proxyOption(proxy: Pick<Proxy, 'id' | 'type' | 'host' | 'port'>): string {
  return `${proxy.id} · ${proxyAddress(proxy)}`;
}

/** The non-empty lines of a pasted block (keys, proxy addresses), trimmed, in order. */
export function linesOf(text: string): string[] {
  return text.split(/\r?\n/).map(line => line.trim()).filter(line => line !== '');
}

/** A proxy's address as the page sends it: `scheme://[user[:password]@]host:port`, the user name and password escaped. */
export function proxyUrl(proxy: { type: string; host: string; port: string; username: string; password: string }): string {
  const host = proxy.host.trim(), user = proxy.username.trim();
  const login = user === '' ? '' : `${encodeURIComponent(user)}${proxy.password === '' ? '' : `:${encodeURIComponent(proxy.password)}`}@`;
  return `${proxy.type}://${login}${host.includes(':') && !host.startsWith('[') ? `[${host}]` : host}:${proxy.port.trim()}`;
}

/** The ids of a `?ids=a,b` query, in order, each once. */
export function idsOf(value: string | null): string[] {
  return [...new Set((value ?? '').split(',').map(id => id.trim()).filter(id => id !== ''))];
}

export type PushWords = { tone: 'neutral' | 'success' | 'danger'; text: string; detail: string | null; again: boolean };

/** The push in the shell's words; null while there is nothing to say (no push yet). */
export function pushWords(push: PushView | null, now: number): PushWords | null {
  if (!push || push.state === 'idle') return null;
  const count = typeof push.accounts === 'number' ? push.accounts : null;
  const what = count === null ? 'the accounts' : count === 1 ? '1 account' : `${count} accounts`;
  if (push.state === 'running') return { tone: 'neutral', text: `Sending ${what} to the VM…`, detail: null, again: false };
  const when = push.at_ms === null ? '' : ` ${clockText(push.at_ms, now)}`;
  if (push.state === 'ok') {
    const out = push.accounts_left_out ?? 0;
    return { tone: 'success', text: `Sent ${what} to the VM${when}${out > 0 ? ` · ${out} left out` : ''}`, detail: null, again: false };
  }
  const detail = push.message?.trim() || (push.code ? push.code.replaceAll('_', ' ') : null);
  return push.state === 'refused'
    // Gray or the VM refused them: the command's own words say which and why.
    ? { tone: 'danger', text: `The accounts were refused${when}`, detail, again: true }
    : { tone: 'danger', text: `The accounts didn’t reach the VM${when}`, detail, again: true };
}

/** A group field's suggestions, as on Gray's panel: the groups in use that hold what is typed, the ones that start with it first. */
export function groupSuggestions(names: readonly string[], typed: string): { value: string }[] {
  const text = typed.trim().toLowerCase();
  const held = names.filter(name => name.toLowerCase().includes(text) && name !== typed.trim());
  return [...held.filter(name => name.toLowerCase().startsWith(text)), ...held.filter(name => !name.toLowerCase().startsWith(text))].slice(0, 8).map(value => ({ value }));
}

/** The account's entry on Gray's panel: by its panel id when the file's id is not one. */
export function panelAccount(panel: PanelView | undefined, account: Pick<Account, 'account_id' | 'panel_id'>): PanelAccount | null {
  return panel?.accounts.find(item => item.account_id === (account.panel_id ?? account.account_id)) ?? null;
}

/** The tone of each state of Gray's panel (relay-stack-state.ts): problems red, what ends by itself amber. */
const STATE_TONE: Readonly<Record<AccountHealth['state'], 'success' | 'warning' | 'danger' | 'neutral'>> = {
  serving: 'success', paused: 'neutral', not_served: 'danger', waiting_credential: 'warning', held: 'danger', at_limit: 'warning', cooling: 'warning',
  proxy_failing: 'danger', credential_expiring: 'warning', failing: 'danger',
};

export type PanelState =
  | { known: true; label: string; tone: 'success' | 'warning' | 'danger' | 'neutral'; short: string; reason: string }
  | { known: false; label: string; reason: string };

/**
 * An account's state on Gray, in the words Gray's panel uses (`serverStateText`, `shortReason`). Not known while Gray
 * does not answer, for an account Gray's panel does not list, and before the VM's first report of it.
 */
export function panelState(panel: PanelView | undefined, account: Pick<Account, 'account_id' | 'panel_id'>, now: number): PanelState {
  if (!panel) return { known: false, label: 'Not available', reason: 'Gray doesn’t answer right now. The account’s state shows on Gray’s panel.' };
  const id = account.panel_id ?? account.account_id;
  const health = panel.health.accounts.find(item => item.account_id === id);
  if (!health) {
    return panel.accounts.some(item => item.account_id === id)
      ? { known: false, label: 'Not reported yet', reason: 'The VM hasn’t reported this account yet.' }
      : { known: false, label: 'Not on Gray', reason: 'Gray’s panel doesn’t list this account. It appears there after the accounts reach the VM.' };
  }
  const clock = (ms: number) => clockText(ms, now);
  const text = serverStateText(health, { clock });
  // The badge says the state and the line under it why, each once: a ban's fix ("replace") is the line's, and "Needs
  // sign-in" under "Waiting for its sign-in" would say one thing twice (what its last sign-in failed on stays).
  const label = health.state === 'held' ? text.label.split(' · ')[0]! : text.label;
  const why = shortReason(health, { clock });
  const short = health.reason === 'login_waiting' ? why.replace(/^Needs sign-in(?: · )?/, '').replace(/^./, c => c.toUpperCase()) : why;
  return { known: true, label, tone: health.reason === 'credential_expired' ? 'danger' : STATE_TONE[health.state] ?? 'neutral', short, reason: text.reason };
}

// ---------------------------------------------------------------------------------------------------------------------
// Times

const MINUTE = 60_000, HOUR = 60 * MINUTE, DAY = 24 * HOUR;

/** "just now", "3 minutes ago", "in 2 days", in whole units; precise enough for a status line. */
export function relativeTime(ms: number, now: number): string {
  const delta = ms - now;
  const size = Math.abs(delta);
  if (size < 45_000) return delta < 0 ? 'just now' : 'in a moment';
  const format = new Intl.RelativeTimeFormat('en-US', { numeric: 'always' });
  if (size < HOUR) return format.format(Math.round(delta / MINUTE), 'minute');
  if (size < DAY) return format.format(Math.round(delta / HOUR), 'hour');
  return format.format(Math.round(delta / DAY), 'day');
}

/** A remaining time as days and hours ("3 days 4 hours", "40 minutes"). */
export function durationText(ms: number): string {
  if (ms <= 0) return 'now';
  if (ms < HOUR) return `${Math.max(1, Math.round(ms / MINUTE))} minute${Math.round(ms / MINUTE) === 1 ? '' : 's'}`;
  const days = Math.floor(ms / DAY), hours = Math.round((ms % DAY) / HOUR);
  if (days === 0) return `${hours} hour${hours === 1 ? '' : 's'}`;
  return hours === 0 ? `${days} day${days === 1 ? '' : 's'}` : `${days} day${days === 1 ? '' : 's'} ${hours} hour${hours === 1 ? '' : 's'}`;
}

/**
 * A moment in the reader's zone, naming it, as Gray's panel writes it: "2:02 PM UTC" today, else "Oct 29, 2:02 PM UTC"
 * (the year only when it isn't this year's). The kit's output and the API say UTC, so a time without its zone misleads.
 */
export function clockText(ms: number, now: number): string {
  const date = new Date(ms), today = new Date(now);
  // As Gray's panel writes a moment (relay-stack-state.ts clockText): the time alone today, else with its day.
  if (date.toDateString() === today.toDateString()) return date.toLocaleTimeString('en-US', { hour: 'numeric', minute: '2-digit', timeZoneName: 'short' });
  const sameYear = date.getFullYear() === today.getFullYear();
  return date.toLocaleString('en-US', { month: 'short', day: 'numeric', ...(sameYear ? {} : { year: 'numeric' }), hour: 'numeric', minute: '2-digit', timeZoneName: 'short' });
}

/** A countdown like "14:05" for the device code. */
export function countdown(ms: number): string {
  const seconds = Math.max(0, Math.ceil(ms / 1000));
  return `${Math.floor(seconds / 60)}:${String(seconds % 60).padStart(2, '0')}`;
}

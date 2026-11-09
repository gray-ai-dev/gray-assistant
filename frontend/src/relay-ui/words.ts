// The local page's words: vendor and credential names, states, times and the sentences for the server's closed
// refusal codes. Pure, so `words.test.mjs` reads each in Node.
import { COMPATIBLE_VENDORS, compatibleRows, isCompatibleVendor } from '../runtime/lane-vendors.ts';
import type { Account, AgentState, CredentialType, Login, LoginState, RelayInfo, Release, SignIn, Vendor } from './api';

export const VENDORS: readonly Vendor[] = ['anthropic', 'openai', 'chatgpt_codex', ...COMPATIBLE_VENDORS.map(v => v.id)];

export const VENDOR_LABEL: Record<Vendor, string> = { anthropic: 'Anthropic', openai: 'OpenAI', chatgpt_codex: 'ChatGPT Codex', ...compatibleRows(v => v.name) };

/** The credential kinds each vendor takes, in the order the form offers them; the first is the default. */
export const CREDENTIAL_CHOICES: Record<Vendor, readonly CredentialType[]> = {
  anthropic: ['api_key', 'oauth_access_token'],
  openai: ['api_key'],
  chatgpt_codex: ['oauth_login', 'oauth_access_token'],
  ...compatibleRows(() => ['api_key'] as const),
};

export function credentialLabel(vendor: Vendor, type: CredentialType): string {
  if (type === 'oauth_login') return 'Sign in with ChatGPT';
  if (type === 'api_key') return 'API key';
  return vendor === 'anthropic' ? 'Subscription token' : 'Access token';
}

/** What the key field expects, for its hint. */
export function keyHint(vendor: Vendor, type: CredentialType): string {
  if (vendor === 'anthropic' && type === 'api_key') return 'Starts with sk-ant-api03-.';
  if (vendor === 'anthropic') return 'A Claude subscription token: starts with sk-ant-oat01-.';
  if (vendor === 'openai') return 'Starts with sk- (a project key, sk-proj-, works too). Admin keys are refused.';
  if (isCompatibleVendor(vendor)) return `A ${VENDOR_LABEL[vendor]} pay-as-you-go API key for this region's host. A coding-plan key is not for resale.`;
  return 'A ChatGPT access token (a JWT). It can’t refresh itself; Sign in with ChatGPT can.';
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
  if (/^sk-ant-oat\d\d-/.test(key)) return { kind: 'anthropic_subscription', label: 'Looks like a Claude subscription token' };
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

/** A login name from an account ID: lower-case letters, digits, _ and -, as gray-assistant names its login files. */
export function loginNameFor(accountId: string): string {
  return accountId.trim().toLowerCase().replace(/[^a-z0-9_-]+/g, '-').replace(/^[^a-z0-9]+/, '').slice(0, 63);
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
    detail: 'Certificate Transparency logs show it, so someone else may be able to answer on your relay’s name. gray-assistant tunnel status on the relay’s machine lists each one; once you have explained one, gray-assistant tunnel ack <sha256> clears it.',
  };
}

export function parkReason(reason: string | null): string {
  if (reason === null) return 'gray-assistant left it out.';
  return PARK_REASONS[reason] ?? `gray-assistant left it out (${reason.replaceAll('_', ' ')}).`;
}

/** The account's credential as one short phrase. */
export function credentialPhrase(account: Pick<Account, 'vendor' | 'credential_type' | 'login'>): string {
  if (account.credential_type === 'oauth_login') return 'ChatGPT sign-in';
  return credentialLabel(account.vendor, account.credential_type);
}

export function modelsPhrase(models: Account['models']): string {
  if (models === '*') return 'All models';
  if (models.length === 1) return models[0]!;
  return `${models[0]} and ${models.length - 1} more`;
}

export const LOGIN_WORDS: Record<LoginState, { label: string; tone: 'success' | 'warning' | 'danger' | 'neutral' }> = {
  ok: { label: 'Signed in', tone: 'success' },
  expiring: { label: 'Refresh failing', tone: 'warning' },
  expired: { label: 'Expired', tone: 'danger' },
  failed: { label: 'Needs a new sign-in', tone: 'danger' },
  unreadable: { label: 'Can’t be read', tone: 'danger' },
  missing: { label: 'Not signed in yet', tone: 'neutral' },
};

const LOGIN_FAILED: Record<string, string> = {
  unauthorized: 'ChatGPT refused the login.',
  invalid_grant: 'ChatGPT no longer accepts this login.',
  refresh_token_expired: 'The login’s refresh token expired.',
  refresh_token_reused: 'The login was refreshed somewhere else, so this copy stopped working.',
  refresh_token_invalidated: 'ChatGPT signed this login out.',
  account_mismatch: 'A refresh came back for another ChatGPT account.',
  invalid_access_token: 'ChatGPT sent an access token gray-assistant can’t use.',
  issuer_mismatch: 'The login was made against another sign-in server.',
  unsupported_region: 'OpenAI refuses this relay machine’s region (unsupported_country_region_territory), so it can’t refresh. Its access token is served until it expires; run gray-assistant in a supported region, or route its traffic to auth.openai.com through a proxy there, and sign in again.',
};

export function loginProblem(login: Pick<Login, 'state' | 'failed' | 'failures'>): string | null {
  if (login.state === 'failed') return login.failed === null ? 'Its refresh failed for good.' : LOGIN_FAILED[login.failed] ?? `Its refresh failed (${login.failed.replaceAll('_', ' ')}).`;
  if (login.state === 'expiring') return `${login.failures === 1 ? 'A refresh has' : `${login.failures} refreshes have`} failed; gray-assistant keeps trying.`;
  if (login.state === 'expired') return 'Its access token has expired, so its accounts aren’t served.';
  if (login.state === 'unreadable') return 'Its file must be 0600, owned by gray-assistant’s user, and not a link.';
  if (login.state === 'missing') return 'An account names it, but nobody has signed it in.';
  return null;
}

const SIGN_IN_ERRORS: Record<string, string> = {
  device_code_expired: 'The code expired before it was approved. Start again.',
  device_code_unavailable: 'ChatGPT didn’t offer a device code. Try again later.',
  network: 'gray-assistant couldn’t reach auth.openai.com. Check the relay machine’s internet access.',
  rate_limited: 'ChatGPT asked to slow down. Wait a minute and try again.',
  server_error: 'ChatGPT’s sign-in service had an error. Try again.',
  rejected: 'ChatGPT refused the sign-in.',
  unauthorized: 'ChatGPT refused the sign-in.',
  bad_response: 'ChatGPT answered in a way gray-assistant doesn’t understand.',
  issuer_answer: 'ChatGPT’s answer had no usable token. Try again.',
  login_exists: 'This login is signed in already.',
  unsupported_region: 'OpenAI refuses this relay machine’s region (unsupported_country_region_territory). Run gray-assistant in a supported region, or route its traffic to auth.openai.com through a proxy there.',
};

export function signInError(sign: Pick<SignIn, 'error'>): string {
  return sign.error === null ? 'The sign-in failed.' : SIGN_IN_ERRORS[sign.error] ?? `The sign-in failed (${sign.error.replaceAll('_', ' ')}).`;
}

/** The server's refusals, in the page's words. `field` refusals are said beside their field. */
const REFUSALS: Record<string, string> = {
  signed_out: 'You’re signed out of this page.',
  not_loopback: 'Open this page at 127.0.0.1 or localhost.',
  unreachable: 'gray-assistant doesn’t answer. Is gray-assistant ui still running?',
  csrf: 'This page is out of date. Reload it and try again.',
  cross_site: 'gray-assistant refused a request that didn’t come from this page.',
  source_read_only: 'accounts.json can’t be changed from here: its folder is read-only for gray-assistant.',
  source_not_file: 'Accounts come from your relay software, not from accounts.json.',
  source_unreadable: 'accounts.json can’t be read as it is. Fix it first.',
  refused_by_source: 'gray-assistant would refuse accounts.json with this change.',
  account_not_found: 'That account isn’t in accounts.json any more.',
  busy: 'Another gray-assistant command is changing the same file. Try again in a moment.',
  logins_unconfigured: 'The config gives no folder for logins.',
  too_many_sign_ins: 'Four sign-ins are running already. Finish or cancel one first.',
  sign_in_not_found: 'That sign-in has ended.',
  not_listed: 'Gray’s signed release list doesn’t name it.',
  not_seen: 'gray-assistant hasn’t seen this release in Gray’s list yet. It shows here once gray-assistant reads the list; accept it then.',
  os_image_dev: 'This is a development OS image; it’s never accepted.',
  io: 'gray-assistant couldn’t read a file or reach Gray’s release list.',
  internal: 'Something went wrong in gray-assistant.',
  not_found: 'gray-assistant doesn’t know that request.',
  passkey_refused: 'gray-assistant didn’t accept that passkey.',
  enroll_link_invalid: 'This enrolment link has been used or has expired.',
  ceremony_expired: 'The passkey prompt took too long. Try again.',
  rate_limited: 'Too many tries. Wait a minute and try again.',
};

export function refusalText(code: string, detail?: string | null): string {
  const text = REFUSALS[code] ?? `gray-assistant refused it (${code.replaceAll('_', ' ')}).`;
  return detail ? `${text} (${detail})` : text;
}

/** A refusal said beside one field of the add-account form. */
export function fieldError(field: string, code: string): string {
  if (field === 'account_id') return code === 'taken' ? 'An account with this ID exists already.' : 'Use 1–128 letters, digits and . _ : - (no spaces).';
  if (field === 'credential') {
    if (code === 'format') return 'This isn’t in the format this vendor uses for this kind of key.';
    if (code === 'type_vendor') return 'This vendor doesn’t take this kind of credential.';
    if (code === 'login_account') return 'This account signs in with ChatGPT; sign it in again instead.';
    return 'Paste the key.';
  }
  if (field === 'login') return code === 'login_exists' ? 'This login is signed in already.' : 'Use lower-case letters, digits, _ and -, starting with a letter or digit.';
  if (field === 'models') return 'Give model IDs separated by commas, or leave it empty for all models.';
  if (field === 'proxy') return 'Give a URL like socks5://user:password@host:1080 or http://host:3128.';
  if (field === 'code') return 'That code didn’t work: it was used, it expired, or a character is missing.';
  return 'Check this value.';
}

/** A short name for a release: its version or the start of its commit, never the whole hash. */
export function releaseName(release: Pick<Release, 'kind' | 'version' | 'git_commit' | 'hash'>): string {
  if (release.kind === 'os_image') return release.version ? `OS image ${release.version}` : `OS image ${release.hash.slice(0, 7)}`;
  // Twelve hex digits of the commit: the end of the tag Gray's console names the release by (2026.11.09-745af9427725,
  // the lane's public source), so the two pages name a release alike.
  return release.git_commit ? `Release ${release.git_commit.slice(0, 12)}` : `Release ${release.hash.slice(0, 7)}`;
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

/** A moment in the reader's zone as Gray's panel writes it: "2:02 PM" today, else "Oct 29, 2:02 PM" (the year only when it isn't this year's). */
export function clockText(ms: number, now: number): string {
  const date = new Date(ms), today = new Date(now);
  // As Gray's panel writes a moment (relay-stack-state.ts clockText): the time alone today, else with its day.
  if (date.toDateString() === today.toDateString()) return date.toLocaleTimeString('en-US', { hour: 'numeric', minute: '2-digit' });
  const sameYear = date.getFullYear() === today.getFullYear();
  return date.toLocaleString('en-US', { month: 'short', day: 'numeric', ...(sameYear ? {} : { year: 'numeric' }), hour: 'numeric', minute: '2-digit' });
}

/** A countdown like "14:05" for the device code. */
export function countdown(ms: number): string {
  const seconds = Math.max(0, Math.ceil(ms / 1000));
  return `${Math.floor(seconds / 60)}:${String(seconds % 60).padStart(2, '0')}`;
}

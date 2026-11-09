/**
 * Who may use the local page (`gray-assistant ui`): one-time links (sign-in links on 127.0.0.1, passkey enrolment links in
 * public mode) and the sessions they, or a passkey, open.
 *
 * A link carries a random 256-bit code. Its SHA-256 names a 0600 file in a 0700 directory of the agent's state volume
 * (`<state dir>/ui-links/`), so `gray-assistant ui link` can mint a code for a page another process serves (`gray-assistant
 * run` with `ui.listen`, or `gray-assistant ui` in another container) and the code itself is never stored. Redeeming
 * reads the file and unlinks it: the unlink succeeds once, so two browsers racing one link get one session. A link
 * lives `UI_LINK_LIFETIME_MS`.
 *
 * A session lives in the serving process's memory only: a random 256-bit id in an HttpOnly, SameSite=Strict cookie and
 * a CSRF token the page reads from `GET /api/session` (same origin only; there is no CORS) and sends back on every write.
 * A session ends after `UI_SESSION_IDLE_MS` without a request, `UI_SESSION_MAX_MS` after it opened, on sign-out, and when
 * the process stops.
 */
import { createHash, timingSafeEqual } from "node:crypto";
import { chmodSync, lstatSync, mkdirSync, readdirSync, unlinkSync, type Stats } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { parsePlain, toJsonString } from "@gray/json";
import { RelayKitError } from "../../errors.ts";
import { writeAtomicPrivateFile } from "../daemon/atomic-file.ts";
import { isGroupOrOtherReadable, readPrivateFile } from "../files.ts";

/** How long a printed link works. Long enough to switch to a browser through an SSH tunnel, short enough to not linger. */
export const UI_LINK_LIFETIME_MS = 10 * 60_000;
/** How long an enrolment link works: the operator opens it on the device that will hold the passkey. */
export const UI_ENROLL_LIFETIME_MS = 15 * 60_000;
/** On 127.0.0.1 a session ends after this long without a request… */
export const UI_SESSION_IDLE_MS = 12 * 3_600_000;
/** …and at the latest this long after it opened. */
export const UI_SESSION_MAX_MS = 7 * 86_400_000;
/** In public mode (the page on the relay's internet origin) sessions are short: 30 minutes idle, 12 hours at most. */
export const UI_PUBLIC_SESSION_IDLE_MS = 30 * 60_000;
export const UI_PUBLIC_SESSION_MAX_MS = 12 * 3_600_000;
/** Sessions one process keeps; the oldest goes first. */
export const UI_MAX_SESSIONS = 32;
/** Unredeemed links one directory keeps; minting past it removes the oldest. */
export const UI_MAX_LINKS = 64;

/** A code is 32 random bytes in base64url. */
const CODE = /^[A-Za-z0-9_-]{43}$/u;
const LINK_FILE = /^[0-9a-f]{64}$/u;

/** Where the sign-in links of a config's agent live: beside `state.json`, in the state volume. */
export function uiLinksDirectory(stateFile: string): string {
  return join(dirname(resolve(stateFile)), "ui-links");
}

/** Where the passkey enrolment links live (public mode); a separate directory, so one kind never redeems as the other. */
export function uiEnrollDirectory(stateFile: string): string {
  return join(dirname(resolve(stateFile)), "ui-enroll");
}

function lstatOrNull(path: string): Stats | null {
  try {
    return lstatSync(path);
  } catch {
    return null;
  }
}

function ensureLinksDirectory(dir: string): void {
  const path = resolve(dir);
  const existing = lstatOrNull(path);
  if (existing === null) {
    mkdirSync(path, { recursive: true, mode: 0o700 });
    chmodSync(path, 0o700);
    return;
  }
  if (existing.isSymbolicLink() || !existing.isDirectory()) throw new RelayKitError("io", "the ui-links directory is not a directory");
  if (isGroupOrOtherReadable(existing.mode)) throw new RelayKitError("io", "the ui-links directory is open to group or others; chmod 700 it");
}

function codeHash(code: string): string {
  return createHash("sha256").update(code, "utf8").digest("hex");
}

function base64url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

function linkExpiry(path: string): number | null {
  try {
    const value = parsePlain(readPrivateFile(path, "ui link", 1024)) as { expires_at_ms?: unknown } | null;
    const expires = value === null || typeof value !== "object" ? undefined : value.expires_at_ms;
    return typeof expires === "number" && Number.isSafeInteger(expires) ? expires : null;
  } catch {
    return null;
  }
}

/** Remove expired and unreadable links, and the oldest beyond `keep`. */
export function pruneUiLinks(dir: string, nowMs: number, keep = UI_MAX_LINKS): void {
  let names: string[];
  try {
    names = readdirSync(resolve(dir)).filter((name) => LINK_FILE.test(name));
  } catch {
    return;
  }
  const live: { readonly name: string; readonly expires: number }[] = [];
  for (const name of names) {
    const path = join(resolve(dir), name);
    const expires = linkExpiry(path);
    if (expires === null || expires <= nowMs) {
      try {
        unlinkSync(path);
      } catch {
        // Another process removed it first.
      }
    } else live.push({ name, expires });
  }
  live.sort((a, b) => a.expires - b.expires);
  for (const link of live.slice(0, Math.max(0, live.length - keep))) {
    try {
      unlinkSync(join(resolve(dir), link.name));
    } catch {
      // Already gone.
    }
  }
}

/** Mint a one-time code and record its hash; returns the code (the caller prints it, never logs it). */
export function mintUiLink(dir: string, nowMs: number, random: (length: number) => Uint8Array, lifetimeMs = UI_LINK_LIFETIME_MS): { readonly code: string; readonly expiresAtMs: number } {
  ensureLinksDirectory(dir);
  pruneUiLinks(dir, nowMs, UI_MAX_LINKS - 1);
  const code = base64url(random(32));
  const expiresAtMs = nowMs + lifetimeMs;
  writeAtomicPrivateFile(join(resolve(dir), codeHash(code)), `${toJsonString({ expires_at_ms: expiresAtMs })}\n`);
  return { code, expiresAtMs };
}

/** Whether a code would redeem now, without redeeming it (an enrolment's first step; the last one redeems). */
export function peekUiLink(dir: string, code: string, nowMs: number): boolean {
  if (!CODE.test(code)) return false;
  const path = join(resolve(dir), codeHash(code));
  const stats = lstatOrNull(path);
  if (stats === null || !stats.isFile()) return false;
  const expires = linkExpiry(path);
  return expires !== null && nowMs < expires;
}

/** Redeem a code: true once, while it lives; false for anything else (unknown, used, expired, malformed). */
export function redeemUiLink(dir: string, code: string, nowMs: number): boolean {
  if (!CODE.test(code)) return false;
  const path = join(resolve(dir), codeHash(code));
  const stats = lstatOrNull(path);
  if (stats === null || !stats.isFile()) return false;
  const expires = linkExpiry(path);
  try {
    unlinkSync(path);
  } catch {
    // Someone redeemed it between the read and here.
    return false;
  }
  return expires !== null && nowMs < expires;
}

export interface UiSession {
  readonly id: string;
  readonly csrf: string;
  readonly openedAtMs: number;
  /** The passkey that opened it (public mode); null for a one-time link on 127.0.0.1. */
  readonly passkeyId: string | null;
  lastSeenMs: number;
}

/** The sessions of one serving process. */
export class UiSessions {
  readonly #sessions = new Map<string, UiSession>();
  readonly #random: (length: number) => Uint8Array;
  readonly #idleMs: number;
  readonly #maxMs: number;

  constructor(random: (length: number) => Uint8Array, limits: { readonly idleMs: number; readonly maxMs: number } = { idleMs: UI_SESSION_IDLE_MS, maxMs: UI_SESSION_MAX_MS }) {
    this.#random = random;
    this.#idleMs = limits.idleMs;
    this.#maxMs = limits.maxMs;
  }

  open(nowMs: number, passkeyId: string | null = null): UiSession {
    this.#prune(nowMs);
    while (this.#sessions.size >= UI_MAX_SESSIONS) {
      const oldest = [...this.#sessions.values()].sort((a, b) => a.lastSeenMs - b.lastSeenMs)[0];
      if (oldest === undefined) break;
      this.#sessions.delete(oldest.id);
    }
    const session: UiSession = { id: base64url(this.#random(32)), csrf: base64url(this.#random(32)), openedAtMs: nowMs, passkeyId, lastSeenMs: nowMs };
    this.#sessions.set(session.id, session);
    return session;
  }

  /** The live session a cookie names, touched; null for none. */
  find(id: string | null, nowMs: number): UiSession | null {
    if (id === null || !CODE.test(id)) return null;
    const session = this.#sessions.get(id);
    if (session === undefined) return null;
    if (nowMs - session.lastSeenMs >= this.#idleMs || nowMs - session.openedAtMs >= this.#maxMs) {
      this.#sessions.delete(id);
      return null;
    }
    session.lastSeenMs = nowMs;
    return session;
  }

  close(id: string): void {
    this.#sessions.delete(id);
  }

  clear(): void {
    this.#sessions.clear();
  }

  #prune(nowMs: number): void {
    for (const session of [...this.#sessions.values()]) {
      if (nowMs - session.lastSeenMs >= this.#idleMs || nowMs - session.openedAtMs >= this.#maxMs) this.#sessions.delete(session.id);
    }
  }
}

/** A fixed-window counter per key: at most `limit` events in each `windowMs`, plus one cap across all keys. */
export class RateLimiter {
  readonly #limit: number;
  readonly #globalLimit: number;
  readonly #windowMs: number;
  #windowStart = 0;
  #counts = new Map<string, number>();
  #total = 0;

  constructor(limit: number, globalLimit: number, windowMs: number) {
    this.#limit = limit;
    this.#globalLimit = globalLimit;
    this.#windowMs = windowMs;
  }

  /** Count one event for `key`; false when the key or everyone together is over the limit this window. */
  take(key: string, nowMs: number): boolean {
    if (nowMs - this.#windowStart >= this.#windowMs) {
      this.#windowStart = nowMs - (nowMs % this.#windowMs);
      this.#counts = new Map();
      this.#total = 0;
    }
    const count = this.#counts.get(key) ?? 0;
    if (count >= this.#limit || this.#total >= this.#globalLimit) return false;
    if (this.#counts.size < 10_000 || this.#counts.has(key)) this.#counts.set(key, count + 1);
    this.#total += 1;
    return true;
  }
}

/** Whether a request's CSRF header is the session's token, compared in constant time. */
export function csrfMatches(session: UiSession, header: string | undefined): boolean {
  if (header === undefined) return false;
  const expected = Buffer.from(session.csrf, "utf8");
  const given = Buffer.from(header, "utf8");
  return given.length === expected.length && timingSafeEqual(given, expected);
}

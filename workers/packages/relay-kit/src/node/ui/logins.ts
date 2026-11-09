/**
 * The relay's own ChatGPT/Codex logins on the local page: what each login's state is, and device-code sign-ins the
 * operator starts from the browser. A sign-in is `gray-assistant login codex` (`../login/sign-in.ts`) run by the serving
 * process: the same exchanges, the same lock, the same 0600 record in the state volume. The verification link and
 * the one-time code go to the page that started the sign-in and nowhere else (no stdout, no log); the token family
 * never leaves the record.
 */
import { setTimeout as delay } from "node:timers/promises";
import { RelayKitError } from "../../errors.ts";
import type { CodexOAuthEndpoint } from "../login/codex-oauth.ts";
import type { LoginRoutes } from "../login/proxy.ts";
import { LOGIN_NAME, loginAgentView, type LoginSettings } from "../login/record.ts";
import { signInCodex } from "../login/sign-in.ts";
import { listLoginNames, readLoginRecord } from "../login/store.ts";
import { UiRefusal } from "./refusal.ts";

/** One login as the page lists it. */
export interface UiLogin {
  readonly login: string;
  /** `unreadable` when the record cannot be read (its mode, a symbolic link, a broken file). */
  readonly state: "ok" | "expiring" | "expired" | "failed" | "unreadable";
  /** Why it stopped refreshing (`invalid_grant`, …); null unless failed. */
  readonly failed: string | null;
  readonly accessExpiresAtMs: number | null;
  readonly refreshedAtMs: number | null;
  readonly signedInAtMs: number | null;
  readonly nextRefreshAtMs: number | null;
  readonly failures: number;
}

/** Every login record in the directory; an absent directory has none. */
export function readLogins(settings: LoginSettings, nowMs: number): readonly UiLogin[] {
  const dir = settings.dir;
  if (dir === null) return [];
  const nowSecs = Math.floor(nowMs / 1000);
  const out: UiLogin[] = [];
  for (const name of listLoginNames(dir)) {
    try {
      const record = readLoginRecord(dir, name);
      if (record === null) continue;
      const view = loginAgentView(record, nowSecs, settings);
      out.push({
        login: name,
        state: view.state,
        failed: view.failed,
        accessExpiresAtMs: view.accessExpiresAtS * 1000,
        refreshedAtMs: view.refreshedAtS === null ? null : view.refreshedAtS * 1000,
        signedInAtMs: record.signedInAt * 1000,
        nextRefreshAtMs: view.nextRefreshAtS === null ? null : view.nextRefreshAtS * 1000,
        failures: view.failures,
      });
    } catch {
      out.push({ login: name, state: "unreadable", failed: null, accessExpiresAtMs: null, refreshedAtMs: null, signedInAtMs: null, nextRefreshAtMs: null, failures: 0 });
    }
  }
  return out;
}

/** Where a sign-in is. */
export type UiSignInState = "starting" | "waiting" | "exchanging" | "done" | "failed" | "cancelled";

/** One sign-in as the page polls it. */
export interface UiSignIn {
  readonly id: string;
  readonly login: string;
  readonly state: UiSignInState;
  /** Where the operator approves the code; set once the issuer gave a code. */
  readonly verificationUrl: string | null;
  readonly userCode: string | null;
  readonly expiresAtMs: number | null;
  readonly startedAtMs: number;
  readonly finishedAtMs: number | null;
  /** A closed code for `failed`: `device_code_expired`, `network`, `rejected`, `rate_limited`, … */
  readonly error: string | null;
  /** The new access token's expiry, for `done`. */
  readonly accessExpiresAtMs: number | null;
}

interface Flow {
  view: UiSignIn;
  readonly abort: AbortController;
}

/** How long a finished sign-in stays listed, so a page that polls late still sees how it ended. */
export const SIGN_IN_KEEP_MS = 30 * 60_000;
/** Sign-ins one process runs at once. */
export const MAX_ACTIVE_SIGN_INS = 4;

export interface SignInsOptions {
  readonly settings: LoginSettings;
  readonly endpoint: CodexOAuthEndpoint;
  /**
   * Where each sign-in leaves from (`../login/proxy.ts`): the login's account's own proxy, else `endpoint.fetch`'s
   * default. Absent: `endpoint.fetch` for every sign-in.
   */
  readonly routes?: Pick<LoginRoutes, "route">;
  readonly nowMs: () => number;
  readonly random: (length: number) => Uint8Array;
}

/** The device-code sign-ins one serving process runs. */
export class UiSignIns {
  readonly #flows = new Map<string, Flow>();
  readonly #options: SignInsOptions;

  constructor(options: SignInsOptions) {
    this.#options = options;
  }

  /**
   * Start a sign-in for `login`. A login that exists is replaced only with `force` (a re-login); a sign-in already
   * running for the same login is returned as it is rather than started twice.
   */
  start(login: string, force: boolean): UiSignIn {
    const dir = this.#options.settings.dir;
    if (dir === null) throw new UiRefusal(409, "logins_unconfigured");
    if (!LOGIN_NAME.test(login)) throw new UiRefusal(422, "invalid", "login");
    this.#prune();
    const running = [...this.#flows.values()].find((flow) => flow.view.login === login && active(flow.view.state));
    if (running !== undefined) return running.view;
    if (!force) {
      let existing;
      try {
        existing = readLoginRecord(dir, login);
      } catch {
        existing = "unreadable";
      }
      if (existing !== null) throw new UiRefusal(409, "login_exists", "login");
    }
    if ([...this.#flows.values()].filter((flow) => active(flow.view.state)).length >= MAX_ACTIVE_SIGN_INS) throw new UiRefusal(429, "too_many_sign_ins");
    const id = Buffer.from(this.#options.random(16)).toString("hex");
    const abort = new AbortController();
    const flow: Flow = {
      view: { id, login, state: "starting", verificationUrl: null, userCode: null, expiresAtMs: null, startedAtMs: this.#options.nowMs(), finishedAtMs: null, error: null, accessExpiresAtMs: null },
      abort,
    };
    this.#flows.set(id, flow);
    void this.#run(flow, dir, force);
    return flow.view;
  }

  get(id: string): UiSignIn | null {
    return this.#flows.get(id)?.view ?? null;
  }

  /** The sign-ins still running or recently finished, newest first. */
  list(): readonly UiSignIn[] {
    this.#prune();
    return [...this.#flows.values()].map((flow) => flow.view).sort((a, b) => b.startedAtMs - a.startedAtMs);
  }

  cancel(id: string): UiSignIn | null {
    const flow = this.#flows.get(id);
    if (flow === undefined) return null;
    if (active(flow.view.state)) {
      flow.abort.abort();
      flow.view = { ...flow.view, state: "cancelled", finishedAtMs: this.#options.nowMs() };
    }
    return flow.view;
  }

  /** Stop every running sign-in (the process is stopping). */
  stop(): void {
    for (const flow of this.#flows.values()) flow.abort.abort();
  }

  async #run(flow: Flow, dir: string, force: boolean): Promise<void> {
    const signal = flow.abort.signal;
    try {
      let endpoint = this.#options.endpoint;
      try {
        if (this.#options.routes !== undefined) endpoint = { ...endpoint, fetch: this.#options.routes.route(flow.view.login).fetch };
      } catch {
        // An accounts.json that can't be read names no proxy: the sign-in takes the default, as the CLI's does.
      }
      const record = await signInCodex({
        dir,
        name: flow.view.login,
        force,
        endpoint,
        nowMs: this.#options.nowMs,
        sleep: (ms) => delay(ms, undefined, { signal }),
        random: this.#options.random,
        // Never stdout: the code is shown on the page that asked for it.
        print: () => undefined,
        onDeviceCode: (code) => {
          if (!signal.aborted) flow.view = { ...flow.view, state: "waiting", verificationUrl: code.verificationUrl, userCode: code.userCode, expiresAtMs: code.expiresAtMs };
        },
        onApproved: () => {
          if (!signal.aborted) flow.view = { ...flow.view, state: "exchanging" };
        },
        signal,
      });
      if (!signal.aborted) {
        flow.view = { ...flow.view, state: "done", userCode: null, finishedAtMs: this.#options.nowMs(), accessExpiresAtMs: record.accessExpiresAt * 1000 };
      }
    } catch (error) {
      if (signal.aborted) return;
      flow.view = { ...flow.view, state: "failed", userCode: null, finishedAtMs: this.#options.nowMs(), error: signInFailure(error) };
    }
  }

  #prune(): void {
    const now = this.#options.nowMs();
    for (const [id, flow] of this.#flows) {
      if (flow.view.finishedAtMs !== null && now - flow.view.finishedAtMs > SIGN_IN_KEEP_MS) this.#flows.delete(id);
    }
  }
}

function active(state: UiSignInState): boolean {
  return state === "starting" || state === "waiting" || state === "exchanging";
}

/** The closed code of a failed sign-in: the OAuth step's code (`approval: device_code_expired` → `device_code_expired`). */
function signInFailure(error: unknown): string {
  if (error instanceof RelayKitError) {
    if (error.code === "login_failed") {
      const detail = error.detail ?? "";
      const code = detail.includes(": ") ? detail.slice(detail.lastIndexOf(": ") + 2) : "";
      return /^[a-z_]{1,64}$/u.test(code) ? code : "issuer_answer";
    }
    if (error.code === "usage") return "login_exists";
    return error.code;
  }
  return "internal";
}

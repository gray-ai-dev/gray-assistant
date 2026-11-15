/**
 * A subscription account's sign-in, run for gray-assistant's page (docs/design/relay-operator-page.md section 7): the
 * command's own `loginVm` in this process, with the page's session in place of the terminal. The tokens are born in
 * the VM as with the command; what passes here is the vendor's link or device code on the way out and the code or the
 * address the operator pastes on the way in, and none of it is kept after the session ends or logged.
 *
 * There is no local listener: the operator's browser is on their own machine, not the relay's, so the browser's return
 * is pasted (the path `gray-assistant login` takes when the browser is elsewhere).
 *
 * Sessions live in this process's memory: a page that reloads asks again by the account and gets the session it had; a
 * page server that stops cancels them, and the VM voids a session 30 s after its last poll anyway.
 */
import type { RelayLoginPrompt } from "@gray/relay-connector";
import type { LoginVmEvent, LoginVmIo } from "../login-vm.ts";
import { UiRefusal } from "./refusal.ts";

/** How many sign-ins run at once: each holds a poll loop to the VM, and an operator signs accounts in one at a time. */
export const UI_SIGN_INS_MAX = 4;
/** How long an ended session is still answered, so the page that started it reads how it ended. */
export const UI_SIGN_IN_KEEP_MS = 10 * 60_000;

export type UiSignInState = "starting" | "prompt" | "working" | "done" | "failed";

/** What the operator acts on. `paste` says what the page's field takes back: a code, the address the browser ended on, or nothing (a device code is entered at the vendor). */
export interface UiSignInPrompt {
  readonly kind: "url" | "device_code";
  readonly url: string;
  readonly code?: string;
  readonly paste: "code" | "address" | null;
  readonly expires_at_ms: number;
}

export interface UiSignInView {
  readonly session: string;
  readonly account_id: string;
  readonly state: UiSignInState;
  readonly vendor?: string;
  readonly prompt?: UiSignInPrompt;
  /** Where the sign-in stands, or what went wrong with the last input, in a sentence. */
  readonly message?: string;
  /** `failed` only: the closed code (`cancelled`, `expired`, a refusal of the VM's). */
  readonly code?: string;
}

/** One sign-in: `loginVm` for the account, with the io and the events given (the page's server binds the config and the relay key). */
export type UiSignInRunner = (accountId: string, io: LoginVmIo, onEvent: (event: LoginVmEvent) => void) => Promise<number>;

export interface UiSignInsOptions {
  readonly run: UiSignInRunner;
  readonly now: () => number;
  readonly sleep: (ms: number) => Promise<void>;
  readonly random: (length: number) => Uint8Array;
}

const PROGRESS: Readonly<Record<(LoginVmEvent & { kind: "progress" })["step"], string>> = {
  checking: "Checking the VM.",
  waiting_account: "The VM does not serve this account yet. One added just now reaches it within a minute; waiting.",
  asking: "Asking your software in the VM to start the sign-in.",
};

const NOTICES: Readonly<Record<(LoginVmEvent & { kind: "notice" })["code"], string>> = {
  input_refused: "The VM did not take that. Try again.",
  not_callback_address: "That is not the address the browser ended on. Copy the whole address from its address bar.",
  wrong_callback: "That address is not this sign-in's return. Copy the whole address the browser ended on.",
  vendor_refused: "The vendor refused the code. Paste it again, or open the link again for a new one.",
  prompt_refused: "The VM refused the sign-in address your software made. Your software may offer another.",
  prompt_changed: "The sign-in changed. Use the new link.",
};

interface Session {
  readonly id: string;
  readonly accountId: string;
  state: UiSignInState;
  vendor: string | null;
  prompt: UiSignInPrompt | null;
  message: string | null;
  code: string | null;
  /** The reader `loginVm` gave for the operator's lines while a prompt takes one. */
  onLine: ((line: string) => void) | null;
  onCancel: (() => void) | null;
  /** Cancel was asked before `loginVm` listened for it (the first moments of a start): it is told once it listens. */
  cancelAsked: boolean;
  endedAtMs: number | null;
  finished: Promise<void>;
}

const hex = (bytes: Uint8Array): string => Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");

function promptOf(prompt: RelayLoginPrompt): UiSignInPrompt {
  if (prompt.kind === "device_code") return { kind: "device_code", url: prompt.url, code: prompt.code, paste: null, expires_at_ms: prompt.expires_at_ms };
  return { kind: "url", url: prompt.url, paste: prompt.flow === "code" ? "code" : "address", expires_at_ms: prompt.expires_at_ms };
}

export class UiSignIns {
  readonly #options: UiSignInsOptions;
  readonly #sessions = new Map<string, Session>();

  constructor(options: UiSignInsOptions) {
    this.#options = options;
  }

  /** Starts the account's sign-in, or answers the one that runs for it (a reloaded page asks again). */
  start(accountId: string): UiSignInView {
    this.#sweep();
    const running = [...this.#sessions.values()].filter((session) => session.endedAtMs === null);
    const same = running.find((session) => session.accountId === accountId);
    // One that was cancelled and has not ended yet is on its way out: a start now is a new sign-in, after it.
    if (same !== undefined && !same.cancelAsked) return this.#view(same);
    if (running.filter((session) => !session.cancelAsked).length >= UI_SIGN_INS_MAX) throw new UiRefusal(429, "sign_in_busy");
    const before = same?.finished;
    const session: Session = {
      id: hex(this.#options.random(16)),
      accountId,
      state: "starting",
      vendor: null,
      prompt: null,
      message: null,
      code: null,
      onLine: null,
      onCancel: null,
      cancelAsked: false,
      endedAtMs: null,
      finished: Promise.resolve(),
    };
    this.#sessions.set(session.id, session);
    const end = (state: "done" | "failed", code: string | null, message: string): void => {
      if (session.endedAtMs !== null) return;
      session.state = state;
      session.code = code;
      session.message = message;
      session.prompt = null;
      session.onLine = null;
      session.onCancel = null;
      session.endedAtMs = this.#options.now();
    };
    const io: LoginVmIo = {
      // Every moment the terminal's text says arrives as an event too; the text itself is not shown.
      stdout: () => undefined,
      stderr: () => undefined,
      now: this.#options.now,
      sleep: this.#options.sleep,
      random: this.#options.random,
      readLines: (onLine) => {
        session.onLine = onLine;
        return () => {
          session.onLine = null;
        };
      },
      onCancel: (onCancel) => {
        session.onCancel = onCancel;
        if (session.cancelAsked) onCancel();
        return () => {
          session.onCancel = null;
        };
      },
    };
    const onEvent = (event: LoginVmEvent): void => {
      if (session.endedAtMs !== null) return;
      switch (event.kind) {
        case "progress":
          session.message = PROGRESS[event.step];
          return;
        case "prompt":
          session.state = "prompt";
          session.vendor = event.vendor;
          session.prompt = promptOf(event.prompt);
          session.message = null;
          return;
        case "prompt_closed":
          session.prompt = null;
          session.state = "working";
          return;
        case "notice":
          // The input was not it: the prompt stands, and the page says why beside its field.
          if (session.prompt !== null) session.state = "prompt";
          session.message = NOTICES[event.code];
          return;
        case "signed_in":
          end("done", null, "Signed in. Your software in the VM holds the tokens and refreshes them.");
          return;
        case "cancelled":
          end("failed", "cancelled", "Cancelled.");
          return;
        case "failed":
          end("failed", event.code, event.message);
          return;
      }
    };
    // The runner starts now, as before; after a cancelled one only once that one has let go of the VM.
    session.finished = (before === undefined ? this.#options.run(accountId, io, onEvent) : before.then(() => this.#options.run(accountId, io, onEvent)))
      .then((exit) => {
        // Every way out is an event; this only covers a runner that returned without one.
        end(exit === 0 ? "done" : "failed", exit === 0 ? null : "ended", exit === 0 ? "Signed in." : "The sign-in ended.");
      })
      .catch((error: unknown) => {
        end("failed", "internal", error instanceof Error ? error.message : "The sign-in could not run.");
      });
    return this.#view(session);
  }

  view(sessionId: string): UiSignInView | null {
    this.#sweep();
    const session = this.#sessions.get(sessionId);
    return session === undefined ? null : this.#view(session);
  }

  /** The operator's paste; false when the session takes none now (no prompt with a field, or it ended). */
  input(sessionId: string, text: string): boolean {
    const session = this.#sessions.get(sessionId);
    if (session === undefined || session.endedAtMs !== null || session.state !== "prompt" || session.onLine === null || session.prompt?.paste == null) return false;
    session.state = "working";
    session.message = "Sent. Waiting for the vendor.";
    session.onLine(text);
    return true;
  }

  /** Cancels a running sign-in; false when there is none to cancel. */
  cancel(sessionId: string): boolean {
    const session = this.#sessions.get(sessionId);
    if (session === undefined || session.endedAtMs !== null) return false;
    session.cancelAsked = true;
    session.onCancel?.();
    return true;
  }

  /** The page stops: every running sign-in is cancelled, and this waits for each to close its session with the VM. */
  async stop(): Promise<void> {
    const running = [...this.#sessions.values()].filter((session) => session.endedAtMs === null);
    for (const session of running) {
      session.cancelAsked = true;
      session.onCancel?.();
    }
    await Promise.allSettled(running.map((session) => session.finished));
  }

  #view(session: Session): UiSignInView {
    return {
      session: session.id,
      account_id: session.accountId,
      state: session.state,
      ...(session.vendor === null ? {} : { vendor: session.vendor }),
      ...(session.prompt === null ? {} : { prompt: session.prompt }),
      ...(session.message === null ? {} : { message: session.message }),
      ...(session.code === null ? {} : { code: session.code }),
    };
  }

  #sweep(): void {
    const now = this.#options.now();
    for (const [id, session] of this.#sessions) {
      if (session.endedAtMs !== null && now - session.endedAtMs > UI_SIGN_IN_KEEP_MS) this.#sessions.delete(id);
    }
  }
}

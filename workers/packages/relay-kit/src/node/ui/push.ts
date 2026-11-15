/**
 * The push after a change made on gray-assistant's page (docs/design/relay-operator-page.md section 7): what
 * `gray-assistant accounts push` does, by the same function, so an operator who adds an account or changes a proxy
 * needs no terminal. The page shows where the push stands and, when the VM or Gray refuses it, the command's own words.
 *
 * One push runs at a time. A change made while one runs asks for one more after it, never two at once: a push sends the
 * whole account file, so the one that starts after the last change carries every change before it.
 */
import { isObject, parseStrict, type Json } from "@gray/json";

export type UiPushState = "idle" | "running" | "ok" | "refused" | "failed";

export interface UiPushView {
  readonly state: UiPushState;
  /** When the state was reached; null before the first push of this page. */
  readonly at_ms: number | null;
  /** `ok`: the accounts the VM holds now, and how many of the file's were left out (each named by `source check`). */
  readonly accounts?: number;
  readonly accounts_left_out?: number;
  /** `refused`: the command's closed code. */
  readonly code?: string;
  /** `refused`, `failed`: why, in the command's words. */
  readonly message?: string;
}

/** What one run of the command left: its exit status, the lines it wrote to stdout (its last is its JSON) and to stderr. */
export interface UiPushResult {
  readonly exit: number;
  readonly stdout: string;
  readonly stderr: string;
}

/** One push: the command run with its output kept (the page's server binds the config, the chain and the relay key). */
export type UiPushRunner = () => Promise<UiPushResult>;

/** The command's last JSON line (its result, or its refusal with a code). */
function resultOf(stdout: string): Record<string, Json> | null {
  const lines = stdout.split("\n").filter((line) => line.trim().startsWith("{"));
  const last = lines.at(-1);
  if (last === undefined) return null;
  try {
    const value = parseStrict(last);
    return isObject(value) ? value : null;
  } catch {
    return null;
  }
}

const count = (value: Json | undefined): number | undefined => (typeof value === "bigint" ? Number(value) : typeof value === "number" ? value : undefined);

/** The refusal's sentence: the command says it on stderr as `gray-assistant accounts push: <why>`, its last such line. */
function refusalText(stderr: string): string | undefined {
  const lines = stderr.split("\n").filter((line) => line.startsWith("gray-assistant ") && !line.includes(": note: ") && !line.includes(": left out "));
  const last = lines.at(-1);
  if (last === undefined) return undefined;
  const text = last.slice(last.indexOf(": ") + 2).trim();
  return text === "" ? undefined : text;
}

/** What the page says of a finished run. */
export function pushViewOf(result: UiPushResult, atMs: number): UiPushView {
  const value = resultOf(result.stdout);
  if (value !== null && value["ok"] === true && result.exit === 0) {
    const accounts = count(value["accounts"]);
    const leftOut = count(value["accounts_left_out"]);
    return { state: "ok", at_ms: atMs, ...(accounts === undefined ? {} : { accounts }), ...(leftOut === undefined ? {} : { accounts_left_out: leftOut }) };
  }
  const message = refusalText(result.stderr);
  if (value !== null && value["ok"] === false && typeof value["code"] === "string") {
    return { state: "refused", at_ms: atMs, code: value["code"], ...(message === undefined ? {} : { message }) };
  }
  return { state: "failed", at_ms: atMs, message: message ?? "The push did not finish. `gray-assistant doctor` checks the path to the VM." };
}

export class UiPush {
  readonly #run: UiPushRunner;
  readonly #now: () => number;
  #view: UiPushView = { state: "idle", at_ms: null };
  #running: Promise<void> | null = null;
  /** A change arrived while a push ran: one more follows it. */
  #again = false;

  readonly #onDone: ((view: UiPushView) => void) | undefined;

  /** `onDone` hears how each push ended (the page then does what waits for the VM and Gray to have the accounts). */
  constructor(options: { readonly run: UiPushRunner; readonly now: () => number; readonly onDone?: (view: UiPushView) => void }) {
    this.#run = options.run;
    this.#now = options.now;
    this.#onDone = options.onDone;
  }

  view(): UiPushView {
    return this.#view;
  }

  /** Sends the account file now, or once more after the push that runs. */
  request(): void {
    if (this.#running !== null) {
      this.#again = true;
      return;
    }
    this.#running = this.#loop().finally(() => {
      this.#running = null;
    });
  }

  /** Resolves once no push runs (tests, and the page's stop). */
  async idle(): Promise<void> {
    while (this.#running !== null) await this.#running;
  }

  async #loop(): Promise<void> {
    do {
      this.#again = false;
      this.#view = { state: "running", at_ms: this.#now() };
      try {
        this.#view = pushViewOf(await this.#run(), this.#now());
      } catch (error) {
        this.#view = { state: "failed", at_ms: this.#now(), message: error instanceof Error ? error.message : "The push could not run." };
      }
      try {
        this.#onDone?.(this.#view);
      } catch {
        // What follows a push is the listener's own; it never changes how the push went.
      }
    } while (this.#again);
  }
}

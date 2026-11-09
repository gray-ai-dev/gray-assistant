/**
 * `gray-assistant doctor` on the local page: the same checks (`../doctor.ts`), run on request by the serving process, one
 * run at a time, with the last report kept so the page shows it again "as of" its time. Each line that is not `ok`
 * carries the next step the operator guide gives for it (deploy/relay/GUIDE.en.md, "Troubleshooting by doctor line"),
 * in the page's words. A run can take a minute: it attests every lane origin and calls the scheduler through its proxy.
 */
import type { DoctorLine, DoctorOptions, DoctorReport } from "../doctor.ts";

export interface UiHealthLine {
  readonly id: string;
  readonly status: DoctorLine["status"];
  readonly message: string;
  /** What to do about a `fail` or `warn` line; null for `ok` and `skip`. */
  readonly nextStep: string | null;
}

export interface UiHealthView {
  readonly running: boolean;
  readonly startedAtMs: number | null;
  readonly finishedAtMs: number | null;
  readonly ok: boolean | null;
  readonly lines: readonly UiHealthLine[] | null;
  /** The run itself failed (the config does not load, …): one closed code. */
  readonly error: string | null;
}

/** The next step for one line id, keyed the way the guide's table is (a prefix before `:` names a family). */
const NEXT_STEPS: Readonly<Record<string, string>> = {
  config: "Fix gray-assistant.jsonc: fill every value the line names with the one Gray published for your relay.",
  key_permissions: "Make the relay key a regular file owned by the agent's user (uid 10001) with mode 0600.",
  key_content: "Restore relay-key.json from your backup. If it is lost, register the relay again with a new key.",
  accounts_permissions: "Make accounts.json a regular file owned by the agent's user (uid 10001) with mode 0600.",
  token_permissions: "Make the source token file a regular file owned by the agent's user (uid 10001) with mode 0600.",
  admin_token_permissions: "Make the scheduler's admin token file mode 0600, or remove scheduler.admin_token_file.",
  policy_bundle: "Restore the policy bundle gray-assistant init wrote, or your backup of it.",
  state_permissions: "Make the state volume writable by the agent's user (uid 10001).",
  release_key: "Fill the member the line names with the value Gray published for your relay.",
  source_detected: "Add the standard's two account routes to the relay's software (read-only, behind a token) and use the http source.",
  source_contract: "Run gray-assistant source check and fix each FAIL line in the relay's two account routes.",
  source_credential: "Check the source's admin token, the account selection and each account's key format.",
  source_accounts: "The source selected no account: check source.select's vendors, tags and ids.",
  parked: "Fix this account's credential on the Accounts page; the line names why it is left out.",
  release_list: "Check the release list URL, this machine's clock and lane.release_public_key; ask Gray whether the list was republished.",
  release_freshness: "Tell Gray: the freshness document beside the release list has stopped updating.",
  origin: "Read the line: a network or TLS problem, a release missing from the signed list, or one still waiting to be accepted on the Releases page.",
  clock: "Turn on time synchronisation (NTP or chrony) on this machine; signed requests fail when the clocks differ.",
  scheduler_tls: "Check the scheduler's DNS name, its certificate chain and expiry, and that port 443 reaches your proxy.",
  scheduler_echo: "Make your proxy forward the request unchanged: no buffering or rewriting of x-gray-* headers or the body, and no path prefix.",
  stack_files: "Check the stack section's files: the registry token must be 0600, and the issue log's directory writable.",
  stack_registry: "Renew the registry token before it expires and update stack.registry.",
  stack_challenge: "Check that the pull-token service answers through stack.token_url.",
  stack_release_status: "Check the pull-token service's release status: the line names the release it refuses.",
  stack_accounts: "Rename each refused account in your source to its account ID in Gray's panel.",
  stack_account: "Give this account its account ID from Gray's panel in your source.",
  lane_registration: "Ask Gray to check this relay's registration; gray-assistant tries again every 5 minutes.",
  agent_status: "Do what the line names: register the relay key, create the relay stack, sync the clock, or start gray-assistant run.",
  login: "Sign the login in again on the Logins page. If it keeps expiring, check this machine's HTTPS access to auth.openai.com.",
};

export function nextStepFor(line: Pick<DoctorLine, "id" | "status">): string | null {
  if (line.status === "ok" || line.status === "skip") return null;
  const family = line.id.includes(":") ? line.id.slice(0, line.id.indexOf(":")) : line.id;
  return NEXT_STEPS[line.id] ?? NEXT_STEPS[family] ?? "Run gray-assistant doctor in a terminal for the whole message, then see the operator guide's troubleshooting table.";
}

/** One process's doctor runs: one at a time, the last report kept. */
export class UiHealth {
  #view: UiHealthView = { running: false, startedAtMs: null, finishedAtMs: null, ok: null, lines: null, error: null };
  readonly #run: (options: DoctorOptions) => Promise<DoctorReport>;
  readonly #options: () => DoctorOptions;
  readonly #nowMs: () => number;

  constructor(options: { readonly run: (options: DoctorOptions) => Promise<DoctorReport>; readonly doctorOptions: () => DoctorOptions; readonly nowMs: () => number }) {
    this.#run = options.run;
    this.#options = options.doctorOptions;
    this.#nowMs = options.nowMs;
  }

  view(): UiHealthView {
    return this.#view;
  }

  /** Start a run unless one is running; returns the view at once (the page polls it). */
  start(): UiHealthView {
    if (this.#view.running) return this.#view;
    const startedAtMs = this.#nowMs();
    this.#view = { ...this.#view, running: true, startedAtMs, error: null };
    void this.#run({ ...this.#options(), nowMs: startedAtMs })
      .then((report) => {
        this.#view = {
          running: false,
          startedAtMs,
          finishedAtMs: this.#nowMs(),
          ok: report.ok,
          lines: report.lines.map((line) => ({ id: line.id, status: line.status, message: line.message, nextStep: nextStepFor(line) })),
          error: null,
        };
      })
      .catch((error: unknown) => {
        const code = typeof error === "object" && error !== null && "code" in error && typeof error.code === "string" ? error.code : "internal";
        this.#view = { ...this.#view, running: false, finishedAtMs: this.#nowMs(), error: code };
      });
    return this.#view;
  }
}

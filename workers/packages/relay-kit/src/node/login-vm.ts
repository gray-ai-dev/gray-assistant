/**
 * `gray-assistant login <account>` (docs/design/relay-sign-in-in-vm.md §1, §4.3): sign one subscription account in
 * inside the relay's stack VM, by the relay's own software there; the tokens are born in the VM and never leave it.
 *
 * 1. The stack VM is attested as `debug get` and `deliver` attest it (`attestStackBoot`: the quote, the signed release
 *    list, this relay's boot), and every call goes through the same pinned fetch: Gray's entry carries the TLS session to
 *    the VM, pinned to the key the VM attested, and sees ciphertext only.
 * 2. A start signed by the relay key (`@gray/relay-connector` `loginStartValue`) opens a session; its answer carries the
 *    session's key, which only this process holds. The relay's adapter in the VM sees the session and starts the
 *    program's own login.
 * 3. This command polls the session every 2 s (each poll keeps it alive; the VM voids it 30 s after the last one) and
 *    shows what the VM's prompt says. It has no vendor code: a device code and its address, or an address to open, come
 *    from the VM as they are.
 *    - `code`: the person pastes the code the vendor's page shows; it goes to the VM as input.
 *    - `callback`: a listener on 127.0.0.1 at the port the prompt names takes the browser's return; only the request line
 *      (method, path, query) goes to the VM, which hands it to the program and throws the program's answer away; the
 *      browser gets Gray's fixed page. When the port is taken, or the browser is on another machine, the person pastes
 *      the address the browser ended on and it goes the same way.
 *    - `callback_input`: the same, but the address goes to the VM as input (the program has no listener).
 * 4. "Signed in", or the failure in plain words. Ctrl-C (or a closed terminal) cancels the session.
 *
 * Nothing printed or logged is a token; the prompt's URL and code are the vendor's, meant for the person.
 */
import { bytesToLowerHex, ed25519PublicKey } from "@gray/attest";
import { get, isObject, parseStrictBytes, toJsonString, type Json } from "@gray/json";
import {
  loginStartValue,
  readLoginStartAnswer,
  readLoginView,
  RELAY_LOGIN_KEY_HEADER,
  RELAY_LOGIN_PATH,
  RELAY_LOGIN_ACCOUNT_PATTERN,
  type RelayLoginCode,
  type RelayLoginPrompt,
  type RelayLoginView,
} from "@gray/relay-connector";
import { DaemonTransportError, type DaemonFetch, type DaemonHttpResponse, type StackIssueRecord } from "../daemon/types.ts";
import { RelayKitError } from "../errors.ts";
import type { LoadedRelayConfig } from "./config-file.ts";
import { tunnelOriginOf } from "../lane-origin.ts";
import { attestStackBoot, debugStackVm, type DebugAttest } from "./debug.ts";

/** How often the session is polled (the design's 2 s; the VM voids a session 30 s after the last poll). */
export const LOGIN_POLL_MS = 2_000;
/** How long the VM's software has to show a prompt before the command gives up. */
export const LOGIN_NO_PROMPT_MS = 60_000;
/** Polls failing this long end the command: the VM voids a session after 30 s without one anyway. */
export const LOGIN_UNREACHABLE_MS = 30_000;

/** The browser's page after its return: Gray's own, whatever the VM's software answered (D12). */
export const LOGIN_CALLBACK_PAGE =
  '<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Gray sign-in</title></head>' +
  '<body style="font-family:system-ui,sans-serif;margin:3rem;max-width:36rem"><h1 style="font-size:1.25rem">Gray received the sign-in.</h1>' +
  "<p>You can close this tab and return to gray-assistant in your terminal.</p></body></html>";

/** A request the local listener took: the request line only. */
export interface LocalCallback {
  readonly method: string;
  readonly path: string;
  readonly query: string;
}

/** A listener on 127.0.0.1:<port>; `close` stops it. */
export interface LocalListener {
  close(): Promise<void>;
}

/**
 * Starts the loopback listener: `onRequest` gets every request's line and answers whether it was the sign-in's (the
 * listener then answers the fixed page; otherwise a 404). Null when the port is taken or cannot be bound.
 */
export type Listen = (port: number, onRequest: (request: LocalCallback) => Promise<boolean>) => Promise<LocalListener | null>;

export interface LoginVmIo {
  readonly stdout: (text: string) => void;
  readonly stderr: (text: string) => void;
  readonly now: () => number;
  readonly sleep: (ms: number) => Promise<void>;
  readonly random: (length: number) => Uint8Array;
  /** Calls `onLine` with each line the person types; the returned function stops reading. */
  readonly readLines: (onLine: (line: string) => void) => () => void;
  /** Calls `onCancel` on Ctrl-C or a closed terminal; the returned function stops listening. */
  readonly onCancel: (onCancel: () => void) => () => void;
}

export interface LoginVmOptions {
  readonly config: LoadedRelayConfig;
  /** The relay key's seed. */
  readonly seed: Uint8Array;
  readonly accountId: string;
  readonly io: LoginVmIo;
  /** Tests replace the attestation, the pinned fetch, the pull-token record and the listener; the CLI passes none. */
  readonly attest?: DebugAttest;
  readonly fetch?: DaemonFetch;
  readonly stackIssue?: (nonce: string) => Promise<StackIssueRecord | null>;
  readonly listen?: Listen;
  readonly pollMs?: number;
}

/** A usage error unless `id` is an account id the VM can name. */
export function checkLoginAccountId(id: string): void {
  if (!RELAY_LOGIN_ACCOUNT_PATTERN.test(id)) throw new RelayKitError("usage", "login takes the account's id as the panel and accounts.json name it (letters, digits and _ . : @ + -)");
}

/** The sentence for an ended session's code. */
export function endedMessage(code: RelayLoginCode | null): string {
  switch (code) {
    case "expired":
      return "The code expired. Run the command again.";
    case "held":
      return "The VM is being replaced by a new release; run the command again in a few minutes.";
    case "restarted":
      return "The VM restarted; run the command again.";
    case "prompt_refused":
      return "The relay's software sent a sign-in address unlike the one this image used first (prompt_refused). Its adapter sees the rule in the 422 answer; check your image's sign-in adapter (standard §9).";
    case "replaced":
      return "Another gray-assistant login started for this account; this one stopped.";
    case "idle":
      return "The VM closed the sign-in because this command stopped asking about it; run the command again.";
    case "cancelled":
      return "Cancelled.";
    case "persist_failed":
      return "The VM could not keep the new tokens; run the command again.";
    case "egress_unavailable":
      return "The VM's egress did not answer; run the command again.";
    case "vendor_rejected":
      return "The vendor refused the sign-in. Run the command again.";
    default:
      return "The sign-in ended. Run the command again.";
  }
}

/** The sentence for a refusal of the VM's route. */
function routeRefusal(status: number, code: string | null, accountId: string): string {
  switch (code) {
    case "login_account_unknown":
      return `The VM holds no account ${accountId}. Seal it first (gray-assistant accounts push), then run this again.`;
    case "login_not_subscription":
      return `${accountId} is not a subscription account: it has nothing to sign in.`;
    case "login_held":
      return "The VM is being replaced by a new release; run the command again in a few minutes.";
    case "login_unsupported":
      return "The VM's Gray release has no sign-in inside the VM yet; run it again once the VM runs a newer release.";
    case "login_session_busy":
      return "Another sign-in of this relay is running in the VM; wait for it to finish (at most 15 min) or cancel it, then run this again.";
    case "request_stale":
      return "The VM refused the request as stale (request_stale): this host's clock is more than 5 minutes off; set it right (NTP) and try again.";
    case "bad_signature":
      return "The VM did not accept the request's signature (bad_signature): the config's relay key is not the one the VM booted with.";
    case "unknown_relay":
      return "The VM serves another relay (unknown_relay): the config's relay_id is not the one the VM booted with.";
    case "login_session_unknown":
      return "The VM no longer knows this sign-in (it restarted, or it closed the session); run the command again.";
    default:
      break;
  }
  if (status === 404) return "The VM's Gray release has no sign-in inside the VM yet (404); run it again once the VM runs a newer release.";
  return `The VM refused the sign-in (${status}${code === null ? "" : ` ${code}`}).`;
}

function errorCodeOf(body: Uint8Array): string | null {
  let value: Json;
  try {
    value = parseStrictBytes(body);
  } catch {
    return null;
  }
  const error = get(value, "error");
  const code = isObject(error) ? get(error, "code") : null;
  return typeof code === "string" && /^[a-z0-9_]{1,64}$/.test(code) ? code : null;
}

function minutesLeft(expiresAtMs: number, nowMs: number): number {
  return Math.max(1, Math.round((expiresAtMs - nowMs) / 60_000));
}

/**
 * A pasted address read as the request line of a browser's return: `http://localhost:<port><path>?<query>` or the same
 * on 127.0.0.1. Null for anything else.
 */
export function callbackOfPaste(text: string, port: number): LocalCallback | null {
  let url: URL;
  try {
    url = new URL(text.trim());
  } catch {
    return null;
  }
  if (url.protocol !== "http:" || (url.hostname !== "localhost" && url.hostname !== "127.0.0.1") || Number(url.port || "80") !== port) return null;
  return { method: "GET", path: url.pathname, query: url.search.startsWith("?") ? url.search.slice(1) : url.search };
}

/** The default listener: node:http on 127.0.0.1 only. */
export const nodeListen: Listen = async (port, onRequest) => {
  const { createServer } = await import("node:http");
  const server = createServer((request, response) => {
    const raw = request.url ?? "/";
    const at = raw.indexOf("?");
    const line: LocalCallback = { method: request.method ?? "GET", path: at < 0 ? raw : raw.slice(0, at), query: at < 0 ? "" : raw.slice(at + 1) };
    // The body is never read or forwarded.
    request.resume();
    onRequest(line).then(
      (taken) => {
        response.writeHead(taken ? 200 : 404, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" });
        response.end(taken ? LOGIN_CALLBACK_PAGE : "<!doctype html><title>Not found</title>");
      },
      () => {
        response.writeHead(500, { "content-type": "text/plain; charset=utf-8" });
        response.end("gray-assistant could not hand the sign-in to the VM; see the terminal");
      },
    );
  });
  const bound = await new Promise<boolean>((done) => {
    server.once("error", () => done(false));
    server.listen({ host: "127.0.0.1", port, exclusive: true }, () => done(true));
  });
  if (!bound) return null;
  return { close: () => new Promise<void>((done) => server.close(() => done())) };
};

/** `login <account>`: sign the account in inside the VM. 0 signed in, 1 a refusal or a failed sign-in, 130 cancelled. */
export async function loginVm(options: LoginVmOptions): Promise<number> {
  const { config, io, accountId } = options;
  const relayId = config.daemon.relayId;
  checkLoginAccountId(accountId);
  const vm = debugStackVm(config, "`gray-assistant login <account>` signs an account in inside the relay's stack VM");
  const pollMs = options.pollMs ?? LOGIN_POLL_MS;
  const listen = options.listen ?? nodeListen;
  const fail = (code: string, message: string): number => {
    io.stderr(`${message}\n`);
    io.stderr(`${toJsonString({ command: "login", ok: false, relay_id: relayId, account_id: accountId, code })}\n`);
    return 1;
  };

  io.stdout("Checking the VM … ");
  const fetch = options.fetch ?? (await import("./daemon/fetch.ts")).createPinnedDaemonFetch({ maxResponseBytes: 256 * 1024 });
  const stack = config.daemon.stack;
  const issueReader = options.stackIssue ?? (stack === null ? undefined : (await import("./daemon/pull-token-log.ts")).createPullTokenIssueReader(stack.issueLog));
  const relayPublicKeyHex = bytesToLowerHex(await ed25519PublicKey(options.seed));
  // The entry's newest boot: the serving instance, the one that signs in (a draining one answers login_held).
  const attested = await attestStackBoot({ config, vm, keyset: undefined, nowMs: io.now(), relayPublicKeyHex, ...(options.attest === undefined ? {} : { attest: options.attest }), ...(issueReader === undefined ? {} : { stackIssue: issueReader }) });
  if ("code" in attested) {
    io.stdout("failed\n");
    return fail(attested.code, attested.message);
  }
  const image = attested.bootImage.includes("@") ? attested.bootImage.slice(attested.bootImage.indexOf("@") + 1) : attested.bootImage;
  io.stdout(`ok (attested: relay ${relayId}, image ${image.slice(0, 19)}…)\n`);

  const tunnel = tunnelOriginOf(vm.origin) !== null;
  const call = async (path: string, init: { readonly method: "GET" | "POST"; readonly body?: Json; readonly key?: string }): Promise<DaemonHttpResponse | { readonly transport: string }> => {
    try {
      return await fetch(`${vm.origin}${path}`, {
        method: init.method,
        headers: {
          accept: "application/json",
          "user-agent": "gray-assistant",
          ...(init.body === undefined ? {} : { "content-type": "application/json" }),
          ...(init.key === undefined ? {} : { [RELAY_LOGIN_KEY_HEADER]: init.key }),
        },
        ...(init.body === undefined ? {} : { body: new TextEncoder().encode(toJsonString(init.body)) }),
        expectedSpkiSha256: attested.tlsSpkiSha256,
        // The boot just attested, never the entry's newest one meanwhile (a rollout's new VM has another TLS key).
        ...(tunnel ? { tunnelKeyset: attested.keysetDigest.startsWith("sha256:") ? attested.keysetDigest.slice(7) : attested.keysetDigest } : {}),
        timeoutMs: 30_000,
      });
    } catch (error) {
      return { transport: error instanceof DaemonTransportError || error instanceof RelayKitError ? error.code : "io" };
    }
  };

  const signed = await loginStartValue({ relayId, accountId, signingKey: options.seed, issuedAt: Math.floor(io.now() / 1000), nonce: io.random(16) });
  const started = await call(RELAY_LOGIN_PATH, { method: "POST", body: signed });
  if ("transport" in started) return fail(`transport_${started.transport}`, `The request did not reach the VM through Gray's entry (${started.transport}); \`gray-assistant doctor\` checks the path.`);
  if (started.status !== 200) {
    const code = errorCodeOf(started.body);
    return fail(code ?? `http_${started.status}`, routeRefusal(started.status, code, accountId));
  }
  let startAnswer;
  try {
    startAnswer = readLoginStartAnswer(parseStrictBytes(started.body));
  } catch {
    startAnswer = null;
  }
  if (startAnswer === null) return fail("answer_invalid", "The VM's answer is not a sign-in session; update gray-assistant.");
  const key = startAnswer.key;
  const sessionPath = `${RELAY_LOGIN_PATH}/${startAnswer.session}`;
  io.stdout(`Asking your software in the VM to sign ${accountId} in …\n`);

  /** The 60 s for a prompt run from the start, and again from a prompt the VM refused. */
  let promptWaitFrom = io.now();
  /** The last poll the VM answered: polls failing for longer than `LOGIN_UNREACHABLE_MS` end the command. */
  let answeredAt = io.now();
  let view: RelayLoginView = startAnswer;
  let shown: RelayLoginPrompt | null = null;
  let lastSeen = view.last?.at_ms ?? null;
  let cancelled = false;
  let listener: LocalListener | null = null;
  let stopLines: (() => void) | null = null;
  const pending: Promise<unknown>[] = [];

  const readView = (response: DaemonHttpResponse | { readonly transport: string }): RelayLoginView | { readonly refused: string } => {
    if ("transport" in response) return { refused: `transport_${response.transport}` };
    if (response.status !== 200) return { refused: errorCodeOf(response.body) ?? `http_${response.status}` };
    try {
      return readLoginView(parseStrictBytes(response.body)) ?? { refused: "answer_invalid" };
    } catch {
      return { refused: "answer_invalid" };
    }
  };

  /** One input to the VM: a paste, or (`callback`) the browser's request line; the view it answers becomes the view. */
  const send = async (kind: "input" | "callback", body: Json): Promise<boolean> => {
    const answer = readView(await call(`${sessionPath}/${kind}`, { method: "POST", body, key }));
    if ("refused" in answer) {
      io.stdout(`The VM did not take it (${answer.refused}). Try again.\n`);
      return false;
    }
    view = answer;
    return true;
  };

  const forwardCallback = async (request: LocalCallback, prompt: RelayLoginPrompt & { readonly kind: "url" }): Promise<boolean> => {
    // One GET to the redirect's path: a browser's navigation back (design §4.3); nothing else is forwarded.
    if (prompt.callback === null || request.path !== prompt.callback.path || request.method !== "GET") return false;
    if (prompt.flow === "callback") return send("callback", { method: request.method, path: request.path, query: request.query });
    // callback_input: the program has no listener; the whole address goes to the VM as the input.
    return send("input", { text: `http://localhost:${prompt.callback.port}${request.path}${request.query === "" ? "" : `?${request.query}`}` });
  };

  const showPrompt = async (prompt: RelayLoginPrompt): Promise<void> => {
    const minutes = minutesLeft(prompt.expires_at_ms, io.now());
    io.stdout(`Vendor: ${view.vendor}   Account: ${accountId}\n`);
    if (prompt.kind === "device_code") {
      io.stdout(`Open ${prompt.url} in any browser and enter the code ${prompt.code} within ${minutes} min.\nWaiting … (Ctrl-C cancels)\n`);
      return;
    }
    if (prompt.flow === "code") {
      io.stdout(`Open this address in a browser, sign in and approve:\n  ${prompt.url}\nThe page then shows a code. Paste it here and press Enter (within ${minutes} min):\n> `);
    } else {
      const port = prompt.callback?.port ?? null;
      listener = port === null ? null : await listen(port, (request) => forwardCallback(request, prompt));
      if (listener !== null) {
        io.stdout(
          `Open this address in a browser on this machine, sign in and approve (within ${minutes} min):\n  ${prompt.url}\nListening on localhost:${port} for the browser's return … (Ctrl-C cancels)\n` +
            "If the browser is on another machine, it ends on an address that does not load: copy the whole address from its address bar, paste it here and press Enter.\n",
        );
      } else {
        io.stdout(
          `Open this address in a browser, sign in and approve (within ${minutes} min):\n  ${prompt.url}\n` +
            `${port === null ? "" : `Port ${port} is in use on this machine, so gray-assistant cannot take the browser's return; `}the browser ends on an address that does not load: copy the whole address from its address bar, paste it here and press Enter:\n> `,
        );
      }
    }
    stopLines = io.readLines((line) => {
      const text = line.trim();
      if (text === "") return;
      if (prompt.flow === "code") {
        pending.push(send("input", { text }));
        return;
      }
      const port = prompt.callback?.port ?? 0;
      const request = callbackOfPaste(text, port);
      if (request === null) {
        io.stdout(`That is not the address the browser ended on (http://localhost:${port}…). Paste the whole address:\n> `);
        return;
      }
      pending.push(
        forwardCallback(request, prompt).then((taken) => {
          if (!taken) io.stdout(`That address is not the sign-in's return (${prompt.callback?.path ?? "/"}). Paste the whole address:\n> `);
        }),
      );
    });
  };

  /** Stops what a shown prompt started: its listener and its stdin reader. */
  const stopPrompt = async (): Promise<void> => {
    (stopLines as (() => void) | null)?.();
    stopLines = null;
    const open = listener as LocalListener | null;
    listener = null;
    await open?.close();
  };
  const stopCancel = io.onCancel(() => {
    cancelled = true;
  });
  const cleanup = async (cancel: boolean): Promise<void> => {
    stopCancel();
    (stopLines as (() => void) | null)?.();
    await (listener as LocalListener | null)?.close();
    await Promise.allSettled(pending);
    if (cancel) await call(`${sessionPath}/cancel`, { method: "POST", key });
  };

  try {
    for (;;) {
      if (cancelled) {
        await cleanup(true);
        io.stdout("\nCancelled; the VM closed the sign-in.\n");
        return 130;
      }
      if (view.state === "signed_in") {
        await cleanup(false);
        io.stdout(`Signed in: ${accountId}. Your software in the VM holds the tokens and refreshes them; nothing more to do.\n`);
        io.stderr(`${toJsonString({ command: "login", ok: true, relay_id: relayId, account_id: accountId })}\n`);
        return 0;
      }
      if (view.state === "ended") {
        await cleanup(false);
        return fail(view.code ?? "ended", endedMessage(view.code));
      }
      if (view.last !== null && view.last.at_ms !== lastSeen) {
        lastSeen = view.last.at_ms;
        if (view.last.outcome === "failed" && view.last.code === "prompt_refused") {
          io.stdout("The VM refused the sign-in address your software made; its adapter sees the rule in the 422 answer, and your software may offer another.\n");
          await stopPrompt();
          shown = null;
          promptWaitFrom = io.now();
        } else if (view.last.outcome === "failed") io.stdout("The vendor refused the code. Paste it again, or open the address again for a new one.\n> ");
      }
      // A new prompt (a new device code, a new address) replaces the one shown.
      if (view.prompt !== null && (shown === null || JSON.stringify(shown) !== JSON.stringify(view.prompt))) {
        if (shown !== null) {
          await stopPrompt();
          io.stdout("\nThe sign-in changed; use this instead:\n");
        }
        shown = view.prompt;
        await showPrompt(view.prompt);
      }
      if (io.now() >= view.expires_at_ms) {
        await cleanup(true);
        return fail("expired", endedMessage("expired"));
      }
      if (view.prompt === null && io.now() - promptWaitFrom >= LOGIN_NO_PROMPT_MS) {
        await cleanup(true);
        return fail("no_prompt", "Your software in the VM did not start a sign-in within 60 s. Does your image include a sign-in adapter (standard §9)?");
      }
      await io.sleep(pollMs);
      if (cancelled) continue;
      const next = readView(await call(sessionPath, { method: "GET", key }));
      if ("refused" in next) {
        if (next.refused === "login_session_unknown") {
          await cleanup(false);
          return fail(next.refused, routeRefusal(404, next.refused, accountId));
        }
        // A transport hiccup: the session lives 30 s without a poll; the next poll tries again, until 30 s of them failed.
        if (io.now() - answeredAt >= LOGIN_UNREACHABLE_MS) {
          await cleanup(false);
          return fail("vm_unreachable", `The VM has not answered for 30 s (${next.refused}). It may have been replaced by a new release or restarted; run gray-assistant login ${accountId} again.`);
        }
        continue;
      }
      answeredAt = io.now();
      view = next;
    }
  } catch (error) {
    await cleanup(true).catch(() => undefined);
    throw error;
  }
}

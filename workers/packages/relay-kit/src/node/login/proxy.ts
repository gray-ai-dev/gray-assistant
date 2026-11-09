/**
 * Where the relay's own login exchanges (`./codex-oauth.ts`: the device-code sign-in of `gray-assistant login codex` and
 * of the relay's page, and the agent's refreshes) leave from, so a login signs in and refreshes from the same address
 * as its account's vendor calls (owner decision 2026-11-05):
 *
 * 1. the account's own proxy: the `egress` of the first `accounts.json` entry (file order) whose credential names the
 *    login, with that entry's password; it is the proxy the account is sealed with, so the VM's egress sends the
 *    account's calls through it too (`deploy/tee/egress`, the panel's proxy must match it);
 * 2. else `source.logins.proxy`, the default for a login whose account has no proxy of its own (or no account yet);
 * 3. else this host's own address (`globalThis.fetch`).
 *
 * A refresh never falls back from 1 to 2 or 3: when the account's proxy cannot be reached, the refresh fails as a
 * transient one and is retried after `retry_after` through the same proxy. When `accounts.json` cannot be read, the
 * refresher does not guess either: it skips the refresh (`./refresher.ts`).
 *
 * The proxying is undici 7.30.1's (docs/docs/api at that tag): `ProxyAgent` for an `http:` or `https:` proxy, an HTTP
 * `CONNECT` tunnel so TLS to the issuer runs end to end and the proxy sees only the host name; `Socks5ProxyAgent` for
 * `socks5` and `socks5h`, which sends the issuer's host name to the proxy (RFC 1928 address type 3), as Go's SOCKS5
 * dialer does for both schemes in the VM's egress. The request goes through undici's own `fetch` with that agent as its
 * `dispatcher`, because the docs keep the fetch and the dispatcher of one implementation together (Node's built-in
 * fetch is another undici: 7.x on Node 24, 8.x on Node 26). undici is loaded at the first proxied exchange, so a relay
 * without a proxy never loads it.
 *
 * A proxy's password is a secret: it is never logged and never part of an error; the CLI, the log lines and `doctor`
 * show a proxy's scheme, host and port only (`loginViaText`, `loginProxyDisplay`).
 */
import { existsSync } from "node:fs";
import { parseStrict } from "@gray/json";
import { RelayKitError } from "../../errors.ts";
import type { SourceEgress } from "../../source/types.ts";
import { readPrivateFile } from "../files.ts";
import { loginAccountProxies } from "../source/file.ts";
import { MAX_SOURCE_FILE_BYTES } from "../source/limits.ts";
import { CODEX_CLIENT_ID, CODEX_ISSUER, type CodexOAuthEndpoint } from "./codex-oauth.ts";

type Undici = typeof import("undici");

/** A `fetch` through the dispatcher `make` builds once, at the first exchange. */
function dispatchedFetch(make: (undici: Undici) => object): typeof fetch {
  let loaded: Promise<{ readonly fetch: (input: string, init: object) => Promise<unknown>; readonly dispatcher: object }> | null = null;
  return async (input, init) => {
    loaded ??= import("undici").then((undici) => ({ fetch: undici.fetch as never, dispatcher: make(undici) }));
    const { fetch: proxied, dispatcher } = await loaded;
    // fetchText sends a URL string, plain headers and a string body, which both implementations read alike.
    return (await proxied(String(input), { ...init, dispatcher })) as Response;
  };
}

/** A `fetch` for the login exchanges: through `proxy` (a URL `source.logins.proxy` validated), else the global one. */
export function loginFetch(proxy: string | null): typeof fetch {
  if (proxy === null) return (input, init) => globalThis.fetch(input, init);
  return dispatchedFetch((undici) => new undici.ProxyAgent(proxy));
}

/** An account's own proxy, as its `accounts.json` entry declares it, with the entry's password. */
export interface AccountProxy {
  readonly accountId: string;
  readonly egress: SourceEgress;
  readonly password?: string;
}

/** The proxy's `host:port`, an IPv6 address in brackets. */
function hostPort(egress: SourceEgress): string {
  return `${egress.host.includes(":") ? `[${egress.host}]` : egress.host}:${egress.port}`;
}

/** A `fetch` for the login exchanges through an account's own proxy, whatever its type. */
export function accountProxyFetch(proxy: AccountProxy): typeof fetch {
  const { egress } = proxy;
  const password = proxy.password ?? "";
  if (egress.type === "socks5" || egress.type === "socks5h") {
    // undici's SOCKS5 agent authenticates (RFC 1929) only with both a user name and a password.
    const auth = egress.username !== undefined && password !== "" ? { username: egress.username, password } : {};
    return dispatchedFetch((undici) => new undici.Socks5ProxyAgent(`socks5://${hostPort(egress)}`, auth));
  }
  // The VM's egress sends `Proxy-Authorization: Basic` for a user name even with an empty password; so does this.
  const token = egress.username === undefined ? {} : { token: `Basic ${Buffer.from(`${egress.username}:${password}`, "utf8").toString("base64")}` };
  return dispatchedFetch((undici) => new undici.ProxyAgent({ uri: `${egress.type}://${hostPort(egress)}`, ...token }));
}

/** The issuer and client every login exchange uses, with the config's proxy. */
export function codexLoginEndpoint(proxy: string | null): Omit<CodexOAuthEndpoint, "timeoutMs"> {
  return { issuer: CODEX_ISSUER, clientId: CODEX_CLIENT_ID, fetch: loginFetch(proxy) };
}

/** The proxy as `doctor` shows it: scheme, host and port, never the userinfo. */
export function loginProxyDisplay(proxy: string): string {
  const url = new URL(proxy);
  return `${url.protocol}//${url.host}`;
}

/** Where one login's exchanges leave from (the module comment's order). */
export type LoginVia =
  | { readonly kind: "account_proxy"; readonly proxy: AccountProxy }
  | { readonly kind: "logins_proxy"; readonly proxy: string }
  | { readonly kind: "host" };

/** The path for a login whose account declares `account` (null: no proxy, or no account names the login). */
export function loginVia(account: AccountProxy | null, defaultProxy: string | null): LoginVia {
  if (account !== null) return { kind: "account_proxy", proxy: account };
  return defaultProxy === null ? { kind: "host" } : { kind: "logins_proxy", proxy: defaultProxy };
}

/** The path in one phrase for the CLI and `doctor`: a proxy's scheme, host and port, never its user or password. */
export function loginViaText(via: LoginVia): string {
  switch (via.kind) {
    case "account_proxy":
      return `the account ${via.proxy.accountId}'s own proxy ${via.proxy.egress.type}://${hostPort(via.proxy.egress)}`;
    case "logins_proxy":
      return `source.logins.proxy ${loginProxyDisplay(via.proxy)}`;
    case "host":
      return "this host's own address";
  }
}

/** One login's path now and the `fetch` that takes it. */
export interface LoginRoute {
  readonly via: LoginVia;
  readonly fetch: typeof fetch;
}

export interface LoginRoutes {
  /**
   * The path of `login`'s exchanges, read from `accounts.json` now (a proxy set since the last call takes effect). A
   * missing file names no account, so the login takes the default. Throws `RelayKitError` when the file exists but
   * cannot be read or parsed: the caller must not guess an address then.
   */
  route(login: string): LoginRoute;
}

/** The most dispatchers kept; past it the cache starts over (a relay changing proxies often keeps no stale ones). */
const MAX_CACHED_ROUTES = 256;

export function createLoginRoutes(options: {
  /** The `file` source's `accounts.json`. */
  readonly accountsPath: string;
  /** `source.logins.proxy`. */
  readonly defaultProxy: string | null;
  /** Reads `accounts.json`; default the private-file read the source uses. */
  readonly readAccounts?: (path: string) => string;
}): LoginRoutes {
  const read = options.readAccounts ?? ((path: string) => readPrivateFile(path, "source accounts file", MAX_SOURCE_FILE_BYTES));
  const host = loginFetch(null);
  const fallback = options.defaultProxy === null ? host : loginFetch(options.defaultProxy);
  // One dispatcher per distinct proxy (the key holds the password; it stays in this process's memory).
  const cache = new Map<string, typeof fetch>();
  return {
    route(login: string): LoginRoute {
      let account: AccountProxy | null = null;
      if (existsSync(options.accountsPath)) {
        let value: unknown;
        try {
          value = parseStrict(read(options.accountsPath));
        } catch (error) {
          if (error instanceof RelayKitError) throw error;
          throw new RelayKitError("source_bad_response", "accounts");
        }
        account = loginAccountProxies(value).get(login) ?? null;
      }
      const via = loginVia(account, options.defaultProxy);
      if (via.kind !== "account_proxy") return { via, fetch: via.kind === "host" ? host : fallback };
      const key = JSON.stringify([via.proxy.egress.type, via.proxy.egress.host, via.proxy.egress.port, via.proxy.egress.username ?? null, via.proxy.password ?? null]);
      let proxied = cache.get(key);
      if (proxied === undefined) {
        if (cache.size >= MAX_CACHED_ROUTES) cache.clear();
        proxied = accountProxyFetch(via.proxy);
        cache.set(key, proxied);
      }
      return { via, fetch: proxied };
    },
  };
}

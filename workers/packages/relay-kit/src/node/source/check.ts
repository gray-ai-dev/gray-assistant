/**
 * `gray-assistant source check`: call the relay's two account routes the way the agent does, and check every rule of the
 * standard's "Account source" that a client can see. A relay's coding agent runs it after adding the routes; `doctor`
 * runs it too (`source_contract`).
 *
 * What it checks, in order:
 *
 * - `auth`: both routes refuse a request without the token and one with a wrong token (401 or 403);
 * - `list`: `GET {url}/accounts` answers the contract (every member, its bounds, unique ids, the vendor and
 *   credential type pairing); an account with a vendor this gray-assistant does not serve is a warning;
 * - `list_stable`: a second read a moment later names the same ids with the same `change_mark`, so the agent does not
 *   re-seal an unchanged account on every poll;
 * - `credential:<id>`: every listed account's credential answers the contract, has the list's `credential_type`, is in
 *   the vendor's own form, carries the list's `expires_at_ms`, is not expired, and comes with an `egress_password` only
 *   for a proxy with a username;
 * - `credential_unknown`: an id the list does not name answers 404.
 *
 * Nothing here prints or keeps a credential value or the token: a line names an account id, a member path, a closed
 * reason and times.
 */
import { randomBytes } from "node:crypto";
import { RelayKitError } from "../../errors.ts";
import { credentialParkReason } from "../../daemon/eligibility.ts";
import type { SourceHttpConfig } from "./config-types.ts";
import { fetchJson, fetchText } from "./http-client.ts";
import { httpSourceRoutes, parseHttpAccounts, parseHttpCredential, readHttpSourceToken, type HttpAdapterDeps, type ParsedHttpAccounts } from "./http.ts";

export type SourceCheckStatus = "ok" | "warn" | "fail" | "skip";

export interface SourceCheckLine {
  readonly id: string;
  readonly status: SourceCheckStatus;
  readonly message: string;
}

export interface SourceCheckReport {
  readonly lines: readonly SourceCheckLine[];
  /** No line failed (warnings allowed). */
  readonly ok: boolean;
}

function why(error: unknown): string {
  if (!(error instanceof RelayKitError)) return "io";
  return error.detail === null ? error.code : `${error.code} at ${error.detail}`;
}

function randomHex(bytes: number): string {
  return randomBytes(bytes).toString("hex");
}

function hours(ms: number): string {
  return `${Math.round(ms / 360_000) / 10} h`;
}

/** Check the `http` source a config names, with the adapter's own I/O (`deps.now` decides expiry). */
export async function checkHttpSource(config: SourceHttpConfig, deps: HttpAdapterDeps): Promise<SourceCheckReport> {
  const lines: SourceCheckLine[] = [];
  const add = (id: string, status: SourceCheckStatus, message: string): void => {
    lines.push({ id, status, message });
  };
  const done = (): SourceCheckReport => ({ lines, ok: lines.every((line) => line.status !== "fail") });
  const routes = httpSourceRoutes(config.url);
  const request = (url: string, maxBytes: number, authorization?: string) =>
    fetchText(url, {
      fetch: deps.fetch,
      signal: undefined,
      timeoutMs: config.requestTimeoutMs,
      maxBytes,
      ...(authorization === undefined ? {} : { headers: { authorization } }),
      label: "check",
    });
  const json = (url: string, maxBytes: number, token: string) =>
    fetchJson(url, {
      fetch: deps.fetch,
      signal: undefined,
      timeoutMs: config.requestTimeoutMs,
      maxBytes,
      headers: { authorization: `Bearer ${token}` },
      label: url === routes.accounts ? "accounts" : "credential",
      notFoundCode: "source_not_found",
    });

  let token: string;
  try {
    token = readHttpSourceToken(deps.readTokenFile, config.tokenFile);
  } catch (error) {
    add("token_file", "fail", `the source token file does not read (${why(error)}): a 0600 file owned by the agent's user, one line`);
    return done();
  }
  const wrong = `Bearer gray-assistant-source-check-${randomHex(16)}`;

  // auth: the list route first (it also says whether the URL answers at all).
  try {
    const anonymous = await request(routes.accounts, config.maxResponseBytes);
    const bad = await request(routes.accounts, config.maxResponseBytes, wrong);
    const refused = (status: number): boolean => status === 401 || status === 403;
    if (refused(anonymous.status) && refused(bad.status)) {
      add("auth", "ok", "GET /accounts refuses a request without the token and one with a wrong token");
    } else {
      add("auth", "fail", `GET /accounts answered ${anonymous.status} without the token and ${bad.status} with a wrong one; it must answer 401 (or 403) to both`);
    }
  } catch (error) {
    add("auth", "fail", `GET ${routes.accounts} did not answer (${why(error)}): check source.url and that the agent's container reaches it`);
    return done();
  }

  let first: ParsedHttpAccounts;
  try {
    first = parseHttpAccounts(await json(routes.accounts, config.maxResponseBytes, token), config.maxAccounts);
  } catch (error) {
    add("list", "fail", `GET /accounts with the token does not answer the contract (${why(error)})`);
    return done();
  }
  const byVendor = new Map<string, number>();
  for (const account of first.accounts) byVendor.set(account.vendor, (byVendor.get(account.vendor) ?? 0) + 1);
  const vendors = [...byVendor.entries()].map(([vendor, count]) => `${count} ${vendor}`).join(", ");
  add("list", first.accounts.length === 0 ? "warn" : "ok", first.accounts.length === 0 ? "GET /accounts lists no account" : `GET /accounts lists ${first.accounts.length} account(s): ${vendors}`);
  for (const skipped of first.skipped) {
    add(`vendor:${skipped.sourceId}`, "warn", `${skipped.sourceId} names vendor ${skipped.vendor}, which this gray-assistant does not serve; it is left out until gray-assistant does`);
  }

  try {
    const second = parseHttpAccounts(await json(routes.accounts, config.maxResponseBytes, token), config.maxAccounts);
    const before = new Map(first.accounts.map((account) => [account.sourceId, account.changeMark]));
    const moved = second.accounts.filter((account) => before.has(account.sourceId) && before.get(account.sourceId) !== account.changeMark).map((account) => account.sourceId);
    const sameIds = second.accounts.length === first.accounts.length && second.accounts.every((account) => before.has(account.sourceId));
    if (moved.length > 0) {
      add("list_stable", "warn", `change_mark of ${moved.slice(0, 5).join(", ")}${moved.length > 5 ? ", …" : ""} changed between two reads a moment apart: derive it from what changes with the credential (its update time, a version, a digest of the stored value), not from the clock, or the agent re-seals the account on every poll`);
    } else if (!sameIds) {
      add("list_stable", "warn", "two reads a moment apart listed different accounts: ids must be stable");
    } else {
      add("list_stable", "ok", "a second read lists the same ids with the same change_mark");
    }
  } catch (error) {
    add("list_stable", "fail", `a second GET /accounts failed (${why(error)})`);
  }

  const now = deps.now();
  for (const account of first.accounts) {
    const id = `credential:${account.sourceId}`;
    let answer;
    try {
      answer = parseHttpCredential(await json(routes.credential(account.sourceId), config.maxCredentialBytes, token));
    } catch (error) {
      add(id, "fail", `GET /accounts/${encodeURIComponent(account.sourceId)}/credential does not answer the contract (${why(error)})`);
      continue;
    }
    const problems: string[] = [];
    const warnings: string[] = [];
    if (answer.credential.type !== account.credentialType) problems.push(`type is ${answer.credential.type} where the list says ${account.credentialType}`);
    else {
      const reason = credentialParkReason(account.vendor, answer.credential);
      if (reason !== null) problems.push(`${reason}: the value is not in ${account.vendor}'s ${account.credentialType} form (GUIDE §4 has each form)`);
    }
    const listed = account.credentialExpiresAtMs;
    const expiry = answer.expiresAtMs ?? listed;
    if (listed !== undefined && answer.expiresAtMs !== undefined && listed !== answer.expiresAtMs) {
      problems.push("expires_at_ms differs between the list and the credential");
    } else if ((listed === undefined) !== (answer.expiresAtMs === undefined)) {
      problems.push(`expires_at_ms is only in the ${listed === undefined ? "credential" : "list"}; give it in both or neither`);
    }
    if (expiry !== undefined && expiry <= now) problems.push(`expired ${new Date(expiry).toISOString()}: the software must refresh it before it expires`);
    if (expiry === undefined && account.credentialType === "oauth_access_token") warnings.push("no expires_at_ms: the agent cannot tell an expired subscription token before the vendor refuses it");
    if (answer.egressPassword !== undefined && account.egress?.username === undefined) problems.push("egress_password without a listed egress username");
    if (problems.length > 0) add(id, "fail", problems.join("; "));
    else if (warnings.length > 0) add(id, "warn", warnings.join("; "));
    else {
      // A password is signed in inside the VM by the relay's software (docs/design/relay-in-cvm-login.md); the check
      // names whether a TOTP secret came with it, never the e-mail or a value.
      const kind = answer.credential.type === "password" ? `password (signed in inside the VM, ${answer.credential.totp_secret === undefined ? "no TOTP secret" : "with a TOTP secret"})` : account.credentialType;
      add(id, "ok", `${account.vendor} ${kind}${expiry === undefined ? "" : `, expires in ${hours(expiry - now)}`}${account.status === "active" ? "" : ` (listed ${account.status === "disabled" ? "paused" : account.status})`}`);
    }
  }

  if (first.accounts.length > 0) {
    const sample = (first.accounts[0] as (typeof first.accounts)[number]).sourceId;
    try {
      const anonymous = await request(routes.credential(sample), config.maxCredentialBytes);
      const bad = await request(routes.credential(sample), config.maxCredentialBytes, wrong);
      if ((anonymous.status === 401 || anonymous.status === 403) && (bad.status === 401 || bad.status === 403)) {
        add("credential_auth", "ok", "GET /accounts/{id}/credential refuses a request without the token and one with a wrong token");
      } else {
        add("credential_auth", "fail", `GET /accounts/{id}/credential answered ${anonymous.status} without the token and ${bad.status} with a wrong one; it must answer 401 (or 403) to both`);
      }
    } catch (error) {
      add("credential_auth", "fail", `GET /accounts/{id}/credential did not answer (${why(error)})`);
    }
  }

  const unknown = `gray-assistant-source-check-${randomHex(8)}`;
  try {
    await json(routes.credential(unknown), config.maxCredentialBytes, token);
    add("credential_unknown", "fail", "GET /accounts/{id}/credential answered 200 for an id the list does not name; it must answer 404");
  } catch (error) {
    if (error instanceof RelayKitError && error.code === "source_not_found") add("credential_unknown", "ok", "an id the list does not name answers 404");
    else add("credential_unknown", "fail", `an id the list does not name must answer 404 (${why(error)})`);
  }
  return done();
}

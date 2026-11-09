/**
 * S13's record of every pull token the agent issued: one JSON line per issue, appended to a local
 * file the agent never rewrites or truncates. A line is the time, the boot's compose hash, the
 * SHA-256 of its quote, the boot's challenge nonce, the relay image it named (S51) and the credential's
 * expiry; never the credential.
 *
 * Credential intake reads it back (S54, `readPullTokenIssue`): a stack boot is sealed to only when its
 * `gray-relay-image` event names a nonce and image this record holds for the same compose.
 *
 * The file is created 0600 and opened with O_APPEND (and O_NOFOLLOW, so a planted link is refused);
 * each line is fsynced before the token leaves the agent, so a crash cannot lose the record of a
 * token that was sent.
 */
import { closeSync, constants, existsSync, fsyncSync, mkdirSync, openSync, readFileSync, writeSync } from "node:fs";
import { isObject, parseStrict, type Json } from "@gray/json";
import { dirname, resolve } from "node:path";
import type { PullTokenIssue } from "../../daemon/pull-token.ts";

/** One record line, newline-terminated. */
export function pullTokenIssueLine(issue: PullTokenIssue): string {
  return `${JSON.stringify({
    issue_id: issue.issueId,
    at: new Date(issue.atMs).toISOString(),
    compose_hash: issue.composeHash,
    quote_sha256: issue.quoteSha256,
    nonce: issue.nonce,
    relay_image: issue.relayImage,
    expires_at: issue.expiresAt,
  })}\n`;
}

/** The writer `createPullTokenService` takes: append one line to `path`, durably. */
export function createPullTokenIssueLog(path: string): (issue: PullTokenIssue) => Promise<void> {
  const target = resolve(path);
  return async (issue) => {
    mkdirSync(dirname(target), { recursive: true, mode: 0o700 });
    const descriptor = openSync(target, constants.O_WRONLY | constants.O_APPEND | constants.O_CREAT | constants.O_NOFOLLOW, 0o600);
    try {
      writeSync(descriptor, pullTokenIssueLine(issue), null, "utf8");
      fsyncSync(descriptor);
    } finally {
      closeSync(descriptor);
    }
  };
}

/** S54: the line issued to the boot with `nonce`, as intake needs it, or null. Lines written before S54 have no nonce. */
export function pullTokenIssueOf(text: string, nonce: string): { readonly composeHash: string; readonly relayImage: string } | null {
  let found: { composeHash: string; relayImage: string } | null = null;
  for (const line of text.split("\n")) {
    if (line.trim() === "") continue;
    let value: Json;
    try {
      value = parseStrict(line);
    } catch {
      // A line cut by a crash before its fsync completed names no issue that was sent.
      continue;
    }
    if (!isObject(value) || value.nonce !== nonce) continue;
    const { compose_hash: composeHash, relay_image: relayImage } = value;
    if (typeof composeHash !== "string" || typeof relayImage !== "string") continue;
    // A nonce answers one token request (S11): a second line for it is not this record's.
    if (found !== null) return null;
    found = { composeHash, relayImage };
  }
  return found;
}

/** The lookup `createRelayDaemon`'s `stackIssue` takes: the issue log at `path`, read whole on each call. */
export function createPullTokenIssueReader(path: string): (nonce: string) => Promise<{ readonly composeHash: string; readonly relayImage: string } | null> {
  const target = resolve(path);
  return async (nonce) => (existsSync(target) ? pullTokenIssueOf(readFileSync(target, "utf8"), nonce) : null);
}

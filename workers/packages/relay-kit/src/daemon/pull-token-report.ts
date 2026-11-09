/**
 * The pull-token issue report Gray's console takes (S13; workers/console/src/lane-stack/report.ts):
 * `POST /v1/lane-stack/pull-token-issues` with `{"record": {relay_id, issue_id, issued_ms, expires_ms,
 * compose_hash, quote_sha256}, "signature": <128 hex>}`, the relay key's Ed25519 signature over
 * `@gray/control`'s `pullTokenIssueMessage(record)`. The relay key is the one its lane record publishes
 * as `signing_public_key`, the key the console verifies with. The record is the console's own schema,
 * so a record this builds is one it accepts; a report sent twice is answered `recorded: false`.
 */
import { bytesToLowerHex, ed25519Sign } from "@gray/attest";
import { pullTokenIssueMessage, pullTokenIssueSchema, type PullTokenIssue as ConsoleIssue, type PullTokenIssueReport } from "@gray/control";
import type { PullTokenIssue } from "./pull-token.ts";

export const PULL_TOKEN_ISSUE_REPORT_PATH = "/v1/lane-stack/pull-token-issues";

/** The console's record of one issue. Throws when it would not pass the console's schema (a bug here). */
export function pullTokenIssueRecord(relayId: string, issue: PullTokenIssue): ConsoleIssue {
  return pullTokenIssueSchema.parse({
    relay_id: relayId,
    issue_id: issue.issueId,
    issued_ms: issue.atMs,
    expires_ms: issue.expiresAtMs,
    compose_hash: issue.composeHash,
    quote_sha256: issue.quoteSha256,
  });
}

/** The signed report body. */
export async function pullTokenIssueReport(record: ConsoleIssue, seed: Uint8Array): Promise<PullTokenIssueReport> {
  return { record, signature: bytesToLowerHex(await ed25519Sign(seed, pullTokenIssueMessage(record))) };
}

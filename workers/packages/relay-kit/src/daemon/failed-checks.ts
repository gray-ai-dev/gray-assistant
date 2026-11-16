/**
 * The checks a report failed, as a command names them when it refuses: `gray-assistant doctor`'s line and the refusals
 * of `deliver`, `accounts push`, `login` and the other commands that attest the VM first say the same `id: detail`
 * pairs, so "the VM did not attest" comes with what to act on (staging, 2026-11-16: `attest_verification_failed` alone
 * left a relay, and Gray, with nothing to go on).
 *
 * A check's detail is the verifier's own sentence over measurements and public values (hashes, the relay id, the image,
 * the TLS key), partly in words the VM's report chose. So each is kept to one bounded line, and the list to a bounded
 * number. One detail can name a value of the relay's own: the `quote` check's sentence carries the collateral
 * service's URL when the fetch fails, and a relay's own `pccs_url` may hold a credential. A caller that set one passes
 * `quoteDetail: false`, and that check is named by its id only.
 */
import type { JsonObject } from "@gray/json";

/** One failed check: its id and its own words; `detail` is null where the words are left out. */
export interface FailedCheck {
  readonly id: string;
  readonly detail: string | null;
}

/** The first failed checks of a report, and how many more there were. */
export interface FailedChecks {
  readonly checks: readonly FailedCheck[];
  readonly more: number;
}

/** The checks one refusal names: a report that fails at all fails a few, and one check can fail once per broken event. */
export const FAILED_CHECKS_MAX = 12;
/** The longest sentence the verifier writes is two 64-byte values in hex and a few words. */
export const FAILED_CHECK_DETAIL_MAX = 400;
const FAILED_CHECK_ID_MAX = 64;

/** One line of bounded length: a report's own text never moves the terminal's cursor or starts a line of its own. */
function oneLine(text: string, max: number): string {
  const line = text.replace(/\p{Cc}+/gu, " ").trim();
  return line.length <= max ? line : `${line.slice(0, max - 1)}…`;
}

/** The failed checks of a verification transcript, in its order. */
export function failedChecksOf(
  checks: readonly { readonly id: string; readonly status: string; readonly detail: string }[],
  options: { readonly quoteDetail: boolean },
): FailedChecks {
  const failed = checks.filter((check) => check.status === "fail");
  return {
    checks: failed.slice(0, FAILED_CHECKS_MAX).map((check) => ({
      id: oneLine(check.id, FAILED_CHECK_ID_MAX),
      detail: check.id === "quote" && !options.quoteDetail ? null : oneLine(check.detail, FAILED_CHECK_DETAIL_MAX),
    })),
    more: Math.max(0, failed.length - FAILED_CHECKS_MAX),
  };
}

/** `id: detail; id: detail`, as doctor's line says them; "" when no check is named. */
export function failedChecksText(failed: FailedChecks | undefined): string {
  if (failed === undefined || failed.checks.length === 0) return "";
  const named = failed.checks.map((check) => (check.detail === null || check.detail === "" ? check.id : `${check.id}: ${check.detail}`));
  if (failed.more > 0) named.push(`and ${failed.more} more`);
  return named.join("; ");
}

/** What a refusal's sentence adds after its code: ": the report did not verify (id: detail; …)", or "". */
export function failedChecksClause(failed: FailedChecks | undefined): string {
  const text = failedChecksText(failed);
  return text === "" ? "" : `: the report did not verify (${text})`;
}

/** The members a refusal's JSON line adds: `failed_checks` (and `failed_checks_more`); none when no check is named. */
export function failedChecksJson(failed: FailedChecks | undefined): JsonObject {
  if (failed === undefined || failed.checks.length === 0) return {};
  return {
    failed_checks: failed.checks.map((check) => ({ id: check.id, detail: check.detail })),
    ...(failed.more > 0 ? { failed_checks_more: BigInt(failed.more) } : {}),
  };
}

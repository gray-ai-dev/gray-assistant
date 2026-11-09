/**
 * The small shared loaders the scheduler adapter uses: a key from text and the re-exported verified
 * report functions. Kept apart from `scheduler-server.ts` so the CLI and the tests can load a key the
 * same way without starting a server.
 */
import { parseStrict } from "@gray/json";
import { parseRelayKeyValue, verifyRelayKeyPair, type RelayKeyFile } from "../keys.ts";
import { RelayKitError } from "../errors.ts";

export { checkVerifiedReport, parseVerifiedReportValue, type CheckedVerifiedReport } from "../verified-report.ts";

/** Parse and check one key file's text (the caller has already checked its permissions). */
export async function buildKeyFromText(text: string): Promise<RelayKeyFile> {
  let value: unknown;
  try {
    value = parseStrict(text);
  } catch {
    // A key file's parse error can echo the seed; never forward the platform's message.
    throw new RelayKitError("invalid_key_file", "the file is not JSON");
  }
  const key = parseRelayKeyValue(value);
  await verifyRelayKeyPair(key);
  return key;
}

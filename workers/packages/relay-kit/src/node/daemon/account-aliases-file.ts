/**
 * The account aliases file (S59, `../../daemon/account-aliases.ts`): `account-aliases.json` beside the state file,
 * 0600 (it holds the source's own ids, e-mail addresses among them), written by atomic rename and fsync like the
 * state file (`atomic-file.ts`). A missing file is no aliases yet; a file that does not read is never overwritten:
 * the daemon then gives no new alias, so no id is given twice.
 */
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { parseStrict } from "@gray/json";
import { ACCOUNT_ALIASES_FILE_NAME, accountAliasesText, parseAccountAliasesDocument, type AccountAlias, type AccountAliasStore } from "../../daemon/account-aliases.ts";
import { readAtomicDocument, writeAtomicPrivateFile } from "./atomic-file.ts";

/** The aliases file beside `stateFile`. */
export function accountAliasesPath(stateFile: string): string {
  return join(dirname(stateFile), ACCOUNT_ALIASES_FILE_NAME);
}

/** Read the aliases file: the aliases, none when there is no file, or null when it is there and does not read. */
export function readAccountAliasesFile(path: string): readonly AccountAlias[] | null {
  const text = readAtomicDocument(path);
  if (text === null) return existsSync(path) ? null : [];
  try {
    return parseAccountAliasesDocument(parseStrict(text));
  } catch {
    // Never echo the text: it holds the source ids.
    return null;
  }
}

/** The aliases file as the daemon's store. */
export function createFileAccountAliasStore(path: string): AccountAliasStore {
  return {
    async read() {
      return readAccountAliasesFile(path);
    },
    async write(aliases) {
      writeAtomicPrivateFile(path, accountAliasesText(aliases));
    },
  };
}

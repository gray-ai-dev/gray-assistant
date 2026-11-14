/**
 * Where `releases list` starts when nobody named a block (kit 1.6.2): `chain-start.json`, beside the state file.
 *
 * `releases list` reads the contract's `Proposed` events from a start block. `init --pair` writes no `chain.from_block`
 * (Gray deploys the contract later, at Deploy, and the contract does not record its block), a new relay does not know
 * the number, and finding it from the chain is a wide log scan the public Base endpoints refuse (HTTP 429 after about
 * ten requests, measured 2026-11-14). So the kit keeps the start itself, from what its own commands already read:
 *
 * - each time a command reads that there is **no** code at `chain.contract` (at a block both endpoints agree on:
 *   `doctor` and `releases check` before the first Deploy), it notes that block: the contract is deployed after it;
 * - the first time a command then reads that there **is** code (`doctor`, `deliver`, `releases check|list`), the last
 *   block noted without code becomes the start: no later than the block before the deployment, so no event is before
 *   it.
 *
 * With one observation only (the kit first read the contract when it already had code) nothing is recorded: any
 * earlier block would be a guess, and `releases list` then asks for `--from-block` as before. The record is for one
 * contract on one chain; another pairing's contract starts again. The config's own `chain.from_block` and `--from-block`
 * come first. The file is in the state volume (the config is mounted read-only); it holds no secret.
 *
 * Nothing here throws: a note that cannot be kept changes no command's outcome.
 */
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { get, isObject, parseStrict, toJsonString } from "@gray/json";
import { writeAtomicPrivateFile } from "./daemon/atomic-file.ts";

export const CHAIN_START_FILE = "chain-start.json";

/** `chain-start.json` beside the state file. */
export function chainStartFileBeside(stateFile: string): string {
  return join(dirname(resolve(stateFile)), CHAIN_START_FILE);
}

export interface ChainStart {
  /** The newest block at which the contract was read to have no code; null when none was. */
  readonly noCodeBlock: bigint | null;
  /** The start `releases list` reads from: set once, when code was first read after `noCodeBlock`. */
  readonly fromBlock: bigint | null;
}

const EMPTY: ChainStart = { noCodeBlock: null, fromBlock: null };
const block = (value: unknown): bigint | null => (typeof value === "bigint" && value >= 0n ? value : null);

/** The record for this contract on this chain; the empty one when the file is missing, does not read or is another contract's. */
export function readChainStart(path: string, contract: string, chainId: number): ChainStart {
  try {
    const value = parseStrict(readFileSync(resolve(path), "utf8"));
    if (!isObject(value) || get(value, "contract") !== contract.toLowerCase() || get(value, "chain_id") !== BigInt(chainId)) return EMPTY;
    const noCodeBlock = block(get(value, "no_code_block"));
    const fromBlock = block(get(value, "from_block"));
    // A start is the block noted without code, never another: a file that says otherwise is not this kit's.
    if (fromBlock !== null && fromBlock !== noCodeBlock) return EMPTY;
    return { noCodeBlock, fromBlock };
  } catch {
    return EMPTY;
  }
}

/**
 * Note one reading of the contract's code at `atBlock` (a block both endpoints agree on). Returns the record after it.
 * `path` null (a config with no state file to sit beside) notes nothing.
 */
export function noteContractCode(path: string | null, contract: string, chainId: number, atBlock: bigint, hasCode: boolean): ChainStart {
  if (path === null) return EMPTY;
  const before = readChainStart(path, contract, chainId);
  let after: ChainStart = before;
  if (before.fromBlock === null) {
    if (!hasCode) {
      if (before.noCodeBlock === null || atBlock > before.noCodeBlock) after = { noCodeBlock: atBlock, fromBlock: null };
    } else if (before.noCodeBlock !== null && atBlock > before.noCodeBlock) {
      after = { noCodeBlock: before.noCodeBlock, fromBlock: before.noCodeBlock };
    }
  }
  if (after === before) return before;
  try {
    writeAtomicPrivateFile(path, `${toJsonString({ api_version: 1n, contract: contract.toLowerCase(), chain_id: BigInt(chainId), no_code_block: after.noCodeBlock, from_block: after.fromBlock })}\n`);
    return after;
  } catch {
    return before;
  }
}

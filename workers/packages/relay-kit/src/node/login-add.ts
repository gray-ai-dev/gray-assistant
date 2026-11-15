/**
 * `gray-assistant login <account> --vendor <vendor> [--proxy <url>]`, before its sign-in: the subscription is written
 * to the file source as a `sign_in` account and sealed to the VM, so one command adds an account and signs it in.
 *
 * The seal is `accounts push`. A VM that still waits for its first delivery takes no accounts by themselves
 * (`relay_empty_slot`; on a kit just paired, which has adopted no VM yet, `stack_vm_not_adopted`): the command then
 * makes that delivery itself, as `deliver` does (the account goes with it), so a relay whose only accounts are
 * subscriptions has one command from a deployed VM to a signed-in account. Any other
 * refusal stops the command before the sign-in, with the account left in the file for the next run.
 *
 * The steps are given by the caller (main.ts runs the real commands; the tests run them against a lane fixture).
 */
import { get, parsePlain, type Json } from "@gray/json";
import { EMPTY_SLOT, VM_NOT_ADOPTED } from "./deliver.ts";
import type { SignInAccountChange } from "./ui/accounts-file.ts";

/** One command's end: its exit code and, when it refused, the code its last JSON line names. */
export interface SealStep {
  readonly code: number;
  readonly refusal: string | null;
}

export interface LoginAddSteps {
  /** The account in the file source (`ensureSignInAccount`). */
  readonly ensure: () => Promise<SignInAccountChange>;
  /** `accounts push`. */
  readonly push: () => Promise<SealStep>;
  /** `deliver`: the first delivery. */
  readonly deliver: () => Promise<SealStep>;
}

export interface LoginAddIo {
  readonly stdout: (text: string) => void;
  readonly stderr: (text: string) => void;
}

/** What `accounts push` answers while the VM waits for its first delivery (deliver.ts). */
const FIRST_DELIVERY_FIRST: readonly string[] = [EMPTY_SLOT, VM_NOT_ADOPTED];

/** The `code` of a command's last JSON line when that line says `ok: false`; null for any other end. */
export function refusalOf(lines: readonly string[]): string | null {
  for (let at = lines.length - 1; at >= 0; at -= 1) {
    const line = (lines[at] as string).trim();
    if (!line.startsWith("{")) continue;
    try {
      const value = parsePlain(line) as Json;
      const code = get(value, "code");
      return get(value, "ok") === false && typeof code === "string" ? code : null;
    } catch {
      return null;
    }
  }
  return null;
}

/** Write the account, seal it, and return 0 when the sign-in may start; else the failed command's exit code. */
export async function addAndSeal(accountId: string, vendor: string, steps: LoginAddSteps, io: LoginAddIo): Promise<number> {
  const change = await steps.ensure();
  const did =
    change === "added"
      ? `added ${accountId} (${vendor}) to accounts.json as an account signed in inside the VM`
      : change === "proxy_set"
        ? `accounts.json already lists ${accountId}; its proxy is now the one given`
        : `accounts.json already lists ${accountId}`;
  io.stdout(`gray-assistant login: ${did}; sealing it to the VM (as accounts push does)\n`);
  let step = await steps.push();
  if (step.code !== 0 && step.refusal !== null && FIRST_DELIVERY_FIRST.includes(step.refusal)) {
    io.stdout("gray-assistant login: the VM waits for its first delivery, so this command makes it (as deliver does; the account goes with it)\n");
    step = await steps.deliver();
  }
  if (step.code !== 0) {
    io.stderr(`gray-assistant login: ${accountId} is in accounts.json but was not sealed (the lines above say why), so nothing was signed in. Put that right, then run this command again.\n`);
  }
  return step.code;
}

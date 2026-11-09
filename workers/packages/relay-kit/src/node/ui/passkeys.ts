/**
 * The passkeys that may sign in to the local page in public mode (`ui.public`): WebAuthn credentials registered with
 * `gray-assistant ui enroll`, kept in `ui-passkeys.json` beside `state.json` (0600, written by atomic rename under its own
 * lock, the CLI's control lock). A passkey is a public key, its id and a signature counter; nothing here is a secret,
 * and there is no password anywhere.
 *
 *     {"api_version": 1, "user_id": "<base64url, 32 random bytes>",
 *      "passkeys": [{"id": "<base64url credential id>", "public_key": "<base64url COSE key>", "counter": 0,
 *                    "transports": ["internal", "hybrid"], "label": "Ops laptop", "rp_id": "relay.example.com",
 *                    "created_at_ms": 1790000000000, "last_used_at_ms": null,
 *                    "device_type": "multiDevice", "backed_up": true}]}
 *
 * `rp_id` is the host the passkey was made for (the relay's public origin): a passkey made for another host is never
 * offered or accepted. `gray-assistant ui passkeys revoke <id>` removes one, and a page session opened with it ends at its
 * next request.
 */
import { dirname, join, resolve } from "node:path";
import { existsSync, statSync } from "node:fs";
import { parsePlain, toJsonString, type JsonObject } from "@gray/json";
import { z } from "zod";
import { RelayKitError } from "../../errors.ts";
import { acquireControlLock } from "../control-lock.ts";
import { writeAtomicPrivateFile } from "../daemon/atomic-file.ts";
import { readPrivateFile } from "../files.ts";

/** Passkeys one relay keeps: a few operators with a few devices each. */
export const MAX_PASSKEYS = 64;
/** A passkey's name as the operator typed it at enrolment. */
export const PASSKEY_LABEL = /^[^\u0000-\u001f\u007f]{1,64}$/u;

const base64url = z.string().regex(/^[A-Za-z0-9_-]{1,2048}$/u);

const passkeySchema = z
  .object({
    id: base64url,
    public_key: base64url,
    counter: z.number().int().min(0).max(Number.MAX_SAFE_INTEGER),
    transports: z.array(z.string().regex(/^[a-z-]{1,32}$/u)).max(8),
    label: z.string().regex(PASSKEY_LABEL),
    rp_id: z.string().min(1).max(253),
    created_at_ms: z.number().int().min(0),
    last_used_at_ms: z.number().int().min(0).nullable(),
    device_type: z.enum(["singleDevice", "multiDevice"]),
    backed_up: z.boolean(),
  })
  .strict();

const storeSchema = z
  .object({
    api_version: z.literal(1),
    user_id: base64url,
    passkeys: z.array(passkeySchema).max(MAX_PASSKEYS),
  })
  .strict();

export type StoredPasskey = z.infer<typeof passkeySchema>;
export interface PasskeyStore {
  readonly userId: string;
  readonly passkeys: readonly StoredPasskey[];
}

export function passkeysPath(stateFile: string): string {
  return join(dirname(resolve(stateFile)), "ui-passkeys.json");
}

/** The store, or an empty one (with a fresh user id from `random`) when there is no file yet. */
export function readPasskeys(path: string, random: (length: number) => Uint8Array): PasskeyStore {
  if (!existsSync(path)) return { userId: Buffer.from(random(32)).toString("base64url"), passkeys: [] };
  let value: unknown;
  try {
    value = parsePlain(readPrivateFile(path, "passkey store", 1024 * 1024));
  } catch (error) {
    if (error instanceof RelayKitError) throw error;
    throw new RelayKitError("io", "the passkey store is not JSON");
  }
  const parsed = storeSchema.safeParse(value);
  if (!parsed.success) throw new RelayKitError("io", `the passkey store: ${parsed.error.issues[0]?.path.map(String).join(".") || "document"}`);
  return { userId: parsed.data.user_id, passkeys: parsed.data.passkeys };
}

function storeText(store: PasskeyStore): string {
  const value: JsonObject = {
    api_version: 1n,
    user_id: store.userId,
    passkeys: store.passkeys.map((passkey) => ({
      id: passkey.id,
      public_key: passkey.public_key,
      counter: BigInt(passkey.counter),
      transports: [...passkey.transports],
      label: passkey.label,
      rp_id: passkey.rp_id,
      created_at_ms: BigInt(passkey.created_at_ms),
      last_used_at_ms: passkey.last_used_at_ms === null ? null : BigInt(passkey.last_used_at_ms),
      device_type: passkey.device_type,
      backed_up: passkey.backed_up,
    })),
  };
  return `${toJsonString(value)}\n`;
}

/** Change the store under its lock: read it afresh, apply `edit`, write it atomically as 0600. */
export async function updatePasskeys<T>(path: string, random: (length: number) => Uint8Array, edit: (store: PasskeyStore) => { readonly store: PasskeyStore; readonly result: T }): Promise<T> {
  const lock = await acquireControlLock(`${path}.lock`);
  try {
    const { store, result } = edit(readPasskeys(path, random));
    if (store.passkeys.length > MAX_PASSKEYS) throw new RelayKitError("usage", `a relay keeps at most ${MAX_PASSKEYS} passkeys; revoke one first`);
    writeAtomicPrivateFile(path, storeText(store));
    return result;
  } finally {
    lock.release();
  }
}

/**
 * The store as of its last change, read again only when the file changed (its mtime and size), so a page in public
 * mode can check every request's passkey without reading the file each time.
 */
export class PasskeyCache {
  readonly #path: string;
  readonly #random: (length: number) => Uint8Array;
  #seen: string | null = null;
  #store: PasskeyStore | null = null;

  constructor(path: string, random: (length: number) => Uint8Array) {
    this.#path = path;
    this.#random = random;
  }

  current(): PasskeyStore {
    let stamp = "absent";
    try {
      const stats = statSync(this.#path);
      stamp = `${stats.mtimeMs}:${stats.size}:${stats.ino}`;
    } catch {
      stamp = "absent";
    }
    if (this.#store === null || stamp !== this.#seen) {
      this.#store = readPasskeys(this.#path, this.#random);
      this.#seen = stamp;
    }
    return this.#store;
  }

  /** Forget the cached store (this process just wrote it). */
  invalidate(): void {
    this.#store = null;
  }
}

/** The one passkey an id prefix names (at least 8 characters), or a usage error that says why not. */
export function passkeyByPrefix(store: PasskeyStore, prefix: string): StoredPasskey {
  if (prefix.length < 8) throw new RelayKitError("usage", "name a passkey by at least the first 8 characters of its id (gray-assistant ui passkeys list)");
  const matches = store.passkeys.filter((passkey) => passkey.id.startsWith(prefix));
  if (matches.length === 0) throw new RelayKitError("usage", `no passkey's id starts with ${prefix}`);
  if (matches.length > 1) throw new RelayKitError("usage", `${matches.length} passkeys' ids start with ${prefix}; give more of it`);
  return matches[0] as StoredPasskey;
}

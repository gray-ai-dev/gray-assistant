/**
 * The relay's account pool as the sealing command reads it: the plaintext credential bundle before
 * it is signed, encrypted and handed to the TEE.
 *
 * ```json
 * {"relay_id":"relay-1","issued_at":1790000000,"expires_at":1790003600,
 *  "accounts":[{"account_id":"acc-1","vendor":"anthropic",
 *               "credential":{"type":"api_key","value":"sk-ant-api03-…"}}]}
 * ```
 *
 * The file holds real secrets. Its parse errors are fixed sentences: the platform's JSON errors can
 * echo a snippet of the input, and this package must never print a credential. The structural and
 * credential-class rules are `@gray/relay-connector`'s (`parseCredentialPayload`), so the relay's
 * tooling refuses exactly the bundle the TEE would.
 */
import type { JsonObject } from "@gray/json";
import {
  MAX_ACCOUNTS_PER_BUNDLE,
  MAX_CREDENTIAL_LENGTH,
  RESOURCE_ID,
  egressSchema,
  parseCredentialPayload,
  payloadValue,
  RelayConnectorError,
  VENDORS,
  type Account,
  type CredentialBundle,
  type CredentialUpdate,
  type EgressSpec,
  type Vendor,
} from "@gray/relay-connector";
import { z } from "zod";
import { RelayKitError } from "./errors.ts";

const U64_MAX = 0xffff_ffff_ffff_ffffn;

/** A credential bundle's timestamps and accounts, before the version is chosen. */
export interface AccountsFile {
  readonly relayId: string;
  readonly issuedAt: bigint | null;
  readonly expiresAt: bigint | null;
  readonly accounts: readonly Account[];
}

function u64(value: unknown): bigint | null {
  if (typeof value === "bigint" && value >= 0n && value <= U64_MAX) return value;
  if (typeof value === "number" && Number.isSafeInteger(value) && value >= 0) return BigInt(value);
  return null;
}

const credentialSchema = z
  .object({
    type: z.enum(["api_key", "oauth_access_token"]),
    value: z.string().min(1).max(MAX_CREDENTIAL_LENGTH),
    expires_at: z.union([z.bigint().min(0n).max(U64_MAX), z.number().int().min(0).max(Number.MAX_SAFE_INTEGER)]).optional(),
  })
  .strict();

const accountSchema = z
  .object({
    account_id: z.string().regex(RESOURCE_ID),
    vendor: z.enum(VENDORS),
    credential: credentialSchema,
    // The same E2 member the sealed bundle carries, validated before anything is signed.
    egress: egressSchema.optional(),
  })
  .strict();

const accountsFileSchema = z
  .object({
    relay_id: z.string().regex(RESOURCE_ID),
    issued_at: z.union([z.bigint(), z.number()]).optional(),
    expires_at: z.union([z.bigint(), z.number()]).optional(),
    accounts: z.array(z.unknown()).min(1).max(MAX_ACCOUNTS_PER_BUNDLE),
  })
  .strict();

/** Parse the accounts file. Refusals name only a member path or a fixed sentence. */
export function parseAccountsValue(value: unknown): AccountsFile {
  const parsed = accountsFileSchema.safeParse(value);
  if (!parsed.success) throw new RelayKitError("invalid_accounts");
  const issuedAt = parsed.data.issued_at === undefined ? null : u64(parsed.data.issued_at);
  const expiresAt = parsed.data.expires_at === undefined ? null : u64(parsed.data.expires_at);
  if ((parsed.data.issued_at !== undefined && issuedAt === null) || (parsed.data.expires_at !== undefined && expiresAt === null)) {
    throw new RelayKitError("invalid_accounts", "a timestamp is not a u64");
  }
  const accounts: Account[] = [];
  for (let index = 0; index < parsed.data.accounts.length; index += 1) {
    const account = accountSchema.safeParse(parsed.data.accounts[index]);
    if (!account.success) {
      // A field path only (`accounts.0.egress.port`); the zod message and the input value never
      // reach the error, because an accounts file holds credentials and proxy passwords.
      const issue = account.error.issues[0];
      const suffix = issue === undefined || issue.path.length === 0 ? "" : `.${issue.path.map(String).join(".")}`;
      throw new RelayKitError("invalid_accounts", `accounts.${index}${suffix}`);
    }
    const expiresAt = account.data.credential.expires_at;
    accounts.push({
      account_id: account.data.account_id,
      vendor: account.data.vendor as Vendor,
      credential: {
        type: account.data.credential.type,
        value: account.data.credential.value,
        ...(expiresAt === undefined ? {} : { expires_at: typeof expiresAt === "bigint" ? expiresAt : BigInt(expiresAt) }),
      },
      ...(account.data.egress === undefined ? {} : { egress: account.data.egress }),
    });
  }
  return { relayId: parsed.data.relay_id, issuedAt, expiresAt, accounts };
}

/** What the sealing command knows when it turns the file into a bundle. */
export interface BundleTimes {
  readonly version: bigint;
  readonly issuedAt: bigint;
  readonly expiresAt: bigint;
}

/**
 * The bundle the relay signs, as `@gray/relay-connector` types it. The payload is re-parsed through
 * the connector's own rules, so a credential whose format class does not match its vendor is refused
 * here rather than by the TEE after a round trip.
 */
export function bundleFromAccounts(file: AccountsFile, times: BundleTimes): CredentialBundle {
  if (file.relayId.length === 0) throw new RelayKitError("invalid_accounts", "relay_id");
  if (times.version < 1n || times.version > U64_MAX) throw new RelayKitError("invalid_version");
  const bundle: CredentialBundle = {
    relay_id: file.relayId,
    version: times.version,
    issued_at: times.issuedAt,
    expires_at: times.expiresAt,
    accounts: file.accounts,
  };
  parsePayload(payloadValue(bundle));
  return bundle;
}

/** The single-account update a refreshed token becomes. */
export function updateForToken(input: {
  readonly relayId: string;
  readonly version: bigint;
  readonly accountId: string;
  readonly credential: { readonly type: "api_key" | "oauth_access_token"; readonly value: string; readonly expires_at?: bigint };
  /** Replace the account's proxy, or `null` to clear it (an egress-only update carries no credential change). */
  readonly egress?: EgressSpec | null;
}): CredentialUpdate {
  if (input.version < 1n || input.version > U64_MAX) throw new RelayKitError("invalid_version");
  if (!RESOURCE_ID.test(input.relayId)) throw new RelayKitError("usage", "--relay-id");
  if (!RESOURCE_ID.test(input.accountId)) throw new RelayKitError("usage", "--account");
  const update = {
    relay_id: input.relayId,
    version: input.version,
    account_id: input.accountId,
    credential: input.credential,
    ...(input.egress === undefined ? {} : { egress: input.egress }),
  };
  parsePayload(payloadValue(update));
  return update;
}

function parsePayload(value: JsonObject): void {
  try {
    parseCredentialPayload(value as import("@gray/json").Json);
  } catch (error) {
    if (error instanceof RelayConnectorError) throw new RelayKitError("invalid_accounts", error.code);
    throw error;
  }
}

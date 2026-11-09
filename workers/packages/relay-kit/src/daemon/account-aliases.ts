/**
 * Plain panel ids for source accounts whose own id is not one (docs/confidential-lane-supply-implementation.md S59).
 *
 * The relay-stack origin holds each account under the id Gray's panel knows it by (daemon `#laneAccountId`). A source
 * may name accounts otherwise: CLIProxyAPI names them by e-mail address, which `STACK_ID_PATTERN` refuses and which
 * must not reach Gray anyway. Such an account gets `<vendor word>-<n>` (`anthropic-1`, `openai-1`, `codex-1`) on the
 * relay's host, the lowest `n` that is neither another account's own panel id nor an alias already given, at first
 * sight. Aliases are kept for good (never pruned), so an account that leaves the source and comes back gets its id
 * again, and an id is never given to a second account.
 *
 * The aliases file (`<state dir>/account-aliases.json`, 0600: it holds the source ids) is the Node store's
 * (`../node/daemon/account-aliases-file.ts`); this module is the document and the rule, pure, for Node and workerd:
 *
 *     {"api_version": 1, "aliases": [{"vendor": "anthropic", "source_id": "alice@example.com",
 *                                     "panel_id": "anthropic-1", "assigned_ms": 1793000000000}]}
 */
import { STACK_ID_PATTERN } from "@gray/control";
import { isObject, toJsonString, type Json } from "@gray/json";
import { VENDORS, type Vendor } from "@gray/relay-connector";
import { z } from "zod";

export const ACCOUNT_ALIASES_API_VERSION = 1;
export const ACCOUNT_ALIASES_FILE_NAME = "account-aliases.json";

/** The word an alias starts with, per vendor: the panel's own names for them (an OpenAI-compatible vendor's is its id, `_` as `-`). */
export const ACCOUNT_ALIAS_VENDOR_WORDS: Readonly<Record<Vendor, string>> = Object.freeze(
  Object.fromEntries(VENDORS.map((vendor) => [vendor, vendor === "chatgpt_codex" ? "codex" : vendor.replaceAll("_", "-")])) as Record<Vendor, string>,
);

/** One alias: the source account (by vendor and its own id) and the id the panel knows it by. */
export interface AccountAlias {
  readonly vendor: Vendor;
  readonly sourceId: string;
  readonly panelId: string;
  readonly assignedMs: number;
}

/** Where the daemon keeps them; the Node agent's is a file in the state directory. */
export interface AccountAliasStore {
  /** The aliases kept (none when there is no file yet), or null when a file is there but cannot be read. */
  read(): Promise<readonly AccountAlias[] | null>;
  /** Replace the kept aliases with `aliases`, atomically; throws when it cannot. */
  write(aliases: readonly AccountAlias[]): Promise<void>;
}

/** The key one alias is found by: an id is a source's own only per vendor. */
export function accountAliasKey(vendor: Vendor, sourceId: string): string {
  return `${vendor}\u0000${sourceId}`;
}

const aliasSchema = z
  .object({
    vendor: z.enum(VENDORS),
    source_id: z.string().min(1).max(1024),
    panel_id: z.string().regex(STACK_ID_PATTERN),
    assigned_ms: z.number().int().min(0).max(Number.MAX_SAFE_INTEGER),
  })
  .strict();
const documentSchema = z.object({ api_version: z.literal(ACCOUNT_ALIASES_API_VERSION), aliases: z.array(aliasSchema) }).strict();

/** The file's text: one line, aliases in the order given (the order they were assigned). */
export function accountAliasesText(aliases: readonly AccountAlias[]): string {
  return `${toJsonString({
    api_version: BigInt(ACCOUNT_ALIASES_API_VERSION),
    aliases: aliases.map((a) => ({ vendor: a.vendor, source_id: a.sourceId, panel_id: a.panelId, assigned_ms: BigInt(a.assignedMs) })),
  })}\n`;
}

/** The aliases a parsed file holds; throws for any other document, or one that gives an id or an account twice. */
export function parseAccountAliasesDocument(value: Json): AccountAlias[] {
  // `@gray/json` reads integers as bigints; the schema takes them as numbers.
  const plain = isObject(value)
    ? {
        ...value,
        api_version: typeof value.api_version === "bigint" ? Number(value.api_version) : value.api_version,
        aliases: Array.isArray(value.aliases)
          ? value.aliases.map((a) => (isObject(a) && typeof a.assigned_ms === "bigint" && a.assigned_ms <= BigInt(Number.MAX_SAFE_INTEGER) ? { ...a, assigned_ms: Number(a.assigned_ms) } : a))
          : value.aliases,
      }
    : value;
  const parsed = documentSchema.safeParse(plain);
  if (!parsed.success) throw new Error("not an account aliases document");
  const aliases = parsed.data.aliases.map((a) => ({ vendor: a.vendor, sourceId: a.source_id, panelId: a.panel_id, assignedMs: a.assigned_ms }));
  if (new Set(aliases.map((a) => a.panelId)).size !== aliases.length) throw new Error("an alias is given twice");
  if (new Set(aliases.map((a) => accountAliasKey(a.vendor, a.sourceId))).size !== aliases.length) throw new Error("an account has two aliases");
  return aliases;
}

/**
 * The aliases `accounts` need beyond `kept`, in source-id order: one for every account whose own id is not a panel
 * id and that has none yet, each the lowest `<word>-<n>` (n ≥ 1) that no account of the source has as its own id and
 * no alias holds.
 */
export function newAccountAliases(kept: readonly AccountAlias[], accounts: readonly { readonly vendor: Vendor; readonly sourceId: string }[], nowMs: number): AccountAlias[] {
  const known = new Set(kept.map((a) => accountAliasKey(a.vendor, a.sourceId)));
  const taken = new Set([...kept.map((a) => a.panelId), ...accounts.map((a) => a.sourceId).filter((id) => STACK_ID_PATTERN.test(id))]);
  const out: AccountAlias[] = [];
  const needing = accounts
    .filter((a) => !STACK_ID_PATTERN.test(a.sourceId) && !known.has(accountAliasKey(a.vendor, a.sourceId)))
    .sort((left, right) => (left.sourceId < right.sourceId ? -1 : left.sourceId > right.sourceId ? 1 : left.vendor < right.vendor ? -1 : 1));
  for (const account of needing) {
    const key = accountAliasKey(account.vendor, account.sourceId);
    if (known.has(key)) continue;
    let n = 1;
    while (taken.has(`${ACCOUNT_ALIAS_VENDOR_WORDS[account.vendor]}-${n}`)) n += 1;
    const panelId = `${ACCOUNT_ALIAS_VENDOR_WORDS[account.vendor]}-${n}`;
    taken.add(panelId);
    known.add(key);
    out.push({ vendor: account.vendor, sourceId: account.sourceId, panelId, assignedMs: nowMs });
  }
  return out;
}

/**
 * The panel id of one source account: its alias when it has one; else its own id when that is a panel id no alias
 * holds; else null (an account whose alias could not be kept yet, or whose own id another account's alias holds: it
 * is not sealed to the relay-stack origin, and doctor names it).
 */
export function panelIdOf(aliases: ReadonlyMap<string, AccountAlias>, aliasIds: ReadonlySet<string>, vendor: Vendor, sourceId: string): string | null {
  const alias = aliases.get(accountAliasKey(vendor, sourceId));
  if (alias !== undefined) return alias.panelId;
  return STACK_ID_PATTERN.test(sourceId) && !aliasIds.has(sourceId) ? sourceId : null;
}

/** `panelIdOf` over a list of aliases (a file read once): for `gray-assistant accounts` and the relay's own page. */
export function panelIdLookup(aliases: readonly AccountAlias[]): (vendor: Vendor, sourceId: string) => string | null {
  const byKey = new Map(aliases.map((a) => [accountAliasKey(a.vendor, a.sourceId), a]));
  const ids = new Set(aliases.map((a) => a.panelId));
  return (vendor, sourceId) => panelIdOf(byKey, ids, vendor, sourceId);
}

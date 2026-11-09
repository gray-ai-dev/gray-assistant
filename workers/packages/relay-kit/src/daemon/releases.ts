/**
 * Release acceptance (design v2 §A.7, critique R5, owner answer §11.3).
 *
 * The delay is measured from **the relay's own first-seen time**, kept in the state file. It is never
 * read from the release document's `published_at`: a backdated entry from the publisher would
 * otherwise skip the window in which the operator can veto it. A release is acceptable when
 *
 * - it carries a `git_commit` (a tag alone is not a reproducible identity),
 * - every listed OS image carries all four measurements the quote binds (D20/D36), and
 * - the relay first saw it at least `delay_days` ago, and
 * - it is still in the fetched list (withdrawing an entry withdraws its acceptance), and
 * - in `manual` mode, the operator explicitly accepted it.
 *
 * - the operator has not rejected it (`releases reject`, S11b).
 *
 * The list's OS images follow the same rule (plan S11b, "like an Ethereum upgrade"): a first sight
 * persisted per OS image hash, accepted after `delay_days` unless rejected, an explicit accept to
 * take one early, withdrawn when it leaves the list. On top of that an image must prove itself
 * production: its entry's `sha256sum_txt`/`metadata_json` must bind its hash and say `is_dev: false`
 * (`osImageProvenance`). A verified dev image is refused whatever the operator accepted; an image
 * whose texts are missing or do not bind it is taken only on an explicit accept.
 *
 * First sight is persisted before the alert and before any decision, so a restart neither resets
 * the delay nor alerts twice. The list fetch is a plain GET: the document is public, and what a
 * relay seals is still gated by its own accepted set.
 */
import {
  MAX_RELEASE_FRESHNESS_BYTES,
  MAX_RELEASE_LIST_BYTES,
  osImageProvenance,
  releaseListSha256,
  verifyReleaseListText,
  type OsImageEntry,
  type OsImageProvenance,
  type ReleaseEntry,
  type ReleaseFreshnessReport,
  type ReleaseList,
  type ReleaseListCurrentBy,
  type ReleaseListStaleness,
} from "@gray/lane-verify";
import type { DaemonFetch, DaemonLog, DaemonOsImageStatus, DaemonReleaseStatus } from "./types.ts";

/** The largest release list this tool reads (@gray/lane-verify's, which the list's signer refuses to pass). */
export { MAX_RELEASE_LIST_BYTES };

/** A release list that could not be fetched, verified or parsed. No body text is echoed. */
export type ReleaseListErrorCode =
  | "fetch_failed"
  | "http_status"
  | "not_json"
  | "invalid"
  | "bad_signature"
  | "expired"
  | "stale"
  | "future"
  | "issued_at_regressed"
  | "not_configured";

export class ReleaseListError extends Error {
  override readonly name = "ReleaseListError";
  readonly code: ReleaseListErrorCode;
  /** D137: for `expired` and `stale`, which part is stale (the list itself or its freshness document). */
  readonly staleness: ReleaseListStaleness | null;

  constructor(code: ReleaseListErrorCode, staleness: ReleaseListStaleness | null = null) {
    super(`release list: ${code}${staleness === null ? "" : ` (${staleness})`}`);
    this.code = code;
    this.staleness = staleness;
  }
}

/** What checking a Gray-signed release list needs: the pinned key, the freshness bound and a clock. */
export interface ReleaseListVerification {
  /** Gray's release-signing public key (32 bytes, from the config's pinned hex). */
  readonly publicKey: Uint8Array;
  /** A list older than this is refused, so a withheld withdrawal is noticed (K4-6). */
  readonly maxAgeSeconds: number;
  readonly nowMs: number;
  /**
   * D137: Gray's freshness key and the document's URL. With it a list that carries `expires_at` stays
   * current past `maxAgeSeconds` while the document for its exact bytes counts; without it, or null, the
   * list's own rule only.
   */
  readonly freshness?: { readonly publicKey: Uint8Array; readonly url: string } | null;
}

/** One verified list and the time its publisher says it was issued (used only for freshness). */
export interface VerifiedReleaseList {
  readonly list: ReleaseList;
  readonly issuedAt: bigint;
  /** D137: the list's horizon, the first second it is no longer current, and what made it current. */
  readonly expiresAt: bigint | null;
  readonly currentUntil: bigint;
  readonly currentBy: ReleaseListCurrentBy;
  readonly freshness: ReleaseFreshnessReport;
  /** SHA-256 of the list's bytes: the same list fetched twice has the same one. */
  readonly listSha256: string;
}

/**
 * Whether every OS image the list names carries all four measurements (D20). A list that names an
 * image without them cannot pin the image a boot measured, so it is not an authority for that list.
 */
export function releaseListHasOsMeasurements(list: ReleaseList): boolean {
  return list.osImageHashes.every((hash) => list.osImageMeasurements[hash] !== undefined);
}

/**
 * Fetch and verify the signed release list at `url`. The signature, schema, `git_commit` rule and
 * `issued_at` freshness are `@gray/lane-verify`'s `verifyReleaseListText`; this wrapper only adds
 * the transport, the byte cap and the closed error codes. The caller decides how long a failure may
 * persist. `issued_at` is returned for freshness only: the acceptance delay is the registry's own
 * first-sight rule, never the publisher's timestamp.
 */
async function fetchVerifiedReleaseList(fetch: DaemonFetch, url: string, verification: ReleaseListVerification): Promise<VerifiedReleaseList> {
  // D137: the document first, then the list. A list published between the two GETs is new, so it is
  // current on its own; the other order could pair an old list with the new list's document. A
  // document that cannot be fetched is `unavailable`, never a failed poll by itself.
  const freshness = verification.freshness ?? null;
  const document = freshness === null ? null : await fetchFreshnessText(fetch, freshness.url);
  let response;
  try {
    response = await fetch(url, { method: "GET", headers: { accept: "application/json", "user-agent": "gray-relay-daemon/0" }, timeoutMs: 20_000 });
  } catch {
    throw new ReleaseListError("fetch_failed");
  }
  if (response.status !== 200) throw new ReleaseListError("http_status");
  if (response.body.length > MAX_RELEASE_LIST_BYTES) throw new ReleaseListError("invalid");
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(response.body);
  } catch {
    throw new ReleaseListError("not_json");
  }
  const nowSecs = BigInt(Math.floor(verification.nowMs / 1000));
  const verified = await verifyReleaseListText(text, {
    publicKey: verification.publicKey,
    now: nowSecs,
    maxAgeSeconds: BigInt(verification.maxAgeSeconds),
    ...(freshness === null ? {} : { freshness: { publicKey: freshness.publicKey, text: document } }),
  });
  if (!verified.ok) {
    switch (verified.code) {
      case "bad_signature":
        throw new ReleaseListError("bad_signature");
      case "expired":
      case "stale":
        throw new ReleaseListError(verified.code, verified.staleness ?? null);
      case "future":
        throw new ReleaseListError(verified.code);
      default:
        // `malformed`, `missing_signature`, `missing_issued_at`, `bad_issued_at`, `bad_expires_at`,
        // `missing_git_commit`: one closed code, and no text from the document is echoed.
        throw new ReleaseListError("invalid");
    }
  }
  return {
    list: verified.list,
    issuedAt: verified.issuedAt,
    expiresAt: verified.expiresAt,
    currentUntil: verified.currentUntil,
    currentBy: verified.currentBy,
    freshness: verified.freshness,
    listSha256: releaseListSha256(text),
  };
}

/** The freshness document's text, or null when it is absent or could not be fetched or decoded (D137). */
async function fetchFreshnessText(fetch: DaemonFetch, url: string): Promise<string | null> {
  try {
    const response = await fetch(url, { method: "GET", headers: { accept: "application/json", "user-agent": "gray-relay-daemon/0" }, timeoutMs: 20_000 });
    if (response.status !== 200 || response.body.length > MAX_RELEASE_FRESHNESS_BYTES) return null;
    return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(response.body);
  } catch {
    return null;
  }
}

/**
 * Fetch and verify the signed list, and require that every `os_images` entry carries all four
 * measurements (D20, D36). A signed list that drops them is refused as `invalid` instead of
 * authorising a boot the customer's `verifyAttestation` would reject as `os_image_measurements`.
 */
export async function fetchReleaseList(fetch: DaemonFetch, url: string, verification: ReleaseListVerification): Promise<VerifiedReleaseList> {
  const verified = await fetchVerifiedReleaseList(fetch, url, verification);
  if (!releaseListHasOsMeasurements(verified.list)) throw new ReleaseListError("invalid");
  return verified;
}

/** The persisted slice of release state the registry owns. */
export interface ReleaseStateSlice {
  readonly firstSeen: Readonly<Record<string, number>>;
  /** S11b: OS image hash → first sight, persisted beside the compose hashes'. */
  readonly osImageFirstSeen: Readonly<Record<string, number>>;
  readonly accepted: readonly string[];
  /** compose hash → the wall-clock millisecond the operator accepted it (R27). */
  readonly acceptedAtMs: Readonly<Record<string, number>>;
  /** S11b: the operator's veto, compose and OS image hashes alike. */
  readonly rejected: readonly string[];
}

export interface ReleaseRegistryOptions {
  readonly mode: "auto-after-delay" | "manual";
  readonly delayDays: number;
  readonly wallMs: () => number;
  readonly firstSeen: Readonly<Record<string, number>>;
  /**
   * S11b: the persisted OS image first sights, or `undefined` for a state written before S11b: then
   * the first observed list's OS images are adopted as seen at time 0 (they were already trusted, and
   * an upgrade must not withdraw a running lane for a delay), and logged. A first sight of 0 is only
   * ever an adoption (a real one is a wall-clock time), and an adopted image needs no acceptance in
   * `manual` mode either; it still has to prove itself production by its texts.
   */
  readonly osImageFirstSeen?: Readonly<Record<string, number>>;
  readonly accepted: readonly string[];
  /**
   * When each accepted hash was accepted. An acceptance only shortens a first sight when it is at
   * or after that sight: a withdrawn hash that is re-listed waits a new delay even though the old
   * acceptance is still in the CLI's file (R27).
   */
  readonly acceptedAtMs?: Readonly<Record<string, number>>;
  readonly rejected?: readonly string[];
  /** The accepted hashes that `init --pair` recorded (control.json's `accepted_at_pairing`), for `status` only. */
  readonly acceptedAtPairing?: readonly string[];
  /** Persist a change before it is acted on. */
  readonly persist: (slice: ReleaseStateSlice) => Promise<void>;
  readonly log: DaemonLog;
}

/** What one `observe` changed. */
export interface ReleaseObservation {
  readonly firstSight: readonly string[];
  readonly withdrawn: readonly string[];
  readonly osImageFirstSight: readonly string[];
  readonly osImagesWithdrawn: readonly string[];
}

/** Why S11b refuses a listed OS image, in the order it checks. */
export type OsImageRefusal = "os_image_rejected" | "os_image_dev" | "os_image_unverified" | "os_image_not_accepted";

export type OsImageDecision = { readonly ok: true } | { readonly ok: false; readonly code: OsImageRefusal };

/**
 * S11b without a release registry, for `gray-assistant attest` (the CLI's attest-then-seal path keeps no
 * first sights): a verified dev image is refused; an image its texts prove production is taken; an
 * unproven one only when the operator named it (`--accept-os-image`). The codes are the daemon's.
 */
export function osImageDecisionWithoutRegistry(
  entry: Pick<OsImageEntry, "os_image_hash" | "sha256sum_txt" | "metadata_json">,
  acceptedOsImages: readonly string[],
): OsImageDecision {
  const provenance = osImageProvenance(entry);
  if (provenance.ok && provenance.isDev) return { ok: false, code: "os_image_dev" };
  if (provenance.ok || acceptedOsImages.includes(entry.os_image_hash)) return { ok: true };
  return { ok: false, code: "os_image_unverified" };
}

/** The relay's release memory: first-seen times, the current list and the manual acceptances. */
export class ReleaseRegistry {
  readonly #mode: "auto-after-delay" | "manual";
  readonly #delayMs: number;
  readonly #wallMs: () => number;
  readonly #firstSeen: Map<string, number>;
  readonly #osFirstSeen: Map<string, number>;
  #adoptOsImages: boolean;
  readonly #accepted: Map<string, number>;
  readonly #rejected: Set<string>;
  readonly #atPairing: Set<string>;
  readonly #persist: (slice: ReleaseStateSlice) => Promise<void>;
  readonly #log: DaemonLog;
  #entries = new Map<string, ReleaseEntry>();
  #available = new Set<string>();
  #osImages = new Map<string, OsImageEntry>();
  #list: ReleaseList | null = null;
  #fetchedAtMs: number | null = null;

  constructor(options: ReleaseRegistryOptions) {
    this.#mode = options.mode;
    this.#delayMs = options.delayDays * 86_400_000;
    this.#wallMs = options.wallMs;
    this.#firstSeen = new Map(Object.entries(options.firstSeen));
    this.#osFirstSeen = new Map(Object.entries(options.osImageFirstSeen ?? {}));
    this.#adoptOsImages = options.osImageFirstSeen === undefined;
    this.#accepted = new Map();
    for (const hash of options.accepted) {
      const at = options.acceptedAtMs?.[hash];
      // A stamp-less acceptance from an older control file is kept as "unknown": it counts only
      // while no first sight exists to compare it with (see #acceptanceCounts).
      this.#accepted.set(hash, at === undefined ? -1 : at);
    }
    this.#rejected = new Set(options.rejected ?? []);
    this.#atPairing = new Set(options.acceptedAtPairing ?? []);
    this.#persist = options.persist;
    this.#log = options.log;
  }

  get list(): ReleaseList | null {
    return this.#list;
  }

  get fetchedAtMs(): number | null {
    return this.#fetchedAtMs;
  }

  /** The compose hashes the current list names, whether acceptable or not. */
  get available(): ReadonlySet<string> {
    return this.#available;
  }

  /**
   * Record a fetched list. First sight is persisted before the alert, so an alert is never the only
   * record and a crash cannot reset the delay. Every persisted first sight whose hash is absent from
   * this list is removed and persisted as withdrawn (D49), so that rule holds across a restart too.
   * When that write fails the first-seen map is restored (the removal is retried on the next poll)
   * but the verified withdrawal still takes effect in memory (D79): the registry narrows to the
   * hashes the new list names, so a failed write can never keep a withdrawn release acceptable.
   * OS images (S11b) follow the same rules in their own map.
   */
  async observe(list: ReleaseList): Promise<ReleaseObservation> {
    const now = this.#wallMs();
    const next = new Set(list.releases.map((entry) => entry.compose_hash));
    const nextImages = new Set(list.osImages.map((entry) => entry.os_image_hash));
    const firstSight: string[] = [];
    for (const entry of list.releases) {
      if (this.#firstSeen.has(entry.compose_hash)) continue;
      this.#firstSeen.set(entry.compose_hash, now);
      firstSight.push(entry.compose_hash);
    }
    const adopting = this.#adoptOsImages;
    const osImageFirstSight: string[] = [];
    for (const entry of list.osImages) {
      if (this.#osFirstSeen.has(entry.os_image_hash)) continue;
      this.#osFirstSeen.set(entry.os_image_hash, adopting ? 0 : now);
      osImageFirstSight.push(entry.os_image_hash);
    }
    // D49: every verified list reconciles the *persisted* first-seen record, not just this process's
    // in-memory `#available` set. After a restart `#available` is empty while `#firstSeen` still
    // carries entries from before the restart; without this reconciliation a list that omits one of
    // them would leave its old sight in place, and a later re-listing would skip the delay.
    //
    // R27: a withdrawn hash loses its first sight, so a still-fresh signed list that re-lists it
    // (a replay) must wait a full new delay. The acceptance stamp survives in control.json, but it
    // is older than the new first sight and therefore no longer counts (see #acceptanceCounts).
    const withdrawn = [...this.#firstSeen.keys()].filter((hash) => !next.has(hash)).sort();
    const forgotten: Array<[string, number]> = [];
    for (const hash of withdrawn) {
      const seen = this.#firstSeen.get(hash);
      if (seen === undefined) continue;
      forgotten.push([hash, seen]);
      this.#firstSeen.delete(hash);
    }
    const osImagesWithdrawn = [...this.#osFirstSeen.keys()].filter((hash) => !nextImages.has(hash)).sort();
    const forgottenImages: Array<[string, number]> = [];
    for (const hash of osImagesWithdrawn) {
      const seen = this.#osFirstSeen.get(hash);
      if (seen === undefined) continue;
      forgottenImages.push([hash, seen]);
      this.#osFirstSeen.delete(hash);
    }
    // An adoption is written once, even when it adds no image, so the next start is not an upgrade.
    if (firstSight.length > 0 || forgotten.length > 0 || osImageFirstSight.length > 0 || forgottenImages.length > 0 || adopting) {
      try {
        await this.#persist(this.slice());
      } catch (error) {
        // The delay is not observed if it cannot be persisted: a restart must not lose it and then
        // accept the release on a second sight. Leave the first-seen map as it was, so the next
        // successful poll retries the same withdrawal.
        for (const hash of firstSight) this.#firstSeen.delete(hash);
        for (const [hash, seen] of forgotten) this.#firstSeen.set(hash, seen);
        for (const hash of osImageFirstSight) this.#osFirstSeen.delete(hash);
        for (const [hash, seen] of forgottenImages) this.#osFirstSeen.set(hash, seen);
        // D79: a verified withdrawal is fail-safe, not part of the rolled-back write. Narrow the
        // in-memory authority to the intersection of the previous and the new list, so a failed
        // write can only remove acceptance, never keep a withdrawn entry acceptable. New entries
        // are not adopted here: their first sight was not persisted. The poll still fails (the
        // caller sees this throw), and the next successful poll persists the removal.
        for (const hash of [...this.#entries.keys()]) if (!next.has(hash)) this.#entries.delete(hash);
        for (const hash of [...this.#available]) if (!next.has(hash)) this.#available.delete(hash);
        for (const hash of [...this.#osImages.keys()]) if (!nextImages.has(hash)) this.#osImages.delete(hash);
        throw error;
      }
    }
    this.#adoptOsImages = false;
    this.#entries = new Map(list.releases.map((entry) => [entry.compose_hash, entry]));
    this.#available = next;
    this.#osImages = new Map(list.osImages.map((entry) => [entry.os_image_hash, entry]));
    this.#list = list;
    this.#fetchedAtMs = now;
    for (const hash of firstSight) {
      this.#log({ level: "info", event: "release_first_seen", compose_hash: hash, acceptable_at_ms: this.acceptableAtMs(hash) });
    }
    for (const hash of withdrawn) this.#log({ level: "warn", event: "release_withdrawn", compose_hash: hash });
    for (const hash of osImageFirstSight) {
      const provenance = osImageProvenance(this.#osImages.get(hash) as OsImageEntry);
      const dev = provenance.ok && provenance.isDev;
      this.#log({
        // A verified dev image is never accepted; its first sight is the operator's warning.
        level: dev || !provenance.ok ? "warn" : "info",
        event: adopting ? "os_image_adopted" : "os_image_first_seen",
        os_image_hash: hash,
        acceptable_at_ms: this.osImageAcceptableAtMs(hash),
        provenance: provenance.ok ? "ok" : provenance.code,
        is_dev: provenance.ok ? provenance.isDev : null,
        version: provenance.ok ? provenance.version : null,
      });
    }
    for (const hash of osImagesWithdrawn) this.#log({ level: "warn", event: "os_image_withdrawn", os_image_hash: hash });
    return { firstSight, withdrawn, osImageFirstSight, osImagesWithdrawn };
  }

  /** The earliest wall time this hash can be accepted automatically, or null when it is not listed. */
  acceptableAtMs(composeHash: string): number | null {
    const first = this.#firstSeen.get(composeHash);
    if (first === undefined || !this.#available.has(composeHash)) return null;
    return first + this.#delayMs;
  }

  /** The same for an OS image of the current list (S11b). */
  osImageAcceptableAtMs(osImageHash: string): number | null {
    const first = this.#osFirstSeen.get(osImageHash);
    if (first === undefined || !this.#osImages.has(osImageHash)) return null;
    return first + this.#delayMs;
  }

  /** Whether this relay holds a first sight of the compose or OS image hash (persisted, so across restarts). */
  hasFirstSight(hash: string): boolean {
    return this.#firstSeen.has(hash) || this.#osFirstSeen.has(hash);
  }

  /** Whether the current list still carries the hash. */
  isListed(composeHash: string): boolean {
    return this.#available.has(composeHash);
  }

  /**
   * Whether an explicit acceptance counts for the hash's current sight. An acceptance recorded
   * before that sight (or one from an older control file with no stamp, once a sight exists) does
   * not: after a withdrawal and a replay the operator must accept the release again (R27).
   */
  #acceptanceCounts(hash: string, firstSeen: ReadonlyMap<string, number>): boolean {
    const at = this.#accepted.get(hash);
    if (at === undefined) return false;
    const first = firstSeen.get(hash);
    if (first === undefined) return true;
    return at >= first;
  }

  /** Whether the hash is acceptable at `nowMs`. Tag-only and rejected entries are never acceptable. */
  acceptable(composeHash: string, nowMs = this.#wallMs()): boolean {
    const entry = this.#entries.get(composeHash);
    if (entry === undefined || entry.git_commit === null) return false;
    // S11b: the operator's veto wins over the delay and over an older acceptance.
    if (this.#rejected.has(composeHash)) return false;
    // R05: the documented emergency override works in both modes. It is checked after the list
    // membership and the `git_commit` rule above, so it can never widen what Gray published.
    if (this.#acceptanceCounts(composeHash, this.#firstSeen)) return true;
    if (this.#mode === "manual") return false;
    const at = this.acceptableAtMs(composeHash);
    return at !== null && nowMs >= at;
  }

  /** Whether the operator has rejected the hash (S11b). */
  isRejected(hash: string): boolean {
    return this.#rejected.has(hash);
  }

  /**
   * S11b for one OS image of the current list, or null when the list does not carry it: refused
   * when rejected, when its own texts prove it a dev image (whatever was accepted), when its texts
   * are missing or do not bind it and nobody accepted it explicitly, and until its delay (or, in
   * `manual` mode, an acceptance) otherwise.
   */
  osImageDecision(osImageHash: string, nowMs = this.#wallMs()): OsImageDecision | null {
    const entry = this.#osImages.get(osImageHash);
    if (entry === undefined) return null;
    if (this.#rejected.has(osImageHash)) return { ok: false, code: "os_image_rejected" };
    const provenance = osImageProvenance(entry);
    if (provenance.ok && provenance.isDev) return { ok: false, code: "os_image_dev" };
    if (this.#acceptanceCounts(osImageHash, this.#osFirstSeen)) return { ok: true };
    if (!provenance.ok) return { ok: false, code: "os_image_unverified" };
    // An adopted image (first sight 0) was trusted before S11b: no delay and no acceptance needed.
    if (this.#osFirstSeen.get(osImageHash) === 0) return { ok: true };
    if (this.#mode === "manual") return { ok: false, code: "os_image_not_accepted" };
    const at = this.osImageAcceptableAtMs(osImageHash);
    return at !== null && nowMs >= at ? { ok: true } : { ok: false, code: "os_image_not_accepted" };
  }

  /** Whether an operator has explicitly accepted the hash and the acceptance still counts. */
  isAccepted(composeHash: string): boolean {
    return this.#acceptanceCounts(composeHash, this.#firstSeen);
  }

  /** When the counting acceptance was made, or null (none, or a stamp-less one from an older file). */
  #acceptedAtMs(hash: string, firstSeen: ReadonlyMap<string, number>): number | null {
    if (!this.#acceptanceCounts(hash, firstSeen)) return null;
    const at = this.#accepted.get(hash);
    return at === undefined || at < 0 ? null : at;
  }

  /**
   * Adopt explicit acceptances written by `gray-assistant releases accept` (a second process edits the
   * one state file). The registry keeps its own memory; this is the bridge to the file, and it is
   * called only from the daemon's control-state reload and its pairing acceptances. `atPairing` names the ones
   * `init --pair` recorded, which `status` reports as such.
   */
  setAccepted(accepted: readonly string[], acceptedAtMs: Readonly<Record<string, number>> = {}, atPairing: readonly string[] = []): void {
    this.#accepted.clear();
    for (const hash of accepted) {
      const at = acceptedAtMs[hash];
      this.#accepted.set(hash, at === undefined ? -1 : at);
    }
    this.#atPairing.clear();
    for (const hash of atPairing) this.#atPairing.add(hash);
  }

  /** Adopt the veto set from `control.json` (S11b); the daemon's control reload calls it. */
  setRejected(rejected: readonly string[]): void {
    this.#rejected.clear();
    for (const hash of rejected) this.#rejected.add(hash);
  }

  /**
   * `releases accept <id>`: match a compose hash, a git tag, a git commit or (S11b) an OS image hash
   * from the current list. Returns the hash accepted, or null when the id names nothing in the list.
   */
  async accept(releaseId: string): Promise<string | null> {
    let target: string | null = null;
    for (const [hash, entry] of this.#entries) {
      if (releaseId === hash || releaseId === entry.git_tag || releaseId === entry.git_commit) {
        target = hash;
        break;
      }
    }
    if (target === null && this.#osImages.has(releaseId)) target = releaseId;
    if (target === null) return null;
    const previous = this.#accepted.get(target);
    const wasRejected = this.#rejected.delete(target);
    this.#accepted.set(target, this.#wallMs());
    try {
      await this.#persist(this.slice());
    } catch (error) {
      if (previous === undefined) this.#accepted.delete(target);
      else this.#accepted.set(target, previous);
      if (wasRejected) this.#rejected.add(target);
      throw error;
    }
    this.#log({ level: "info", event: "release_accepted_manually", compose_hash: target });
    return target;
  }

  /** The state slice to persist. */
  slice(): ReleaseStateSlice {
    const sorted = (map: ReadonlyMap<string, number>): Record<string, number> => {
      const out: Record<string, number> = {};
      for (const key of [...map.keys()].sort()) out[key] = map.get(key) as number;
      return out;
    };
    return {
      firstSeen: sorted(this.#firstSeen),
      osImageFirstSeen: sorted(this.#osFirstSeen),
      accepted: [...this.#accepted.keys()].sort(),
      acceptedAtMs: sorted(this.#accepted),
      rejected: [...this.#rejected].sort(),
    };
  }

  /** The operator/status view of every entry in the current list. */
  status(nowMs = this.#wallMs()): readonly DaemonReleaseStatus[] {
    const out: DaemonReleaseStatus[] = [];
    for (const entry of [...this.#entries.values()].sort((left, right) => left.compose_hash.localeCompare(right.compose_hash))) {
      out.push({
        composeHash: entry.compose_hash,
        gitCommit: entry.git_commit,
        firstSeenMs: this.#firstSeen.get(entry.compose_hash) ?? null,
        acceptableAtMs: this.acceptableAtMs(entry.compose_hash),
        acceptable: this.acceptable(entry.compose_hash, nowMs),
        accepted: this.isAccepted(entry.compose_hash),
        acceptedAtMs: this.#acceptedAtMs(entry.compose_hash, this.#firstSeen),
        acceptedAtPairing: this.#atPairing.has(entry.compose_hash) && this.isAccepted(entry.compose_hash),
        rejected: this.#rejected.has(entry.compose_hash),
      });
    }
    return out;
  }

  /** S11b: the operator/status view of every OS image in the current list. */
  osImageStatus(nowMs = this.#wallMs()): readonly DaemonOsImageStatus[] {
    const out: DaemonOsImageStatus[] = [];
    for (const hash of [...this.#osImages.keys()].sort()) {
      const provenance: OsImageProvenance = osImageProvenance(this.#osImages.get(hash) as OsImageEntry);
      const decision = this.osImageDecision(hash, nowMs);
      out.push({
        osImageHash: hash,
        firstSeenMs: this.#osFirstSeen.get(hash) ?? null,
        acceptableAtMs: this.osImageAcceptableAtMs(hash),
        acceptable: decision?.ok === true,
        refusal: decision === null || decision.ok ? null : decision.code,
        accepted: this.#acceptanceCounts(hash, this.#osFirstSeen),
        acceptedAtMs: this.#acceptedAtMs(hash, this.#osFirstSeen),
        acceptedAtPairing: this.#atPairing.has(hash) && this.#acceptanceCounts(hash, this.#osFirstSeen),
        rejected: this.#rejected.has(hash),
        provenance: provenance.ok ? "ok" : provenance.code,
        isDev: provenance.ok ? provenance.isDev : null,
        version: provenance.ok ? provenance.version : null,
      });
    }
    return out;
  }
}

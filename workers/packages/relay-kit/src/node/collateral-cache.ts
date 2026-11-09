/**
 * The DCAP verification collateral the agent fetches from Intel PCS or a PCCS, kept and shared (the
 * plan's DCAP amplification item): every quote the token service or credential intake verifies used to
 * cost four or five PCS/PCCS requests, so a caller that can send quotes could make the relay hammer
 * Intel's service.
 *
 * Kept as `@phala/dcap-qvl` keys it. Its `getCollateral(pccsUrl, quote)` takes the PCK certificate
 * chain from the quote, reads the FMSPC and the issuing CA from its leaf, and fetches the collateral for
 * that (PCCS URL, SGX or TDX, FMSPC, CA); everything it returns but the chain depends on those four
 * alone. This module computes the same key with dcap-qvl's own `intel.getFmspc`/`intel.getCa` and asks
 * `getCollateralForFmspc` for it, then attaches the quote's own chain, so the verifier gets exactly
 * what `getCollateral` would have returned.
 *
 * - **How long:** until the collateral's own `nextUpdate`, the earlier of the TCB info's and the QE
 *   identity's (Intel's dates; dcap-qvl's `verify` refuses collateral past either). No time of ours.
 * - **One fetch per key:** callers that miss at the same time wait for one request.
 * - **Failures are not kept:** the next caller fetches again (an outage must not outlive itself).
 * - A quote whose chain is not in the quote (cert types 2 and 3, a PCCS lookup by encrypted PPID) is
 *   passed straight to `getCollateral`, uncached.
 */
import { createRequire } from "node:module";
import { get, parseStrict } from "@gray/json";
import { Quote, getCollateral, intel, type Collateral } from "@phala/dcap-qvl";

/**
 * dcap-qvl 0.7.0's `getCollateralForFmspc`: declared in its typings, defined in `src/collateral.js`,
 * but not re-exported by its CommonJS `index.js`, so it is taken from the file that defines it.
 */
const { getCollateralForFmspc } = createRequire(import.meta.url)("@phala/dcap-qvl/src/collateral.js") as {
  readonly getCollateralForFmspc: (pccsUrl: string, fmspc: string, ca: string, forSgx: boolean) => Promise<Collateral>;
};

/** Entries kept at most; a real fleet has a handful of FMSPCs. Past it, expired entries are dropped first. */
export const MAX_COLLATERAL_ENTRIES = 256;

export interface CollateralCacheOptions {
  /** Wall-clock Unix milliseconds. */
  readonly now?: () => number;
  /** dcap-qvl's `getCollateralForFmspc` by default; tests inject one. */
  readonly fetchForFmspc?: (pccsUrl: string, fmspc: string, ca: string, forSgx: boolean) => Promise<Collateral>;
  /** dcap-qvl's `getCollateral` by default, for the quotes that carry no PCK chain. */
  readonly fetchForQuote?: (pccsUrl: string, quote: Uint8Array) => Promise<Collateral>;
  readonly maxEntries?: number;
}

/** What the cache knows, for tests and logs. */
export interface CollateralCacheStats {
  readonly entries: number;
  readonly fetches: number;
}

export interface CollateralCache {
  /** The `fetchCollateral` seam of `@gray/lane-verify/dcap`'s `dcapQuoteVerifier`. */
  readonly fetch: (pccsUrl: string, quote: Uint8Array) => Promise<Collateral>;
  stats(): CollateralCacheStats;
}

interface Entry {
  readonly collateral: Collateral;
  readonly expiresAtMs: number;
}

/**
 * The collateral with the quote's own PCK chain, as `getCollateral` returns it (dcap-qvl's `verify` reads
 * `pck_certificate_chain` first; its 0.7.0 typings do not declare the member).
 */
function withChain(collateral: Collateral, chain: string): Collateral {
  return Object.assign({}, collateral, { pck_certificate_chain: chain });
}

/**
 * The earlier `nextUpdate` of the TCB info and the QE identity, in ms; null when either cannot be read.
 * A text with a duplicated key is not read (parseStrict), so a collateral whose expiry is ambiguous is
 * never kept: dcap-qvl verifies it again from a fresh fetch each time.
 */
export function collateralExpiryMs(collateral: Collateral): number | null {
  const nextUpdate = (text: unknown): number => {
    if (typeof text !== "string") return Number.NaN;
    try {
      const value = get(parseStrict(text), "nextUpdate");
      return typeof value === "string" ? Date.parse(value) : Number.NaN;
    } catch {
      return Number.NaN;
    }
  };
  const expiry = Math.min(nextUpdate(collateral.tcb_info), nextUpdate(collateral.qe_identity));
  return Number.isFinite(expiry) ? expiry : null;
}

export function createCollateralCache(options: CollateralCacheOptions = {}): CollateralCache {
  const now = options.now ?? (() => Date.now());
  const fetchForFmspc = options.fetchForFmspc ?? getCollateralForFmspc;
  const fetchForQuote = options.fetchForQuote ?? getCollateral;
  const maxEntries = options.maxEntries ?? MAX_COLLATERAL_ENTRIES;
  const entries = new Map<string, Entry>();
  const inFlight = new Map<string, Promise<Collateral>>();
  let fetches = 0;

  const keep = (key: string, collateral: Collateral): void => {
    const expiresAtMs = collateralExpiryMs(collateral);
    if (expiresAtMs === null || expiresAtMs <= now()) return;
    if (entries.size >= maxEntries) {
      for (const [other, entry] of entries) if (entry.expiresAtMs <= now()) entries.delete(other);
      if (entries.size >= maxEntries) return;
    }
    entries.set(key, { collateral, expiresAtMs });
  };

  return {
    async fetch(pccsUrl: string, quoteBytes: Uint8Array): Promise<Collateral> {
      let key: string;
      let chain: string;
      let forSgx: boolean;
      let fmspc: string;
      let ca: string;
      try {
        const quote = Quote.parse(quoteBytes);
        chain = new TextDecoder().decode(quote.rawCertChain());
        forSgx = quote.header.isSgx();
        fmspc = Buffer.from(intel.getFmspc(quote)).toString("hex").toUpperCase();
        ca = intel.getCa(quote);
        key = JSON.stringify([pccsUrl, forSgx ? "sgx" : "tdx", fmspc, ca]);
      } catch {
        // No PCK chain in the quote (or not a quote at all): dcap-qvl's own path, which refuses or
        // looks the chain up itself.
        fetches += 1;
        return fetchForQuote(pccsUrl, quoteBytes);
      }
      const cached = entries.get(key);
      if (cached !== undefined && cached.expiresAtMs > now()) return withChain(cached.collateral, chain);
      if (cached !== undefined) entries.delete(key);
      let pending = inFlight.get(key);
      if (pending === undefined) {
        fetches += 1;
        pending = fetchForFmspc(pccsUrl, fmspc, ca, forSgx).then(
          (collateral) => {
            keep(key, collateral);
            return collateral;
          },
        );
        const settled = pending.finally(() => inFlight.delete(key));
        // The waiters see the fetch's own outcome; the bookkeeping promise must not be an unhandled rejection.
        settled.catch(() => undefined);
        inFlight.set(key, pending);
      }
      return withChain(await pending, chain);
    },
    stats(): CollateralCacheStats {
      return { entries: entries.size, fetches };
    },
  };
}

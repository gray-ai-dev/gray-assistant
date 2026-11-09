/**
 * The Node-side Intel DCAP adapter for `verifyAttestation`'s `quoteVerifier` seam: `../dcap.ts`'s
 * `collateralQuoteVerifier` (dcap-qvl with the collateral supplied) with the collateral fetched from
 * Intel PCS by default (`INTEL_PCS_URL`) or from any PCCS URL the caller configures. The fetch is a
 * network operation, which is why this is a Node-only subpath rather than part of the workerd-safe
 * entry points; a lane passes the collateral the bridge delivered to `collateralQuoteVerifier` itself.
 *
 * What the adapter binds, and why dcap-qvl, is said in `../dcap.ts`.
 */
import { INTEL_PCS_URL, getCollateral, type Collateral, type VerifiedReport } from "@phala/dcap-qvl";
import type { QuoteVerifier } from "../attestation.ts";
import { collateralQuoteVerifier } from "../dcap.ts";

export { appraise } from "../dcap.ts";

export interface DcapQuoteVerifierOptions {
  /** PCCS base URL; defaults to Intel PCS (`https://api.trustedservices.intel.com`). */
  readonly pccsUrl?: string;
  /** The verifier's clock in Unix seconds; defaults to `Date.now()`. */
  readonly nowSecs?: () => number;
  /** Collateral fetch injection (tests never reach the network). */
  readonly fetchCollateral?: (pccsUrl: string, quote: Uint8Array) => Promise<Collateral>;
  /** Quote verification injection (tests that exercise the mapping without real collateral). */
  readonly verifyQuote?: (quote: Uint8Array, collateral: Collateral, nowSecs: number) => VerifiedReport;
}

/** Build the injected `QuoteVerifier` that uses `@phala/dcap-qvl` and Intel PCS/PCCS collateral. */
export function dcapQuoteVerifier(options: DcapQuoteVerifierOptions = {}): QuoteVerifier {
  const pccsUrl = options.pccsUrl ?? INTEL_PCS_URL;
  const fetchCollateral = options.fetchCollateral ?? getCollateral;
  return collateralQuoteVerifier({
    collateral: async (quote) => {
      try {
        return await fetchCollateral(pccsUrl, quote);
      } catch (error) {
        throw new Error(`collateral fetch from ${pccsUrl} failed: ${messageOf(error)}`);
      }
    },
    ...(options.nowSecs === undefined ? {} : { nowSecs: options.nowSecs }),
    ...(options.verifyQuote === undefined ? {} : { verifyQuote: options.verifyQuote }),
  });
}

function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/**
 * What `gray-assistant upload` is looking at, and where it goes.
 *
 * The lane does not exist yet, so this package defines the two documents it posts and the two paths
 * in `endpoints.ts`. A sealed credential message is one HPKE envelope whatever it contains (a full
 * bundle or a single-account update: the TEE's store tells them apart after decryption), and a policy
 * bundle is the signed JSON document `policy bundle` writes. Classification is by the document's own
 * `api_version`, and each is re-parsed with the TEE-side parser before anything leaves the machine: an
 * upload of a malformed file fails here, not after a round trip.
 */
import { get, isObject } from "@gray/json";
import { RELAY_INTAKE_API_VERSION, parseSealedCredential } from "@gray/relay-connector";
import { LANE_ENDPOINTS, POLICY_BUNDLE_API_VERSION } from "./endpoints.ts";
import { RelayKitError } from "./errors.ts";
import { parsePolicyBundleValue } from "./policy-bundle.ts";

/** One upload: which lane path it belongs to, and its parsed document. */
export interface UploadDocument {
  readonly kind: "policy_bundle" | "credential_envelope";
  readonly path: string;
  readonly relayId: string | null;
  readonly apiVersion: string;
}

/** Classify and validate one parsed upload document. */
export function classifyUpload(value: unknown): UploadDocument {
  const apiVersion = isObject(value as never) ? get(value as never, "api_version") : undefined;
  if (apiVersion === POLICY_BUNDLE_API_VERSION) {
    const bundle = parsePolicyBundleValue(value);
    return { kind: "policy_bundle", path: LANE_ENDPOINTS.policyBundle, relayId: bundle.relayId, apiVersion };
  }
  if (apiVersion === RELAY_INTAKE_API_VERSION) {
    try {
      parseSealedCredential(value as import("@gray/json").Json);
    } catch {
      throw new RelayKitError("invalid_envelope");
    }
    return { kind: "credential_envelope", path: LANE_ENDPOINTS.credentials, relayId: null, apiVersion };
  }
  throw new RelayKitError("unsupported_document", "the file is neither a policy bundle nor a sealed credential envelope");
}

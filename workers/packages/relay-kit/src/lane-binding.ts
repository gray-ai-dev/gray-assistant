/**
 * Which dstack instance a lane origin must be (design gap 23, plan S12): its app id and its key
 * provider. The compose hash and OS image say which build runs; these two say whose instance it is.
 * Without them an instance of another dstack app, or one that took its keys from another KMS, would
 * receive credentials as long as its compose is in the release list.
 *
 * Both values come from pre-`system-ready` RTMR3 runtime events that `@gray/lane-verify` reports once
 * the event log replayed to the quote: `app-id` (20 bytes) and `key-provider` (dstack's
 * `{"name":"kms","id":<hex>}`, where `id` is the KMS root CA public key — on Phala, the node KMS's
 * `ca_pubkey`, the value the deploy tooling pins as `key_provider_id`).
 */
import type { ReportCheck } from "./verified-report.ts";

/** The key-provider name dstack 0.6 writes for a KMS (`KeyProviderInfo::new("kms", …)`). */
export const KMS_KEY_PROVIDER_NAME = "kms";

/** A dstack app id: 20 bytes as 40 lower-case hex digits (the `app-id` event payload). */
export const APP_ID_PATTERN = /^[0-9a-f]{40}$/;

/**
 * The node KMS's `ca_pubkey`: a P-256 SubjectPublicKeyInfo, 91 bytes as 182 lower-case hex digits
 * (the same rule `deploy/tee/app-compose.mjs` applies to `--kms-ca-pubkey`).
 */
export const KMS_CA_PUBKEY_PATTERN = /^3059301306072a8648ce3d020106082a8648ce3d03010703420004[0-9a-f]{128}$/;

/** What one lane origin must be. */
export interface LaneBinding {
  /** The dstack app id, 40 lower-case hex. */
  readonly appId: string;
  /** The KMS root CA public key the instance's key-provider event must name, 182 lower-case hex. */
  readonly kmsCaPubkey: string;
}

/**
 * Whether `value` is a binding with both members in their exact shape. It takes `unknown` because
 * JavaScript callers (the e2e harness, a daemon host) can pass nothing at all; that is a refusal,
 * never a crash or an unchecked attestation.
 */
export function isLaneBinding(value: unknown): value is LaneBinding {
  if (typeof value !== "object" || value === null) return false;
  const { appId, kmsCaPubkey } = value as { appId?: unknown; kmsCaPubkey?: unknown };
  return typeof appId === "string" && typeof kmsCaPubkey === "string" && APP_ID_PATTERN.test(appId) && KMS_CA_PUBKEY_PATTERN.test(kmsCaPubkey);
}

/** The instance identity a verification established; every member is null when nothing bound it. */
export interface MeasuredInstance {
  readonly appId: string | null;
  readonly keyProviderPayload: string | null;
  readonly keyProvider: { readonly name: string; readonly id: string } | null;
}

/**
 * The two checks, `app_id` and `key_provider`, in the transcript's shape. Deterministic in the event
 * log and the expectation, so a saved record's lines can be recomputed and compared.
 */
export function laneBindingChecks(measured: MeasuredInstance, expected: LaneBinding): readonly ReportCheck[] {
  return [appIdCheck(measured, expected), keyProviderCheck(measured, expected)];
}

function appIdCheck(measured: MeasuredInstance, expected: LaneBinding): ReportCheck {
  if (measured.appId === null) {
    return { id: "app_id", status: "fail", detail: "the quote-bound event log carries no pre-system-ready app-id event" };
  }
  if (measured.appId !== expected.appId) {
    return { id: "app_id", status: "fail", detail: `app-id ${measured.appId} is not the expected ${expected.appId}` };
  }
  return { id: "app_id", status: "pass", detail: `app-id ${measured.appId}` };
}

function keyProviderCheck(measured: MeasuredInstance, expected: LaneBinding): ReportCheck {
  if (measured.keyProviderPayload === null) {
    return { id: "key_provider", status: "fail", detail: "the quote-bound event log carries no pre-system-ready key-provider event" };
  }
  const provider = measured.keyProvider;
  if (provider === null) {
    return { id: "key_provider", status: "fail", detail: "the key-provider event payload is not dstack's {name, id} JSON" };
  }
  if (provider.name !== KMS_KEY_PROVIDER_NAME) {
    return { id: "key_provider", status: "fail", detail: `the key provider is ${JSON.stringify(provider.name)}, not "${KMS_KEY_PROVIDER_NAME}"` };
  }
  if (provider.id !== expected.kmsCaPubkey) {
    return { id: "key_provider", status: "fail", detail: `the KMS CA public key ${provider.id} is not the expected ${expected.kmsCaPubkey}` };
  }
  return { id: "key_provider", status: "pass", detail: `kms ${provider.id}` };
}

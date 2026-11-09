/**
 * `gray-assistant policy test --bundle <signed bundle> --fixtures <jsonl>`: run a relay's module through
 * the TEE's own engine and budgets, one fixture per line, and print what the receipt would say.
 *
 * The run is the same `preparePolicy` + `runPolicy` pair the gateway calls: the module's upload
 * validation, its declared memory maximum, the per-protocol input cap and the fuel formula
 * `base + per_kib × ceil(input_bytes / 1024)`. The fuel figure printed beside each answer is the
 * interpreter's own `last_fuel_consumed` for that exact input and budget (a second fresh instance,
 * because `runPolicy` deliberately does not expose engine internals).
 *
 * The receipt-shaped event is `@gray/relay-policy`'s `policyOutcomeEvent`: `relay_policy.applied`
 * for an allow (with template ids, positions and text hashes), `relay_policy.refused` for a block.
 * No template text is printed, and no fixture body is echoed in an error.
 */
import { readFileText } from "./files.ts";
import { RelayKitError } from "../errors.ts";
import { parseStrict, toJsonString, type Json, type JsonObject } from "@gray/json";
import { isLaneProtocol, type LaneProtocol } from "@gray/lane";
import {
  buildPolicyInput,
  memoryBytesOf,
  policyFuel,
  policyOutcomeEvent,
  preparePolicy,
  runPolicy,
  type PreparedPolicy,
} from "@gray/relay-policy";
import { parsePolicyBundleValue, verifyPolicyBundleDocument, type PolicyBundleDocument } from "../policy-bundle.ts";

/** The largest fixtures file and fixture body this command reads. */
export const MAX_FIXTURES_BYTES = 64 * 1024 * 1024;
/** The most fixtures one run accepts; a policy test is a spot check, not a benchmark. */
export const MAX_FIXTURES = 10_000;

/** One fixture line, already validated. */
export interface PolicyFixture {
  readonly line: number;
  readonly name: string;
  readonly protocol: LaneProtocol;
  readonly model: string;
  readonly body: Uint8Array;
}

/** The outcome of one fixture after the sandbox and the receipt builder saw it. */
export interface PolicyFixtureResult {
  readonly fixture: PolicyFixture;
  readonly outcome: "allow" | "block";
  readonly reasonCode: string | null;
  readonly appends: number;
  readonly fuelUsed: bigint;
  readonly fuelCap: bigint;
  readonly cause: string | null;
  readonly event: JsonObject;
}

export interface PolicyTestResult {
  readonly relayId: string;
  readonly version: bigint;
  readonly moduleSha256: string;
  readonly fixtures: readonly PolicyFixtureResult[];
}

function bodyBytes(value: Json): Uint8Array {
  return new TextEncoder().encode(toJsonString(value));
}

/** Parse one JSONL fixture file. A malformed line is a refusal naming its line, never the body. */
export function parsePolicyFixtures(text: string): readonly PolicyFixture[] {
  const fixtures: PolicyFixture[] = [];
  const lines = text.split(/\r?\n/u);
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index] as string;
    if (line.trim() === "") continue;
    if (fixtures.length >= MAX_FIXTURES) throw new RelayKitError("usage", `the fixtures file has more than ${MAX_FIXTURES} lines`);
    let value: unknown;
    try {
      // serde_json's reader: an integer body stays an integer (`bigint`), so `toJsonString` writes
      // the same bytes a customer's body would, not `1.0` for `1`.
      value = parseStrict(line);
    } catch {
      throw new RelayKitError("usage", `fixtures line ${index + 1} is not JSON`);
    }
    if (typeof value !== "object" || value === null || Array.isArray(value)) {
      throw new RelayKitError("usage", `fixtures line ${index + 1} is not an object`);
    }
    const record = value as Record<string, unknown>;
    const protocol = record.protocol;
    if (typeof protocol !== "string" || !isLaneProtocol(protocol)) {
      throw new RelayKitError("usage", `fixtures line ${index + 1}: protocol`);
    }
    if (record.model !== undefined && typeof record.model !== "string") throw new RelayKitError("usage", `fixtures line ${index + 1}: model`);
    if (record.name !== undefined && typeof record.name !== "string") throw new RelayKitError("usage", `fixtures line ${index + 1}: name`);
    const hasBody = Object.prototype.hasOwnProperty.call(record, "body");
    const hasRaw = Object.prototype.hasOwnProperty.call(record, "body_raw");
    if (hasBody === hasRaw) throw new RelayKitError("usage", `fixtures line ${index + 1}: exactly one of body or body_raw`);
    let body: Uint8Array;
    if (hasRaw) {
      if (typeof record.body_raw !== "string") throw new RelayKitError("usage", `fixtures line ${index + 1}: body_raw`);
      body = new TextEncoder().encode(record.body_raw);
    } else {
      body = bodyBytes(record.body as Json);
    }
    fixtures.push({
      line: index + 1,
      name: typeof record.name === "string" && record.name !== "" ? record.name : `line-${index + 1}`,
      protocol,
      model: typeof record.model === "string" ? record.model : "",
      body,
    });
  }
  if (fixtures.length === 0) throw new RelayKitError("usage", "the fixtures file has no fixtures");
  return fixtures;
}

/** Run every fixture against one prepared policy. */
export function runPolicyFixtures(policy: PreparedPolicy, fixtures: readonly PolicyFixture[]): readonly PolicyFixtureResult[] {
  const results: PolicyFixtureResult[] = [];
  for (const fixture of fixtures) {
    const request = { protocol: fixture.protocol, model: fixture.model, body: fixture.body };
    const result = runPolicy(policy, request);
    // A second fresh instance with the same bytes and budget: the ABI's own fuel accounting is the
    // only place the number exists, and `runPolicy` keeps the engine internal on purpose.
    const input = buildPolicyInput(request, policy.maxInputBytes[fixture.protocol] ?? 0);
    let fuelUsed = 0n;
    let fuelCap = 0n;
    if (input.ok) {
      fuelCap = policyFuel(input.bytes.length, policy);
      if (fuelCap > 0n) {
        const answer = policy.session.evaluate(input.bytes, {
          fuel: fuelCap,
          maxMemoryBytes: memoryBytesOf(policy.session),
          maxOutputBytes: policy.maxOutputBytes,
          stackSlots: policy.maxStackSlots,
        });
        if (answer.ok) fuelUsed = answer.fuelConsumed;
      }
    }
    const decision = result.outcome;
    results.push({
      fixture,
      outcome: decision.decision,
      reasonCode: decision.decision === "block" ? decision.reasonCode : null,
      appends: decision.decision === "allow" ? decision.appends.length : 0,
      fuelUsed,
      fuelCap,
      cause: result.cause,
      event: policyOutcomeEvent(policy, result),
    });
  }
  return results;
}

/**
 * Load and verify a signed bundle, then run the fixtures. `--public-key` is the relay's registered
 * key; without it the run is an unverified local check (the CLI says so). The TEE never runs an
 * unverified bundle, so a relay that wants "exactly as the TEE does" passes its key.
 */
export function loadPolicyBundle(path: string): PolicyBundleDocument {
  const text = readFileText(path, "policy bundle", 8 * 1024 * 1024);
  let value: unknown;
  try {
    value = parseStrict(text);
  } catch {
    throw new RelayKitError("invalid_policy_bundle", "the policy bundle is not JSON");
  }
  return parsePolicyBundleValue(value);
}

/** Verify a parsed bundle against the relay's registered key (the TEE's own check). */
export async function verifyPolicyBundleFile(bundle: PolicyBundleDocument, publicKey: Uint8Array): Promise<void> {
  const verified = await verifyPolicyBundleDocument(bundle, publicKey);
  if (!verified.ok) throw new RelayKitError("invalid_policy_bundle", verified.code);
}

/** Prepare and run. The interpreter must already be installed (the CLI calls `initWorkspaceInterpreter`). */
export function testPolicy(bundle: PolicyBundleDocument, fixtures: readonly PolicyFixture[]): PolicyTestResult {
  const prepared = preparePolicy({ relayId: bundle.relayId, version: bundle.version, moduleBytes: bundle.moduleBytes, templates: bundle.templates });
  if (!prepared.ok) throw new RelayKitError("invalid_policy_bundle", `${prepared.code}: ${prepared.detail}`);
  return {
    relayId: prepared.policy.relayId,
    version: prepared.policy.version,
    moduleSha256: prepared.policy.moduleSha256,
    fixtures: runPolicyFixtures(prepared.policy, fixtures),
  };
}

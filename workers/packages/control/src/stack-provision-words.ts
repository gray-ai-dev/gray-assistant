/**
 * The relay-stack provisioner's closed word lists (docs/relay-stack-provisioner.md), re-exported by stack-provision.ts.
 * This file imports nothing, so the console's contract (workers/console/src/lane-stack/provision-contract.ts) and the
 * frontend's tests that read the contract take it without the workers/ workspace's dependencies, as
 * packages/lane-wire/src/stack-health.ts is for the health contract.
 */

/**
 * `rollout` (docs/design/relay-zero-downtime.md): a relay-signed image rollout or rollback, make before break: a second
 * instance of the relay's app boots the image, is sealed and serves, then the first drains and goes. `upgrade`
 * (docs/design/relay-release-zero-downtime.md): the same, onto the newest Gray release the relay accepted, queued by Gray
 * itself; the second instance gets the new release by a compose update of that instance before it boots for real.
 */
export const PROVISION_KINDS = ["deploy", "restart", "delete", "rollout", "upgrade"] as const;
export type ProvisionKind = (typeof PROVISION_KINDS)[number];

// ------------------------------------------------------------------------------------------------- operations (P5)

/** Each kind's steps, in the order the provisioner runs them; the panel shows "step N of M" from this list. */
export const PROVISION_STEPS = {
  deploy: ["check", "provision", "publish", "create", "watch"],
  restart: ["check", "restart", "watch"],
  delete: ["check", "unbind", "remove_vm", "unpublish"],
  // docs/design/relay-zero-downtime.md: a second instance of the relay's app (replicate, then its boot watched, the old
  // VM serving meanwhile), the deployment moved to it (shift), the old VM's requests finishing (drain), the old VM gone.
  rollout: ["check", "replicate", "watch", "shift", "drain", "remove_old"],
  // docs/design/relay-release-zero-downtime.md: as a rollout, the replica held (no value in its env) until `update` gives
  // that instance the new release's compose and its own env.
  upgrade: ["check", "replicate", "update", "watch", "shift", "drain", "remove_old"],
} as const satisfies Record<ProvisionKind, readonly string[]>;
/**
 * A phase-2 Deploy (docs/design/relay-no-always-on-host.md 3.2, 13.11 P5a-2): before the app is provisioned, `contract`
 * puts the relay's own contract on Base (deployed through the CREATE2 proxy, registered on Phala's DstackKms, the
 * guardian's pairing approvals submitted), whose address is the app id. A deploy queued for such a relay counts these.
 */
export const PHASE2_DEPLOY_STEPS = ["check", "contract", "provision", "publish", "create", "watch"] as const;
/**
 * P7 (docs/design/relay-no-always-on-host.md 13.4): a phase-2 VM's image rollout first waits for `copies`, Gray's copy of
 * the vault sealed for the designated image and of the boot box at the receipt's version, so the second instance can
 * open them; its Gray release move first waits for `awaiting_effective`, the release's compose hash effective on the
 * relay's contract, so the second instance's keys are released.
 */
export const PHASE2_ROLLOUT_STEPS = ["check", "copies", "replicate", "watch", "shift", "drain", "remove_old"] as const;
export const PHASE2_UPGRADE_STEPS = ["check", "awaiting_effective", "replicate", "update", "watch", "shift", "drain", "remove_old"] as const;
export type ProvisionStep =
  | (typeof PROVISION_STEPS)[ProvisionKind][number]
  | (typeof PHASE2_DEPLOY_STEPS)[number]
  | (typeof PHASE2_ROLLOUT_STEPS)[number]
  | (typeof PHASE2_UPGRADE_STEPS)[number];

/** The steps an operation of `kind` counts: a phase-2 Deploy's include `contract`, a rollout's `copies`, an upgrade's `awaiting_effective`. */
export function provisionStepsOf(kind: ProvisionKind, phase2: boolean): readonly string[] {
  if (!phase2) return PROVISION_STEPS[kind];
  return kind === "deploy" ? PHASE2_DEPLOY_STEPS : kind === "rollout" ? PHASE2_ROLLOUT_STEPS : kind === "upgrade" ? PHASE2_UPGRADE_STEPS : PROVISION_STEPS[kind];
}

/** Every step of every list, once: what a table of the steps' words must cover. */
export const ALL_PROVISION_STEPS: readonly ProvisionStep[] = [
  ...new Set<ProvisionStep>([...Object.values(PROVISION_STEPS).flat(), ...PHASE2_DEPLOY_STEPS, ...PHASE2_ROLLOUT_STEPS, ...PHASE2_UPGRADE_STEPS]),
];

/**
 * The list an operation's `step_index` is counted on, from the count it keeps (`step_count`): a kind's two lists differ
 * in length wherever they differ at all. What shows "step N of M" names its steps from this list, never from the kind's
 * phase-1 list alone.
 */
export function provisionStepsCounted(op: { readonly kind: ProvisionKind; readonly step_count: number }): readonly string[] {
  const phase2 = provisionStepsOf(op.kind, true);
  return op.step_count === phase2.length ? phase2 : provisionStepsOf(op.kind, false);
}

/**
 * Where `step` puts an operation as it starts: the list the operation counts on from here and the step's place in it
 * (from 1), or null when `step` is no step of the operation. The phase-2 list is the one the operation counted at its
 * request, or, when the relay became phase 2 between the request and the plan, the one its first phase-2 step (a
 * Deploy's `contract`, a rollout's `copies`, an upgrade's `awaiting_effective`) brings.
 */
export function provisionPlaceOf(op: { readonly kind: ProvisionKind; readonly step_count: number }, step: string): { readonly steps: readonly string[]; readonly index: number } | null {
  const phase1 = provisionStepsOf(op.kind, false);
  const phase2 = provisionStepsOf(op.kind, true);
  const steps = op.step_count === phase2.length || (!phase1.includes(step) && phase2.includes(step)) ? phase2 : phase1;
  const at = steps.indexOf(step);
  return at < 0 ? null : { steps, index: at + 1 };
}

/**
 * Steps no list has any more, in the words they had. An operation from before keeps such a step as its place (`step`),
 * and what names a step in words reads these after its own table, so an old operation never shows a step's identifier.
 * 2026-11-06: `dns` (a Deploy's) and `remove_dns` (a Delete's) went when the provisioner stopped writing DNS records.
 */
export const RETIRED_PROVISION_STEP_WORDS = {
  dns: "writing the lane's DNS records",
  remove_dns: "removing the DNS records",
} as const satisfies Readonly<Record<string, string>>;

/**
 * Why Gray does not move a relay's running VM to the release a Deploy would boot now (docs/design/relay-release-zero-
 * downtime.md section 2), as the panel's `release.move.blocked` names it:
 *
 * - `moves_off`: Gray has not turned release moves on (LANE_STACK_RELEASE_MOVES, or the rollout gate and the entry);
 * - `kit_below_rollout`: the relay's gray-assistant is below the rollout gate's kit (it would not seal a second instance);
 * - `not_running`: the VM is not running (failed, or Gray has no instance id for it);
 * - `busy`: an operation is queued or running;
 * - `not_outbound`, `key_per_app`, `os_image`, `kms`: the release is not one an instance of this app can take (a public
 *   name, one bridge key id per app, another OS image, another KMS); a Delete and Deploy boots it;
 * - `kit_outdated`, `relay_incomplete`: as for a Deploy;
 * - `retry_wait`: a move to it failed; Gray tries again at `retry_ms`.
 */
export const RELEASE_MOVE_BLOCKS = [
  "moves_off",
  "kit_below_rollout",
  "not_running",
  "busy",
  "not_outbound",
  "key_per_app",
  "os_image",
  "kms",
  "kit_outdated",
  "relay_incomplete",
  "retry_wait",
] as const;
export type ReleaseMoveBlock = (typeof RELEASE_MOVE_BLOCKS)[number];

export const PROVISION_OP_STATES = ["queued", "running", "succeeded", "failed"] as const;
export type ProvisionOpState = (typeof PROVISION_OP_STATES)[number];

/** A relay's deployment as the panel shows it (lane_stack_deployments.state). */
export const DEPLOYMENT_STATES = ["none", "deploying", "running", "failed", "restarting", "deleting", "deleted"] as const;
export type DeploymentState = (typeof DEPLOYMENT_STATES)[number];

/**
 * Where one encrypted env value comes from (P4). The provisioner fills every name of the profile's `allowed_envs` from
 * exactly one of these; a literal is for a public value the profile fixes (a bridge URL), never a secret.
 * - `bridge_seed`: the VM's bridge key seed, made inside the create step and stored nowhere (P2);
 * - `gray_registry`, `gray_registry_username`, `gray_registry_password`: Gray's image-pull credential (the
 *   provisioner's vars and its one registry secret, S8a), named only by the profile of a release on the earlier
 *   private lane image; a release on the public ghcr.io/gray-ai-dev/gray-lane maps the three names to empty literals;
 * - `relay_id`, `relay_token_url`, `relay_registry`, `relay_public_key`: the relay's record and its lane record's
 *   signing key (lifecycle §3.2: the relay's identity comes at boot);
 * - `lane_hostname`, `lane_origin`, `lane_key_id`: the deployment's own values, from the profile's templates.
 */
export const PROVISION_ENV_SOURCES = [
  "bridge_seed",
  "gray_registry",
  "gray_registry_username",
  "gray_registry_password",
  "relay_id",
  "relay_token_url",
  "relay_registry",
  "relay_public_key",
  "lane_hostname",
  "lane_origin",
  "lane_key_id",
] as const;
export type ProvisionEnvSource = (typeof PROVISION_ENV_SOURCES)[number];
export type ProvisionEnvValue = ProvisionEnvSource | { readonly literal: string };

/**
 * The boot timeline's closed words, in the order a good boot reaches them. The provisioner writes the first two itself;
 * the serial console gives the rest: the kernel's first line, the measured pre-launch's fixed status lines
 * (`gray-prelaunch: <label>`, deploy/tee/pre-launch.stack.sh), dstack's compose service's container lines, and the
 * lane's /healthz answering (`serving`). A failure is `prelaunch_failed`, `compose_failed` or `boot_timed_out`.
 * `token_service_waiting` is the provisioner's own: the relay's token service did not answer, and the VM is restarted
 * after a wait (P8a); it opens the next boot's timeline, its `step` the attempt (`2/4`).
 */
export const BOOT_EVENTS = [
  "requested",
  "vm_created",
  "kernel_started",
  "prelaunch_cert_dir",
  "prelaunch_tmpfs",
  "prelaunch_bridges_closed",
  "prelaunch_gray_images",
  "prelaunch_challenge",
  "prelaunch_quote",
  "prelaunch_token",
  "prelaunch_registry_login",
  "prelaunch_relay_image",
  "prelaunch_no_volume",
  "prelaunch_credential_deleted",
  "prelaunch_sealed",
  "prelaunch_identity",
  "prelaunch_image_signature",
  "prelaunch_image_slot",
  "prelaunch_image_measured",
  "prelaunch_token_retry",
  "prelaunch_token_held",
  // P2d (docs/design/relay-no-always-on-host.md 13.11): a phase-2 boot opens the sealed boot box instead of asking a token
  // service, or runs the empty slot (its reason in `step`).
  "prelaunch_boot_box_retry",
  "prelaunch_boot_box",
  "prelaunch_designation_signature",
  "prelaunch_no_boot_box",
  "prelaunch_empty_slot",
  // Review 1109b design #2: the designated image's login or pull retried, or an image the boot cannot run (the empty
  // slot, waiting for the relay's repair; the reason in `step`).
  "prelaunch_relay_image_retry",
  "prelaunch_relay_image_unusable",
  "prelaunch_other",
  "egress_started",
  "acme_started",
  "acme_exited",
  "lane_started",
  "isolation_check_started",
  "isolation_check_exited",
  "relay_started",
  "compose_finished",
  "serving",
  "prelaunch_failed",
  "compose_failed",
  "boot_timed_out",
  "token_service_waiting",
] as const;
export type BootEvent = (typeof BOOT_EVENTS)[number];

/**
 * Whose side a failed boot is on, and so what the relay can do about it (P9). `token_service`: the relay's token
 * service did not answer; `token_refused`: it answered with a refusal, whose code (TOKEN_SERVICE_CODES) the boot event
 * carries and whose words (`TOKEN_SERVICE_CODE_WORDS`) say whose side that one is on.
 */
export const BOOT_FAILURE_CLASSES = ["token_service", "token_refused", "relay_registry", "relay_image", "gray_registry", "gray_platform", "timeout"] as const;
export type BootFailureClass = (typeof BOOT_FAILURE_CLASSES)[number];

/**
 * The relay's token service's refusal codes (relay-kit `PULL_TOKEN_REFUSALS`, whose test holds the two lists equal):
 * what a refusal answers as `{"error": "<code>"}`, what the measured pre-launch prints on the serial console when it
 * reads one (`gray-prelaunch: pull-token service held the boot (<code>), retrying` for a 5xx or 429 it waits out,
 * `gray-prelaunch: FAILED: the pull-token request (<code>)` for any other), and what gray-assistant's agent status reports
 * as its latest (`boot`). A code outside the list is read as `other`, its text dropped.
 */
export const TOKEN_SERVICE_CODES = [
  "method_not_allowed",
  "request_too_large",
  "request_invalid",
  "spki_invalid",
  "challenge_capacity",
  "registry_credential_expired",
  "relay_image_unlisted",
  "verifier_busy",
  "nonce_unknown",
  "nonce_used",
  "nonce_expired",
  "quote_invalid",
  "tee_not_tdx",
  "tcb_not_up_to_date",
  "event_log_invalid",
  "rtmr3_mismatch",
  "event_log_after_system_ready",
  "stack_identity_missing",
  "stack_identity_invalid",
  "stack_identity_mismatch",
  "report_data_mismatch",
  "compose_hash_mismatch",
  "release_list_unavailable",
  "compose_not_listed",
  "release_rejected",
  "release_not_accepted",
  "os_image_missing",
  "os_image_not_listed",
  "os_image_rejected",
  "os_image_dev",
  "os_image_unverified",
  "os_image_not_accepted",
  "os_image_retiring",
  "os_image_measurements",
  "app_id_mismatch",
  "key_provider_mismatch",
  "release_not_stack",
  "pre_launch_not_pinned",
  "app_compose_refused",
  "issue_record_failed",
] as const;
export type TokenServiceCode = (typeof TOKEN_SERVICE_CODES)[number];

/**
 * Phase 2's release notices (docs/design/relay-no-always-on-host.md 3.2 "How the relay learns of a proposal", 13.11
 * P5b-2): a Gray release proposed on the relay's contract, a reminder two days before it takes effect while it is still undecided (for a wait of 3 days or more), and the
 * release taking effect, and a day before the release's traffic window closes while the VM still serves an older one
 * (`relay_release_traffic`, @gray/control release-traffic.ts). Each is told once per release (lane_stack_relay_releases), not an open/resolved condition.
 */
export const RELAY_RELEASE_NOTICE_KINDS = ["relay_release_proposed", "relay_release_reminder", "relay_release_effective", "relay_release_traffic"] as const;
export type RelayReleaseNoticeKind = (typeof RELAY_RELEASE_NOTICE_KINDS)[number];

/**
 * What a relay is told about by e-mail and webhook (lifecycle §3.7): a failed boot (the token service unreachable is
 * its `token_service` class), its registry token near its end (only once gray-assistant reports it), Gray's release list
 * stale, a release waiting for the relay, a container crash loop, account-health problems (S46's states), and the VM's
 * credential lease past its renewal (S45, the credentials list's `lease_expiring`), most of its calls failing for a few
 * minutes (`relay_failing`, its container's own failures included), and a non-compliant change: the relay
 * taken out of routing (`relay_ejected`), or the change recorded with the relay left routing (`relay_violation`).
 */
export const RELAY_ALERT_KINDS = [
  "boot_failed",
  "registry_token_expiring",
  "release_list_stale",
  "release_pending",
  "container_crash_loop",
  "account_health",
  "lease_expiring",
  "relay_failing",
  "relay_ejected",
  "relay_violation",
  ...RELAY_RELEASE_NOTICE_KINDS,
] as const;
/**
 * The kinds a relay cannot turn off (docs/design/relay-ejection.md): Gray took the relay out of routing for a
 * non-compliant change to a request or an answer, which only Gray's operators undo (`relay_ejected`), or, while the
 * console runs LANE_STACK_EJECTION=record, recorded such a change and left the relay routing (`relay_violation`).
 */
export const RELAY_ALERT_REQUIRED_KINDS = ["relay_ejected", "relay_violation"] as const satisfies readonly (typeof RELAY_ALERT_KINDS)[number][];
export type RelayAlertKind = (typeof RELAY_ALERT_KINDS)[number];
/**
 * What to do about the VM's lease past its renewal (`lease_expiring`), in the alert's e-mail and webhook; the panel's
 * Overview, Credentials and Alerts say the same (frontend relay-stack-health.ts, whose test holds the two together).
 */
export const LEASE_OVERDUE_FIX = "gray-assistant normally renews it well before then. Past it the VM serves no account. Run gray-assistant doctor on your relay's host.";
export const LEASE_EXPIRED_FIX = "The VM serves no account until gray-assistant renews it. Run gray-assistant doctor on your relay's host.";

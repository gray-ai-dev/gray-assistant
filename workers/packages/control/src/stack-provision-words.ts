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
 * What a relay is told about by e-mail and webhook (lifecycle §3.7): a failed boot (the token service unreachable is
 * its `token_service` class), its registry token near its end (only once gray-assistant reports it), Gray's release list
 * stale, a release waiting for the relay, a container crash loop, account-health problems (S46's states), and the VM's
 * credential lease past its renewal (S45, the credentials list's `lease_expiring`), and a non-compliant change: the relay
 * taken out of routing (`relay_ejected`), or the change recorded with the relay left routing (`relay_violation`).
 */
export const RELAY_ALERT_KINDS = ["boot_failed", "registry_token_expiring", "release_list_stale", "release_pending", "container_crash_loop", "account_health", "lease_expiring", "relay_ejected", "relay_violation"] as const;
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

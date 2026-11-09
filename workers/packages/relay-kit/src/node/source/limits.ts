/**
 * Bounds the source adapters share. They are constants rather than `@gray/config` rows because
 * these limits protect one parse (a response, a file) against unbounded input; they are not
 * deployment tunables. The values that an operator may need to change (timeouts and response
 * caps) are members of the source config schema with a default and a bound.
 */
import { MAX_ACCOUNTS_PER_BUNDLE, MAX_CREDENTIAL_LENGTH } from "@gray/relay-connector";

/** The largest `accounts.json` this package reads (the sealing CLI uses the same cap). */
export const MAX_SOURCE_FILE_BYTES = 16 * 1024 * 1024;

/** The largest token file: a management key or bearer token, one line. */
export const MAX_SOURCE_TOKEN_BYTES = 8 * 1024;

/** The largest URL or path in the config. */
export const MAX_URL_LENGTH = 2048;
export const MAX_PATH_LENGTH = 4096;

/** The default per-request deadline and its bounds, in milliseconds. */
export const DEFAULT_REQUEST_TIMEOUT_MS = 10_000;
export const MIN_REQUEST_TIMEOUT_MS = 100;
export const MAX_REQUEST_TIMEOUT_MS = 120_000;

/** The detection probe's deadline and its bounds. */
export const DEFAULT_PROBE_TIMEOUT_MS = 2_000;
export const MIN_PROBE_TIMEOUT_MS = 100;
export const MAX_PROBE_TIMEOUT_MS = 30_000;

/** The largest response body the source contract may return. */
export const DEFAULT_MAX_RESPONSE_BYTES = 8 * 1024 * 1024;
export const MIN_MAX_RESPONSE_BYTES = 4 * 1024;
export const MAX_MAX_RESPONSE_BYTES = 16 * 1024 * 1024;

/** The largest credential body; one credential is at most `MAX_CREDENTIAL_LENGTH` characters. */
export const DEFAULT_MAX_CREDENTIAL_BYTES = 32 * 1024;
export const MIN_MAX_CREDENTIAL_BYTES = 1024;
export const MAX_MAX_CREDENTIAL_BYTES = 64 * 1024;

/** The most accounts one snapshot may hold (the relay connector's own bundle limit). */
export const MAX_SOURCE_ACCOUNTS = MAX_ACCOUNTS_PER_BUNDLE;

/** The largest credential a source may hand back. */
export const MAX_SOURCE_CREDENTIAL_LENGTH = MAX_CREDENTIAL_LENGTH;

/** A source id as the software writes it: printable ASCII, no controls, bounded. */
export const SOURCE_ID = /^[\u0020-\u007e]{1,256}$/;

/** An opaque change mark (the file adapter emits SHA-256 hex). */
export const CHANGE_MARK = /^[\u0021-\u007e]{1,256}$/;

/** A model id as the scheduler wire accepts it. */
export const MODEL_ID = /^[\u0021-\u007e]{1,256}$/;

/** A group or label the software exposes. */
export const SOURCE_TAG = /^[\u0020-\u007e]{1,128}$/;

/** A credential value: the connector's own class, before the vendor-specific check. */
export const PRINTABLE_CREDENTIAL = /^[\u0021-\u007e]+$/;

/** A u64, for timestamps a source may report. */
export const U64_MAX = 0xffff_ffff_ffff_ffffn;

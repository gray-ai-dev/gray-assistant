/**
 * Loading one or more saved verified reports: the file rules and the re-check every sealing or
 * upload command runs. The CLI's `--report`/`--reports` and a daemon's persisted reports use this
 * one implementation, so a command can never disagree with the daemon about a report's freshness,
 * origin or pinning.
 */
import { isObject, parseStrict, type Json } from "@gray/json";
import { RelayKitError } from "../errors.ts";
import { checkVerifiedReport, parseVerifiedReportValue, type CheckedVerifiedReport, type VerifiedReportFile } from "../verified-report.ts";
import { readFileText } from "./files.ts";

/** The largest saved report this tool will read (a dstack report with its event log fits below). */
export const MAX_REPORT_FILE_BYTES = 16 * 1024 * 1024;

/** The most reports one `--reports` list may name. */
export const MAX_REPORTS_IN_LIST = 64;

export interface ReportLoadOptions {
  /** The verifier's clock in Unix seconds. */
  readonly nowSecs: bigint;
  /** The greatest age accepted; the CLI's `--max-report-age`, default 3600 s. */
  readonly maxAgeSeconds: bigint;
  /** When given, every report must be from exactly this lane origin. */
  readonly origin?: string;
  /** Accept a record whose release list did not pin both measurements. */
  readonly acceptUnpinned?: boolean;
  /** S11b: the record's OS image must be production by the texts `attest` kept (sealing commands). */
  readonly requireProductionOsImage?: boolean;
}

/** Read and re-check one saved report. */
export function loadVerifiedReportFile(path: string, options: ReportLoadOptions): CheckedVerifiedReport {
  const text = readFileText(path, "verified report", MAX_REPORT_FILE_BYTES);
  let value: unknown;
  try {
    value = parseStrict(text);
  } catch {
    throw new RelayKitError("invalid_verified_report", "the file is not JSON");
  }
  return checkVerifiedReport(parseVerifiedReportValue(value), options);
}

/** Read and re-check a JSON array (or `{"reports":[…]}`) of saved reports. */
export function loadVerifiedReportList(path: string, options: ReportLoadOptions): readonly CheckedVerifiedReport[] {
  const text = readFileText(path, "reports list", MAX_REPORT_FILE_BYTES);
  let value: Json;
  try {
    value = parseStrict(text);
  } catch {
    throw new RelayKitError("invalid_verified_report", "the reports file is not JSON");
  }
  const entries = Array.isArray(value) ? value : isObject(value) && Array.isArray((value as { reports?: unknown }).reports) ? ((value as { reports: unknown[] }).reports as unknown[]) : null;
  if (entries === null || entries.length === 0) throw new RelayKitError("invalid_verified_report", "the reports file is not a non-empty array");
  if (entries.length > MAX_REPORTS_IN_LIST) throw new RelayKitError("invalid_verified_report", "the reports file has too many entries");
  const out: CheckedVerifiedReport[] = [];
  for (const entry of entries) out.push(checkVerifiedReport(parseVerifiedReportValue(entry as VerifiedReportFile), options));
  return out;
}

/** The two places reports come from: repeated paths and one list file. */
export interface ReportSelection {
  readonly paths: readonly string[];
  readonly listPath: string | null;
}

/**
 * Load the selection, run the same re-check on every entry and refuse two reports for one origin:
 * two envelopes for one replica would be ambiguous.
 */
export function loadVerifiedReports(selection: ReportSelection, options: ReportLoadOptions): readonly CheckedVerifiedReport[] {
  if (selection.paths.length === 0 && selection.listPath === null) throw new RelayKitError("usage", "missing --report");
  const checked = selection.paths.map((path) => loadVerifiedReportFile(path, options));
  if (selection.listPath !== null) checked.push(...loadVerifiedReportList(selection.listPath, options));
  const seen = new Set<string>();
  for (const report of checked) {
    if (seen.has(report.file.origin)) throw new RelayKitError("duplicate_replica", report.file.origin);
    seen.add(report.file.origin);
  }
  return checked;
}
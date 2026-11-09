/**
 * Which accounts serve the lane. The selection is an intersection: an account must match every
 * criterion that is present. Empty arrays mean "no restriction", so an empty `select` selects all.
 */
import type { Vendor } from "@gray/relay-connector";
import type { SourceAccount } from "../../source/types.ts";
import type { SourceSelection } from "./config-types.ts";

/** Whether an account with this vendor/tag/id passes the selection. */
export function selectedBy(
  selection: SourceSelection,
  account: { readonly sourceId: string; readonly vendor: Vendor; readonly tags?: readonly string[] },
): boolean {
  if (selection.vendors.length > 0 && !selection.vendors.includes(account.vendor)) return false;
  if (selection.ids.length > 0 && !selection.ids.includes(account.sourceId)) return false;
  if (selection.tags.length > 0) {
    const tags = account.tags ?? [];
    if (!selection.tags.some((tag) => tags.includes(tag))) return false;
  }
  return true;
}

/** Filter a snapshot, preserving the source's order. */
export function selectAccounts(selection: SourceSelection, accounts: readonly SourceAccount[]): SourceAccount[] {
  return accounts.filter((account) => selectedBy(selection, account));
}

/** Moves focus to a heading rendered by a design-system `Section` (`headingId`),
 *  e.g. a review step that just opened. Those headings are not tab stops, so the
 *  heading is made programmatically focusable first. */
export function focusHeading(id: string) {
  const heading = document.getElementById(id);
  if (!heading) return;
  heading.tabIndex = -1;
  heading.focus();
}

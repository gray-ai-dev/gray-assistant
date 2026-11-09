import { Tabs, type TabItem } from './Segmented';

/**
 * A section's own pages, as a band under the app bar: the section's name, then its pages as link `Tabs`, the current
 * one underlined. The app bar marks the section and this band the page, so a page of the section says where it is
 * at both levels, and the app bar's other sections stay one click away. The band spans the app bar's width and starts
 * on the brand's edge; the strip scrolls sideways when it is wider than its room (a phone, enlarged text), keeping the
 * current page in view. The page's own tabs, inside its column, stay a third level.
 */
export function SectionNav<T extends string>({ title, items, value }: {
  /** The section's name, which also names the `nav` landmark ("Provide models"). */
  title: string;
  /** The section's pages, each with its `href`. */
  items: readonly (TabItem<T> & { href: string })[];
  value: T;
}) {
  return <div className="ui-section-nav">
    <span className="ui-section-nav__title" aria-hidden="true">{title}</span>
    <Tabs aria-label={title} items={items} value={value} />
  </div>;
}

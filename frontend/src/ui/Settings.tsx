import type { HTMLAttributes, ReactNode } from 'react';
import { cx } from './cx';
import './settings.css';

/** A bordered list of settings, one row per child, separated by dividers.
 *  Children are `SettingsRow`s, `Switch`es, or any block that reads as a row
 *  (a confirmation form, a status line). `danger` marks destructive settings. */
export function SettingsList({ tone = 'default', className, children, ...rest }: HTMLAttributes<HTMLDivElement> & { tone?: 'default' | 'danger' }) {
  return <div className={cx('ui-settings', tone === 'danger' && 'ui-settings--danger', className)} {...rest}>{children}</div>;
}

/** One setting: its name and a short explanation at the start, its control at
 *  the end of the row (under the text on phones). Selects and text inputs in
 *  the control share one width, so the rows of a list line up. */
export function SettingsRow({ title, description, level = 3, details, children }: {
  title: ReactNode;
  description?: ReactNode;
  /** Heading level of the title (default 3, under a section's h2). */
  level?: 3 | 4;
  /** Full-width content under the title and control, e.g. a preview of what the current value does. */
  details?: ReactNode;
  /** The control: a select, a button, a small inline form. */
  children?: ReactNode;
}) {
  const Heading = `h${level}` as const;
  return <div className="ui-settings-row">
    <div className="ui-settings-row__text">
      <Heading className="ui-settings-row__title">{title}</Heading>
      {description != null && <p className="ui-settings-row__description">{description}</p>}
    </div>
    {children != null && <div className="ui-settings-row__control">{children}</div>}
    {details != null && details !== false && <div className="ui-settings-row__details">{details}</div>}
  </div>;
}

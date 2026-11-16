import { useId, type ReactNode } from 'react';
import { Check } from '../components/icons';
import { cx } from './cx';

export type OptionCard<T extends string> = {
  value: T;
  /** The option's name: the card's title and its link's accessible name. */
  title: string;
  /** What the option promises, one line under the title; the link's description. */
  promise: ReactNode;
  /** A few short facts, one a line. */
  facts?: readonly ReactNode[];
  /** Who the option is for, at the card's foot. */
  footer?: ReactNode;
  /** The page where this option's flow is. */
  href: string;
  /** A 16px icon on a tile before the title. */
  icon?: ReactNode;
  /** A short mark beside the title (a `Badge`): something the option gives, which other pages show too. */
  badge?: ReactNode;
};

/**
 * A choice between a few ways to do something, each a card that opens its own flow: a title, a short promise, a few
 * facts and who it is for, side by side so they compare at a glance (stacked once a card would be narrower than
 * 18rem). The card is the choice, as a tile is in a radio group, but each option is a page, so each is a link
 * (`aria-current="page"` on the chosen one, like link `Tabs`; a link needs no Base UI part): the title is the link, its
 * box stretched over the card, so the whole card takes the click while the link's name stays the title. Every card is
 * drawn alike, so none reads as the better choice; the chosen card has an ink edge and a filled check, the others an
 * empty ring.
 */
export function OptionCards<T extends string>({ items, value, 'aria-label': label }: {
  items: readonly OptionCard<T>[];
  /** The option of the page this is on. */
  value: T;
  /** Names the `nav` landmark ("What you connect"). */
  'aria-label': string;
}) {
  const id = useId();
  return <nav className="ui-option-cards" aria-label={label}>
    <ul className="ui-option-cards__list">
      {items.map(item => {
        const current = item.value === value, promise = `${id}-${item.value}`;
        return <li key={item.value} className={cx('ui-option-card', item.icon != null && 'ui-option-card--icon')} data-current={current || undefined}>
          <div className="ui-option-card__head">
            {item.icon && <span className="ui-option-card__icon" aria-hidden="true">{item.icon}</span>}
            <div className="ui-option-card__heading">
              <span className="ui-option-card__title">
                <a className="ui-option-card__link" href={item.href} aria-current={current ? 'page' : undefined} aria-describedby={promise}>{item.title}</a>
                {item.badge}
              </span>
              <p className="ui-option-card__promise" id={promise}>{item.promise}</p>
            </div>
            <span className="ui-option-card__mark" aria-hidden="true">{current && <Check size={12} weight="bold" />}</span>
          </div>
          {item.facts && item.facts.length > 0 && <ul className="ui-option-card__facts">
            {item.facts.map((fact, index) => <li key={index}>
              <span className="ui-option-card__bullet" aria-hidden="true"><span className="ui-option-card__dot" /></span>
              <span>{fact}</span>
            </li>)}
          </ul>}
          {item.footer != null && <p className="ui-option-card__footer">{item.footer}</p>}
        </li>;
      })}
    </ul>
  </nav>;
}

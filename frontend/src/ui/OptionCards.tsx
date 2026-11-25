import { useId, type ReactNode } from 'react';
import { RadioGroup } from '@cloudflare/kumo/primitives/radio-group';
import { Radio } from '@cloudflare/kumo/primitives/radio';
import { Check } from '../components/icons';
import { cx } from './cx';

export type OptionCard<T extends string> = {
  value: T;
  /** The option's name: the card's title and its link's (or radio's) accessible name. */
  title: string;
  /** What the option promises, one line under the title; the link's (or radio's) description. */
  promise: ReactNode;
  /** A few short facts, one a line. */
  facts?: readonly ReactNode[];
  /** Who the option is for, at the card's foot. */
  footer?: ReactNode;
  /** The page where this option's flow is (link mode only). */
  href?: string;
  /** A 16px icon on a tile before the title. */
  icon?: ReactNode;
  /** A short mark beside the title (a `Badge`): something the option gives, which other pages show too. */
  badge?: ReactNode;
  /** A page of the option's own at the card's foot, e.g. its guide: a link of its own above the card's, so it takes its click. */
  more?: { label: string; href: string };
};

type LinkMode<T extends string> = {
  /** Each option is a page: every card links to its `href`. */
  items: readonly (OptionCard<T> & { href: string })[];
  /** The option of the page this is on; none while nothing is chosen. */
  value?: T;
  onValueChange?: never;
  'aria-controls'?: never;
};

type SelectMode<T extends string> = {
  /** The options are chosen on this page: the cards are a radio group. */
  items: readonly (OptionCard<T> & { href?: never })[];
  /** The chosen option; null while nothing is chosen. */
  value: T | null;
  onValueChange: (value: T) => void;
  /** The id of the panel the choice shows, below the cards. */
  'aria-controls'?: string;
};

/**
 * A choice between a few ways to do something, each a card: a title, a short promise, a few facts and who it is for,
 * side by side so they compare at a glance (stacked once a card would be narrower than 18rem). The card is the choice,
 * as a tile is in a radio group. Two modes:
 * - link mode (`href` on every item): each option is a page, so each card is a link (`aria-current="page"` on the
 *   chosen one, like link `Tabs`), in a `nav`;
 * - select mode (`onValueChange`): the choice stays on the page and shows a panel below, so the cards are a Base UI
 *   radio group (`role="radiogroup"`, one tab stop, arrow keys between cards, Space to choose).
 * Either way the title is the control and its accessible name, its box stretched over the card, so the whole card
 * takes the click. Every card is drawn alike, so none reads as the better choice; the chosen card has an ink edge and
 * a filled check, the others an empty ring. With no `value` none is chosen: a choice not made yet.
 */
export function OptionCards<T extends string>(props: (LinkMode<T> | SelectMode<T>) & {
  /** Names the `nav` landmark or the radio group ("What you connect"). */
  'aria-label': string;
}) {
  const { items, value, 'aria-label': label } = props;
  const id = useId();
  const list = <ul className="ui-option-cards__list">
    {items.map(item => {
      const current = item.value === value, promise = `${id}-${item.value}`;
      return <li key={item.value} className={cx('ui-option-card', item.icon != null && 'ui-option-card--icon')} data-current={current || undefined}>
        <div className="ui-option-card__head">
          {item.icon && <span className="ui-option-card__icon" aria-hidden="true">{item.icon}</span>}
          <div className="ui-option-card__heading">
            <span className="ui-option-card__title">
              {props.onValueChange
                ? <Radio.Root className="ui-option-card__link ui-option-card__radio" value={item.value} aria-describedby={promise}>{item.title}</Radio.Root>
                : <a className="ui-option-card__link" href={item.href} aria-current={current ? 'page' : undefined} aria-describedby={promise}>{item.title}</a>}
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
        {(item.footer != null || item.more) && <p className="ui-option-card__footer">
          {item.footer != null && <span>{item.footer}</span>}
          {item.more && <a className="ui-link ui-option-card__more" href={item.more.href}>{item.more.label}</a>}
        </p>}
      </li>;
    })}
  </ul>;
  if (props.onValueChange) {
    const change = props.onValueChange;
    return <RadioGroup className="ui-option-cards" aria-label={label} aria-controls={props['aria-controls']} value={value ?? null} onValueChange={next => change(next as T)}>
      {list}
    </RadioGroup>;
  }
  return <nav className="ui-option-cards" aria-label={label}>{list}</nav>;
}

import { Children, type CSSProperties, type ElementType, type HTMLAttributes, type ReactNode, type Ref } from 'react';
import { ArrowLeft } from '../components/icons';
import { cx } from './cx';

type Gap = 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8;
type Box = Omit<HTMLAttributes<HTMLElement>, 'title'> & { as?: ElementType; className?: string; children?: ReactNode };

/** The page column under the app bar. `narrow` suits settings and forms. */
export function Page({ size = 'default', as: Tag = 'div', className, ...rest }: Box & { size?: 'default' | 'narrow' | 'wide' }) {
  return <Tag className={cx('ui-page', size !== 'default' && `ui-page--${size}`, className)} {...rest} />;
}

/** Page title, one-line description and page-level actions. */
export function PageHeader({ title, description, actions, back, className, children }: {
  title: ReactNode;
  description?: ReactNode;
  actions?: ReactNode;
  /** A "back to …" link above the title. */
  back?: { href: string; label: ReactNode };
  className?: string;
  /** Extra content under the description, e.g. badges. */
  children?: ReactNode;
}) {
  return <header className={cx('ui-page-header', className)}>
    <div className="ui-page-header__text">
      {back && <a className="ui-page-header__back" href={back.href}><ArrowLeft size={15} aria-hidden="true" />{back.label}</a>}
      <h1 className="ui-page-header__title">{title}</h1>
      {description && <p className="ui-page-header__description">{description}</p>}
      {children}
    </div>
    {actions && <div className="ui-page-header__actions">{actions}</div>}
  </header>;
}

type SectionHeaderProps = {
  title: ReactNode;
  description?: ReactNode;
  actions?: ReactNode;
  icon?: ReactNode;
  /** Heading level; defaults to 2. */
  level?: 2 | 3 | 4;
  /** `sm` uses the subsection size (18px) for groups inside a section. */
  size?: 'md' | 'sm';
  id?: string;
  /** Makes the heading a programmatic focus target (tabIndex -1), e.g. after a step changes. */
  headingRef?: Ref<HTMLHeadingElement>;
};

export function SectionHeader({ title, description, actions, icon, level = 2, size = 'md', id, headingRef }: SectionHeaderProps) {
  const Heading = `h${level}` as const;
  return <div className={cx('ui-section-header', size === 'sm' && 'ui-section-header--sm')}>
    <div className="ui-section-header__text">
      <Heading className="ui-section-header__title" id={id} ref={headingRef} tabIndex={headingRef ? -1 : undefined}>{icon}{title}</Heading>
      {description && <p className="ui-section-header__description">{description}</p>}
    </div>
    {actions && <div className="ui-section-header__actions">{actions}</div>}
  </div>;
}

/** A titled group of content. Sections stack with `Stack gap={8}`. */
export function Section({ title, description, actions, icon, level, size, headingId, headingRef, className, children, ...rest }: Omit<Box, 'as'> & Partial<Omit<SectionHeaderProps, 'id'>> & { headingId?: string }) {
  return <section className={cx('ui-section', className)} {...rest}>
    {title != null && <SectionHeader title={title} description={description} actions={actions} icon={icon} level={level} size={size} id={headingId} headingRef={headingRef} />}
    {children}
  </section>;
}

/** A bordered surface. With a title it gets a header bar; `flush` removes body
 *  padding for tables and code that bring their own. With nothing to show under its header it has no body. */
export function Panel({ title, description, actions, icon, level = 2, headingRef, flush, tone, as: Tag = 'section', className, children, ...rest }: Box & Partial<Omit<SectionHeaderProps, 'size' | 'id'>> & { flush?: boolean; tone?: 'default' | 'muted' }) {
  return <Tag className={cx('ui-panel', tone === 'muted' && 'ui-panel--muted', className)} {...rest}>
    {title != null && <SectionHeader title={title} description={description} actions={actions} icon={icon} level={level} size="sm" headingRef={headingRef} />}
    {(title == null || Children.toArray(children).length > 0) && <div className={cx('ui-panel__body', flush && 'ui-panel__body--flush')}>{children}</div>}
  </Tag>;
}

/** Vertical rhythm: children stacked with a gap from the spacing scale. */
export function Stack({ gap = 4, as: Tag = 'div', className, ...rest }: Box & { gap?: Gap }) {
  return <Tag className={cx('ui-stack', `ui-gap-${gap}`, className)} {...rest} />;
}

/** A row of items, centred on one line and wrapping when space runs out. Use
 *  it for every row of controls so their heights and centres line up. */
export function Inline({ gap = 3, align = 'center', justify = 'start', wrap = true, as: Tag = 'div', className, ...rest }: Box & {
  gap?: Gap;
  align?: 'center' | 'start' | 'end' | 'baseline' | 'stretch';
  justify?: 'start' | 'end' | 'between' | 'center';
  wrap?: boolean;
}) {
  return <Tag className={cx('ui-inline', `ui-gap-${gap}`, align !== 'center' && `ui-inline--align-${align}`, justify !== 'start' && `ui-inline--justify-${justify}`, !wrap && 'ui-inline--nowrap', className)} {...rest} />;
}

/** Lets one item in an `Inline` take the remaining width. `basis` is the width it keeps before the items after it wrap
 *  to the next line (a heading beside a control, read on a phone); without it, it shrinks to make room. */
export function Grow({ as: Tag = 'div', basis, className, style, ...rest }: Box & { basis?: string }) {
  return <Tag className={cx('ui-grow', className)} style={basis ? { ...style, flexBasis: basis } : style} {...rest} />;
}

/** Form fields in columns; collapses to one column on phones. `auto` fits as
 *  many 14rem columns as the width allows. */
export function FormGrid({ columns = 2, as: Tag = 'div', className, style, ...rest }: Box & { columns?: 1 | 2 | 3 | 4 | 'auto' }) {
  return <Tag className={cx('ui-form-grid', columns === 'auto' && 'ui-form-grid--auto', className)} style={columns === 'auto' ? style : { ...style, '--ui-columns': columns } as CSSProperties} {...rest} />;
}

/** Main content with a fixed-width side column (e.g. editor + settings). */
export function Split({ aside, asideWidth, className, children, ...rest }: Omit<Box, 'as'> & { aside: ReactNode; asideWidth?: string }) {
  return <div className={cx('ui-split', className)} style={asideWidth ? { '--ui-aside': asideWidth } as CSSProperties : undefined} {...rest}>
    <div className="ui-stack ui-gap-7">{children}</div>
    {aside}
  </div>;
}

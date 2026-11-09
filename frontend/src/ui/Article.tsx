import { lazy, Suspense, type ReactNode } from 'react';
import { Skeleton } from './Feedback';

// The renderer, its styles and its libraries load with the first article: a bundle that never shows one (the relay's
// own page, src/relay-ui) carries none of them.
const Content = lazy(() => import('./ArticleContent').then(module => ({ default: module.ArticleView })));

export type ArticleLang = 'en' | 'zh';

/** An image's address, and its version for the site's dark theme (shown while the site is dark, whatever the
 *  system's setting). */
export type ArticleImage = { src: string; dark?: string };

export type ArticleProps = {
  /** The text in Markdown (CommonMark and GitHub's tables); its `#` heading is the title. Undefined while it loads. */
  markdown?: string;
  /** The language the text is written in: the article's `lang`, and its typesetting (Chinese has its own faces, line
   *  height and measure). */
  lang: ArticleLang;
  /** A link above the title back to where the article is listed. */
  back?: { href: string; label: ReactNode };
  /** Controls at the end of that row, e.g. the language switch. */
  tools?: ReactNode;
  /** Where a link in the text goes on this site, or null to show its words without a link (a file the reader cannot
   *  open). Absolute http(s) addresses open in a new tab. */
  resolveLink?: (href: string) => string | null;
  /** An image's address on this site, with its dark theme's version if it has one; an image without one is left out. */
  resolveImage?: (src: string) => ArticleImage | undefined;
  /** A heading's own address, for the link beside it. Headings get GitHub's ids (`## Known limits` is `known-limits`). */
  headingHref?: (id: string) => string;
  /** The heading to scroll to once the text and its images are in place. */
  section?: string | null;
  /** The title's text, once it is on screen (for the document title). */
  onTitle?: (title: string) => void;
  /** Said to assistive technology while the text loads. */
  loadingLabel?: string;
};

/**
 * A long text for reading: a guide or an engineering post, rendered from Markdown by react-markdown with remark-gfm
 * and rehype-slug. The text sits at a reading measure; tables, code and figures take the column's full width and scroll
 * sideways inside their own frames when they need more.
 */
export function Article(props: ArticleProps) {
  return <Suspense fallback={<Skeleton lines={8} label={props.loadingLabel ?? 'Loading the article'} />}><Content {...props} /></Suspense>;
}

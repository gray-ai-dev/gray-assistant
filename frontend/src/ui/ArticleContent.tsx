import { useEffect, useMemo, useRef, useState, type CSSProperties, type ReactNode, type SyntheticEvent } from 'react';
import Markdown, { type Components, type ExtraProps } from 'react-markdown';
import rehypeSlug from 'rehype-slug';
import remarkGfm from 'remark-gfm';
import { ArrowLeft } from '../components/icons';
import type { ArticleImage, ArticleLang, ArticleProps } from './Article';
import { CodeBlock, type CodeLanguage } from './Code';
import { Table, TableBody, TableCell, TableHead, TableHeaderCell, TableRow } from './Data';
import { Skeleton } from './Feedback';
import { InlineCode } from './Text';
import './article.css';

type Node = NonNullable<ExtraProps['node']>;
type Child = Node['children'][number];

/** The words the article itself adds, in its language. */
const WORDS: Record<ArticleLang, { anchor: string; table: string }> = {
  en: { anchor: 'Link to this section', table: 'Table' },
  zh: { anchor: '本节链接', table: '表格' },
};

const LANGUAGES: readonly CodeLanguage[] = ['bash', 'javascript', 'python', 'json', 'toml'];

/** The text inside a node of the rendered tree (a code block's source, a header cell's words). */
function textOf(node: Child | Node): string {
  if (node.type === 'text') return node.value;
  return 'children' in node ? node.children.map(textOf).join('') : '';
}

function elements(node: Node | undefined, tagName: string): Node[] {
  const found: Node[] = [];
  const walk = (child: Child | Node) => {
    if (child.type !== 'element') return;
    if (child.tagName === tagName) found.push(child);
    child.children.forEach(walk);
  };
  if (node) walk(node);
  return found;
}

/** A figure at its natural width, never wider than the column; on a narrow screen it keeps a readable size and the
 *  frame scrolls sideways instead of shrinking it further. The caption is the image's alt text, shown: assistive
 *  technology reads it once, as the image's name. With a dark version, the site's theme picks which one shows (the
 *  other is display: none, so it is neither seen nor read). */
function Figure({ image, alt }: { image: ArticleImage; alt: string }) {
  const [natural, setNatural] = useState<number>();
  const style = natural ? { '--ui-article-figure-width': `${natural}px` } as CSSProperties : undefined;
  const onLoad = (event: SyntheticEvent<HTMLImageElement>) => { if (event.currentTarget.naturalWidth) setNatural(event.currentTarget.naturalWidth); };
  return <figure className="ui-article__figure">
    <div className={image.dark ? 'ui-article__figure-frame ui-article__figure-frame--themed' : 'ui-article__figure-frame'}>
      <img className={image.dark ? 'ui-article__figure-light' : undefined} src={image.src} alt={alt} decoding="async" onLoad={onLoad} style={style} />
      {image.dark && <img className="ui-article__figure-dark" src={image.dark} alt={alt} decoding="async" onLoad={onLoad} style={style} />}
    </div>
    {alt && <figcaption aria-hidden="true">{alt}</figcaption>}
  </figure>;
}

/** The article's page column: the row above the title (`back`, `tools`), then the text, or its shape while it loads. */
export function ArticleView({ back, tools, markdown, loadingLabel = 'Loading the article', ...content }: ArticleProps) {
  return <div className="ui-article-frame">
    {(back || tools) && <div className="ui-article__bar">
      {back && <a className="ui-article__back" href={back.href}><ArrowLeft size={15} aria-hidden="true" />{back.label}</a>}
      {tools && <div className="ui-article__tools">{tools}</div>}
    </div>}
    {markdown == null ? <div className="ui-article ui-article--loading"><Skeleton lines={8} label={loadingLabel} /></div>
      : <ArticleContent markdown={markdown} {...content} />}
  </div>;
}

function ArticleContent({ markdown, lang, resolveLink, resolveImage, headingHref, section, onTitle }: Omit<ArticleProps, 'back' | 'tools' | 'loadingLabel'> & { markdown: string }) {
  const root = useRef<HTMLElement>(null);
  const words = WORDS[lang];

  useEffect(() => {
    const title = root.current?.querySelector('h1')?.textContent?.trim();
    if (title) onTitle?.(title);
  }, [markdown, onTitle]);

  // The heading asked for, once the images above it have their height.
  useEffect(() => {
    const article = root.current;
    if (!section || !article) return;
    let active = true;
    const images = [...article.querySelectorAll('img')].map(image => image.decode().catch(() => undefined));
    void Promise.all(images).then(() => {
      if (active) article.querySelector(`#${CSS.escape(section)}`)?.scrollIntoView({ block: 'start' });
    });
    return () => { active = false; };
  }, [section, markdown]);

  const components = useMemo<Components>(() => {
    const heading = (level: 1 | 2 | 3 | 4) => function Heading({ id, children }: { id?: string; children?: ReactNode }) {
      const Tag = `h${level}` as const;
      const href = level > 1 && id && headingHref ? headingHref(id) : undefined;
      return <Tag id={id} className={`ui-article__h${level}`}>
        {children}
        {href && <a className="ui-article__anchor" href={href} aria-label={words.anchor}><span aria-hidden="true">#</span></a>}
      </Tag>;
    };
    const image = (src: unknown, alt: unknown) => {
      const address = typeof src === 'string' ? resolveImage?.(src) : undefined;
      return address ? <Figure image={address} alt={typeof alt === 'string' ? alt : ''} /> : null;
    };
    return {
      h1: heading(1), h2: heading(2), h3: heading(3), h4: heading(4), h5: heading(4), h6: heading(4),
      // An image alone in its paragraph is a figure, not a picture in a line of text.
      p: ({ node, children }) => {
        const content = node?.children.filter(child => !(child.type === 'text' && !child.value.trim())) ?? [];
        const only = content.length === 1 && content[0].type === 'element' && content[0].tagName === 'img' ? content[0] : null;
        if (only) return image(only.properties.src, only.properties.alt);
        return <p>{children}</p>;
      },
      img: ({ src, alt }) => image(src, alt),
      a: ({ href, children }) => {
        const to = href == null ? null : resolveLink ? resolveLink(href) : /^https?:\/\//i.test(href) ? href : null;
        if (to == null) return <>{children}</>;
        return /^https?:\/\//i.test(to) ? <a href={to} target="_blank" rel="noreferrer">{children}</a> : <a href={to}>{children}</a>;
      },
      code: ({ children }) => <InlineCode>{children}</InlineCode>,
      pre: ({ node }) => {
        const code = elements(node, 'code')[0];
        const classes = code?.properties.className;
        const named = (Array.isArray(classes) ? classes : []).map(String).find(name => name.startsWith('language-'))?.slice('language-'.length);
        const language = LANGUAGES.find(item => item === named) ?? 'text';
        return <CodeBlock className="ui-article__code" code={code ? textOf(code).replace(/\n$/, '') : ''} language={language} copy={false} />;
      },
      table: ({ node, children }) => {
        // A column needs about 11rem before its sentences break every few words: a wider table scrolls in its frame.
        const headers = elements(elements(node, 'thead')[0], 'th').map(cell => textOf(cell).trim());
        const columns = headers.length;
        return <Table className={columns > 1 && !headers[0] ? 'ui-article__table ui-article__table--rows' : 'ui-article__table'} label={[words.table, headers.filter(Boolean).join(', ')].filter(Boolean).join(': ')}
          minWidth={columns > 2 ? `${columns * 11}rem` : undefined}>{children}</Table>;
      },
      thead: ({ children }) => <TableHead>{children}</TableHead>,
      tbody: ({ children }) => <TableBody>{children}</TableBody>,
      tr: ({ children }) => <TableRow>{children}</TableRow>,
      th: ({ children, style }) => <TableHeaderCell style={style}>{children}</TableHeaderCell>,
      td: ({ children, style }) => <TableCell top style={style}>{children}</TableCell>,
    };
  }, [headingHref, resolveImage, resolveLink, words]);

  return <article ref={root} lang={lang} className={`ui-article ui-article--${lang}`}>
    <Markdown remarkPlugins={[remarkGfm]} rehypePlugins={[rehypeSlug]} components={components}>{markdown}</Markdown>
  </article>;
}

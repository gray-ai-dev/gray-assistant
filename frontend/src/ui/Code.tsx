import { useEffect, useState, type CSSProperties, type ReactNode } from 'react';
import type { HighlighterCore, ThemedToken } from 'shiki/core';
import { Check, Copy } from '../components/icons';
import { Button, IconButton } from './Button';
import { cx } from './cx';
import { SegmentedControl } from './Segmented';
import { VisuallyHidden } from './Text';
import { toast } from './Toast';

/** Languages the console shows. Grammars load on first use, in their own chunk. */
export type CodeLanguage = 'bash' | 'javascript' | 'python' | 'json' | 'toml' | 'text';

let highlighter: Promise<HighlighterCore> | undefined;
function loadHighlighter() {
  highlighter ??= Promise.all([import('shiki/core'), import('shiki/engine/javascript')]).then(([{ createHighlighterCore }, { createJavaScriptRegexEngine }]) => createHighlighterCore({
    themes: [import('shiki/themes/github-light-default.mjs'), import('shiki/themes/github-dark-default.mjs')],
    langs: [import('shiki/langs/shellscript.mjs'), import('shiki/langs/javascript.mjs'), import('shiki/langs/python.mjs'), import('shiki/langs/json.mjs'), import('shiki/langs/toml.mjs')],
    engine: createJavaScriptRegexEngine(),
  }));
  return highlighter;
}

const grammar: Record<Exclude<CodeLanguage, 'text'>, string> = { bash: 'shellscript', javascript: 'javascript', python: 'python', json: 'json', toml: 'toml' };

/** Shiki tokens for both themes; null until the highlighter has loaded, so the
 *  code shows as plain text first and never shifts layout. */
function useTokens(code: string, language: CodeLanguage) {
  const [tokens, setTokens] = useState<{ code: string; language: CodeLanguage; lines: ThemedToken[][] } | null>(null);
  useEffect(() => {
    if (language === 'text') return;
    let active = true;
    loadHighlighter().then(shiki => {
      if (!active) return;
      const { tokens: lines } = shiki.codeToTokens(code, { lang: grammar[language], themes: { light: 'github-light-default', dark: 'github-dark-default' }, defaultColor: false });
      setTokens({ code, language, lines });
    }).catch(() => { /* Plain text stays readable when highlighting is unavailable. */ });
    return () => { active = false; };
  }, [code, language]);
  return tokens && tokens.code === code && tokens.language === language ? tokens.lines : null;
}

/**
 * A command's tokens as words: what stands between two spaces is one unbreakable box (`ui-code__word`), so the line
 * wraps at its spaces and never inside `--config` or a path; a word longer than the whole line (a 64-character hash on
 * a phone) wraps inside its own box. Each piece keeps its token's colour.
 */
function words(tokens: readonly { content: string; style?: CSSProperties }[]): ReactNode[] {
  const out: ReactNode[] = [];
  let word: ReactNode[] = [];
  const flush = () => { if (word.length) { out.push(<span key={out.length} className="ui-code__word">{word}</span>); word = []; } };
  for (const token of tokens) {
    for (const piece of token.content.split(/(\s+)/)) {
      if (!piece) continue;
      if (/^\s+$/.test(piece)) { flush(); out.push(piece); }
      else word.push(<span key={word.length} className={token.style ? 'ui-token' : undefined} style={token.style}>{piece}</span>);
    }
  }
  flush();
  return out;
}

function CodeContent({ code, language, byWord = false }: { code: string; language: CodeLanguage; byWord?: boolean }) {
  const lines = useTokens(code, language);
  // Several commands, each wrapped at its spaces: every source line is a block of its own whose wrapped rows hang two
  // characters in (`ui-code__line`), so a wrapped command never reads as the next one.
  if (byWord && code.includes('\n')) {
    const rows = lines ? lines.map(line => line.map(token => ({ content: token.content, style: token.htmlStyle as CSSProperties }))) : code.split('\n').map(line => [{ content: line }]);
    // The line break stays in the text (a copy by selection, a reader of the text): at a block's end it adds no row.
    return <code>{rows.map((row, index) => <span key={index} className="ui-code__line">{row.some(token => token.content) ? words(row) : ' '}{index < rows.length - 1 ? '\n' : null}</span>)}</code>;
  }
  if (!lines) return <code>{byWord ? words([{ content: code }]) : code}</code>;
  return <code>{lines.map((line, index) => <span key={index}>
    {byWord ? words(line.map(token => ({ content: token.content, style: token.htmlStyle as CSSProperties })))
      : line.map((token, part) => <span key={part} className="ui-token" style={token.htmlStyle as CSSProperties}>{token.content}</span>)}
    {index < lines.length - 1 ? '\n' : null}
  </span>)}</code>;
}

/**
 * Copies `code` and says so. CodeBlock's, or on its own for text a step hands over without showing it (agent
 * instructions): then `variant` "primary" when it is the step's action, `disabled` while there is nothing to copy.
 * `load`, instead of `code`, makes the text at the click (agent instructions that carry a one-time code): the button
 * says `busyLabel` meanwhile, and a `load` that fails copies nothing and leaves its error to its caller. The clipboard
 * gets the text as a pending item, so the copy keeps the click's user activation while the text is made.
 */
export function CopyButton({ code = '', load, label = 'Copy code', busyLabel = 'Preparing…', variant = 'secondary', disabled, iconOnly }: {
  code?: string; load?: () => Promise<string>; label?: string; busyLabel?: string; variant?: 'primary' | 'secondary'; disabled?: boolean;
  /** A square icon button: `label` is its accessible name and tooltip, a check replaces the icon once copied, and a status
   *  line says the result to assistive technology. A failed copy is a toast, since the button has no words to change. */
  iconOnly?: boolean;
}) {
  const [state, setState] = useState<'idle' | 'busy' | 'copied' | 'failed'>('idle');
  useEffect(() => { setState('idle'); }, [code]);
  async function copy() {
    if (!load) {
      try { await navigator.clipboard.writeText(code); setState('copied'); }
      catch { setState('failed'); if (iconOnly) toast.error('Copy failed', { description: 'Select the code and copy it.' }); }
      return;
    }
    setState('busy');
    const text = load();
    let loaded = true;
    text.catch(() => { loaded = false; });
    try {
      if (typeof ClipboardItem !== 'undefined' && navigator.clipboard.write) await navigator.clipboard.write([new ClipboardItem({ 'text/plain': text.then(value => new Blob([value], { type: 'text/plain' })) })]);
      else await navigator.clipboard.writeText(await text);
      setState('copied');
    } catch {
      // A text that was never made is its caller's error to show; a clipboard that refused it is this button's.
      await text.catch(() => undefined);
      setState(loaded ? 'failed' : 'idle');
    }
  }
  const text = state === 'copied' ? 'Copied' : state === 'busy' ? busyLabel : state === 'failed' ? (load ? 'Copy failed — try again' : 'Copy failed — select the code') : label;
  const icon = state === 'copied' ? <Check size={15} aria-hidden="true" /> : <Copy size={15} aria-hidden="true" />;
  if (iconOnly) return <>
    <IconButton size="sm" variant={variant} label={text} icon={icon} disabled={disabled || state === 'busy'} onClick={() => void copy()} />
    <VisuallyHidden><span role="status">{state === 'copied' ? 'Copied.' : ''}</span></VisuallyHidden>
  </>;
  return <Button size="sm" variant={variant} disabled={disabled || state === 'busy'} icon={icon} onClick={() => void copy()}>
    <span aria-live="polite">{text}</span>
  </Button>;
}

export type CodeBlockProps = {
  code: string;
  language: CodeLanguage;
  /** Heading in the block's header bar. */
  title?: ReactNode;
  /** Heading level of the title (default 2). */
  level?: 2 | 3;
  icon?: ReactNode;
  description?: ReactNode;
  /** Controls in the header before the copy button, e.g. a language switch. */
  tools?: ReactNode;
  /** Adds a copy button (default true). */
  copy?: boolean;
  /** The copy button's text when copying says what is copied, e.g. "Copy key" (default "Copy code"). */
  copyLabel?: string;
  /**
   * One command with only its copy button: the button is an icon pinned at the block's top right, named by `copyLabel`
   * (its tooltip), so the block stays one row in a narrow column whatever the command's length. The line scrolls in the
   * space left of the icon, so no part of it, its end scrolled to included, is ever under the icon.
   */
  copyIcon?: boolean;
  /** Muted note under the code. */
  footer?: ReactNode;
  /**
   * Wrap long lines instead of scrolling (logs, JSON responses). A one-line command wraps at its spaces by itself,
   * with or without a header; `false` keeps it on one scrolling line. `"words"`: several commands, each wrapped at its
   * spaces with its wrapped rows indented, so that a long one (an image reference, a one-time code at its end) is read
   * in full without scrolling.
   */
  wrap?: boolean | 'words';
  maxHeight?: string;
  /** Accessible name for the scrollable code region. */
  label?: string;
  className?: string;
  /** No frame, for code inside another surface. */
  bare?: boolean;
};

/** A highlighted, copyable code sample. */
export function CodeBlock({ code, language, title, level = 2, icon, description, tools, copy = true, copyLabel, copyIcon, footer, wrap, maxHeight, label, className, bare }: CodeBlockProps) {
  // A header bar only when there is something besides the copy button to put
  // in it; a lone copy button sits in the corner of the code instead.
  const header = title != null || description != null || tools != null;
  // One line of code with only its copy button (a command): the button at the line's end, or under it when the line is
  // long; `copyIcon` makes it an icon pinned at the top right, beside a line of any length. A command wraps (at its
  // spaces, never inside a word that fits a line) unless `wrap` says otherwise, so its last words (`--config …`) are
  // read without scrolling, on a phone too.
  const line = !header && copy && !bare && !code.includes('\n');
  const iconOnly = line && copyIcon === true && !footer;
  // A one-line command under a header (a description, a title) wraps the same way: on a phone its last words were
  // cut off behind a scroll nobody sees (review of 2026-11-14).
  const byWord = wrap === 'words' || (wrap === undefined && !code.includes('\n') && (line || (header && language === 'bash')));
  const Heading = `h${level}` as const;
  return <section className={cx('ui-code', line && 'ui-code--line', iconOnly && 'ui-code--line-icon', bare && 'ui-code--bare', className)} aria-label={label ?? (typeof title === 'string' ? title : undefined)}
    style={maxHeight ? { '--ui-code-max-height': maxHeight } as CSSProperties : undefined}>
    {header && !bare && <div className="ui-code__header">
      {(title != null || description != null) && <div className="ui-code__title">
        {title != null && <Heading className="ui-code__title-text">{icon}{title}</Heading>}
        {description != null && <p className="ui-code__description">{description}</p>}
      </div>}
      <div className="ui-code__tools">{tools}{copy && <CopyButton code={code} label={copyLabel} />}</div>
    </div>}
    {!header && copy && !bare && !line && <div className="ui-code__corner"><CopyButton code={code} label={copyLabel} /></div>}
    <pre className={cx('ui-code__pre', wrap === true && 'ui-code__pre--wrap', byWord && 'ui-code__pre--words')} data-language={language} tabIndex={0} translate="no"><CodeContent code={code} language={language} byWord={byWord} /></pre>
    {line && <div className="ui-code__end"><CopyButton code={code} label={copyLabel} iconOnly={iconOnly} /></div>}
    {footer && <p className="ui-code__footer">{footer}</p>}
  </section>;
}

export type CodeExample<T extends string> = { id: T; label: string; language: CodeLanguage; code: string };

/** The same request in several languages, with a switch between them. */
export function CodeExamples<T extends string>({ examples, value, onValueChange, ...block }: Omit<CodeBlockProps, 'code' | 'language' | 'tools'> & {
  examples: readonly CodeExample<T>[];
  value: T;
  onValueChange: (value: T) => void;
}) {
  const current = examples.find(example => example.id === value) ?? examples[0];
  return <CodeBlock {...block} code={current.code} language={current.language}
    tools={<SegmentedControl size="sm" aria-label="Code language" value={current.id} onValueChange={onValueChange} options={examples.map(example => ({ value: example.id, label: example.label }))} />} />;
}

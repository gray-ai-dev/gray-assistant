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

function CodeContent({ code, language }: { code: string; language: CodeLanguage }) {
  const lines = useTokens(code, language);
  if (!lines) return <code>{code}</code>;
  return <code>{lines.map((line, index) => <span key={index}>
    {line.map((token, part) => <span key={part} className="ui-token" style={token.htmlStyle as CSSProperties}>{token.content}</span>)}
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
  /** Wrap long lines instead of scrolling (logs, JSON responses). */
  wrap?: boolean;
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
  // long; `copyIcon` makes it an icon pinned at the top right, beside a line of any length.
  const line = !header && copy && !bare && !code.includes('\n');
  const iconOnly = line && copyIcon === true && !footer;
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
    <pre className={cx('ui-code__pre', wrap && 'ui-code__pre--wrap')} data-language={language} tabIndex={0}><CodeContent code={code} language={language} /></pre>
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

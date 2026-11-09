import { MarkdownTextPrimitive, type SyntaxHighlighterProps } from '@assistant-ui/react-markdown';
import { CodeBlock, type CodeLanguage } from './Code';
import './chat-markdown.css';

function ChatCode({ code, language }: SyntaxHighlighterProps) {
  const supported = ['bash', 'javascript', 'python', 'json', 'toml', 'text'];
  const grammar = supported.includes(language) ? language as CodeLanguage : 'text';
  return <CodeBlock code={code} language={grammar} />;
}

/** Official assistant-ui text-part renderer, with Gray's existing code blocks. */
export function ChatMarkdown() {
  return <MarkdownTextPrimitive className="ui-chat-markdown" smooth={false} components={{
    SyntaxHighlighter: ChatCode,
    CodeHeader: () => null,
    h1: ({ children }) => <h3>{children}</h3>,
    h2: ({ children }) => <h3>{children}</h3>,
    a: ({ children, href }) => <a href={href} target="_blank" rel="noreferrer">{children}</a>,
  }} />;
}

import { lazy, Suspense } from 'react';
import { Text } from './Text';

const Content = lazy(() => import('./ChatMarkdownContent').then(module => ({ default: module.ChatMarkdown })));

/** Load the official renderer only on surfaces that render an assistant message. */
export function ChatMarkdown() {
  return <Suspense fallback={<Text tone="muted">Preparing message…</Text>}><Content /></Suspense>;
}

// Entry of the relay's local page (`gray-assistant ui`), built by relay-ui/vite.config.ts into
// workers/packages/relay-kit/assets/ui. Same fonts, tokens and design system as Gray's console.
import '@fontsource-variable/plus-jakarta-sans';
import '@fontsource-variable/geist-mono';
import '../styles.css';
import './relay-ui.css';
import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { QueryClientProvider } from '@tanstack/react-query';
import { UiProvider } from '../ui';
import { App } from './App';
import { createQueryClient } from './data';

const client = createQueryClient();
createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <QueryClientProvider client={client}><UiProvider><App /></UiProvider></QueryClientProvider>
  </StrictMode>,
);

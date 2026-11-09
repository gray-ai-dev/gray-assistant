// The relay's local page (`gray-assistant ui`): its own entry beside the console, built from frontend/src/relay-ui with the
// console's design system, into the relay kit, where gray-assistant serves it from (workers/packages/relay-kit/assets/ui,
// committed: the relay's image runs the workspace's files with no build step). `npm run build:relay-ui` writes it;
// `RELAY_UI_OUT` sends a build elsewhere (the bundle check, design review and e2e).
import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

const here = fileURLToPath(new URL('.', import.meta.url));
const out = process.env.RELAY_UI_OUT || fileURLToPath(new URL('../../workers/packages/relay-kit/assets/ui', import.meta.url));

export default defineConfig({
  root: here,
  // The page lives under /ui/ on 127.0.0.1 and on the relay's public origin alike.
  base: '/ui/',
  // The page has no public folder: its favicon and fonts are imported, so each is a hashed file of the bundle.
  publicDir: false,
  plugins: [react()],
  build: {
    outDir: out,
    emptyOutDir: true,
    assetsDir: 'assets',
    sourcemap: false,
    reportCompressedSize: false,
    // The libraries the page loads up front in one chunk that changes only with the lockfile, the page in a small one: a
    // change to the page commits a few kilobytes, not the whole bundle again. A library only a lazy part loads (Shiki,
    // Recharts behind a sparkline) is not named here, so it stays in that part's own chunk.
    chunkSizeWarningLimit: 1024,
    rolldownOptions: {
      // `lazy(() => import(…))` at a module's top level is pure, so a design-system component the page never uses
      // (charts, the date picker) leaves no chunk behind.
      treeshake: { manualPureFunctions: ['lazy'] },
      output: { codeSplitting: { groups: [{ name: 'vendor', test: /[\\/]node_modules[\\/](react|react-dom|scheduler|@base-ui|@cloudflare[\\/]kumo|@floating-ui|@tanstack|sonner|lucide-react|tabbable|use-sync-external-store|@simplewebauthn|@fontsource-variable)[\\/]/ }] } },
    },
  },
  // `vite preview` (design review): every page path under /ui/ answers with index.html, as gray-assistant does.
  preview: { host: '127.0.0.1' },
});

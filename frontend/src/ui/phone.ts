import { useSyncExternalStore } from 'react';

/** `StackedTable`'s breakpoint: below it a table is cards, and nothing hovers. */
export const PHONE = '(max-width: 600px)';
const watchPhone = (change: () => void) => { const query = matchMedia(PHONE); query.addEventListener('change', change); return () => query.removeEventListener('change', change); };

/**
 * Whether the window is a phone's (`PHONE`), kept current as it resizes. For what is shown in script rather than in
 * ui.css below the breakpoint: the relay's local page ships a build of that stylesheet (workers/packages/relay-kit/assets/ui).
 */
export const usePhone = () => useSyncExternalStore(watchPhone, () => matchMedia(PHONE).matches);

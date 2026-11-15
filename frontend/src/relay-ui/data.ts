// Reads of the local page: TanStack Query over `read`, as the console's `useResource` is. A view that only shows data
// keeps itself current (`live`), faster while something is on its way (a seal, a sign-in, a doctor run), so the page
// needs no Refresh button. A read that comes back signed out sends the whole page to its sign-in screen.
import { useEffect, useState } from 'react';
import { QueryClient, useQuery, useQueryClient } from '@tanstack/react-query';
import { ApiError, read } from './api';

/** How often a view refreshes while nothing is in flight. */
export const LIVE_MS = 15_000;
/** And while it waits for gray-assistant to finish something it started. */
export const BUSY_MS = 2_000;

export function useLocal<T>(path: string, options: { live?: number | ((data: T | undefined) => number | false); enabled?: boolean } = {}) {
  const client = useQueryClient();
  const query = useQuery<T, ApiError>({
    queryKey: [path],
    queryFn: async ({ signal }) => {
      try {
        return await read<T>(path, signal);
      } catch (error) {
        if (error instanceof ApiError && error.status === 401) void client.invalidateQueries({ queryKey: ['session'] });
        throw error;
      }
    },
    refetchInterval: typeof options.live === 'function' ? query => (options.live as (data: T | undefined) => number | false)(query.state.data) : options.live ?? LIVE_MS,
    refetchOnWindowFocus: true,
    enabled: options.enabled ?? true,
  });
  return {
    data: query.data ?? null,
    /** The first read only: a background refresh keeps the data on screen. */
    loading: query.isLoading,
    error: query.error ?? null,
    updatedAt: query.dataUpdatedAt || null,
    reload: () => query.refetch(),
    set: (data: T) => client.setQueryData([path], data),
  };
}

/**
 * After a write: the account file changed and gray-assistant started sending it to the VM, so the reads of the accounts,
 * the proxies and the push start over (the push's state shows in the shell at once).
 */
export function useChanged(): () => Promise<void> {
  const client = useQueryClient();
  return async () => {
    await Promise.all(['accounts', 'proxies', 'push'].map(key => client.invalidateQueries({ queryKey: [key] })));
  };
}

// A sign-in under way belongs to the page, not to one screen: leaving an account and coming back finds it again, and
// the add form hands a new subscription account to its sign-in steps. Kept in memory only (a reload starts over).
const signInSessions = new Map<string, string>();
const signInWanted = new Set<string>();
export const signInSession = (accountId: string): string | null => signInSessions.get(accountId) ?? null;
export function keepSignInSession(accountId: string, session: string | null) {
  if (session === null) signInSessions.delete(accountId);
  else signInSessions.set(accountId, session);
}
/** The add form asks for the new account's sign-in to start once its screen opens; the screen takes the request once. */
export const wantSignIn = (accountId: string) => { signInWanted.add(accountId); };
export const takeSignIn = (accountId: string): boolean => signInWanted.delete(accountId);

export function createQueryClient(): QueryClient {
  return new QueryClient({
    defaultOptions: {
      queries: {
        // A signed-out or refused read is an answer, not a network blip; only a missing server is retried.
        retry: (count: number, error: unknown) => error instanceof ApiError && error.code === 'unreachable' && count < 2,
        staleTime: 1_000,
      },
    },
  });
}

/** The current time, ticking every `everyMs` while the component is shown (countdowns, "2 minutes ago"). */
export function useNow(everyMs = 1_000): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const timer = window.setInterval(() => setNow(Date.now()), everyMs);
    return () => window.clearInterval(timer);
  }, [everyMs]);
  return now;
}

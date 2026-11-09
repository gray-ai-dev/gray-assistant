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

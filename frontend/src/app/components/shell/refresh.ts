"use client";

import { useEffect, useRef, useSyncExternalStore } from "react";

/** The header's "synced 14:32 ↻". A page that can reload its own data
 *  registers here; the header then shows when it last did and offers the
 *  button. A page that registers nothing gets no button, rather than one
 *  that does nothing. */

type State = { handler: (() => void) | null; syncedAt: number | null };
let state: State = { handler: null, syncedAt: null };
const subs = new Set<() => void>();
const emit = () => subs.forEach(s => s());

function subscribe(fn: () => void) {
  subs.add(fn);
  return () => { subs.delete(fn); };
}

export function useShellRefreshState(): State {
  return useSyncExternalStore(subscribe, () => state, () => state);
}

/** Register the current page's reload. Call `markSynced()` whenever fresh
 *  data has arrived, by whatever route. */
export function useShellRefresh(reload: () => void) {
  const ref = useRef(reload);
  ref.current = reload;
  useEffect(() => {
    const handler = () => ref.current();
    state = { handler, syncedAt: state.syncedAt };
    emit();
    return () => {
      if (state.handler === handler) { state = { handler: null, syncedAt: null }; emit(); }
    };
  }, []);
  return { markSynced };
}

/** Stable across renders, so a page can list it as a dependency. */
function markSynced() {
  state = { ...state, syncedAt: Date.now() };
  emit();
}

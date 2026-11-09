import { createContext, useContext, type ReactNode } from 'react';

/**
 * Where a design-system popup is placed: `positionMethod` on each Base UI Positioner (SelectField, MultiSelectField,
 * Picker, AutocompleteInput, Menu, Tooltip, InfoTip, the workspace switcher's menu), chosen by the layer its trigger
 * sits in. Floating UI, which Base UI positions with, documents the two (floating-ui.com/docs/computePosition,
 * `strategy`): `'absolute'` "usually requires the browser to do the least work when updating the position", and
 * `'fixed'` "is useful when the reference element is also fixed to reduce jumpiness with positioning while scrolling".
 *
 * A trigger in the page keeps Base UI's default, `'absolute'`: the popup is in page coordinates, so the browser moves
 * it with its trigger in the same frame as any scroll of the page. In viewport coordinates it would stay put until
 * the scroll event placed it again, a frame or more behind a scroll the browser runs off the main thread.
 *
 * A trigger inside a `FixedLayer` (the sticky app bar, the sticky catalog filter rail, a Drawer sheet, the confirm
 * dialog) does not move while the page under it scrolls, so its popup takes `'fixed'`. In page coordinates it went
 * with the page for a frame until it was placed again, and a press across that frame was released off the option
 * (the workspace menu in the sheet, PR #114). Base UI renders every popup fixed until its first position is known.
 */
const InFixedLayer = createContext(false);

/** Content that stays where it is while the page under it scrolls: a sticky bar, a fixed sheet or dialog. Popups
 * opened from inside it are placed in viewport coordinates. It renders no element of its own. */
export function FixedLayer({ children }: { children: ReactNode }) {
  return <InFixedLayer.Provider value>{children}</InFixedLayer.Provider>;
}

/** `positionMethod` for a Base UI Positioner whose trigger renders here. */
export function usePopupPositionMethod(): 'absolute' | 'fixed' {
  return useContext(InFixedLayer) ? 'fixed' : 'absolute';
}

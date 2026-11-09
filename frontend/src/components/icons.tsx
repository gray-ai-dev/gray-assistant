// The console's icon set: Lucide (ISC), the open-source set OpenRouter's
// console uses, drawn with a 2px stroke. Pages import icons from here by the
// names below; each comes from its own Lucide module, so the dev server never
// loads the whole library. `weight="bold"` maps to a heavier stroke.
import type { LucideIcon, LucideProps } from 'lucide-react';

import ArrowClockwiseGlyph from 'lucide-react/dist/esm/icons/rotate-cw.mjs';
import ArrowDownGlyph from 'lucide-react/dist/esm/icons/arrow-down.mjs';
import ArrowLeftGlyph from 'lucide-react/dist/esm/icons/arrow-left.mjs';
import ArrowRightGlyph from 'lucide-react/dist/esm/icons/arrow-right.mjs';
import ArrowUpGlyph from 'lucide-react/dist/esm/icons/arrow-up.mjs';
import ArrowsDownUpGlyph from 'lucide-react/dist/esm/icons/arrow-up-down.mjs';
import CaretDownGlyph from 'lucide-react/dist/esm/icons/chevron-down.mjs';
import CaretLeftGlyph from 'lucide-react/dist/esm/icons/chevron-left.mjs';
import CaretRightGlyph from 'lucide-react/dist/esm/icons/chevron-right.mjs';
import CalendarBlankGlyph from 'lucide-react/dist/esm/icons/calendar.mjs';
import CaretUpGlyph from 'lucide-react/dist/esm/icons/chevron-up.mjs';
import CheckGlyph from 'lucide-react/dist/esm/icons/check.mjs';
import CheckCircleGlyph from 'lucide-react/dist/esm/icons/circle-check.mjs';
import CodeGlyph from 'lucide-react/dist/esm/icons/code.mjs';
import CopyGlyph from 'lucide-react/dist/esm/icons/copy.mjs';
import DotsThreeGlyph from 'lucide-react/dist/esm/icons/ellipsis.mjs';
import DownloadSimpleGlyph from 'lucide-react/dist/esm/icons/download.mjs';
import FunnelGlyph from 'lucide-react/dist/esm/icons/funnel.mjs';
import GridFourGlyph from 'lucide-react/dist/esm/icons/layout-grid.mjs';
import InfoGlyph from 'lucide-react/dist/esm/icons/info.mjs';
import ListGlyph from 'lucide-react/dist/esm/icons/list.mjs';
import MenuGlyph from 'lucide-react/dist/esm/icons/menu.mjs';
import MagnifyingGlassGlyph from 'lucide-react/dist/esm/icons/search.mjs';
import MinusGlyph from 'lucide-react/dist/esm/icons/minus.mjs';
import MoonGlyph from 'lucide-react/dist/esm/icons/moon.mjs';
import PauseGlyph from 'lucide-react/dist/esm/icons/pause.mjs';
import PlayGlyph from 'lucide-react/dist/esm/icons/play.mjs';
import ShieldCheckGlyph from 'lucide-react/dist/esm/icons/shield-check.mjs';
import SunGlyph from 'lucide-react/dist/esm/icons/sun.mjs';
import UploadSimpleGlyph from 'lucide-react/dist/esm/icons/upload.mjs';
import TrashGlyph from 'lucide-react/dist/esm/icons/trash-2.mjs';
import UserGlyph from 'lucide-react/dist/esm/icons/user.mjs';
import WarningGlyph from 'lucide-react/dist/esm/icons/triangle-alert.mjs';
import WarningCircleGlyph from 'lucide-react/dist/esm/icons/circle-alert.mjs';
import XGlyph from 'lucide-react/dist/esm/icons/x.mjs';
import XCircleGlyph from 'lucide-react/dist/esm/icons/circle-x.mjs';

export type IconProps = Omit<LucideProps, 'ref'> & { weight?: 'regular' | 'bold' };

function icon(Glyph: LucideIcon, name: string) {
  function Icon({ weight, size = '1em', strokeWidth, ...rest }: IconProps) {
    return <Glyph size={size} strokeWidth={strokeWidth ?? (weight === 'bold' ? 2.5 : 2)} {...rest} />;
  }
  Icon.displayName = name;
  return Icon;
}

export const ArrowClockwise = icon(ArrowClockwiseGlyph, 'ArrowClockwise');
export const ArrowDown = icon(ArrowDownGlyph, 'ArrowDown');
export const ArrowLeft = icon(ArrowLeftGlyph, 'ArrowLeft');
export const ArrowRight = icon(ArrowRightGlyph, 'ArrowRight');
export const ArrowUp = icon(ArrowUpGlyph, 'ArrowUp');
export const ArrowsDownUp = icon(ArrowsDownUpGlyph, 'ArrowsDownUp');
export const CaretDown = icon(CaretDownGlyph, 'CaretDown');
export const CaretLeft = icon(CaretLeftGlyph, 'CaretLeft');
export const CaretRight = icon(CaretRightGlyph, 'CaretRight');
export const CalendarBlank = icon(CalendarBlankGlyph, 'CalendarBlank');
export const CaretUp = icon(CaretUpGlyph, 'CaretUp');
export const Check = icon(CheckGlyph, 'Check');
export const CheckCircle = icon(CheckCircleGlyph, 'CheckCircle');
export const Code = icon(CodeGlyph, 'Code');
export const Copy = icon(CopyGlyph, 'Copy');
export const DotsThree = icon(DotsThreeGlyph, 'DotsThree');
export const DownloadSimple = icon(DownloadSimpleGlyph, 'DownloadSimple');
export const Funnel = icon(FunnelGlyph, 'Funnel');
export const GridFour = icon(GridFourGlyph, 'GridFour');
export const Info = icon(InfoGlyph, 'Info');
export const List = icon(ListGlyph, 'List');
export const Menu = icon(MenuGlyph, 'Menu');
export const MagnifyingGlass = icon(MagnifyingGlassGlyph, 'MagnifyingGlass');
export const Minus = icon(MinusGlyph, 'Minus');
export const Moon = icon(MoonGlyph, 'Moon');
export const Pause = icon(PauseGlyph, 'Pause');
export const Play = icon(PlayGlyph, 'Play');
export const ShieldCheck = icon(ShieldCheckGlyph, 'ShieldCheck');
export const Sun = icon(SunGlyph, 'Sun');
export const Trash = icon(TrashGlyph, 'Trash');
export const User = icon(UserGlyph, 'User');
export const Warning = icon(WarningGlyph, 'Warning');
export const WarningCircle = icon(WarningCircleGlyph, 'WarningCircle');
export const UploadSimple = icon(UploadSimpleGlyph, 'UploadSimple');
export const X = icon(XGlyph, 'X');
export const XCircle = icon(XCircleGlyph, 'XCircle');

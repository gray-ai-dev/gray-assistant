import { useMemo } from 'react';
import { cx } from './cx';
import { qrPath } from './qr';

/**
 * A QR code of `value` (a deposit address: the bare `0x…` string, which exchanges and wallets scan as an address), drawn
 * as an inline SVG from a local encoder: no image request, no third party. Dark modules on white in both themes,
 * since cameras read a light quiet zone best. It never stands alone: the same text sits beside it to read and copy.
 */
export function QrCode({ value, size = 160, label, className }: { value: string; size?: number; label: string; className?: string }) {
  const code = useMemo(() => qrPath(value), [value]);
  return <span className={cx('ui-qr', className)}>
    <svg role="img" aria-label={label} width={size} height={size} viewBox={`0 0 ${code.size} ${code.size}`} shapeRendering="crispEdges">
      <rect width={code.size} height={code.size} fill="#ffffff" />
      <path d={code.path} fill="#171717" />
    </svg>
  </span>;
}

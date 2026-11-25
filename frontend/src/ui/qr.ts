import { encode } from 'uqr';

/**
 * The SVG path of a QR code's dark modules, one `h1v1h-1z` square per module in the code's own coordinates, and the
 * code's width in modules (a 2-module margin included; QrCode's white padding adds the rest of the quiet zone).
 * Made in the browser from `value` alone: no image URL, no request.
 */
export function qrPath(value: string) {
  const { data, size } = encode(value, { ecc: 'M', border: 2 });
  let path = '';
  for (let y = 0; y < size; y++) for (let x = 0; x < size; x++) if (data[y][x]) path += `M${x} ${y}h1v1h-1z`;
  return { path, size };
}

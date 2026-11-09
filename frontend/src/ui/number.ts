// How the console writes a count or a limit: short when it is round, complete when shortening would drop digits.
const LOCALE = 'en-US';
const three = new Intl.NumberFormat(LOCALE, { notation: 'compact', maximumSignificantDigits: 3 });
const exact = new Intl.NumberFormat(LOCALE, { notation: 'compact', maximumSignificantDigits: 21 });
const grouped = new Intl.NumberFormat(LOCALE, { maximumFractionDigits: 20 });

/** Whether a number of 1,000 or more reads the same in three significant digits of compact notation: 1,000,000 is
 *  "1M" and 2,500 is "2.5K", while 32,768 would lose its last digits as "32.8K". */
export function compactsCleanly(value: number) {
  return Math.abs(value) >= 1000 && three.format(value) === exact.format(value);
}

/** A count or limit as text: "600", "1.2K", "1M", "1T" when nothing is lost, otherwise every digit with thousands
 *  separators ("32,768"). `NumberInput` shows the same text while it is not being edited. */
export function formatCount(value: number) {
  return compactsCleanly(value) ? three.format(value) : grouped.format(value);
}

/** A figure in a summary (a report's headline, a breakdown): exact below 1,000, then compact with at most three
 *  significant digits ("117K", "32.9K", "1.2M"). Rounding is fine here; tables keep every digit. */
export function formatShort(value: number) {
  return Math.abs(value) >= 1000 ? three.format(value) : grouped.format(value);
}

const cents = new Intl.NumberFormat(LOCALE, { style: 'currency', currency: 'USD', minimumFractionDigits: 2, maximumFractionDigits: 2 });
const small = new Intl.NumberFormat(LOCALE, { style: 'currency', currency: 'USD', maximumSignificantDigits: 3 });
const shortUsd = new Intl.NumberFormat(LOCALE, { style: 'currency', currency: 'USD', notation: 'compact', maximumSignificantDigits: 3 });
/** Microdollars in a summary: "$1,234.56", "$12.3K" from $10,000, and three significant digits under a dollar
 *  ("$0.0868"), so small spend still shows. Billing records keep their exact amounts elsewhere. */
export function formatMoneyShort(micro: number) {
  const value = micro / 1_000_000;
  if (value === 0) return cents.format(0);
  return Math.abs(value) >= 10_000 ? shortUsd.format(value) : Math.abs(value) >= 1 ? cents.format(value) : small.format(value);
}

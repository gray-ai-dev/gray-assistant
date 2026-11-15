export type Modality = 'text' | 'embeddings' | 'image' | 'audio' | 'video';
export type BillingUnit = 'images' | 'videos' | 'seconds' | 'characters' | 'requests';
/**
 * Image, audio and unit prices in micro-USD per million tokens or units. An unset image or audio rate is the text
 * input or output rate. A route with a unit price bills units alone: the tokens its API reports are recorded but not
 * charged. A unit-billed route without a unit price is billed by the tokens its API reports, at its token rates (the
 * gateway rejects a response from such a route that reports units).
 */
export type MediaRates = { image_input_microusd_per_million?: number | null; audio_input_microusd_per_million?: number | null; image_output_microusd_per_million?: number | null; audio_output_microusd_per_million?: number | null; unit_microusd_per_million?: number | null };
export type RateKey = Exclude<keyof MediaRates, 'unit_microusd_per_million'>;
/** Offer terms: the modality rates plus unit prices by selector ("*" is the default). */
export type OfferMedia = Partial<Record<RateKey, number>> & { unit_prices?: Record<string, number> };
export type MediaUsage = { image_input_tokens?: number; audio_input_tokens?: number; image_output_tokens?: number; audio_output_tokens?: number; units?: number; unit?: string | null };

const protocols: Record<string, { label: string; modality: Modality; unit?: BillingUnit }> = {
  open_ai_chat: { label: 'Chat Completions', modality: 'text' },
  open_ai_responses: { label: 'Responses', modality: 'text' },
  anthropic_messages: { label: 'Messages', modality: 'text' },
  gemini: { label: 'Gemini', modality: 'text' },
  system_one: { label: 'System One', modality: 'text' },
  open_ai_embeddings: { label: 'Embeddings', modality: 'embeddings' },
  rerank: { label: 'Rerank', modality: 'embeddings', unit: 'requests' },
  open_ai_image_generations: { label: 'Image generations', modality: 'image', unit: 'images' },
  open_ai_image_edits: { label: 'Image edits', modality: 'image', unit: 'images' },
  open_ai_speech: { label: 'Speech', modality: 'audio', unit: 'characters' },
  open_ai_transcriptions: { label: 'Transcriptions', modality: 'audio', unit: 'seconds' },
  open_ai_translations: { label: 'Translations', modality: 'audio', unit: 'seconds' },
  open_ai_videos: { label: 'Videos', modality: 'video', unit: 'seconds' },
};
export const protocolLabel = (protocol: string) => protocols[protocol]?.label || protocol;
export const protocolModality = (protocol: string): Modality | null => protocols[protocol]?.modality ?? null;
export const protocolUnit = (protocol: string): BillingUnit | null => protocols[protocol]?.unit ?? null;
/** APIs that settle only in units: speech, translations and videos report no tokens a route could bill. */
const unitOnly = ['open_ai_speech', 'open_ai_translations', 'open_ai_videos'];
/**
 * Whether an offer must set a default ("*") unit price: an API that settles only in units, or an image API behind a
 * vendor adapter other than Gemini, which reports image counts alone (the gateway's adapter_requires_unit_price).
 */
export const requiresUnitPrice = (protocol: string, adapter?: string | null) => unitOnly.includes(protocol) || (protocolModality(protocol) === 'image' && !!adapter && adapter !== 'gemini');
/** Catalog types for available models, one per protocol modality. */
export const liveModelTypes = ['All', 'Text', 'Image', 'Audio', 'Video', 'Embeddings'] as const;
/** Whether any of a model's protocols has the type's modality; 'All' and unknown types match everything. */
export const matchesModality = (modelProtocols: string[], type: string) => type === 'All' || !(liveModelTypes as readonly string[]).includes(type) || modelProtocols.some(protocol => protocolModality(protocol) === type.toLowerCase());

export const rateFields: { key: RateKey; label: string; modality: 'image' | 'audio'; text: 'input' | 'output' }[] = [
  { key: 'image_input_microusd_per_million', label: 'Image input', modality: 'image', text: 'input' },
  { key: 'audio_input_microusd_per_million', label: 'Audio input', modality: 'audio', text: 'input' },
  { key: 'image_output_microusd_per_million', label: 'Image output', modality: 'image', text: 'output' },
  { key: 'audio_output_microusd_per_million', label: 'Audio output', modality: 'audio', text: 'output' },
];
/** Modality token rates a protocol can bill: all four for text APIs, its own modality for image and audio APIs, none otherwise. */
export function rateFieldsFor(protocol: string) {
  const modality = protocolModality(protocol);
  return modality === 'text' ? rateFields : rateFields.filter(field => field.modality === modality);
}

/** Singular and plural names. A rerank unit ("requests" in usage) is one search unit: up to 100 documents or chunks. */
const units: Record<BillingUnit, [one: string, many: string]> = { images: ['image', 'images'], videos: ['video', 'videos'], seconds: ['second', 'seconds'], characters: ['character', 'characters'], requests: ['search unit', 'search units'] };
export const isBillingUnit = (value: unknown): value is BillingUnit => typeof value === 'string' && Object.hasOwn(units, value);
export const unitName = (unit: BillingUnit, count = 1) => units[unit][count === 1 ? 0 : 1];
/** Characters are priced per million, like tokens; every other unit is priced per unit. */
const perMillion = (unit: BillingUnit) => unit === 'characters';
const unitDigits = (unit: BillingUnit) => perMillion(unit) ? 6 : 12;
/** What one price buys: "1M characters", "search unit (up to 100 documents or chunks)", else the unit itself. */
export const unitBasis = (unit: BillingUnit) => perMillion(unit) ? '1M characters' : unit === 'requests' ? 'search unit (up to 100 documents or chunks)' : units[unit][0];

/** Highest token price, including image and audio token rates: $1,000,000 per million tokens (the gateway's MAX_PRICE_MICROUSD_PER_MILLION). */
export const MAX_MICROUSD_PER_MILLION = 1_000_000_000_000;
/** Highest unit price: $100 per image, second or request, or $100,000,000 per 1M characters (the gateway's MAX_UNIT_PRICE_MICROUSD_PER_MILLION). */
export const MAX_UNIT_MICROUSD_PER_MILLION = 100_000_000_000_000;
/** Exact integer for a nonnegative decimal string scaled by 10^digits (string and BigInt math, so no float drift). */
function parseScaled(value: string, digits: number, max: number, cap: string) {
  const text = value.trim();
  if (!new RegExp(`^\\d+(?:\\.\\d{1,${digits}})?$`).test(text)) throw new Error(`Enter USD prices with up to ${digits === 6 ? 'six' : digits} decimal places.`);
  const [whole, fraction = ''] = text.split('.');
  const amount = BigInt(whole) * 10n ** BigInt(digits) + BigInt(fraction.padEnd(digits, '0'));
  if (amount > BigInt(max)) throw new Error(`A price cannot exceed ${cap}.`);
  return Number(amount);
}
/** Exact decimal string for an integer scaled by 10^digits, without trailing zeros. */
function scaledText(value: number, digits: number) {
  if (!Number.isSafeInteger(value) || value < 0) throw new RangeError('Price must be a nonnegative integer.');
  const text = String(value).padStart(digits + 1, '0'), fraction = text.slice(-digits).replace(/0+$/, '');
  return fraction ? `${text.slice(0, -digits)}.${fraction}` : text.slice(0, -digits);
}
function usd(decimal: string) {
  const [whole, fraction = ''] = decimal.split('.');
  return `$${new Intl.NumberFormat('en-US').format(BigInt(whole))}.${fraction.padEnd(2, '0')}`;
}

/** USD per million tokens → micro-USD per million tokens. */
export const parseTokenPrice = (value: string) => parseScaled(value, 6, MAX_MICROUSD_PER_MILLION, '$1,000,000 per million tokens');
export const tokenPriceText = (micro: number) => scaledText(micro, 6);
/** USD per unit (per 1M characters) → micro-USD per million units. */
export const parseUnitPrice = (value: string, unit: BillingUnit) => parseScaled(value, unitDigits(unit), MAX_UNIT_MICROUSD_PER_MILLION, perMillion(unit) ? '$100,000,000 per 1M characters' : `$100 per ${units[unit][0]}`);
/** Micro-USD per million units → the exact USD per unit (per 1M characters) a provider edits. */
export const unitPriceText = (micro: number, unit: BillingUnit) => scaledText(micro, unitDigits(unit));
/** "$0.04 per image", "$0.10 per second", "$15.00 per 1M characters", "$0.002 per search unit (up to 100 documents or chunks)". */
export const formatUnitPrice = (micro: number, unit: BillingUnit) => `${unitUsd(micro, unit)} per ${unitBasis(unit)}`;
/** The USD amount alone, with at least two decimals: "$0.04". */
export const unitUsd = (micro: number, unit: BillingUnit) => usd(unitPriceText(micro, unit));

export const MAX_UNIT_PRICES = 32;
const selectorPattern = /^[a-z0-9x._-]+(?::[a-z0-9x._-]+)*$/;
/** Null when `key` is "*" or lowercase [a-z0-9x._-] segments joined by ":" with at most 64 characters. */
export function selectorError(key: string): string | null {
  if (key === '*') return null;
  if (!key) return 'Enter a selector, or * for the default price.';
  if (key.length > 64) return `Selector "${key.slice(0, 16)}…" is longer than 64 characters.`;
  return selectorPattern.test(key) ? null : `Selector "${key}" must be * or lowercase letters, digits, ".", "_" or "-" in segments joined by ":" (for example 1024x1024:hd).`;
}
/** Selectors in display order: the default first, then alphabetical. */
export const unitPriceEntries = (prices: Record<string, number> = {}) => Object.entries(prices).sort(([a], [b]) => a === '*' ? -1 : b === '*' ? 1 : a.localeCompare(b));
/**
 * A catalog route's customer unit prices by selector (fee included): its `unit_prices`, else the default price in
 * `media` as "*". Null when the route sets no unit price and so bills by the tokens its API reports.
 */
export function routeUnitPrices(route: { media?: MediaRates | null; unit_prices?: Record<string, number> | null }): Record<string, number> | null {
  if (route.unit_prices && Object.keys(route.unit_prices).length) return route.unit_prices;
  const fallback = route.media?.unit_microusd_per_million;
  return fallback == null ? null : { '*': fallback };
}
/** A catalog route's customer media prices as offer terms: its image and audio token rates and its unit prices by selector. */
export function routeMediaTerms(route: { media?: MediaRates | null; unit_prices?: Record<string, number> | null }): OfferMedia {
  const media: OfferMedia = {};
  for (const { key } of rateFields) { const value = route.media?.[key]; if (value != null) media[key] = value; }
  const prices = routeUnitPrices(route);
  if (prices) media.unit_prices = prices;
  return media;
}
/** The price for the first selector `prices` lists, most specific first, else the "*" price (the gateway's OfferMediaTerms::unit_price); null when neither is set. */
export function unitPriceFor(prices: Record<string, number> | null | undefined, selectors: readonly string[]): { selector: string; price: number } | null {
  if (!prices) return null;
  const selector = selectors.find(candidate => Object.hasOwn(prices, candidate)) ?? (Object.hasOwn(prices, '*') ? '*' : null);
  return selector === null ? null : { selector, price: prices[selector] };
}

export type UnitPriceRow = { selector: string; price: string };
export type MediaDraft = Record<RateKey, string> & { units: UnitPriceRow[] };
export const emptyMediaDraft = (): MediaDraft => ({ image_input_microusd_per_million: '', audio_input_microusd_per_million: '', image_output_microusd_per_million: '', audio_output_microusd_per_million: '', units: [{ selector: '*', price: '' }] });
/** Editable values for an offer's media terms; unit prices need the protocol's unit for their scale. */
export function mediaDraft(media: OfferMedia | undefined, protocol: string): MediaDraft {
  const draft = emptyMediaDraft(), unit = protocolUnit(protocol);
  for (const { key } of rateFields) { const value = media?.[key]; if (value != null) draft[key] = tokenPriceText(value); }
  const rows = unit ? unitPriceEntries(media?.unit_prices).map(([selector, value]) => ({ selector, price: unitPriceText(value, unit) })) : [];
  if (rows.length) draft.units = rows;
  return draft;
}
/**
 * Offer media terms for the fields `protocol` bills, or undefined when none is set (the backend treats absence as
 * text-only). An offer that `requiresUnitPrice` needs a default price. Throws an Error naming the first invalid field.
 */
export function parseOfferMedia(draft: MediaDraft, protocol: string, adapter?: string | null): OfferMedia | undefined {
  const media: OfferMedia = {}, unit = protocolUnit(protocol);
  for (const { key, label } of rateFieldsFor(protocol)) {
    if (!draft[key].trim()) continue;
    try { media[key] = parseTokenPrice(draft[key]); } catch (e) { throw new Error(`${label} price: ${(e as Error).message}`); }
  }
  if (unit) {
    const rows = draft.units.map(row => ({ selector: row.selector.trim(), price: row.price.trim() })).filter(row => row.selector !== '*' || row.price);
    if (rows.length > MAX_UNIT_PRICES) throw new Error(`Set at most ${MAX_UNIT_PRICES} unit prices.`);
    const prices: Record<string, number> = {};
    for (const row of rows) {
      const error = selectorError(row.selector); if (error) throw new Error(error);
      if (Object.hasOwn(prices, row.selector)) throw new Error(`Selector "${row.selector}" is listed twice.`);
      if (!row.price) throw new Error(`Enter a price for selector "${row.selector}".`);
      try { prices[row.selector] = parseUnitPrice(row.price, unit); } catch (e) { throw new Error(`Unit price for "${row.selector}": ${(e as Error).message}`); }
    }
    if (!Object.hasOwn(prices, '*') && requiresUnitPrice(protocol, adapter)) throw new Error(`Set a default (*) price per ${unitBasis(unit)}; this API settles only in units.`);
    if (rows.length && !Object.hasOwn(prices, '*')) throw new Error('Set a default (*) unit price before adding selectors.');
    if (rows.length) media.unit_prices = prices;
  }
  return Object.keys(media).length ? media : undefined;
}

/**
 * The media prices requests are charged at: with a default unit price, the unit prices alone, since a route that bills
 * units does not charge the tokens its API reports; else the image and audio token rates.
 */
export function chargedMedia(media: OfferMedia | undefined): OfferMedia | undefined {
  return media?.unit_prices && Object.hasOwn(media.unit_prices, '*') ? { unit_prices: media.unit_prices } : media;
}

const positive = (value: number | null | undefined): value is number => typeof value === 'number' && value > 0;
/** Lines of set media prices, e.g. "Image input $5.00 per million tokens", "1024x1024:hd $0.08 per image". */
export function mediaPriceLines(media: OfferMedia | MediaRates | null | undefined, unit: BillingUnit | null, format: (micro: number) => string): string[] {
  if (!media) return [];
  const lines = rateFields.flatMap(({ key, label }) => media[key] == null ? [] : [`${label} ${format(media[key]!)} per million tokens`]);
  if (!unit) return lines;
  if ('unit_prices' in media && media.unit_prices) for (const [selector, value] of unitPriceEntries(media.unit_prices)) lines.push(`${selector === '*' ? 'Default' : selector} ${formatUnitPrice(value, unit)}`);
  if ('unit_microusd_per_million' in media && media.unit_microusd_per_million != null) lines.push(formatUnitPrice(media.unit_microusd_per_million, unit));
  return lines;
}
export const hasMediaUsage = (usage: MediaUsage | null | undefined) => !!usage && [usage.image_input_tokens, usage.audio_input_tokens, usage.image_output_tokens, usage.audio_output_tokens, usage.units].some(positive);

/** Image, audio and unit counts for display; empty for text-only usage. */
export function mediaUsageParts(usage: MediaUsage | null | undefined) {
  const count = (value: number | undefined, label: string) => positive(value) ? [`${value.toLocaleString()} ${label}`] : [];
  const unit = isBillingUnit(usage?.unit) ? usage.unit : null;
  return {
    input: [...count(usage?.image_input_tokens, 'image'), ...count(usage?.audio_input_tokens, 'audio')],
    output: [...count(usage?.image_output_tokens, 'image'), ...count(usage?.audio_output_tokens, 'audio')],
    units: positive(usage?.units) ? `${usage.units.toLocaleString()} ${unit ? unitName(unit, usage.units) : 'units'}` : '',
  };
}

export type BillingUsage = { input_tokens: number; output_tokens: number; cache_read_input_tokens?: number; cache_write_input_tokens?: number; cache_write_1h_input_tokens?: number; image_input_tokens?: number; audio_input_tokens?: number; image_output_tokens?: number; audio_output_tokens?: number; units?: number };
export type BillingRecord = { input_microusd_per_million: number; output_microusd_per_million: number; cache_read_microusd_per_million: number; cache_write_microusd_per_million: number; cache_write_1h_microusd_per_million: number; billable_usage: BillingUsage; customer_media?: MediaRates | null; unit?: string | null };
export type BillingRow = { label: string; quantity: number; rate: number | null; units?: true; unit?: BillingUnit | null };
/**
 * Charge components that add up to the request charge. input_tokens includes the cache subsets, and the
 * uncached input and the output include their image and audio subsets, so each row shows only its own share.
 * Unset modality rates are the text rates. A request billed at a unit price charges its units alone: the tokens the
 * API reported are evidence, shown at rate 0. A unit row without a unit price has rate null; the gateway bills a route
 * without a unit price by tokens and rejects units from it, so new charges do not have one.
 */
export function billingRows(b: BillingRecord): BillingRow[] {
  const u = b.billable_usage, m = b.customer_media || {};
  const tokens = m.unit_microusd_per_million == null, rate = (value: number) => tokens ? value : 0;
  const read = u.cache_read_input_tokens ?? 0, write = u.cache_write_input_tokens ?? 0, write1h = u.cache_write_1h_input_tokens ?? 0;
  const imageIn = u.image_input_tokens ?? 0, audioIn = u.audio_input_tokens ?? 0, imageOut = u.image_output_tokens ?? 0, audioOut = u.audio_output_tokens ?? 0;
  const mediaIn = imageIn || audioIn, mediaOut = imageOut || audioOut;
  const rows: BillingRow[] = [{ label: read || write ? mediaIn ? 'Input · uncached text' : 'Input · uncached' : mediaIn ? 'Input · text' : 'Input', quantity: u.input_tokens - read - write - imageIn - audioIn, rate: rate(b.input_microusd_per_million) }];
  if (imageIn) rows.push({ label: 'Input · image', quantity: imageIn, rate: rate(m.image_input_microusd_per_million ?? b.input_microusd_per_million) });
  if (audioIn) rows.push({ label: 'Input · audio', quantity: audioIn, rate: rate(m.audio_input_microusd_per_million ?? b.input_microusd_per_million) });
  if (read) rows.push({ label: 'Input · cache read', quantity: read, rate: rate(b.cache_read_microusd_per_million) });
  if (write - write1h) rows.push({ label: 'Input · cache write', quantity: write - write1h, rate: rate(b.cache_write_microusd_per_million) });
  if (write1h) rows.push({ label: 'Input · 1-hour cache write', quantity: write1h, rate: rate(b.cache_write_1h_microusd_per_million) });
  rows.push({ label: mediaOut ? 'Output · text' : 'Output', quantity: u.output_tokens - imageOut - audioOut, rate: rate(b.output_microusd_per_million) });
  if (imageOut) rows.push({ label: 'Output · image', quantity: imageOut, rate: rate(m.image_output_microusd_per_million ?? b.output_microusd_per_million) });
  if (audioOut) rows.push({ label: 'Output · audio', quantity: audioOut, rate: rate(m.audio_output_microusd_per_million ?? b.output_microusd_per_million) });
  if (positive(u.units)) { const unit = isBillingUnit(b.unit) ? b.unit : null; rows.push({ label: unit ? `Units · ${unitName(unit, 2)}` : 'Units', quantity: u.units, rate: m.unit_microusd_per_million ?? null, units: true, unit }); }
  return rows;
}

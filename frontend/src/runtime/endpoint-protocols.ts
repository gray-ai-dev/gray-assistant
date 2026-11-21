import { protocolModality, type Modality } from './media-price.ts';

/** Every gray-control Protocol, by its serde name. */
export type ProtocolId = 'open_ai_chat' | 'open_ai_responses' | 'anthropic_messages' | 'gemini' | 'system_one' | 'open_ai_embeddings' | 'rerank'
  | 'open_ai_image_generations' | 'open_ai_image_edits' | 'open_ai_speech' | 'open_ai_transcriptions' | 'open_ai_translations' | 'open_ai_videos';

/**
 * Provider-facing protocol choices for an endpoint mapping, with the gateway's native request path
 * (Protocol::endpoint_path). Gemini's path names the upstream model, so it has none of its own here: see
 * `defaultNativePath`.
 */
export const endpointProtocols: { id: ProtocolId; label: string; path: string | null }[] = [
  { id: 'open_ai_chat', label: 'OpenAI Chat', path: '/v1/chat/completions' },
  { id: 'open_ai_responses', label: 'OpenAI Responses', path: '/v1/responses' },
  { id: 'anthropic_messages', label: 'Anthropic Messages', path: '/v1/messages' },
  { id: 'gemini', label: 'Gemini', path: null },
  { id: 'system_one', label: 'System One', path: '/v1/systemone' },
  { id: 'open_ai_embeddings', label: 'OpenAI Embeddings', path: '/v1/embeddings' },
  { id: 'rerank', label: 'Rerank', path: '/v1/rerank' },
  { id: 'open_ai_image_generations', label: 'OpenAI Image generations', path: '/v1/images/generations' },
  { id: 'open_ai_image_edits', label: 'OpenAI Image edits', path: '/v1/images/edits' },
  { id: 'open_ai_speech', label: 'OpenAI Speech', path: '/v1/audio/speech' },
  { id: 'open_ai_transcriptions', label: 'OpenAI Transcriptions', path: '/v1/audio/transcriptions' },
  { id: 'open_ai_translations', label: 'OpenAI Translations', path: '/v1/audio/translations' },
  { id: 'open_ai_videos', label: 'OpenAI Videos', path: '/v1/videos' },
];
const modalityGroups: Record<Modality, string> = { text: 'Text', embeddings: 'Embeddings', image: 'Image', audio: 'Audio', video: 'Video' };
/** The protocol choices grouped by modality, in table order. */
export function protocolGroups() {
  const groups: { label: string; protocols: typeof endpointProtocols }[] = [];
  for (const protocol of endpointProtocols) {
    const label = modalityGroups[protocolModality(protocol.id) ?? 'text'];
    const group = groups.find(item => item.label === label);
    if (group) group.protocols.push(protocol); else groups.push({ label, protocols: [protocol] });
  }
  return groups;
}
export const isProtocolId = (value: unknown): value is ProtocolId => endpointProtocols.some(protocol => protocol.id === value);
export const endpointProtocolLabel = (id: string) => endpointProtocols.find(protocol => protocol.id === id)?.label ?? id;
/** A base URL Gray can call, or null while it is not one (still being typed, another scheme, a query or a user). */
function parsedBase(baseUrl: string): URL | null {
  let url: URL;
  try { url = new URL(baseUrl.trim()); } catch { return null; }
  return (url.protocol === 'https:' || url.protocol === 'http:') && !url.username && !url.password && !url.search && !url.hash ? url : null;
}
/** A base URL's path without its trailing slashes: '' for a bare host, or while the URL is not one. */
function basePath(baseUrl: string): string {
  let path = parsedBase(baseUrl)?.pathname ?? '';
  while (path.endsWith('/')) path = path.slice(0, -1);
  return path;
}
/**
 * The native request path Gray fills in for a mapping: the path a check takes when it is given none (verifier
 * runner.ts `nativeUrl`, runner.rs `native_url`): the base URL's path, its trailing slashes dropped, then `/v1`
 * (Gemini's `/v1beta`) unless the path already ends in it, then the protocol's own path. So base URLs
 * `https://openrouter.ai/api/v1` and `https://openrouter.ai/api` both give `/api/v1/chat/completions`, and
 * `https://api.example.com` gives `/v1/chat/completions`. Gray sends a stored path as written, in place of the base
 * URL's path (`requestUrl`), so the path is filled in whole. Gemini's names the upstream model,
 * `…/v1beta/models/<upstream model>:generateContent` (switched to `:streamGenerateContent` for a stream), so it is blank
 * until that model is known. Blank for an unknown protocol.
 */
export function defaultNativePath(protocol: string, upstreamModel = '', baseUrl = ''): string {
  const gemini = protocol === 'gemini', model = upstreamModel.trim();
  const own = gemini ? (model ? `/models/${model}:generateContent` : '') : (endpointProtocols.find(item => item.id === protocol)?.path?.slice('/v1'.length) ?? '');
  if (!own) return '';
  const version = gemini ? '/v1beta' : '/v1', prefix = basePath(baseUrl);
  return `${prefix.endsWith(version) ? prefix : `${prefix}${version}`}${own}`;
}
/** The Gemini default the console once filled in. Nothing substitutes `{model}`, so a mapping saved with it never worked. */
const RETIRED_GEMINI_TEMPLATE = '/v1beta/models/{model}:generateContent';
/**
 * Whether Gray filled in `path` for this protocol, upstream model and base URL: blank, the retired Gemini template, the
 * default under the base URL's path, or the default under none (what Gray filled in before it read the base URL).
 */
export function isFilledInPath(path: string, protocol: string, upstreamModel: string, baseUrl = '') {
  const value = path.trim();
  return !value || value === RETIRED_GEMINI_TEMPLATE || value === defaultNativePath(protocol, upstreamModel) || value === defaultNativePath(protocol, upstreamModel, baseUrl);
}
type PathInputs = { protocol: string; upstream: string; base?: string };
/**
 * The native path after a mapping's protocol, upstream model or base URL changes from `before` to `after`: a path Gray
 * filled in follows them, so a Gemini path keeps naming the upstream model and a path stays under the base URL's; a
 * path the provider typed stays as typed.
 */
export function followNativePath(path: string, before: PathInputs, after: PathInputs): string {
  return isFilledInPath(path, before.protocol, before.upstream, before.base) && isProtocolId(after.protocol) ? defaultNativePath(after.protocol, after.upstream, after.base) : path;
}

/**
 * `valid_native_path` (verifier runner.ts `validNativePath`): a path a check sends as written. A check of any other
 * path sends nothing (`invalid_target`).
 */
export function validNativePath(path: string): boolean {
  return path.startsWith('/') && !path.startsWith('//') && new TextEncoder().encode(path).length <= 2048
    && !/[\p{Cc}?#\\%{}]/u.test(path) && !path.split('/').some(part => part === '.' || part === '..');
}
/**
 * `gemini_method_path` (@gray/protocol paths.ts `geminiMethodPath`): a Gemini native path with `method` in place of the
 * method it names; null when its last segment names no model with a generation method.
 */
function geminiMethodPath(path: string, method: string): string | null {
  const colon = path.lastIndexOf(':');
  if (colon < 0) return null;
  const prefix = path.slice(0, colon), named = path.slice(colon + 1);
  if (!prefix.slice(prefix.lastIndexOf('/') + 1) || (named !== 'generateContent' && named !== 'streamGenerateContent')) return null;
  return `${prefix}:${method}`;
}
/**
 * Where Gray sends a mapping's requests, its checks and customers' alike (verifier runner.ts `nativeUrl` with a native
 * path; serving's `routeUrl` and `geminiOperationUrl`): the base URL with its path replaced by the native path, a Gemini
 * path's method by the call's (`streamGenerateContent` and `?alt=sse` for a stream). Null while the base URL or the
 * path cannot be used, as a check then sends nothing.
 */
export function requestUrl(baseUrl: string, nativePath: string, protocol: string, stream = false): string | null {
  const url = parsedBase(baseUrl), path = nativePath.trim();
  if (!url || !validNativePath(path)) return null;
  const sent = protocol === 'gemini' ? geminiMethodPath(path, stream ? 'streamGenerateContent' : 'generateContent') : path;
  if (sent === null) return null;
  const host = url.host;
  url.pathname = sent;
  url.search = stream && protocol === 'gemini' ? 'alt=sse' : '';
  return url.host === host ? url.href : null;
}
/**
 * Where Gray reads an API's model list (verifier discovery.ts `catalogPath` and `pageQuery`): one GET at the base URL's
 * path plus `/v1/models`, or `/models` under a path ending in `/v1`; Gemini's at `/v1beta/models`, or `/models` under a
 * path ending in `/v1beta`, where its requests go too (`defaultNativePath`). Anthropic's list asks for 1,000 models a
 * page and Gemini's too. Null while the base URL is not one Gray can call.
 */
export function catalogUrl(baseUrl: string, protocol: string): string | null {
  const url = parsedBase(baseUrl);
  if (!url) return null;
  const prefix = basePath(baseUrl);
  url.pathname = protocol === 'gemini'
    ? prefix.endsWith('/v1beta') ? `${prefix}/models` : `${prefix}/v1beta/models`
    : prefix.endsWith('/v1') ? `${prefix}/models` : `${prefix}/v1/models`;
  url.search = protocol === 'anthropic_messages' ? 'limit=1000' : protocol === 'gemini' ? 'pageSize=1000' : '';
  return url.href;
}

export type AdapterId = 'gemini' | 'volcengine' | 'minimax' | 'kling' | 'fal';
/**
 * Vendor-native media APIs (gray-media-adapters). `protocols` is what each serves (gray-control adapter_serves, from
 * Vendor::supports); `baseUrls` carry the vendor's API version and become the endpoint base URL.
 */
export const mediaAdapters: { id: AdapterId; label: string; protocols: ProtocolId[]; baseUrls: string[]; credential: string }[] = [
  { id: 'gemini', label: 'Google Gemini (Imagen, Veo)', protocols: ['open_ai_image_generations', 'open_ai_image_edits', 'open_ai_videos'], baseUrls: ['https://generativelanguage.googleapis.com/v1beta'], credential: 'A Gemini API key.' },
  { id: 'volcengine', label: 'Volcengine Ark / BytePlus ModelArk', protocols: ['open_ai_image_generations', 'open_ai_image_edits', 'open_ai_videos'], baseUrls: ['https://ark.cn-beijing.volces.com/api/v3', 'https://ark.ap-southeast.bytepluses.com/api/v3'], credential: 'An Ark API key.' },
  { id: 'minimax', label: 'MiniMax', protocols: ['open_ai_image_generations', 'open_ai_image_edits', 'open_ai_speech', 'open_ai_videos'], baseUrls: ['https://api.minimax.io/v1', 'https://api.minimax.cn/v1'], credential: 'A MiniMax API key.' },
  { id: 'kling', label: 'Kling', protocols: ['open_ai_image_generations', 'open_ai_image_edits', 'open_ai_videos'], baseUrls: ['https://api-singapore.klingai.com/v1'], credential: 'Your access key and secret key joined by a colon: access_key:secret_key. Gray signs a short-lived token for each call.' },
  { id: 'fal', label: 'fal', protocols: ['open_ai_image_generations', 'open_ai_image_edits', 'open_ai_videos'], baseUrls: ['https://queue.fal.run'], credential: 'A fal API key.' },
];
export const adaptersFor = (protocol: string) => mediaAdapters.filter(adapter => (adapter.protocols as string[]).includes(protocol));
export const adapterServes = (adapter: string, protocol: string) => adaptersFor(protocol).some(item => item.id === adapter);
export const mediaAdapter = (id: string | null | undefined) => mediaAdapters.find(adapter => adapter.id === id) ?? null;

export type MappingFields = { protocol: string; native_path: string; adapter?: string | null; upstream_model?: string };
/**
 * A mapping after its protocol changes: a native path Gray filled in follows the protocol (`followNativePath`), and
 * an adapter that does not serve the new protocol is dropped.
 */
export function withProtocol<M extends MappingFields>(mapping: M, protocol: string, base = ''): M {
  const upstream = mapping.upstream_model ?? '';
  const next: M = { ...mapping, protocol, native_path: followNativePath(mapping.native_path, { protocol: mapping.protocol, upstream, base }, { protocol, upstream, base }) };
  if (next.adapter && !adapterServes(next.adapter, protocol)) delete next.adapter;
  return next;
}
/** A mapping after its upstream model changes: a Gemini path Gray filled in keeps naming the upstream model. */
export function withUpstreamModel<M extends MappingFields>(mapping: M, upstream: string, base = ''): M {
  return { ...mapping, upstream_model: upstream, native_path: followNativePath(mapping.native_path, { protocol: mapping.protocol, upstream: mapping.upstream_model ?? '', base }, { protocol: mapping.protocol, upstream, base }) };
}
/** A mapping after the endpoint's base URL changes from `before` to `after`: a path Gray filled in moves under the new base URL's path. */
export function withBaseUrl<M extends MappingFields>(mapping: M, before: string, after: string): M {
  const upstream = mapping.upstream_model ?? '';
  return { ...mapping, native_path: followNativePath(mapping.native_path, { protocol: mapping.protocol, upstream, base: before }, { protocol: mapping.protocol, upstream, base: after }) };
}
/**
 * A stored mapping as the edit form opens it: the retired Gemini template becomes the path that names the upstream
 * model, so saving the edit repairs a mapping that could never pass its check. Any other path is left as saved.
 */
export function repairedMapping<M extends MappingFields>(mapping: M, base = ''): M {
  return mapping.native_path.trim() === RETIRED_GEMINI_TEMPLATE && mapping.protocol === 'gemini' && mapping.upstream_model?.trim()
    ? { ...mapping, native_path: defaultNativePath('gemini', mapping.upstream_model, base) } : mapping;
}
/** A mapping with `adapter` set, or without the field when none is chosen: the control API rejects an empty adapter and omits an unset one. */
export function withAdapter<M extends MappingFields>(mapping: M, adapter: string): M {
  const next: M = { ...mapping };
  if (adapter) next.adapter = adapter; else delete next.adapter;
  return next;
}
/** The mapping as saved: no adapter field unless a known adapter that serves its protocol is chosen. */
export function mappingForSave<M extends MappingFields>(mapping: M): M {
  return withAdapter(mapping, mapping.adapter && adapterServes(mapping.adapter, mapping.protocol) ? mapping.adapter : '');
}
/** Why a mapping's native path would fail the control API's validation, or null. */
export function nativePathError(path: string): string | null {
  if (!path.startsWith('/') || path.startsWith('//')) return 'The native request path must start with a single "/".';
  if (/[?#]/.test(path)) return 'The native request path cannot contain "?" or "#".';
  if (/[{}]/.test(path)) return 'Gray sends the path exactly as written and fills in no placeholder. Write the upstream model ID into it, e.g. /v1beta/models/gemini-2.5-flash:generateContent.';
  return null;
}

/**
 * How an upstream takes its key (`EndpointConfig.auth`). `lane_relay` is a stored kind, never a choice here:
 * a confidential-lane relay's credential is the sentinel of its lane record, not a key Gray sends.
 */
export type UpstreamAuth = 'protocol_native' | 'bearer' | 'lane_relay';
/** The choices in plain words; `AuthField` (EndpointProtocolFields.tsx) names the headers Gray sends. */
export const upstreamAuthChoices: { id: UpstreamAuth; label: string }[] = [
  { id: 'protocol_native', label: 'Each protocol’s own header' },
  { id: 'bearer', label: 'Authorization: Bearer for every protocol' },
];
export const isUpstreamAuth = (value: unknown): value is UpstreamAuth => upstreamAuthChoices.some(choice => choice.id === value);
/**
 * `config` with `auth` set, or without the field for the default: the control API leaves the default out, so an
 * endpoint saved without it keeps its configuration fingerprint (and its checks).
 */
export function withAuth<C extends { auth?: UpstreamAuth }>(config: C, auth: UpstreamAuth): C {
  const next: C = { ...config };
  if (auth === 'bearer') next.auth = auth; else delete next.auth;
  return next;
}

/** A model ID the control API registers (gray-control `valid_model_id`): a letter or digit, then letters, digits and
 * `. _ : @ + / -`, at most 256 characters. */
const MODEL_ID = /^[A-Za-z0-9][A-Za-z0-9._:@+/-]{0,255}$/;
export const validModelId = (id: string) => MODEL_ID.test(id);
/** Why a model ID typed for Gray would be refused, or null. */
export function modelIdError(id: string): string | null {
  return validModelId(id) ? null : 'A model ID starts with a letter or digit and uses only letters, digits and . _ : @ + / -, at most 256 characters.';
}

/**
 * The input allowance for hidden prompt text (`EndpointConfig.prompt_overhead_tokens`): every endpoint gets the
 * default, and a provider whose API adds its own hidden prompt to every request declares up to the maximum.
 */
export const PROMPT_OVERHEAD_TOKENS = { default: 4096, max: 65_536 };
/** The allowance as typed: null when blank, which is the default; an error when it is not a whole number in range. */
export function parsePromptOverhead(text: string): number | null {
  const value = text.trim().replaceAll(',', '');
  if (!value) return null;
  const tokens = Number(value);
  if (!/^\d+$/.test(value) || tokens < PROMPT_OVERHEAD_TOKENS.default || tokens > PROMPT_OVERHEAD_TOKENS.max) {
    throw new Error(`Enter a hidden prompt allowance from ${PROMPT_OVERHEAD_TOKENS.default.toLocaleString('en-US')} to ${PROMPT_OVERHEAD_TOKENS.max.toLocaleString('en-US')} tokens, or leave it empty.`);
  }
  return tokens;
}
/**
 * `config` with the allowance set, or without the field for the default (blank or 4,096): the control API leaves it
 * out, so an endpoint saved without one keeps its configuration fingerprint (and its checks).
 */
export function withPromptOverhead<C extends { prompt_overhead_tokens?: number | null }>(config: C, tokens: number | null): C {
  const next: C = { ...config };
  if (tokens !== null && tokens !== PROMPT_OVERHEAD_TOKENS.default) next.prompt_overhead_tokens = tokens; else delete next.prompt_overhead_tokens;
  return next;
}
/** The allowance an endpoint gets, for display. */
export const promptOverheadOf = (config: { prompt_overhead_tokens?: number | null }) => config.prompt_overhead_tokens ?? PROMPT_OVERHEAD_TOKENS.default;

/**
 * The output an endpoint's API may bill beyond a request's own limit (`EndpointConfig.output_overhead_tokens`), for a
 * model whose reasoning the limit does not bound: none by default, up to the maximum when declared.
 */
export const OUTPUT_OVERHEAD_TOKENS = { min: 1, max: 65_536 };
/** The output allowance as typed: null when blank, which declares none; an error when it is not a whole number in range. */
export function parseOutputOverhead(text: string): number | null {
  const value = text.trim().replaceAll(',', '');
  if (!value) return null;
  const tokens = Number(value);
  if (!/^\d+$/.test(value) || tokens < OUTPUT_OVERHEAD_TOKENS.min || tokens > OUTPUT_OVERHEAD_TOKENS.max) {
    throw new Error(`Enter an output allowance from ${OUTPUT_OVERHEAD_TOKENS.min.toLocaleString('en-US')} to ${OUTPUT_OVERHEAD_TOKENS.max.toLocaleString('en-US')} tokens, or leave it empty.`);
  }
  return tokens;
}
/** `config` with the output allowance set, or without the field for none, as the control API saves an endpoint without one. */
export function withOutputOverhead<C extends { output_overhead_tokens?: number | null }>(config: C, tokens: number | null): C {
  const next: C = { ...config };
  if (tokens) next.output_overhead_tokens = tokens; else delete next.output_overhead_tokens;
  return next;
}
/** The output allowance an endpoint declares, 0 for none. */
export const outputOverheadOf = (config: { output_overhead_tokens?: number | null }) => config.output_overhead_tokens ?? 0;

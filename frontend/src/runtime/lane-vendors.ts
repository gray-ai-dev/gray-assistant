// The lane's OpenAI-compatible vendors, as the panel names them: the console's table
// (workers/packages/lane/vendors/openai-compatible-vendors.json, @gray/lane vendors.ts; relay-stack.test.mjs holds this
// list to it). Each is an API-key account that serves OpenAI Chat Completions only, on one host; `publisher` is the Gray
// model ID prefix of the vendor's own models, which the model picker offers. Pure data, so `node --test` loads it.
export const COMPATIBLE_VENDORS = [
  { id: 'gemini', name: 'Google Gemini', publisher: 'google' },
  { id: 'deepseek', name: 'DeepSeek', publisher: 'deepseek' },
  { id: 'moonshot', name: 'Moonshot Kimi', publisher: 'moonshotai' },
  { id: 'moonshot_cn', name: 'Moonshot Kimi (China)', publisher: 'moonshotai' },
  { id: 'zhipu', name: 'Z.ai GLM', publisher: 'z-ai' },
  { id: 'zhipu_cn', name: 'Zhipu GLM (China)', publisher: 'z-ai' },
  { id: 'minimax', name: 'MiniMax', publisher: 'minimax' },
  { id: 'minimax_cn', name: 'MiniMax (China)', publisher: 'minimax' },
  { id: 'qwen', name: 'Qwen (Model Studio)', publisher: 'qwen' },
  { id: 'qwen_cn', name: 'Qwen (Model Studio China)', publisher: 'qwen' },
] as const;
export type CompatibleVendor = (typeof COMPATIBLE_VENDORS)[number]['id'];
export const isCompatibleVendor = (vendor: string): vendor is CompatibleVendor => COMPATIBLE_VENDORS.some(v => v.id === vendor);
/** One value per OpenAI-compatible vendor, keyed by its id. */
export const compatibleRows = <T,>(of: (vendor: (typeof COMPATIBLE_VENDORS)[number]) => T) =>
  Object.fromEntries(COMPATIBLE_VENDORS.map(v => [v.id, of(v)])) as Record<CompatibleVendor, T>;

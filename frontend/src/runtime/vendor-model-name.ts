// The vendor's own name for a Gray model ID, as Gray suggests it, and the way back, and which catalog models a stack
// vendor can serve at all. One rule for the panel's model form (relay-stack.ts, RelayStackSetup.tsx) and the console's
// `GET /v1/setup/relay-models.json` (workers/console/src/provider-setup/relay-models.ts), which imports this file.
// Pure, so `node --test` loads it.

/**
 * The vendor's name suggested for a Gray model ID: the ID without its publisher, and Anthropic's with dashes for dots,
 * as its API spells versions (`anthropic/claude-opus-5.5` → `claude-opus-5-5`). Only a suggestion: the relay keeps the
 * name its accounts call.
 */
export function vendorModelName(vendor: string, id: string): string {
  const name = id.slice(id.indexOf('/') + 1);
  return vendor === 'anthropic' ? name.replaceAll('.', '-') : name;
}

/**
 * The way back: the vendor's name each of `ids` is suggested as for `vendor`, with every Gray model ID that gives it
 * (more than one when two IDs differ only where the rule makes them the same). Names and IDs in the order `ids` has.
 */
export function upstreamIndex(vendor: string, ids: readonly string[]): Map<string, string[]> {
  const index = new Map<string, string[]>();
  for (const id of ids) {
    const name = vendorModelName(vendor, id);
    const known = index.get(name);
    if (known === undefined) index.set(name, [id]);
    else if (!known.includes(id)) known.push(id);
  }
  return index;
}

/**
 * Whether a stack vendor can serve a catalog model at all: a relay stack speaks Anthropic Messages, OpenAI Chat
 * Completions and OpenAI Responses only (@gray/lane `LANE_PROTOCOLS`), which answer with text, so a model whose output
 * has no text (embeddings, transcription, an image-only model) is no stack vendor's. A model whose output the catalog
 * does not state is kept.
 */
export function stackServes(model: { readonly output_modalities?: readonly string[] | null }): boolean {
  const output = model.output_modalities;
  return output === undefined || output === null || output.length === 0 || output.includes('text');
}

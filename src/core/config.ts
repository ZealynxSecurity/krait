import { KraitConfig, DEFAULT_CONFIG } from './types.js';

export function resolveConfig(overrides: Partial<KraitConfig> = {}): KraitConfig {
  const apiKey = overrides.apiKey || process.env.ANTHROPIC_API_KEY;
  if (!apiKey) {
    throw new Error(
      'Anthropic API key required. Set ANTHROPIC_API_KEY env var or pass --api-key flag.'
    );
  }

  // Strip undefined values so they don't override defaults
  const cleaned: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(overrides)) {
    if (value !== undefined) {
      cleaned[key] = value;
    }
  }

  return {
    ...DEFAULT_CONFIG,
    ...cleaned,
    apiKey,
  } as KraitConfig;
}

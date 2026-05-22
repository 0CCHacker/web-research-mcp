/**
 * Zod schemas for tool inputs and a builder for Gemini responseSchema.
 */
import { z } from 'zod';

// ── Tool input schemas ────────────────────────────────────────────────────────

export const FetchPageInputSchema = z.object({
  url: z.string().url('Must be a valid URL (http or https).'),
});

export const ExtractDataInputSchema = z.object({
  url: z.string().url('Must be a valid URL (http or https).'),
  fields: z
    .string()
    .min(1, 'fields must not be empty.')
    .max(1000, 'fields description too long (max 1000 chars).'),
});

export const SummarizePageInputSchema = z.object({
  url: z.string().url('Must be a valid URL (http or https).'),
  focus: z.string().max(500, 'focus hint too long (max 500 chars).').optional(),
});

// ── Gemini JSON response schema builder ───────────────────────────────────────

/**
 * Builds a Gemini responseSchema (OpenAPI-subset object) that asks the model
 * to return a JSON object with the keys it inferred from the plain-English
 * `fields` description.
 *
 * We can't know the exact keys in advance, so we use:
 *   type: "object", additionalProperties: { type: "string" }
 * which is the broadest safe schema for Gemini's structured-output mode.
 */
export function buildExtractionResponseSchema(): object {
  return {
    type: 'object',
    description: 'Extracted fields as key-value pairs.',
    additionalProperties: {
      type: 'string',
    },
  };
}

// ── Runtime validation of Gemini extraction output ───────────────────────────

export const ExtractionOutputSchema = z
  .record(z.string(), z.unknown())
  .refine((v) => Object.keys(v).length > 0, {
    message: 'Extraction returned an empty object.',
  });

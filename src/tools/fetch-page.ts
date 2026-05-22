/**
 * fetch_page tool
 * ──────────────
 * SSRF-guarded fetch → robots.txt check → HTML clean → readable text.
 * Works with NO Google credentials.
 */
import { safeFetch } from '../lib/fetch.js';
import { cleanHtml, MAX_TEXT_CHARS } from '../lib/clean.js';
import { checkRobots } from '../lib/robots.js';

export type FetchPageResult =
  | { ok: true; text: string; title: string; truncated: boolean; finalUrl: string; bytes: number }
  | { ok: false; error: string };

export async function fetchPage(url: string): Promise<FetchPageResult> {
  // 1. robots.txt compliance (runs its own SSRF-guarded fetch internally)
  const robots = await checkRobots(url);
  if (!robots.allowed) {
    return { ok: false, error: `Blocked by robots.txt: ${robots.reason}` };
  }

  // 2. Safe fetch (SSRF guard + timeout + size cap + manual redirects)
  const fetched = await safeFetch(url);
  if (!fetched.ok) {
    return { ok: false, error: `Fetch failed (${fetched.code}): ${fetched.message}` };
  }

  // 3. Clean HTML → readable text
  const { text, truncated, title } = cleanHtml(fetched.body);

  const truncationNote = truncated
    ? `\n\n[Content was truncated at ${MAX_TEXT_CHARS.toLocaleString()} characters. The page may have additional content.]`
    : '';

  return {
    ok: true,
    text: text + truncationNote,
    title,
    truncated,
    finalUrl: fetched.finalUrl,
    bytes: fetched.bytes,
  };
}

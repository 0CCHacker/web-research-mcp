/**
 * robots.txt compliance check.
 * Caches results in memory for the process lifetime to avoid
 * repeated fetches during a single MCP session.
 */
import { createRequire } from 'node:module';
const _require = createRequire(import.meta.url);
// robots-parser is a CJS module; its .d.ts ambient declaration is not
// compatible with NodeNext module resolution for default imports.
const robotsParser = _require('robots-parser') as (url: string, robotstxt: string) => {
  isAllowed(url: string, ua?: string): boolean | undefined;
  isDisallowed(url: string, ua?: string): boolean | undefined;
  getCrawlDelay(ua?: string): number | undefined;
  getSitemaps(): string[];
  getPreferredHost(): string | null;
};
import { safeFetch, USER_AGENT } from './fetch.js';

type CacheEntry = { body: string; fetchedAt: number };

// In-process cache: robots.txt is re-fetched after 24 hours
const cache = new Map<string, CacheEntry>();
const CACHE_TTL_MS = 24 * 60 * 60 * 1000;

export type RobotsResult = { allowed: true } | { allowed: false; reason: string };

export async function checkRobots(targetUrl: string): Promise<RobotsResult> {
  let origin: string;
  try {
    origin = new URL(targetUrl).origin;
  } catch {
    return { allowed: false, reason: 'Invalid URL — cannot determine origin for robots.txt check.' };
  }

  const now = Date.now();
  let entry = cache.get(origin);
  if (!entry || now - entry.fetchedAt > CACHE_TTL_MS) {
    const r = await safeFetch(`${origin}/robots.txt`);
    const body = r.ok ? r.body : '';
    entry = { body, fetchedAt: now };
    cache.set(origin, entry);
  }

  // If we got no robots.txt (404, fetch error, etc.) → treat as allow-all
  if (!entry.body) return { allowed: true };

  const parser = robotsParser(`${origin}/robots.txt`, entry.body);
  const allowed = parser.isAllowed(targetUrl, USER_AGENT);

  if (allowed === false) {
    return {
      allowed: false,
      reason: `robots.txt on ${origin} disallows crawling by ${USER_AGENT}.`,
    };
  }
  return { allowed: true };
}

/**
 * Safe fetch: 8-second timeout, 2 MB body cap, manual redirect handling
 * with SSRF re-validation on every hop.
 */
import { ssrfGuard } from './ssrf.js';

export const FETCH_TIMEOUT_MS = 8_000;
export const MAX_BODY_BYTES = 2 * 1024 * 1024; // 2 MB
export const MAX_REDIRECTS = 5;
export const USER_AGENT = 'WebResearchMCP/0.1 (+https://github.com/0CCHacker)';

export type FetchOk = {
  ok: true;
  finalUrl: string;
  status: number;
  contentType: string;
  bytes: number;
  body: string;
};

export type FetchFail = {
  ok: false;
  code:
    | 'BLOCKED_SCHEME'
    | 'BLOCKED_HOSTNAME'
    | 'BLOCKED_PRIVATE_IP'
    | 'DNS_FAIL'
    | 'TIMEOUT'
    | 'TOO_LARGE'
    | 'TOO_MANY_REDIRECTS'
    | 'HTTP_ERROR'
    | 'FETCH_FAIL';
  message: string;
  status?: number;
};

export async function safeFetch(rawUrl: string): Promise<FetchOk | FetchFail> {
  let currentUrl = rawUrl;

  for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
    // SSRF guard on EVERY hop — including redirects
    const guard = await ssrfGuard(currentUrl);
    if (!guard.ok) {
      return { ok: false, code: guard.code, message: guard.message };
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);

    let response: Response;
    try {
      response = await fetch(guard.url.toString(), {
        method: 'GET',
        redirect: 'manual', // we handle redirects ourselves to re-validate each hop
        signal: controller.signal,
        headers: {
          'User-Agent': USER_AGENT,
          Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
          'Accept-Language': 'en-US,en;q=0.9',
        },
      });
    } catch (err) {
      clearTimeout(timer);
      const msg = err instanceof Error ? err.message : 'fetch failed';
      if ((err instanceof Error && err.name === 'AbortError') || msg.includes('aborted')) {
        return { ok: false, code: 'TIMEOUT', message: `Request timed out after ${FETCH_TIMEOUT_MS}ms.` };
      }
      return { ok: false, code: 'FETCH_FAIL', message: msg };
    }

    // Handle redirects manually
    if (response.status >= 300 && response.status < 400) {
      clearTimeout(timer);
      const loc = response.headers.get('location');
      if (!loc) {
        return {
          ok: false,
          code: 'HTTP_ERROR',
          message: 'Redirect response missing Location header.',
          status: response.status,
        };
      }
      try {
        currentUrl = new URL(loc, guard.url).toString();
      } catch {
        return {
          ok: false,
          code: 'HTTP_ERROR',
          message: `Invalid redirect target: ${loc}`,
          status: response.status,
        };
      }
      continue;
    }

    if (!response.ok) {
      clearTimeout(timer);
      return {
        ok: false,
        code: 'HTTP_ERROR',
        message: `Server returned HTTP ${response.status}.`,
        status: response.status,
      };
    }

    const contentType = response.headers.get('content-type') ?? 'text/html';
    const body = await readBodyCapped(response, controller, timer);
    if (!body.ok) return body;

    return {
      ok: true,
      finalUrl: guard.url.toString(),
      status: response.status,
      contentType,
      bytes: body.bytes,
      body: body.text,
    };
  }

  return {
    ok: false,
    code: 'TOO_MANY_REDIRECTS',
    message: `Exceeded ${MAX_REDIRECTS} redirects.`,
  };
}

async function readBodyCapped(
  response: Response,
  controller: AbortController,
  timer: ReturnType<typeof setTimeout>
): Promise<{ ok: true; text: string; bytes: number } | FetchFail> {
  const reader = response.body?.getReader();
  if (!reader) {
    clearTimeout(timer);
    return { ok: false, code: 'FETCH_FAIL', message: 'No response body.' };
  }

  const decoder = new TextDecoder('utf-8', { fatal: false });
  let total = 0;
  let text = '';

  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > MAX_BODY_BYTES) {
        controller.abort();
        clearTimeout(timer);
        return {
          ok: false,
          code: 'TOO_LARGE',
          message: `Response body exceeded the ${MAX_BODY_BYTES / 1024 / 1024} MB cap.`,
        };
      }
      text += decoder.decode(value, { stream: true });
    }
    text += decoder.decode(); // flush
  } catch (err) {
    clearTimeout(timer);
    const msg = err instanceof Error ? err.message : 'stream error';
    if ((err instanceof Error && err.name === 'AbortError') || msg.includes('aborted')) {
      return { ok: false, code: 'TIMEOUT', message: `Body read timed out after ${FETCH_TIMEOUT_MS}ms.` };
    }
    return { ok: false, code: 'FETCH_FAIL', message: msg };
  }

  clearTimeout(timer);
  return { ok: true, text, bytes: total };
}

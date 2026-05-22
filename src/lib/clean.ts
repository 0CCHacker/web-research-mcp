/**
 * HTML → readable text extractor using cheerio.
 * Strips chrome (nav, footer, scripts, styles) and returns plain text
 * suitable for LLM consumption.
 */
import * as cheerio from 'cheerio';

export const MAX_TEXT_CHARS = 50_000;

const STRIP_SELECTORS = [
  'script',
  'style',
  'noscript',
  'svg',
  'iframe',
  'object',
  'embed',
  'link',
  'meta',
  'nav',
  'footer',
  'header',
  'aside',
  'form',
  'button',
  '[role="navigation"]',
  '[role="banner"]',
  '[role="contentinfo"]',
  '[role="complementary"]',
  '[aria-hidden="true"]',
  '.cookie-banner',
  '.ad',
  '.advertisement',
  '.sidebar',
];

export type CleanResult = {
  text: string;
  truncated: boolean;
  title: string;
};

export function cleanHtml(html: string): CleanResult {
  const $ = cheerio.load(html);

  // Grab the page title before stripping
  const title = $('title').text().trim() || $('h1').first().text().trim() || '';

  // Remove chrome elements
  for (const sel of STRIP_SELECTORS) {
    $(sel).remove();
  }

  // Strip inline event handlers and style attributes (defence-in-depth)
  $('*').each((_, el) => {
    const attribs = (el as unknown as { attribs?: Record<string, string> }).attribs;
    if (!attribs) return;
    for (const name of Object.keys(attribs)) {
      if (name.startsWith('on') || name === 'style') {
        delete attribs[name];
      }
    }
  });

  // Extract readable text: prefer <main> or <article>, fall back to <body>
  let content =
    $('main').text() ||
    $('article').text() ||
    $('[role="main"]').text() ||
    $('body').text();

  // Collapse whitespace and strip HTML comments
  content = content
    .replace(/<!--[\s\S]*?-->/g, '')
    .replace(/\t/g, ' ')
    .replace(/ {2,}/g, ' ')
    .replace(/\n{3,}/g, '\n\n')
    .trim();

  if (content.length <= MAX_TEXT_CHARS) {
    return { text: content, truncated: false, title };
  }

  return {
    text: content.slice(0, MAX_TEXT_CHARS),
    truncated: true,
    title,
  };
}

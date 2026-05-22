#!/usr/bin/env node
/**
 * web-research-mcp — MCP server (stdio transport)
 * Portfolio Project #11 · Tai Huynh
 *
 * Exposes 3 tools to any MCP-compatible AI assistant:
 *   fetch_page      — SSRF-guarded fetch → readable text  (no credentials needed)
 *   extract_data    — fetch + Gemini structured JSON extraction  (needs GCP creds)
 *   summarize_page  — fetch + Gemini text summary  (needs GCP creds)
 *
 * CRITICAL: this is a stdio MCP server. NEVER write to stdout — it corrupts the
 * JSON-RPC stream. All logging must use console.error (stderr).
 */
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';

import { fetchPage } from './tools/fetch-page.js';
import { extractData } from './tools/extract-data.js';
import { summarizePage } from './tools/summarize-page.js';

// ── Server setup ──────────────────────────────────────────────────────────────

const server = new McpServer({
  name: 'web-research-mcp',
  version: '0.1.0',
});

// ── Tool: fetch_page ──────────────────────────────────────────────────────────

server.registerTool(
  'fetch_page',
  {
    title: 'Fetch Page',
    description:
      'Fetch a web page and return its readable text content. ' +
      'Applies SSRF protection, respects robots.txt, strips navigation/scripts/styles, ' +
      'and truncates at 50 000 characters. Works without Google credentials.',
    inputSchema: {
      url: z
        .string()
        .url()
        .describe('The full URL of the page to fetch (http or https only).'),
    },
  },
  async ({ url }) => {
    console.error(`[fetch_page] url=${url}`);
    try {
      const result = await fetchPage(url);
      if (!result.ok) {
        return {
          content: [{ type: 'text', text: `Error: ${result.error}` }],
          isError: true,
        };
      }
      const meta = `URL: ${result.finalUrl}\nTitle: ${result.title || '(no title)'}\nSize: ${result.bytes.toLocaleString()} bytes\n\n`;
      return {
        content: [{ type: 'text', text: meta + result.text }],
      };
    } catch (err) {
      // Catch-all: never leak stack traces
      const msg = err instanceof Error ? err.message : 'unexpected error';
      console.error('[fetch_page] unhandled error:', err);
      return {
        content: [{ type: 'text', text: `Error: ${msg}` }],
        isError: true,
      };
    }
  }
);

// ── Tool: extract_data ────────────────────────────────────────────────────────

server.registerTool(
  'extract_data',
  {
    title: 'Extract Data',
    description:
      'Fetch a web page and extract specific fields as structured JSON using Gemini 2.5 Flash. ' +
      'Describe the fields you want in plain English. Requires Google Cloud credentials ' +
      '(GOOGLE_CLOUD_PROJECT + GOOGLE_APPLICATION_CREDENTIALS or GOOGLE_APPLICATION_CREDENTIALS_JSON).',
    inputSchema: {
      url: z
        .string()
        .url()
        .describe('The full URL of the page to fetch (http or https only).'),
      fields: z
        .string()
        .min(1)
        .max(1000)
        .describe(
          'Plain-English description of the data to extract, e.g. ' +
          '"product name, price, rating, number of reviews, availability".'
        ),
    },
  },
  async ({ url, fields }) => {
    console.error(`[extract_data] url=${url} fields="${fields}"`);
    try {
      const result = await extractData(url, fields);
      if (!result.ok) {
        return {
          content: [{ type: 'text', text: `Error: ${result.error}` }],
          isError: true,
        };
      }
      const meta = `URL: ${result.finalUrl}\nTitle: ${result.title || '(no title)'}\n\n`;
      const json = JSON.stringify(result.data, null, 2);
      return {
        content: [{ type: 'text', text: meta + json }],
      };
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'unexpected error';
      console.error('[extract_data] unhandled error:', err);
      return {
        content: [{ type: 'text', text: `Error: ${msg}` }],
        isError: true,
      };
    }
  }
);

// ── Tool: summarize_page ──────────────────────────────────────────────────────

server.registerTool(
  'summarize_page',
  {
    title: 'Summarize Page',
    description:
      'Fetch a web page and return a concise text summary using Gemini 2.5 Flash. ' +
      'Optionally provide a focus hint to steer the summary. Requires Google Cloud credentials.',
    inputSchema: {
      url: z
        .string()
        .url()
        .describe('The full URL of the page to fetch (http or https only).'),
      focus: z
        .string()
        .max(500)
        .optional()
        .describe(
          'Optional: what aspect of the page to focus the summary on, e.g. ' +
          '"pricing information" or "technical specifications".'
        ),
    },
  },
  async ({ url, focus }) => {
    console.error(`[summarize_page] url=${url} focus="${focus ?? ''}"`);
    try {
      const result = await summarizePage(url, focus);
      if (!result.ok) {
        return {
          content: [{ type: 'text', text: `Error: ${result.error}` }],
          isError: true,
        };
      }
      const meta = `URL: ${result.finalUrl}\nTitle: ${result.title || '(no title)'}\n\n`;
      return {
        content: [{ type: 'text', text: meta + result.summary }],
      };
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'unexpected error';
      console.error('[summarize_page] unhandled error:', err);
      return {
        content: [{ type: 'text', text: `Error: ${msg}` }],
        isError: true,
      };
    }
  }
);

// ── Start server ──────────────────────────────────────────────────────────────

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error('[web-research-mcp] Server started — listening on stdio.');
}

main().catch((err) => {
  console.error('[web-research-mcp] Fatal startup error:', err);
  process.exit(1);
});

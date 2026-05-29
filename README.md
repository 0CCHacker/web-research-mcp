# Web Research MCP

Give any AI assistant safe, structured web access — fetch, extract, and summarize pages.

> Portfolio Project #11 · [Tai Huynh](https://github.com/huynhchitai)

---

## What it is

`web-research-mcp` is a **Model Context Protocol (MCP) server** that runs locally and plugs into Claude Desktop, Claude Code, or any other MCP-compatible client. It exposes three tools that let an AI assistant browse the web without needing a headless browser or a search API key.

The headline feature is security: an MCP server is driven by an LLM that can be prompt-injected by malicious page content into fetching attacker-chosen URLs. Every outbound request is gated behind a hardened SSRF guard that blocks cloud metadata endpoints, private IP ranges, loopback, link-local, and internal hostnames — and re-validates every redirect hop independently.

---

## Tools

### `fetch_page`

Fetch a public web page and return its readable text.

| Input | Type | Description |
|-------|------|-------------|
| `url` | `string` | Full URL (`http` or `https` only) |

**Returns:** Page title, final URL (after redirects), byte count, and cleaned text (stripped of scripts, styles, nav, footer). Truncated at 50 000 characters with a note.

**Requires credentials:** No — works with zero configuration.

---

### `extract_data`

Fetch a page and extract specific fields as structured JSON using Gemini 2.5 Flash.

| Input | Type | Description |
|-------|------|-------------|
| `url` | `string` | Full URL (`http` or `https` only) |
| `fields` | `string` | Plain-English description of what to extract |

**Example `fields`:** `"product name, price, rating, number of reviews, stock availability"`

**Returns:** A JSON object with one key per requested field (null when the field is absent).

**Requires credentials:** Yes — `GOOGLE_CLOUD_PROJECT` + GCP credentials.

---

### `summarize_page`

Fetch a page and return a concise text summary using Gemini 2.5 Flash.

| Input | Type | Description |
|-------|------|-------------|
| `url` | `string` | Full URL (`http` or `https` only) |
| `focus` | `string?` | Optional focus hint, e.g. `"pricing information"` |

**Returns:** A 3–7 sentence summary (shorter for short pages), steered by the focus hint if provided.

**Requires credentials:** Yes — `GOOGLE_CLOUD_PROJECT` + GCP credentials.

---

## Pipeline at a glance

```
MCP Client (Claude Desktop / Claude Code)
         │  JSON-RPC over stdio
         ▼
  ┌─────────────────────────────┐
  │   web-research-mcp server   │
  │                             │
  │  ① SSRF guard               │  blocks private IPs, metadata,
  │     (every hop)             │  loopback, .local, .internal
  │         │                   │
  │  ② robots.txt check         │  respects Disallow rules
  │         │                   │
  │  ③ safeFetch                │  8s timeout · 2 MB cap
  │     manual redirects        │  re-validates each redirect
  │         │                   │
  │  ④ cleanHtml (cheerio)      │  strips script/style/nav/footer
  │         │                   │  → readable text ≤ 50 000 chars
  │         │                   │
  │  ⑤ (optional) Gemini        │  extract_data: JSON schema mode
  │     2.5 Flash               │  summarize_page: free-text
  │                             │
  └─────────────────────────────┘
         │  tool result
         ▼
  MCP Client
```

---

## Build

```bash
npm install
npm run build       # tsc → dist/
npm test            # vitest (ssrf.test.ts)
npm run typecheck   # tsc --noEmit
```

The compiled entry point is `dist/index.js`. It has a `#!/usr/bin/env node` shebang and is declared as the `web-research-mcp` bin.

---

## Register with Claude Desktop

Edit `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "web-research-mcp": {
      "command": "node",
      "args": ["/absolute/path/to/web-research-mcp/dist/index.js"],
      "env": {
        "GOOGLE_CLOUD_PROJECT": "your-gcp-project-id",
        "GOOGLE_APPLICATION_CREDENTIALS": "/path/to/sa-key.json"
      }
    }
  }
}
```

Restart Claude Desktop after editing.

---

## Register with Claude Code

**Option A — `.mcp.json` in your project root:**

```json
{
  "mcpServers": {
    "web-research-mcp": {
      "command": "node",
      "args": ["/absolute/path/to/web-research-mcp/dist/index.js"],
      "env": {
        "GOOGLE_CLOUD_PROJECT": "your-gcp-project-id",
        "GOOGLE_APPLICATION_CREDENTIALS": "/path/to/sa-key.json"
      }
    }
  }
}
```

**Option B — `claude mcp add` CLI:**

```bash
claude mcp add web-research-mcp \
  --command node \
  --args /absolute/path/to/web-research-mcp/dist/index.js
```

---

## Environment variables

| Variable | Required | Description |
|----------|----------|-------------|
| `GOOGLE_CLOUD_PROJECT` | For `extract_data` / `summarize_page` | Your GCP project ID |
| `GOOGLE_CLOUD_REGION` | No (default: `us-central1`) | Vertex AI region |
| `GOOGLE_APPLICATION_CREDENTIALS` | One of the two | Path to a service-account JSON key file |
| `GOOGLE_APPLICATION_CREDENTIALS_JSON` | One of the two | Entire service-account JSON as a single-line string (for environments where writing files is not possible) |

`fetch_page` works with **no credentials at all**.

Copy `.env.example` for documentation of every variable.

---

## Security stance

**What is defended:**

- **SSRF** — every outbound URL, including every redirect hop, is checked against a scheme allowlist (`http`/`https` only), a literal-host blocklist (localhost, metadata.google.internal, instance-data, etc.), and a full DNS resolution that rejects all private/reserved IPv4 and IPv6 ranges (RFC 1918, loopback, link-local/169.254.x.x, CGNAT, ULA, IPv4-mapped IPv6, 6to4 tunnels).
- **Redirect chasing** — redirects are followed manually, not by the browser/fetch stack, so the SSRF guard runs on every intermediate URL.
- **Size and timeout** — responses are capped at 2 MB and 8 seconds; the body is streamed and the stream is aborted immediately on cap breach.
- **robots.txt** — `Disallow` rules are respected for the server's User-Agent before any fetch.
- **Input validation** — all tool inputs are validated with zod at the MCP layer; oversized or malformed inputs are rejected before any network I/O.
- **LLM output validation** — Gemini's JSON output is parsed and validated with zod; malformed or empty responses produce a structured error, not a crash.
- **No stack traces in tool output** — errors surface as `{ isError: true, content: [{ type: "text", text: "Error: …" }] }`. Internal detail goes to stderr only.
- **Prompt injection** — page content is always placed in a `PAGE CONTENT:` section of the prompt, explicitly labelled as untrusted data.
- **Credential isolation** — service-account keys are read from the environment or a file path; they are never written into tool output or logs.

**Known gaps (honest disclosure):**

- **DNS-rebinding TOCTOU window.** The IP address is validated at the time of the DNS lookup, but the TCP connection happens moments later. A DNS record with a very short TTL could rotate to a private IP between the two operations, bypassing the guard. This is a well-known gap in any guard that separates DNS resolution from TCP connection. The production-grade fix is to use a custom `undici.Agent` that pins the resolved IP into the socket — not implemented here because it adds significant complexity and the demo threat model is low-risk. Flagging the gap is part of taking security seriously.
- **No rate limiting.** An MCP server is invoked by the AI assistant, not directly by an end user, so per-IP rate limiting does not apply. However, a compromised or prompt-injected session could trigger a large number of fetches. A per-session fetch budget is not implemented.
- **No TLS certificate pinning.** HTTPS is used but certificates are validated by the Node.js default trust store. A CA-compromised or MITM scenario is not mitigated.

---

## Known limits

- Truncation at 50 000 characters means very long pages (documentation sites, long-form articles) are cut off. The truncation note in the output tells the AI assistant that content is incomplete.
- JavaScript-rendered pages are not supported. Only server-rendered HTML is fetched; SPAs that require JS execution will return sparse content or just the `<noscript>` fallback.
- `extract_data` uses a generic `additionalProperties: { type: "string" }` response schema because the fields are described in free text. Gemini infers the key names. For production use with known schemas, replace `buildExtractionResponseSchema()` with a precise schema.
- robots.txt is cached in process memory for 24 hours. There is no persistent cache.
- The Gemini `responseMimeType: "application/json"` mode requires Gemini 2.5 Flash or later. Older model IDs will fail or return plain text.

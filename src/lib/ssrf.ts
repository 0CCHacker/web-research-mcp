/**
 * SSRF guard — adapted from web-scraper/src/lib/ssrf.ts.
 *
 * Threat model: an MCP server is driven by an LLM that can be prompt-injected
 * by malicious page content into fetching attacker-chosen URLs. Without this
 * guard, a pivot to 169.254.169.254 (cloud metadata), localhost, or internal
 * services is trivial. This guard runs before EVERY outbound fetch and before
 * EVERY redirect hop.
 *
 * Residual gap: DNS-rebinding TOCTOU window — the IP validated here may rotate
 * to a private address before the actual TCP connection. Production fix: use a
 * pinned-IP undici.Agent. See SECURITY.md.
 */
import { promises as dns } from 'node:dns';
import { isIP, isIPv4, isIPv6 } from 'node:net';

export type SsrfReject = {
  ok: false;
  code: 'BLOCKED_SCHEME' | 'BLOCKED_HOSTNAME' | 'BLOCKED_PRIVATE_IP' | 'DNS_FAIL';
  message: string;
};

export type SsrfAccept = {
  ok: true;
  url: URL;
  resolvedIps: string[];
};

const ALLOWED_SCHEMES = new Set(['http:', 'https:']);

const LITERAL_BLOCKED_HOSTS = new Set([
  'localhost',
  'ip6-localhost',
  'ip6-loopback',
  '0.0.0.0',
  '::',
  '::1',
  'metadata.google.internal',
  'metadata.goog',
  'instance-data',
  // AWS / Azure / GCP metadata endpoints
  '169.254.169.254',
]);

export function isPrivateOrReservedIp(ip: string): boolean {
  if (isIPv4(ip)) return isPrivateOrReservedIpv4(ip);
  if (isIPv6(ip)) return isPrivateOrReservedIpv6(ip);
  return true; // unrecognised format — block by default
}

function isPrivateOrReservedIpv4(ip: string): boolean {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) {
    return true;
  }
  const [a, b, c] = parts;
  if (a === 10) return true;                                   // RFC 1918 class A
  if (a === 127) return true;                                  // loopback
  if (a === 0) return true;                                    // "this" network
  if (a === 169 && b === 254) return true;                    // link-local / cloud metadata
  if (a === 172 && b >= 16 && b <= 31) return true;           // RFC 1918 class B
  if (a === 192 && b === 168) return true;                    // RFC 1918 class C
  if (a === 192 && b === 0 && c === 0) return true;           // IETF protocol assignments
  if (a === 192 && b === 0 && c === 2) return true;           // TEST-NET-1
  if (a === 198 && (b === 18 || b === 19)) return true;       // benchmarking
  if (a === 198 && b === 51 && c === 100) return true;        // TEST-NET-2
  if (a === 203 && b === 0 && c === 113) return true;         // TEST-NET-3
  if (a >= 224) return true;                                   // multicast + reserved
  if (a === 100 && b >= 64 && b <= 127) return true;          // CGNAT
  return false;
}

function isPrivateOrReservedIpv6(ip: string): boolean {
  const lower = ip.toLowerCase();
  if (lower === '::' || lower === '::1') return true;
  // link-local fe80::/10
  if (lower.startsWith('fe80:') || lower.startsWith('fe8') ||
      lower.startsWith('fe9') || lower.startsWith('fea') || lower.startsWith('feb')) return true;
  // ULA fc00::/7
  if (lower.startsWith('fc') || lower.startsWith('fd')) return true;
  // multicast ff00::/8
  if (lower.startsWith('ff')) return true;
  // IPv4-mapped ::ffff:0:0/96 — accept BOTH the dotted-quad form
  // (::ffff:127.0.0.1) and the hex-group form (::ffff:7f00:1). The URL parser
  // emits the hex form, and both decode to the same IPv4 address — so the hex
  // form must be decoded too, or it becomes an SSRF bypass to loopback/metadata.
  if (lower.startsWith('::ffff:')) {
    const suffix = lower.slice('::ffff:'.length);
    if (isIPv4(suffix)) return isPrivateOrReservedIpv4(suffix);
    const hex = suffix.match(/^([0-9a-f]{1,4}):([0-9a-f]{1,4})$/);
    if (hex) {
      const hi = parseInt(hex[1], 16);
      const lo = parseInt(hex[2], 16);
      const v4 = `${(hi >> 8) & 0xff}.${hi & 0xff}.${(lo >> 8) & 0xff}.${lo & 0xff}`;
      return isPrivateOrReservedIpv4(v4);
    }
    // Any other IPv4-mapped form we cannot decode — reject conservatively.
    return true;
  }
  // 6to4 2002::/16 — can tunnel private IPv4
  if (lower.startsWith('2002:')) return true;
  return false;
}

export async function ssrfGuard(rawUrl: string): Promise<SsrfAccept | SsrfReject> {
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    return { ok: false, code: 'BLOCKED_SCHEME', message: 'Invalid URL.' };
  }

  if (!ALLOWED_SCHEMES.has(url.protocol)) {
    return {
      ok: false,
      code: 'BLOCKED_SCHEME',
      message: `Scheme "${url.protocol}" not allowed. Only http and https are permitted.`,
    };
  }

  const hostname = url.hostname.toLowerCase().replace(/^\[|\]$/g, '');
  if (!hostname) {
    return { ok: false, code: 'BLOCKED_HOSTNAME', message: 'Missing hostname.' };
  }

  if (
    LITERAL_BLOCKED_HOSTS.has(hostname) ||
    hostname.endsWith('.localhost') ||
    hostname.endsWith('.local') ||
    hostname.endsWith('.internal') ||
    hostname.endsWith('.corp')
  ) {
    return { ok: false, code: 'BLOCKED_HOSTNAME', message: `Hostname "${hostname}" is not allowed.` };
  }

  // If the hostname is already a literal IP, validate it directly without DNS
  if (isIP(hostname)) {
    if (isPrivateOrReservedIp(hostname)) {
      return {
        ok: false,
        code: 'BLOCKED_PRIVATE_IP',
        message: `Literal IP "${hostname}" is in a private/reserved range.`,
      };
    }
    return { ok: true, url, resolvedIps: [hostname] };
  }

  // DNS resolution — check every resolved address
  let records: { address: string; family: number }[];
  try {
    records = await dns.lookup(hostname, { all: true });
  } catch {
    return { ok: false, code: 'DNS_FAIL', message: `Could not resolve "${hostname}".` };
  }

  if (records.length === 0) {
    return { ok: false, code: 'DNS_FAIL', message: `No DNS records found for "${hostname}".` };
  }

  for (const r of records) {
    if (isPrivateOrReservedIp(r.address)) {
      return {
        ok: false,
        code: 'BLOCKED_PRIVATE_IP',
        message: `"${hostname}" resolves to ${r.address}, which is in a private/reserved range.`,
      };
    }
  }

  return { ok: true, url, resolvedIps: records.map((r) => r.address) };
}

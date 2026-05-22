import { describe, it, expect } from 'vitest';
import { ssrfGuard, isPrivateOrReservedIp } from '../lib/ssrf.js';

describe('isPrivateOrReservedIp', () => {
  it.each([
    '127.0.0.1',
    '10.0.0.1',
    '10.255.255.255',
    '172.16.0.1',
    '172.31.255.255',
    '192.168.1.1',
    '169.254.169.254',
    '169.254.0.1',
    '0.0.0.0',
    '100.64.0.1',
    '100.127.255.255',
    '224.0.0.1',
    '240.0.0.1',
    '255.255.255.255',
    '::1',
    '::',
    'fc00::1',
    'fd00::1',
    'fe80::1',
    'ff00::1',
    '::ffff:127.0.0.1',
    '::ffff:192.168.1.1',
    // Hex-group form of IPv4-mapped IPv6 — must decode to the same IPv4 address.
    '::ffff:7f00:1', // -> 127.0.0.1 (loopback)
    '::ffff:a9fe:a9fe', // -> 169.254.169.254 (cloud metadata)
    '::ffff:c0a8:101', // -> 192.168.1.1 (RFC 1918)
    '::ffff:ac10:1', // -> 172.16.0.1 (RFC 1918)
  ])('rejects %s as private/reserved', (ip) => {
    expect(isPrivateOrReservedIp(ip)).toBe(true);
  });

  it.each([
    '8.8.8.8',
    '1.1.1.1',
    '93.184.216.34',
    '104.21.0.1',
    '2606:4700:4700::1111',
    '::ffff:808:808', // -> 8.8.8.8, a public IPv4-mapped address, must be allowed
  ])('accepts %s as a public IP', (ip) => {
    expect(isPrivateOrReservedIp(ip)).toBe(false);
  });
});

describe('ssrfGuard — scheme checks', () => {
  it('rejects file:// scheme', async () => {
    const r = await ssrfGuard('file:///etc/passwd');
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.code).toBe('BLOCKED_SCHEME');
  });

  it('rejects gopher:// scheme', async () => {
    const r = await ssrfGuard('gopher://example.com/');
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.code).toBe('BLOCKED_SCHEME');
  });

  it('rejects ftp:// scheme', async () => {
    const r = await ssrfGuard('ftp://example.com/');
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.code).toBe('BLOCKED_SCHEME');
  });

  it('rejects javascript: pseudo-scheme', async () => {
    const r = await ssrfGuard('javascript:alert(1)');
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.code).toBe('BLOCKED_SCHEME');
  });

  it('rejects a completely invalid URL', async () => {
    const r = await ssrfGuard('not a url at all');
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.code).toBe('BLOCKED_SCHEME');
  });
});

describe('ssrfGuard — hostname blocklist', () => {
  it('rejects http://localhost', async () => {
    const r = await ssrfGuard('http://localhost');
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.code).toBe('BLOCKED_HOSTNAME');
  });

  it('rejects http://localhost:6379', async () => {
    const r = await ssrfGuard('http://localhost:6379');
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.code).toBe('BLOCKED_HOSTNAME');
  });

  it('rejects http://LOCALHOST (case-insensitive)', async () => {
    const r = await ssrfGuard('http://LOCALHOST/');
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.code).toBe('BLOCKED_HOSTNAME');
  });

  it('rejects metadata.google.internal', async () => {
    const r = await ssrfGuard('http://metadata.google.internal/');
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.code).toBe('BLOCKED_HOSTNAME');
  });

  it('rejects *.localhost subdomains', async () => {
    const r = await ssrfGuard('http://foo.localhost/');
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.code).toBe('BLOCKED_HOSTNAME');
  });

  it('rejects *.local domains', async () => {
    const r = await ssrfGuard('http://mydevbox.local/');
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.code).toBe('BLOCKED_HOSTNAME');
  });

  it('rejects *.internal domains', async () => {
    const r = await ssrfGuard('http://service.internal/');
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.code).toBe('BLOCKED_HOSTNAME');
  });

  it('rejects empty hostname (http:///path)', async () => {
    const r = await ssrfGuard('http:///path');
    expect(r.ok).toBe(false);
  });
});

describe('ssrfGuard — literal private IPs', () => {
  it('rejects http://169.254.169.254 (AWS/GCP metadata)', async () => {
    const r = await ssrfGuard('http://169.254.169.254/');
    expect(r.ok).toBe(false);
    // 169.254.169.254 is in LITERAL_BLOCKED_HOSTS so it is caught as BLOCKED_HOSTNAME
    // before the literal-IP private-range check; both paths block the request.
    if (!r.ok) expect(['BLOCKED_HOSTNAME', 'BLOCKED_PRIVATE_IP']).toContain(r.code);
  });

  it('rejects http://127.0.0.1', async () => {
    const r = await ssrfGuard('http://127.0.0.1/');
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.code).toBe('BLOCKED_PRIVATE_IP');
  });

  it('rejects http://10.0.0.1', async () => {
    const r = await ssrfGuard('http://10.0.0.1/');
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.code).toBe('BLOCKED_PRIVATE_IP');
  });

  it('rejects http://192.168.1.1', async () => {
    const r = await ssrfGuard('http://192.168.1.1/');
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.code).toBe('BLOCKED_PRIVATE_IP');
  });

  it('rejects http://172.16.0.1', async () => {
    const r = await ssrfGuard('http://172.16.0.1/');
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.code).toBe('BLOCKED_PRIVATE_IP');
  });

  it('rejects http://[::1] (IPv6 loopback)', async () => {
    const r = await ssrfGuard('http://[::1]/');
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.code).toBe('BLOCKED_HOSTNAME');
  });

  it('rejects http://[fc00::1] (IPv6 ULA)', async () => {
    const r = await ssrfGuard('http://[fc00::1]/');
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.code).toBe('BLOCKED_PRIVATE_IP');
  });

  it('rejects http://[fe80::1] (IPv6 link-local)', async () => {
    const r = await ssrfGuard('http://[fe80::1]/');
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.code).toBe('BLOCKED_PRIVATE_IP');
  });
});

describe('ssrfGuard — public URLs (live DNS required)', () => {
  it('accepts https://example.com', async () => {
    const r = await ssrfGuard('https://example.com/');
    expect(r.ok).toBe(true);
  });

  it('accepts http://books.toscrape.com', async () => {
    const r = await ssrfGuard('http://books.toscrape.com/');
    expect(r.ok).toBe(true);
  });

  it('accepts https://news.ycombinator.com', async () => {
    const r = await ssrfGuard('https://news.ycombinator.com/');
    expect(r.ok).toBe(true);
  });
});

/** Native adapter tests: mocked transport only. Live relay interop is
 * verified separately against the funnel lab (see FUNNEL-LAB.md). */
import test from 'node:test';
import assert from 'node:assert/strict';
import { createPrivateKey, createPublicKey, createHash, verify, randomBytes } from 'node:crypto';
import { writeFileSync, chmodSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  NativeError, loadNativeConfig, deriveKeyID, publicKeyFromSeed,
  signMgmt, NativeOclivClient, assertIssuerScoped, readCappedJson, readCappedBody,
} from '../src/core/ocliv-native.mjs';

// Fixed 32-byte seed so signatures are reproducible (test-only).
const SEEDB = Buffer.from(
  '0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20', 'hex');

function keyEnv(extra = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'ocliv-native-test-'));
  const kf = join(dir, 'agent.key');
  writeFileSync(kf, SEEDB.toString('base64'));
  chmodSync(kf, 0o600);
  return { OCLIV_RELAY_URL: 'https://relay.example.org', OCLIV_AGENT_KEY_FILE: kf, ...extra };
}

const json = (v, status = 200) => new Response(JSON.stringify(v), { status, headers: { 'content-type': 'application/json' } });

test('config requires bare https origin and a 0600 seed key file', () => {
  const good = keyEnv();
  const c = loadNativeConfig(good);
  assert.equal(c.relay, 'https://relay.example.org');
  assert.match(c.keyID, /^key-[0-9a-f]{16}$/); // wire form carries the key- prefix
  // Explicit override accepted with or without prefix, normalized.
  const hex = c.keyID.slice(4);
  assert.equal(loadNativeConfig({ ...good, OCLIV_AGENT_KEY_ID: hex }).keyID, c.keyID);
  assert.equal(loadNativeConfig({ ...good, OCLIV_AGENT_KEY_ID: c.keyID }).keyID, c.keyID);
  for (const [k, v] of [
    ['OCLIV_RELAY_URL', 'http://relay.example.org'],
    ['OCLIV_RELAY_URL', 'https://relay.example.org/extra'],
    ['OCLIV_RELAY_URL', 'https://relay.example.org?x=1'],
    ['OCLIV_RELAY_URL', ''],
  ]) assert.throws(() => loadNativeConfig({ ...good, [k]: v }), { code: 'INVALID_CONFIG' });
  assert.throws(() => loadNativeConfig({ ...good, OCLIV_AGENT_KEY_FILE: '/nonexistent/key' }), { code: 'INVALID_CONFIG' });
});

test('trusted issuers default empty, entries must be https', () => {
  assert.deepEqual(loadNativeConfig(keyEnv()).trustedIssuers, []);
  assert.deepEqual(loadNativeConfig(keyEnv({ OCLIV_TRUSTED_ISSUERS: 'https://idp.example.com/, https://other.example/x' })).trustedIssuers,
    ['https://idp.example.com/', 'https://other.example/x']);
  assert.throws(() => loadNativeConfig(keyEnv({ OCLIV_TRUSTED_ISSUERS: 'http://evil.test/' })), { code: 'INVALID_CONFIG' });
});

test('unsafe key permissions fail closed', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ocliv-native-test-'));
  const kf = join(dir, 'agent.key');
  writeFileSync(kf, SEEDB.toString('base64'));
  chmodSync(kf, 0o644);
  assert.throws(() => loadNativeConfig({ OCLIV_RELAY_URL: 'https://relay.example.org', OCLIV_AGENT_KEY_FILE: kf }), { code: 'INVALID_CONFIG' });
});

test('derived key id matches Go identity.ID (sha256(pub)[:8] hex)', () => {
  // Independent re-derivation: raw pubkey from SPKI tail, not via deriveKeyID.
  const pubDer = createPublicKey(createPrivateKey({
    key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), SEEDB]),
    format: 'der', type: 'pkcs8',
  })).export({ format: 'der', type: 'spki' });
  const want = createHash('sha256').update(Buffer.from(pubDer.subarray(pubDer.length - 32))).digest('hex').slice(0, 16);
  assert.equal(deriveKeyID(SEEDB), want);
  assert.deepEqual(publicKeyFromSeed(SEEDB), Buffer.from(pubDer.subarray(pubDer.length - 32)));
});

test('signatures verify under the derived public key (ed25519)', () => {
  const keyID = deriveKeyID(SEEDB);
  const h = signMgmt(SEEDB, keyID, 'GET', '/v1/agent/mcp-routes');
  assert.equal(h['X-Ocliv-Key'], keyID);
  const msg = `ocliv-mgmt-v1\n${keyID}\nGET\n/v1/agent/mcp-routes\n${Math.floor(Date.now() / 1000)}\n${h['X-Ocliv-Nonce']}`;
  const pub = createPublicKey(createPrivateKey({
    key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), SEEDB]),
    format: 'der', type: 'pkcs8',
  }));
  // Timestamp skew of a second is possible across the second boundary;
  // verify against both candidate seconds.
  const unix = Math.floor(Date.now() / 1000);
  const ok = [unix, unix - 1, unix + 1].some((u) => {
    const m = `ocliv-mgmt-v1\n${keyID}\nGET\n/v1/agent/mcp-routes\n${u}\n${h['X-Ocliv-Nonce']}`;
    return verify(null, Buffer.from(m), pub, Buffer.from(h['X-Ocliv-Sig'], 'base64'));
  });
  assert.ok(ok, 'self-produced signature must verify');
  assert.ok(!verify(null, Buffer.from(msg + 'tampered'), pub, Buffer.from(h['X-Ocliv-Sig'], 'base64')));
});

function relayListResponse() {
  return {
    publications: [{
      route_id: 'ZyTjyKtv8cWzCILrqcaaVg', external_host: 'relay.example.org',
      profile: 'upstream-oauth', pub_name: 'funnel-oauth', lease_id: 'lse-1',
      created_at: '2026-11-01T00:00:00Z', revoked_at: null, verified_at: '2026-11-01T00:01:00Z',
    }, {
      route_id: 'pending-route-123', external_host: 'relay.example.org',
      profile: 'upstream-oauth', pub_name: 'draft', lease_id: 'lse-2',
      created_at: '2026-11-01T00:00:00Z', revoked_at: null, verified_at: null,
    }],
  };
}

test('list maps relay fields to typed publications (state is publication state)', async () => {
  const calls = [];
  const client = new NativeOclivClient(loadNativeConfig(keyEnv()), async (url, opts) => {
    calls.push({ url, opts });
    return json(relayListResponse());
  });
  const pubs = await client.list();
  assert.equal(pubs.length, 2);
  assert.equal(pubs[0].id, 'ZyTjyKtv8cWzCILrqcaaVg');
  assert.equal(pubs[0].label, 'funnel-oauth');
  assert.equal(pubs[0].state, 'active');
  assert.equal(pubs[0].publicUrl, 'https://relay.example.org/r/ZyTjyKtv8cWzCILrqcaaVg/mcp');
  assert.equal(pubs[1].state, 'pending');
  assert.ok(calls[0].opts.headers['X-Ocliv-Sig']);
  assert.equal(calls[0].opts.headers['X-Ocliv-Key'], calls[0].opts.headers['X-Ocliv-Key']);
  assert.equal(calls[0].url, 'https://relay.example.org/v1/agent/mcp-routes');
  assert.equal(calls[0].opts.redirect, 'manual');
});

test('revoked publications surface as revoked, never active', async () => {
  const client = new NativeOclivClient(loadNativeConfig(keyEnv()), async () => json({
    publications: [{ route_id: 'dead-route-1', external_host: 'h', profile: 'p', pub_name: 'x', lease_id: null, created_at: '', revoked_at: 't', verified_at: 't' }],
  }));
  const pubs = await client.list();
  assert.equal(pubs[0].state, 'revoked');
});

test('malformed relay JSON fails closed', async () => {
  for (const body of [{ nope: 1 }, { publications: [{ route_id: '../x' }] }, { publications: 'x' }]) {
    const client = new NativeOclivClient(loadNativeConfig(keyEnv()), async () => json(body));
    await assert.rejects(client.list(), { code: 'UPSTREAM_CONTRACT' });
  }
});

test('get finds by exact id, rejects unknown and traversal', async () => {
  const client = new NativeOclivClient(loadNativeConfig(keyEnv()), async () => json(relayListResponse()));
  assert.equal((await client.get('ZyTjyKtv8cWzCILrqcaaVg')).label, 'funnel-oauth');
  await assert.rejects(client.get('missing-route-1'), { code: 'NOT_FOUND' });
  await assert.rejects(client.get('../evil'), { code: 'INVALID_ID' });
});

test('unpublish deletes exactly one route and rechecks', async () => {
  let remaining = ['gone-route-12', 'keep-route-34'];
  const calls = [];
  const client = new NativeOclivClient(loadNativeConfig(keyEnv()), async (url, opts) => {
    calls.push({ url, method: opts.method, nonce: opts.headers['X-Ocliv-Nonce'] });
    if (opts.method === 'DELETE') {
      assert.match(url, /\/v1\/agent\/mcp-routes\/gone-route-12$/);
      assert.ok(opts.headers['X-Ocliv-Nonce'], 'mutations must carry a nonce');
      remaining = remaining.filter((r) => r !== 'gone-route-12');
      return json({ status: 'deleted' });
    }
    return json({ publications: remaining.map((id) => ({ route_id: id, external_host: 'h', profile: 'p', pub_name: id, lease_id: null, created_at: '', revoked_at: null, verified_at: 't' })) });
  });
  const out = await client.unpublish('gone-route-12');
  assert.deepEqual(out, { id: 'gone-route-12', deleted: true });
});

test('unpublish reports unconfirmed deletion, never success', async () => {
  const client = new NativeOclivClient(loadNativeConfig(keyEnv()), async (url, opts) => {
    if (opts.method === 'DELETE') return json({ status: 'deleted' });
    return json({ publications: [{ route_id: 'stubborn-1', external_host: 'h', profile: 'p', pub_name: 'x', lease_id: null, created_at: '', revoked_at: null, verified_at: 't' }] });
  });
  await assert.rejects(client.unpublish('stubborn-1'), { code: 'UNCONFIRMED' });
});

test('relay auth failures and redirects map to typed errors', async () => {
  for (const [status, code] of [[401, 'UPSTREAM_AUTH'], [403, 'UPSTREAM_AUTH'], [500, 'UPSTREAM_FAILURE']]) {
    const client = new NativeOclivClient(loadNativeConfig(keyEnv()), async () => new Response('x', { status }));
    await assert.rejects(client.list(), { code });
  }
  const redir = new NativeOclivClient(loadNativeConfig(keyEnv()), async () => new Response('', { status: 302 }));
  await assert.rejects(redir.list(), { code: 'UPSTREAM_REDIRECT' });
});

const PUBS = { publications: [{ route_id: 'route-abc-123', external_host: 'relay.example.org', profile: 'upstream-oauth', pub_name: 'lab', lease_id: 'lse-1', created_at: '', revoked_at: null, verified_at: 't' }] };
const PUBURL = 'https://relay.example.org/r/route-abc-123/mcp';
const ISS = 'https://relay.example.org/r/route-abc-123/oauth';
const PRM = { resource: PUBURL, authorization_servers: [ISS] };
const ASM = { issuer: ISS, authorization_endpoint: ISS + '/authorize', token_endpoint: ISS + '/token', registration_endpoint: ISS + '/register', code_challenge_methods_supported: ['S256'] };

// Test-only unsigned JWTs: the client checks aud binding, never the
// signature (the stub upstream decides acceptance by exact value).
const b64u = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
const boundToken = (aud) => `${b64u({ alg: 'none', typ: 'JWT' })}.${b64u({ aud, scope: 'mcp:verify' })}.test-sig`;
const GOOD_TOKEN = boundToken(PUBURL);

function verifyFetch({ tokenTools = null } = {}) {
  return async (url, opts = {}) => {
    if (url === 'https://relay.example.org/v1/agent/mcp-routes') return json(PUBS);
    if (url === 'https://relay.example.org/.well-known/oauth-protected-resource/r/route-abc-123/mcp') return json(PRM);
    if (url === 'https://relay.example.org/.well-known/oauth-authorization-server/r/route-abc-123/oauth') return json(ASM);
    if (url === ISS + '/register' && opts.method === 'POST') throw new Error('DCR must not run during verify: ' + url);
    if (url === PUBURL && opts.method === 'POST') {
      const body = JSON.parse(opts.body);
      const authed = (opts.headers.authorization || '') === 'Bearer ' + GOOD_TOKEN;
      if (!authed) return new Response('unauthorized', { status: 401 });
      if (body.method === 'notifications/initialized') return new Response('', { status: 202 });
      if (tokenTools === 'ok' && body.method === 'initialize') {
        return json({ jsonrpc: '2.0', id: body.id, result: { protocolVersion: '2026-07-28', capabilities: {}, serverInfo: {} } });
      }
      if (tokenTools === 'ok' && body.method === 'tools/list') {
        return json({ jsonrpc: '2.0', id: body.id, result: { tools: [{ name: 'ping' }] } });
      }
      return new Response('denied', { status: 403 });
    }
    throw new Error('unexpected fetch: ' + url);
  };
}

test('verify without token stops at OAUTH_REQUIRED (never verified)', async () => {
  const client = new NativeOclivClient(loadNativeConfig(keyEnv()), verifyFetch());
  const out = await client.verifyPublication('route-abc-123');
  assert.equal(out.verified, false);
  assert.equal(out.code, 'OAUTH_REQUIRED');
  assert.ok(out.authorizeUrl.endsWith('/authorize'));
  assert.equal(out.registeredClient, null);
});

test('verify with valid token proves initialize + tools/list', async () => {
  const client = new NativeOclivClient(loadNativeConfig(keyEnv()), verifyFetch({ tokenTools: 'ok' }));
  const out = await client.verifyPublication('route-abc-123', { verifyToken: GOOD_TOKEN });
  assert.equal(out.verified, true);
  assert.equal(out.protocolVersion, '2026-07-28');
  assert.deepEqual(out.tools, ['ping']);
});

test('verify denies anonymous execution and bad tokens', async () => {
  const client = new NativeOclivClient(loadNativeConfig(keyEnv()), verifyFetch());
  const out = await client.verifyPublication('route-abc-123', { verifyToken: GOOD_TOKEN + 'tampered' });
  assert.equal(out.verified, false);
  assert.equal(out.code, 'MCP_DENIED');
});

test('verify never sends an unbound credential upstream (opaque token)', async () => {
  const sent = [];
  const client = new NativeOclivClient(loadNativeConfig(keyEnv()), async (url, opts = {}) => {
    sent.push({ url, auth: opts.headers?.authorization ?? null, method: opts.method });
    return verifyFetch()(url, opts);
  });
  const out = await client.verifyPublication('route-abc-123', { verifyToken: 'opaque-foreign-token' });
  assert.equal(out.verified, false);
  assert.equal(out.code, 'OAUTH_REQUIRED');
  assert.ok(sent.every((s) => s.auth == null), 'opaque credential must never be sent upstream');
});

test('verify never sends publication A credential to publication B', async () => {
  const BURL = 'https://relay.example.org/r/route-def-456/mcp';
  const BISS = 'https://relay.example.org/r/route-def-456/oauth';
  const pubs = { publications: [
    { route_id: 'route-abc-123', external_host: 'relay.example.org', profile: 'upstream-oauth', pub_name: 'a', lease_id: 'lse-1', created_at: '', revoked_at: null, verified_at: 't' },
    { route_id: 'route-def-456', external_host: 'relay.example.org', profile: 'upstream-oauth', pub_name: 'b', lease_id: 'lse-2', created_at: '', revoked_at: null, verified_at: 't' },
  ] };
  const sent = [];
  const fetch = async (url, opts = {}) => {
    sent.push({ url, auth: opts.headers?.authorization ?? null, method: opts.method });
    if (url === 'https://relay.example.org/v1/agent/mcp-routes') return json(pubs);
    if (url === 'https://relay.example.org/.well-known/oauth-protected-resource/r/route-def-456/mcp') {
      return json({ resource: BURL, authorization_servers: [BISS] });
    }
    if (url === 'https://relay.example.org/.well-known/oauth-authorization-server/r/route-def-456/oauth') {
      return json({ issuer: BISS, authorization_endpoint: BISS + '/authorize', token_endpoint: BISS + '/token', code_challenge_methods_supported: ['S256'] });
    }
    if (url === BURL && opts.method === 'POST') return new Response('unauthorized', { status: 401 });
    return verifyFetch()(url, opts);
  };
  const client = new NativeOclivClient(loadNativeConfig(keyEnv()), fetch);
  // Token bound to A must not be presented to B.
  const outB = await client.verifyPublication('route-def-456', { verifyToken: GOOD_TOKEN });
  assert.equal(outB.verified, false);
  assert.equal(outB.code, 'OAUTH_REQUIRED');
  assert.ok(sent.filter((s) => s.url === BURL && s.auth).length === 0, "A's credential must never reach B");
  // Same token still verifies A (bound correctly).
  const outA = await client.verifyPublication('route-abc-123', { verifyToken: GOOD_TOKEN });
  assert.equal(outA.code, 'MCP_DENIED'); // stub has no tokenTools:'ok' here; binding passed, upstream refused
});

test('oversized chunked body aborts before full buffering', async () => {
  let pulls = 0, cancelled = false;
  const big = new ReadableStream({
    pull(c) {
      pulls++;
      if (pulls <= 3) c.enqueue(new Uint8Array(40 * 1024));
      else c.close();
    },
    cancel() { cancelled = true; },
  });
  const res = new Response(big); // no Content-Length: unbounded without a streaming cap
  await assert.rejects(readCappedJson(res, 'probe', 65536), { code: 'DISCOVERY_TOO_LARGE' });
  assert.ok(cancelled, 'over-cap stream must be cancelled, not drained');
  assert.ok(pulls <= 2, `must stop early (pulls=${pulls}), not consume the stream`);
});

test('announced over-cap length rejects without reading the body', async () => {
  let pulls = 0;
  const s = new ReadableStream({
    start(c) { c.enqueue(new Uint8Array(10)); c.close(); },
    pull() { pulls++; },
  });
  const res = new Response(s, { headers: { 'content-length': '1000000' } });
  await assert.rejects(readCappedJson(res, 'probe', 65536), { code: 'DISCOVERY_TOO_LARGE' });
  assert.equal(pulls, 0);
});

test('absent length with small body parses, split UTF-8 decodes intact', async () => {
  const euro = new TextEncoder().encode('€ok'); // E2 82 AC split across chunks
  const s = new ReadableStream({
    start(c) { c.enqueue(euro.subarray(0, 1)); c.enqueue(euro.subarray(1)); c.close(); },
  });
  assert.equal(await readCappedBody(new Response(s), 'probe', 65536), '€ok');
  assert.deepEqual(await readCappedJson(new Response('{"a":1}'), 'probe', 65536), { a: 1 });
});

test('upstream tool error body never reaches the caller', async () => {
  const client = new NativeOclivClient(loadNativeConfig(keyEnv()), async (url, opts = {}) => {
    if (url === 'https://relay.example.org/v1/agent/mcp-routes') return json(PUBS);
    if (url.includes('/.well-known/oauth-authorization-server/')) return json(ASM);
    if (url.startsWith('https://relay.example.org/.well-known/')) return json(PRM);
    const body = JSON.parse(opts.body);
    if (!opts.headers.authorization) return new Response('unauthorized', { status: 401 });
    if (body.method === 'notifications/initialized') return new Response('', { status: 202 });
    if (body.method === 'initialize') return json({ jsonrpc: '2.0', id: body.id, result: { protocolVersion: '2026-07-28' } });
    return json({ jsonrpc: '2.0', id: body.id, error: { code: -32001, message: 'db password hunter2 at 10.0.0.9' } });
  });
  const out = await client.verifyPublication('route-abc-123', { verifyToken: GOOD_TOKEN });
  assert.equal(out.verified, false);
  assert.equal(out.code, 'MCP_TOOL_ERROR');
  assert.ok(!out.message.includes('hunter2') && !out.message.includes('10.0.0.9'), 'upstream error body must not surface');
});

test('oversized signed management response fails closed as contract error', async () => {
  const client = new NativeOclivClient(loadNativeConfig(keyEnv()), async () => new Response('x'.repeat(300000)));
  await assert.rejects(client.list(), { code: 'UPSTREAM_CONTRACT' });
});

test('verify fails closed on resource mismatch and missing issuer', async () => {
  const bad = verifyFetch();
  const evil = new NativeOclivClient(loadNativeConfig(keyEnv()), async (url, opts) => {
    if (url === 'https://relay.example.org/v1/agent/mcp-routes') return json(PUBS);
    return json({ resource: 'https://evil.test/r/x/mcp', authorization_servers: [] });
  });
  assert.equal((await evil.verifyPublication('route-abc-123')).code, 'RESOURCE_MISMATCH');
  void bad;
});

test('adapter refuses to sign outside the publication API', async () => {
  const client = new NativeOclivClient(loadNativeConfig(keyEnv()), async () => json({}));
  for (const p of ['/v1/agent/lease/x/close', '/v1/agent/enroll', '/v1/agent/mcp-routes/../x', '/v1/agent/mcp-routes/']) {
    await assert.rejects(client.request('POST', p), { code: 'INVALID_PATH' });
  }
});

test('offline relay maps to UPSTREAM_UNAVAILABLE, slow relay aborts', async () => {
  const down = new NativeOclivClient(loadNativeConfig(keyEnv()), async () => { throw new Error('connect refused'); });
  await assert.rejects(down.list(), { code: 'UPSTREAM_UNAVAILABLE' });
  const hanging = new NativeOclivClient(loadNativeConfig(keyEnv()), () => new Promise((_, rej) => {
    setTimeout(() => rej(new DOMException('The operation was aborted.', 'AbortError')), 50);
  }));
  await assert.rejects(hanging.list(), { code: 'UPSTREAM_UNAVAILABLE' });
});

test('safeError preserves typed codes, redacts everything else', async () => {
  const { safeError } = await import('../src/core/ocliv.mjs');
  assert.deepEqual(safeError(new NativeError('UPSTREAM_AUTH', 'x')), { ok: false, code: 'UPSTREAM_AUTH', message: 'x' });
  assert.equal(safeError(new Error('boom')).code, 'INTERNAL_ERROR');
  assert.equal(safeError(new NativeError('lowercase', 'x')).code, 'INTERNAL_ERROR');
});

test('verify pins all egress to the publication host (SSRF guard)', async () => {
  const rid = 'route-ssrf-1';
  const rurl = `https://relay.example.org/r/${rid}/mcp`;
  const iss = `https://relay.example.org/r/${rid}/oauth`;
  const base = { publications: [{ route_id: rid, external_host: 'relay.example.org', profile: 'upstream-oauth', pub_name: 's', lease_id: null, created_at: '', revoked_at: null, verified_at: 't' }] };
  const mk = (prm, asm = null) => new NativeOclivClient(loadNativeConfig(keyEnv()), async (url) => {
    if (url === 'https://relay.example.org/v1/agent/mcp-routes') return json(base);
    if (asm && url.includes('/.well-known/oauth-authorization-server/')) return json(asm);
    if (url.startsWith('https://relay.example.org/.well-known/')) return json(prm);
    if (asm && url.startsWith('https://relay.example.org/')) return json(asm);
    throw new Error('off-host fetch attempted: ' + url);
  });
  const goodAsm = { issuer: iss, authorization_endpoint: iss + '/authorize', token_endpoint: iss + '/token', registration_endpoint: iss + '/register', code_challenge_methods_supported: ['S256'] };
  // Evil issuer host: must fail before any off-host fetch.
  const evil = await mk({ resource: rurl, authorization_servers: ['https://evil.test/oauth'] }).verifyPublication(rid);
  assert.equal(evil.verified, false);
  assert.equal(evil.code, 'ISSUER_UNTRUSTED');
  // Endpoint escaping issuer scope.
  const asmOff = { ...goodAsm, token_endpoint: 'https://relay.example.org/other/token' };
  const off = await mk({ resource: rurl, authorization_servers: [iss] }, asmOff).verifyPublication(rid);
  assert.equal(off.verified, false);
  assert.equal(off.code, 'AS_ENDPOINT');
  // Oversized discovery document rejected.
  const big = new NativeOclivClient(loadNativeConfig(keyEnv()), async (url) => {
    if (url === 'https://relay.example.org/v1/agent/mcp-routes') return json(base);
    return new Response('x'.repeat(70000), { status: 200, headers: { 'content-type': 'application/json' } });
  });
  const bigOut = await big.verifyPublication('route-ssrf-1');
  assert.equal(bigOut.verified, false);
  assert.equal(bigOut.code, 'DISCOVERY_TOO_LARGE');
});

test('hostname-prefix endpoints rejected (exact origin compare)', () => {
  const iss = 'https://login.example.com/';
  assert.equal(assertIssuerScoped(iss, 'https://login.example.com/oauth/token', 'token_endpoint'), 'https://login.example.com/oauth/token');
  for (const evil of [
    'https://login.example.com.evil.invalid/token',
    'https://login.example.com:8443@evil.invalid/token',
    'http://login.example.com/token',
    'not-a-url',
  ]) assert.throws(() => assertIssuerScoped(iss, evil, 'token_endpoint'), { code: 'AS_ENDPOINT' });
});

test('sibling-prefix endpoints rejected (segment-scoped path)', () => {
  const iss = 'https://relay.example/r/a/oauth';
  assert.equal(assertIssuerScoped(iss, 'https://relay.example/r/a/oauth/authorize', 'x'), 'https://relay.example/r/a/oauth/authorize');
  assert.equal(assertIssuerScoped(iss, 'https://relay.example/r/a/oauth/token', 'x'), 'https://relay.example/r/a/oauth/token');
  for (const evil of [
    'https://relay.example/r/a/oauth-evil/token',
    'https://relay.example/r/a/oauthevil',
    'https://relay.example/r/a/oauth/../evil',
    'https://relay.example/r/a/oauth#frag',
    'https://relay.example/r/a/oauth?x=1#frag',
    'https://user:pass@relay.example/r/a/oauth/token',
    'https://relay.example/r/a/oauth%2fevil',
  ]) assert.throws(() => assertIssuerScoped(iss, evil, 'x'), { code: 'AS_ENDPOINT' });
  assert.throws(() => assertIssuerScoped('https://relay.example/r/a/oauth#frag', 'https://relay.example/r/a/oauth/token', 'x'), { code: 'AS_ENDPOINT' });
});

test('allowlisted different-host issuer verifies without same-host pin', async () => {
  const rid = 'route-ext-iss';
  const rurl = `https://relay.example.org/r/${rid}/mcp`;
  const iss = 'https://idp.example.com/';
  const base = { publications: [{ route_id: rid, external_host: 'relay.example.org', profile: 'upstream-oauth', pub_name: 's', lease_id: null, created_at: '', revoked_at: null, verified_at: 't' }] };
  const fetched = [];
  const client = new NativeOclivClient(
    loadNativeConfig(keyEnv({ OCLIV_TRUSTED_ISSUERS: iss })),
    async (url, opts = {}) => {
      fetched.push(url);
      if (url === 'https://relay.example.org/v1/agent/mcp-routes') return json(base);
      if (url === 'https://relay.example.org/.well-known/oauth-protected-resource/r/route-ext-iss/mcp') {
        return json({ resource: rurl, authorization_servers: [iss] });
      }
      if (url === iss + '.well-known/oauth-authorization-server/') {
        return json({ issuer: iss, authorization_endpoint: iss + 'authorize', token_endpoint: iss + 'oauth/token',
          registration_endpoint: iss + 'register', code_challenge_methods_supported: ['S256'] });
      }
      if (url === iss + 'register' && opts.method === 'POST') throw new Error('DCR must not run during verify: ' + url);
      if (url === rurl && opts.method === 'POST') return new Response('unauthorized', { status: 401 });
      throw new Error('off-host fetch attempted: ' + url);
    });
  const out = await client.verifyPublication(rid);
  assert.equal(out.verified, false);
  assert.equal(out.code, 'OAUTH_REQUIRED');
  assert.equal(out.issuer, iss);
  assert.equal(out.registeredClient, null);
});

test('verification without advertised DCR skips registration', async () => {
  const rid = 'route-nodcr-1';
  const rurl = `https://relay.example.org/r/${rid}/mcp`;
  const iss = `https://relay.example.org/r/${rid}/oauth`;
  const base = { publications: [{ route_id: rid, external_host: 'relay.example.org', profile: 'upstream-oauth', pub_name: 's', lease_id: null, created_at: '', revoked_at: null, verified_at: 't' }] };
  const asm = { issuer: iss, authorization_endpoint: iss + '/authorize', token_endpoint: iss + '/token', code_challenge_methods_supported: ['S256'] };
  const client = new NativeOclivClient(loadNativeConfig(keyEnv()), async (url, opts = {}) => {
    if (url === 'https://relay.example.org/v1/agent/mcp-routes') return json(base);
    if (url.includes('/.well-known/oauth-authorization-server/')) return json(asm);
    if (url.startsWith('https://relay.example.org/.well-known/')) return json({ resource: rurl, authorization_servers: [iss] });
    if (url === rurl && opts.method === 'POST') return new Response('unauthorized', { status: 401 });
    throw new Error('unexpected fetch (DCR must not run): ' + url);
  });
  const out = await client.verifyPublication(rid);
  assert.equal(out.verified, false);
  assert.equal(out.code, 'OAUTH_REQUIRED');
  assert.equal(out.registeredClient, null);
});

test('public URL uses the publication external_host, never the control host', async () => {
  const mk = (host) => new NativeOclivClient(loadNativeConfig(keyEnv()), async (url) => {
    if (url === 'https://control.example.org/v1/agent/mcp-routes') {
      return json({ publications: [{ route_id: 'route-ext-1', external_host: host, profile: 'p', pub_name: 'x', lease_id: null, created_at: '', revoked_at: null, verified_at: 't' }] });
    }
    throw new Error('unexpected');
  });
  const cfg = loadNativeConfig({ ...keyEnv(), OCLIV_RELAY_URL: 'https://control.example.org' });
  const c = new NativeOclivClient(cfg, mk('mcp.example.org').fetch);
  const pubs = await c.list();
  assert.equal(pubs[0].publicUrl, 'https://mcp.example.org/r/route-ext-1/mcp');
  const bad = new NativeOclivClient(cfg, mk('evil host/../x').fetch);
  await assert.rejects(bad.list(), { code: 'UPSTREAM_CONTRACT' });
});

test('verify never touches the registration endpoint, rejects bad id echo', async () => {
  const base = { publications: [{ route_id: 'route-strict-1', external_host: 'relay.example.org', profile: 'upstream-oauth', pub_name: 's', lease_id: null, created_at: '', revoked_at: null, verified_at: 't' }] };
  const rurl = 'https://relay.example.org/r/route-strict-1/mcp';
  const iss = 'https://relay.example.org/r/route-strict-1/oauth';
  const prm = { resource: rurl, authorization_servers: [iss] };
  const asm = { issuer: iss, authorization_endpoint: iss + '/authorize', token_endpoint: iss + '/token', registration_endpoint: iss + '/register', code_challenge_methods_supported: ['S256'] };
  const noDcr = async (url, opts = {}) => {
    if (url === 'https://relay.example.org/v1/agent/mcp-routes') return json(base);
    if (url.includes('/.well-known/oauth-authorization-server/')) return json(asm);
    if (url.startsWith('https://relay.example.org/.well-known/')) return json(prm);
    if (url === iss + '/register') throw new Error('DCR must not run during verify: ' + url);
    if (url === rurl) {
      if (!opts.headers.authorization) return new Response('unauthorized', { status: 401 });
      const body = JSON.parse(opts.body);
      if (body.method === 'notifications/initialized') return new Response('', { status: 202 });
      return json({ jsonrpc: '2.0', id: 999, result: {} });
    }
    throw new Error('unexpected: ' + url);
  };
  // No token: discovery passes, registration never attempted.
  const noTok = await new NativeOclivClient(loadNativeConfig(keyEnv()), noDcr).verifyPublication('route-strict-1');
  assert.equal(noTok.code, 'OAUTH_REQUIRED');
  assert.equal(noTok.registeredClient, null);
  // Wrong id echo on initialize.
  const wrongId = new NativeOclivClient(loadNativeConfig(keyEnv()), async (url, opts = {}) => {
    if (url === 'https://relay.example.org/v1/agent/mcp-routes') return json(base);
    if (url.includes('/.well-known/oauth-authorization-server/')) return json(asm);
    if (url.startsWith('https://relay.example.org/.well-known/')) return json(prm);
    if (url === iss + '/register') throw new Error('DCR must not run during verify: ' + url);
    if (url === rurl) {
      if (!opts.headers.authorization) return new Response('unauthorized', { status: 401 });
      const body = JSON.parse(opts.body);
      if (body.method === 'notifications/initialized') return new Response('', { status: 202 });
      return json({ jsonrpc: '2.0', id: 999, result: {} });
    }
    throw new Error('unexpected: ' + url);
  });
  const badEcho = await wrongId.verifyPublication('route-strict-1', { verifyToken: boundToken(rurl) });
  assert.equal(badEcho.code, 'MCP_CONTRACT');
});

test('approvals bind subject/action/target, single-use, expiring', async () => {
  const { Approvals } = await import('../src/core/approvals.mjs');
  let t = 1000;
  const a = new Approvals({ ttlMs: 60000, now: () => t });
  // Wrong subject / action / target / code all fail (fresh grant each:
  // redeem consumes on first attempt by design).
  const fresh = () => a.request({ subject: 'op-1', action: 'publish', target: 'lab' });
  const g = fresh();
  assert.ok(g.approvalId && g.code);
  assert.throws(() => a.redeem({ subject: 'op-2', action: 'publish', target: 'lab', approvalId: fresh().approvalId, code: g.code }), { code: 'APPROVAL_SUBJECT' });
  assert.throws(() => a.redeem({ subject: 'op-1', action: 'unpublish', target: 'lab', approvalId: fresh().approvalId, code: g.code }), { code: 'APPROVAL_BINDING' });
  assert.throws(() => a.redeem({ subject: 'op-1', action: 'publish', target: 'lab', approvalId: fresh().approvalId, code: 'wrong' }), { code: 'APPROVAL_CODE' });
  // Success consumes: replay fails.
  assert.deepEqual(a.redeem({ subject: 'op-1', action: 'publish', target: 'lab', approvalId: g.approvalId, code: g.code }), { approved: true, action: 'publish', target: 'lab' });
  assert.throws(() => a.redeem({ subject: 'op-1', action: 'publish', target: 'lab', approvalId: g.approvalId, code: g.code }), { code: 'APPROVAL_INVALID' });
  // Expiry fails.
  const g2 = a.request({ subject: 'op-1', action: 'unpublish', target: 'route-1' });
  t += 61000;
  assert.throws(() => a.redeem({ subject: 'op-1', action: 'unpublish', target: 'route-1', approvalId: g2.approvalId, code: g2.code }), { code: 'APPROVAL_EXPIRED' });
  // Listing never exposes codes.
  a.request({ subject: 'op-1', action: 'publish', target: 'lab' });
  assert.equal(JSON.stringify(a.list()).includes(g.code), false);
});

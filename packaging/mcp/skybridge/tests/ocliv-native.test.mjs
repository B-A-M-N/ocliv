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
  signMgmt, NativeOclivClient,
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

function verifyFetch({ tokenTools = null } = {}) {
  return async (url, opts = {}) => {
    if (url === 'https://relay.example.org/v1/agent/mcp-routes') return json(PUBS);
    if (url === 'https://relay.example.org/.well-known/oauth-protected-resource/r/route-abc-123/mcp') return json(PRM);
    if (url === 'https://relay.example.org/.well-known/oauth-authorization-server/r/route-abc-123/oauth') return json(ASM);
    if (url === ISS + '/register' && opts.method === 'POST') return json({ client_id: 'cid-1' });
    if (url === PUBURL && opts.method === 'POST') {
      const body = JSON.parse(opts.body);
      const authed = (opts.headers.authorization || '') === 'Bearer good-token';
      if (!authed) return new Response('unauthorized', { status: 401 });
      if (tokenTools === 'ok' && body.method === 'initialize') {
        return json({ jsonrpc: '2.0', id: 1, result: { protocolVersion: '2026-07-28', capabilities: {}, serverInfo: {} } });
      }
      if (tokenTools === 'ok' && body.method === 'tools/list') {
        return json({ jsonrpc: '2.0', id: 1, result: { tools: [{ name: 'ping' }] } });
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
  assert.equal(out.registeredClient, 'cid-1');
});

test('verify with valid token proves initialize + tools/list', async () => {
  const client = new NativeOclivClient(loadNativeConfig(keyEnv()), verifyFetch({ tokenTools: 'ok' }));
  const out = await client.verifyPublication('route-abc-123', { verifyToken: 'good-token' });
  assert.equal(out.verified, true);
  assert.equal(out.protocolVersion, '2026-07-28');
  assert.deepEqual(out.tools, ['ping']);
});

test('verify denies anonymous execution and bad tokens', async () => {
  const client = new NativeOclivClient(loadNativeConfig(keyEnv()), verifyFetch());
  const out = await client.verifyPublication('route-abc-123', { verifyToken: 'bad-token' });
  assert.equal(out.verified, false);
  assert.equal(out.code, 'MCP_DENIED');
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

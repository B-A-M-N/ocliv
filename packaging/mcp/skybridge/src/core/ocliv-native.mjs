/** Ocliv-native management adapter: talks Ocliv's actual signed Ed25519
 * management protocol (ocliv-mgmt-v1), not the assumed Bearer/JSON
 * control API. Publisher-side only: the agent private key never leaves
 * this host; nothing here is exposed to visitors or the public edge.
 *
 * Relay contract (see internal/relay/relay_mgmt_routes.go,
 * internal/agent/agent_ws.go MgmtMessage):
 *   GET  /v1/agent/mcp-routes        key-scoped publication list (JSON)
 *   DELETE /v1/agent/mcp-routes/{id}  exact publication removal (JSON)
 * Headers: X-Ocliv-Key, X-Ocliv-TS (RFC3339), X-Ocliv-Nonce (base64,
 * required for mutations), X-Ocliv-Sig (base64 ed25519 over
 * "ocliv-mgmt-v1\n{key}\n{METHOD}\n{path}\n{unix}\n{nonce}").
 * No new relay authentication scheme is invented here.
 *
 * Publication `state` is durable publication state only
 * (active = verified binding, pending = unverified, revoked =
 * tombstoned). It is NEVER tunnel liveness: an active publication
 * with an offline lease admits nothing.
 */
import { createPrivateKey, createPublicKey, sign, randomBytes, createHash } from 'node:crypto';
import { statSync, readFileSync } from 'node:fs';

export class NativeError extends Error {
  constructor(code, message) { super(message); this.code = code; }
}

function required(name, env) {
  const v = (env[name] ?? '').trim();
  if (!v) throw new NativeError('INVALID_CONFIG', `Missing ${name}: the native adapter fails closed`);
  return v;
}

/** Load and validate the native adapter config. Key file must be a
 * 0600 base64 32-byte seed — the exact format `ocliv login` writes. */
export function loadNativeConfig(env = process.env) {
  const relayRaw = required('OCLIV_RELAY_URL', env);
  let relay;
  try { relay = new URL(relayRaw); } catch { throw new NativeError('INVALID_CONFIG', 'OCLIV_RELAY_URL must be a valid URL'); }
  if (relay.protocol !== 'https:' || relay.username || relay.password || relay.pathname !== '/' || relay.search || relay.hash) {
    throw new NativeError('INVALID_CONFIG', 'OCLIV_RELAY_URL must be a bare https origin (no path, query, or credentials)');
  }
  const keyFile = required('OCLIV_AGENT_KEY_FILE', env);
  let st;
  try { st = statSync(keyFile); } catch { throw new NativeError('INVALID_CONFIG', `Agent key file unreadable: ${keyFile}`); }
  if (!st.isFile() || (st.mode & 0o077) !== 0) {
    throw new NativeError('INVALID_CONFIG', `Agent key file must have owner-only permissions (0600): ${keyFile}`);
  }
  const seed = Buffer.from(readFileSync(keyFile, 'utf8').trim(), 'base64');
  if (seed.length !== 32) throw new NativeError('INVALID_CONFIG', 'Agent key is corrupt (want 32-byte base64 seed)');
  // Wire key IDs carry the "key-" prefix (cli loadKey: "key-" + ID()).
  // Accept the override with or without it, normalize to prefixed form.
  let keyID = (env.OCLIV_AGENT_KEY_ID ?? '').trim();
  if (keyID.startsWith('key-')) keyID = keyID.slice(4);
  if (keyID === '') keyID = deriveKeyID(seed);
  if (!/^[0-9a-f]{16}$/.test(keyID)) throw new NativeError('INVALID_CONFIG', 'OCLIV_AGENT_KEY_ID must be 16 lowercase hex chars (optional key- prefix allowed)');
  return { relay: relay.origin, keyFile, seed, keyID: 'key-' + keyID };
}

export function deriveKeyID(seed) {
  const pub = createPublicKey(privateKeyFromSeed(seed)).export({ format: 'der', type: 'spki' });
  // SPKI DER ends with the 32-byte raw public key for Ed25519.
  const raw = pub.subarray(pub.length - 32);
  return createHash('sha256').update(raw).digest('hex').slice(0, 16);
}

function privateKeyFromSeed(seed) {
  // Build PKCS#8 DER around the raw seed (1.3.101.112 curve OID).
  const seedDer = Buffer.concat([
    Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.from(seed),
  ]);
  return createPrivateKey({ key: seedDer, format: 'der', type: 'pkcs8' });
}

export function publicKeyFromSeed(seed) {
  const pub = createPublicKey(privateKeyFromSeed(seed)).export({ format: 'der', type: 'spki' });
  return Buffer.from(pub.subarray(pub.length - 32));
}

/** Sign one management request. Returns the four X-Ocliv-* headers. */
export function signMgmt(seed, keyID, method, path, now = new Date()) {
  const ts = now.toISOString(); // RFC3339 with ms: valid RFC3339Nano
  const nonce = randomBytes(16).toString('base64');
  const msg = `ocliv-mgmt-v1\n${keyID}\n${method}\n${path}\n${Math.floor(now.getTime() / 1000)}\n${nonce}`;
  const sig = sign(null, Buffer.from(msg), privateKeyFromSeed(seed)).toString('base64');
  return { 'X-Ocliv-Key': keyID, 'X-Ocliv-TS': ts, 'X-Ocliv-Nonce': nonce, 'X-Ocliv-Sig': sig };
}

const ROUTE_ID = /^[A-Za-z0-9_-]{3,64}$/;

/** RFC 9728 placement: insert the well-known suffix after the authority,
 * before the resource path. */
export function wellKnown(resourceUrl, suffix) {
  const u = new URL(resourceUrl);
  return `${u.origin}${suffix}${u.pathname}`;
}

function cleanPublication(p, relayHost) {
  if (!p || typeof p !== 'object') throw new NativeError('UPSTREAM_CONTRACT', 'Invalid publication record from relay');
  const id = p.route_id;
  if (typeof id !== 'string' || !ROUTE_ID.test(id)) throw new NativeError('UPSTREAM_CONTRACT', 'Invalid route_id from relay');
  let state = 'active';
  if (p.revoked_at != null) state = 'revoked';
  else if (p.verified_at == null) state = 'pending';
  return {
    id,
    label: typeof p.pub_name === 'string' ? p.pub_name.slice(0, 120) : '',
    profile: typeof p.profile === 'string' ? p.profile.slice(0, 48) : 'unknown',
    state, // durable publication state, NOT tunnel liveness
    publicUrl: `https://${relayHost}/r/${id}/mcp`,
    leaseId: typeof p.lease_id === 'string' ? p.lease_id : null,
  };
}

/** The only relay paths this adapter may sign for. The agent key stays
 * publisher-side, but even a confused caller cannot turn it into a
 * lease-close, rebind, or enrollment signature. */
export function assertMgmtPath(path) {
  if (path === '/v1/agent/mcp-routes' ||
      /^\/v1\/agent\/mcp-routes\/[A-Za-z0-9_-]{3,64}$/.test(path)) return path;
  throw new NativeError('INVALID_PATH', 'Refusing to sign outside the publication management API');
}

export class NativeOclivClient {
  constructor(config, fetchImpl = fetch) { this.c = config; this.fetch = fetchImpl; }
  relayHost() { return new URL(this.c.relay).hostname; }

  async request(method, path) {
    assertMgmtPath(path);
    const headers = signMgmt(this.c.seed, this.c.keyID, method, path);
    headers.accept = 'application/json';
    let response;
    try {
      response = await this.fetch(this.c.relay + path, {
        method, redirect: 'manual', signal: AbortSignal.timeout(8000), headers,
      });
    } catch (e) {
      if (e instanceof NativeError) throw e;
      throw new NativeError('UPSTREAM_UNAVAILABLE', 'Relay management endpoint is unreachable');
    }
    if (response.status >= 300 && response.status < 400) throw new NativeError('UPSTREAM_REDIRECT', 'Relay redirected unexpectedly');
    if (response.status === 401 || response.status === 403) throw new NativeError('UPSTREAM_AUTH', 'Relay rejected the agent key (revoked, suspended, or unknown)');
    if (!response.ok) throw new NativeError('UPSTREAM_FAILURE', `Relay management returned HTTP ${response.status}`);
    const text = await response.text();
    try { return JSON.parse(text); } catch { throw new NativeError('UPSTREAM_CONTRACT', 'Expected JSON from relay management'); }
  }

  /** List every publication owned by this agent key. */
  async list() {
    const body = await this.request('GET', '/v1/agent/mcp-routes');
    if (!body || !Array.isArray(body.publications)) throw new NativeError('UPSTREAM_CONTRACT', 'Expected {publications:[...]} from relay');
    const host = this.relayHost();
    return body.publications.map((p) => cleanPublication(p, host));
  }

  /** Get one publication by exact route ID (filter of the owned list). */
  async get(id) {
    if (!ROUTE_ID.test(id)) throw new NativeError('INVALID_ID', 'Unknown publication id');
    const pubs = await this.list();
    const found = pubs.find((p) => p.id === id);
    if (!found) throw new NativeError('NOT_FOUND', 'No owned publication with that id');
    return found;
  }

  /** Read-only status: relay reachability + durable publication states.
   * Never reports tunnel liveness. */
  async status() {
    let relayReachable = false;
    try {
      const r = await this.fetch(this.c.relay + '/v1/agent/challenge', { method: 'GET', redirect: 'manual', signal: AbortSignal.timeout(8000) });
      relayReachable = r.status !== 0; // any HTTP answer proves reachability
    } catch { relayReachable = false; }
    let publications = [];
    let listError = null;
    try { publications = await this.list(); } catch (e) { listError = e.code || 'LIST_FAILED'; }
    const byState = {};
    for (const p of publications) byState[p.state] = (byState[p.state] || 0) + 1;
    return { relay: this.c.relay, relayReachable, publications: byState, listError };
  }

  /** Verify a publication's public OAuth+MCP surface with the real
   * handshake, never a static assumption:
   *  1. protected-resource metadata: resource must equal the public URL,
   *     authorization_servers must name exactly one issuer;
   *  2. authorization-server metadata: issuer match, S256 advertised;
   *  3. dynamic client registration (proves the token endpoint lives);
   *  4. unauthenticated tools/list must 401 (never anonymous);
   *  5. with a provisioned access token (OCLIV_VERIFY_TOKEN): initialize
   *     + tools/list must succeed.
   * Without a token the result is discovery-verified with user-consent
   * still required — reported as OAUTH_REQUIRED, never as verified.
   * NOTE: there is deliberately no publish() here. Publishing needs a
   * live local publisher lifecycle, not a management call. */
  async verifyPublication(id, { verifyToken } = {}) {
    const pub = await this.get(id);
    const fail = (code, message, detail = {}) => ({ id, publicUrl: pub.publicUrl, verified: false, code, message, ...detail });
    const metaUrl = wellKnown(pub.publicUrl, '/.well-known/oauth-protected-resource');
    let prm;
    try {
      const r = await this.fetch(metaUrl, { redirect: 'manual', signal: AbortSignal.timeout(8000) });
      if (!r.ok) return fail('DISCOVERY_HTTP', `Resource metadata answered HTTP ${r.status}`);
      prm = await r.json();
    } catch { return fail('DISCOVERY_UNREACHABLE', 'Resource metadata unreachable'); }
    if (!prm || prm.resource !== pub.publicUrl) return fail('RESOURCE_MISMATCH', 'Upstream advertises a different resource than the published route');
    if (!Array.isArray(prm.authorization_servers) || prm.authorization_servers.length !== 1 || typeof prm.authorization_servers[0] !== 'string') {
      return fail('ISSUER_MISSING', 'Resource metadata names no usable authorization server');
    }
    const issuer = prm.authorization_servers[0];
    let asm;
    try {
      const r = await this.fetch(wellKnown(issuer, '/.well-known/oauth-authorization-server'), { redirect: 'manual', signal: AbortSignal.timeout(8000) });
      if (!r.ok) return fail('AS_HTTP', `AS metadata answered HTTP ${r.status}`);
      asm = await r.json();
    } catch { return fail('AS_UNREACHABLE', 'Authorization-server metadata unreachable'); }
    if (!asm || asm.issuer !== issuer) return fail('ISSUER_MISMATCH', 'AS metadata issuer does not match the advertised server');
    if (!Array.isArray(asm.code_challenge_methods_supported) || !asm.code_challenge_methods_supported.includes('S256')) {
      return fail('PKCE_UNSUPPORTED', 'AS metadata does not advertise S256');
    }
    for (const ep of ['authorization_endpoint', 'token_endpoint', 'registration_endpoint']) {
      if (typeof asm[ep] !== 'string' || !asm[ep].startsWith('https://')) return fail('AS_ENDPOINT', `AS metadata endpoint missing: ${ep}`);
    }
    // Dynamic registration proves the token endpoint lives.
    let clientId = null;
    try {
      const r = await this.fetch(asm.registration_endpoint, {
        method: 'POST', redirect: 'manual', signal: AbortSignal.timeout(8000),
        headers: { 'content-type': 'application/json', accept: 'application/json' },
        body: JSON.stringify({ redirect_uris: [`${issuer}/../local-verify-callback`], grant_types: ['authorization_code'] }),
      });
      // Any redirect_uri the lab server rejects still proves liveness;
      // only hard failures (unreachable/5xx) fail the check.
      if (r.status >= 500) return fail('REGISTER_HTTP', `Registration endpoint answered HTTP ${r.status}`);
      try { clientId = (await r.json()).client_id || null; } catch { clientId = null; }
    } catch { return fail('REGISTER_UNREACHABLE', 'Registration endpoint unreachable'); }
    // Unauthenticated tools/list must 401: no anonymous execution.
    try {
      const r = await this.fetch(pub.publicUrl, {
        method: 'POST', redirect: 'manual', signal: AbortSignal.timeout(8000),
        headers: { 'content-type': 'application/json', accept: 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} }),
      });
      if (r.status !== 401) return fail('AUTH_BYPASS', `Unauthenticated tools/list answered HTTP ${r.status} (want 401)`);
    } catch { return fail('MCP_UNREACHABLE', 'Tool endpoint unreachable'); }
    if (!verifyToken) {
      return {
        id, publicUrl: pub.publicUrl, verified: false, code: 'OAUTH_REQUIRED',
        message: 'Discovery + registration verified; user consent + token still required (no access token provisioned)',
        issuer, authorizeUrl: asm.authorization_endpoint, registeredClient: clientId,
      };
    }
    // Authenticated proof with a provisioned token.
    const call = async (method, params) => {
      const r = await this.fetch(pub.publicUrl, {
        method: 'POST', redirect: 'manual', signal: AbortSignal.timeout(8000),
        headers: { 'content-type': 'application/json', accept: 'application/json', authorization: `Bearer ${verifyToken}` },
        body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
      });
      if (r.status !== 200) throw new NativeError('MCP_DENIED', `Authenticated ${method} answered HTTP ${r.status}`);
      return r.json();
    };
    try {
      const init = await call('initialize', { protocolVersion: '2026-07-28', capabilities: {}, clientInfo: { name: 'ocliv-verify', version: '1' } });
      if (!init || !init.result || typeof init.result.protocolVersion !== 'string') {
        return fail('MCP_CONTRACT', 'initialize did not negotiate a protocol version');
      }
      const list = await call('tools/list', {});
      const tools = list && list.result && Array.isArray(list.result.tools) ? list.result.tools : null;
      if (!tools) return fail('MCP_CONTRACT', 'tools/list returned no tool array');
      return { id, publicUrl: pub.publicUrl, verified: true, protocolVersion: init.result.protocolVersion, tools: tools.map((t) => t.name) };
    } catch (e) {
      if (e instanceof NativeError) return fail(e.code, e.message);
      return fail('MCP_UNREACHABLE', 'Authenticated tool call failed');
    }
  }

  /** Permanently delete exactly one owned publication, then re-query to
   * confirm it is gone. A failed recheck is reported, never success. */
  async unpublish(id) {
    if (!ROUTE_ID.test(id)) throw new NativeError('INVALID_ID', 'Unknown publication id');
    const body = await this.request('DELETE', `/v1/agent/mcp-routes/${id}`);
    if (!body || body.status !== 'deleted') throw new NativeError('UPSTREAM_CONTRACT', 'Relay did not confirm deletion');
    const pubs = await this.list();
    if (pubs.some((p) => p.id === id)) throw new NativeError('UNCONFIRMED', 'Deletion unconfirmed: route still listed after delete');
    return { id, deleted: true };
  }
}

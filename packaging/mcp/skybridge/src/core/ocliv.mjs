/** Transport-independent Ocliv management boundary. No fabricated remote state. */
const ID = /^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}$/;
const SAFE_PATH = /^\/(?:[a-zA-Z0-9._~/-]|\{id\})+$/;
const RESERVED = /\.{2}|\/\//;
const MAX_BODY_BYTES = 1024 * 1024;
async function readLimited(response, limit) {
  const len = Number(response.headers?.get('content-length') || 0);
  if (len > limit) throw new OclivError('UPSTREAM_CONTRACT', 'Response exceeds size limit');
  if (!response.body) return '';
  const reader = response.body.getReader();
  const chunks = []; let length = 0;
  try {
    for (;;) {
      const {done,value} = await reader.read(); if (done) break;
      length += value.byteLength;
      if (length > limit) throw new OclivError('UPSTREAM_CONTRACT','Response exceeds size limit');
      chunks.push(value);
    }
  } finally { try { await reader.cancel(); } catch {} reader.releaseLock(); }
  return Buffer.concat(chunks, length).toString('utf8');
}

export class OclivError extends Error {
  constructor(code, message) { super(message); this.name = 'OclivError'; this.code = code; }
}

export function validId(id) {
  if (typeof id !== 'string' || !ID.test(id) || id === '.' || id === '..') {
    throw new OclivError('INVALID_INPUT', 'Invalid Ocliv resource ID');
  }
  return id;
}

export function loadConfig(env = process.env) {
  const required = (k) => { const v = env[k]?.trim(); if (!v) throw new OclivError('NOT_CONFIGURED', `${k} must be configured`); return v; };
  const base = new URL(required('OCLIV_CONTROL_URL'));
  if (base.protocol !== 'https:' || base.username || base.password || base.search || base.hash || base.pathname !== '/') {
    throw new OclivError('INVALID_CONFIG', 'OCLIV_CONTROL_URL must be an HTTPS origin with no credentials, path, query, or fragment');
  }
  const token = required('OCLIV_CONTROL_TOKEN');
  if (token.includes('\n') || token.includes('\r')) throw new OclivError('INVALID_CONFIG','Unsafe credential');
  const paths = {};
  for (const [name, envName, hasId] of [
    ['status', 'OCLIV_STATUS_PATH', false], ['list', 'OCLIV_LIST_PATH', false],
    ['get', 'OCLIV_GET_PATH', true], ['publish', 'OCLIV_PUBLISH_PATH', false],
    ['unpublish', 'OCLIV_UNPUBLISH_PATH', true]
  ]) {
    const path = required(envName);
    if (!SAFE_PATH.test(path) || RESERVED.test(path) || (hasId !== path.includes('{id}'))) {
      throw new OclivError('INVALID_CONFIG', `${envName} must be a fixed absolute API path${hasId ? ' with {id}' : ''}`);
    }
    paths[name] = path;
  }
  const subjects = new Set(required('OCLIV_ALLOWED_SUBJECTS').split(',').map(x=>x.trim()).filter(Boolean));
  const publicHosts = new Set(required('OCLIV_PUBLIC_HOSTS').split(',').map(x=>x.trim().toLowerCase()).filter(Boolean));
  if ([...publicHosts].some(x => !/^[a-z0-9.-]+$/.test(x) || x.startsWith('.') || x.endsWith('.'))) {
    throw new OclivError('INVALID_CONFIG', 'Invalid public hostname allowlist');
  }
  const probeToken = env.OCLIV_PROBE_TOKEN || '';
  if (/[\r\n]/.test(probeToken)) throw new OclivError('INVALID_CONFIG','Unsafe public probe credential');
  return { base: base.origin, token, paths, subjects, publicHosts, probeToken,
    writeEnabled: env.OCLIV_WRITE_ENABLED === 'true' };
}

export function authorize(authInfo, subjects, scope = 'ocliv:read') {
  if (!authInfo || !Array.isArray(authInfo.scopes) || !authInfo.scopes.includes(scope)) {
    throw new OclivError('FORBIDDEN', `Required scope: ${scope}`);
  }
  // Different IdPs use sub/subject in their verified extra claims. Never use a client-provided argument.
  const identity = authInfo.extra?.sub ?? authInfo.extra?.subject;
  if (typeof identity !== 'string' || !subjects.has(identity)) {
    throw new OclivError('FORBIDDEN', 'Identity is not authorized for this Ocliv deployment');
  }
  return identity;
}

function cleanPublication(p) {
  if (!p || typeof p !== 'object' || typeof p.id !== 'string') throw new OclivError('UPSTREAM_CONTRACT','Invalid publication record from Ocliv');
  return {
    id: validId(p.id),
    label: typeof p.label === 'string' ? p.label.slice(0,120) : '',
    status: typeof p.status === 'string' ? p.status.slice(0,48) : 'unknown',
    publicUrl: typeof p.publicUrl === 'string' ? p.publicUrl.slice(0,2048) : null,
    serviceId: typeof p.serviceId === 'string' ? p.serviceId.slice(0,128) : null,
  };
}

export function parsePublicUrl(raw, hosts) {
  let u;
  try { u = new URL(raw); } catch { throw new OclivError('INVALID_PUBLIC_URL','Published endpoint URL is invalid'); }
  if (u.protocol !== 'https:' || u.username || u.password || u.hash || u.port || !hosts.has(u.hostname.toLowerCase())) {
    throw new OclivError('INVALID_PUBLIC_URL','Published URL is not an authorized HTTPS host');
  }
  return u;
}

function boundedTimeout(ms = 8000) { return AbortSignal.timeout(ms); }

export class OclivClient {
  constructor(config, fetchImpl = fetch) { this.c = config; this.fetch = fetchImpl; }
  path(which, id) {
    let path = this.c.paths[which];
    if (!path) throw new OclivError('NOT_CONFIGURED', `Ocliv API mapping missing: ${which}`);
    if (id !== undefined) path = path.replace('{id}', encodeURIComponent(validId(id)));
    return this.c.base + path;
  }
  async request(method, which, { id, body } = {}) {
    let response;
    try {
      response = await this.fetch(this.path(which, id), {
        method, redirect: 'manual', signal: boundedTimeout(),
        headers: { 'accept':'application/json', 'content-type':'application/json', 'authorization':`Bearer ${this.c.token}` },
        ...(body !== undefined ? {body: JSON.stringify(body)} : {})
      });
    } catch (error) {
      if (error instanceof OclivError) throw error;
      throw new OclivError('UPSTREAM_UNAVAILABLE', 'Ocliv management endpoint is unavailable');
    }
    if (response.status >= 300 && response.status < 400) throw new OclivError('UPSTREAM_REDIRECT','Ocliv management redirected unexpectedly');
    if (response.status === 401 || response.status === 403) throw new OclivError('UPSTREAM_AUTH','Ocliv management rejected its service credential');
    if (!response.ok) throw new OclivError('UPSTREAM_FAILURE', `Ocliv management returned HTTP ${response.status}`);
    if (response.status === 204) return {};
    const data = await readLimited(response, MAX_BODY_BYTES);
    try { return JSON.parse(data); } catch { throw new OclivError('UPSTREAM_CONTRACT','Expected JSON from Ocliv management'); }
  }
  async status() {
    const result = await this.request('GET', 'status');
    if (!result || typeof result.status !== 'string') throw new OclivError('UPSTREAM_CONTRACT','Status payload requires status');
    return { status:result.status.slice(0,48), checkedAt:new Date().toISOString() };
  }
  async list() {
    const data = await this.request('GET','list');
    if (!Array.isArray(data.publications) || data.publications.length > 1000) throw new OclivError('UPSTREAM_CONTRACT','Expected {publications:[]}');
    return { publications:data.publications.map(cleanPublication), checkedAt:new Date().toISOString() };
  }
  async get(id) { return cleanPublication(await this.request('GET','get',{id})); }
  async publish({ serviceId, label, confirm }) {
    if (!this.c.writeEnabled) throw new OclivError('WRITES_DISABLED', 'Ocliv publishing is disabled by deployment policy');
    validId(serviceId);
    if (confirm !== 'PUBLISH') throw new OclivError('CONFIRM_REQUIRED','Explicit PUBLISH confirmation is required');
    const data = await this.request('POST','publish',{ body:{ serviceId, label: typeof label === 'string' ? label.slice(0,120) : '', kind:'mcp', access:'authenticated' } });
    return { publication: cleanPublication(data.publication) };
  }
  async unpublish({ publicationId, confirmPublicationId }) {
    if (!this.c.writeEnabled) throw new OclivError('WRITES_DISABLED', 'Ocliv removal is disabled by deployment policy');
    validId(publicationId);
    if (publicationId !== confirmPublicationId) throw new OclivError('CONFIRM_REQUIRED','Confirmation must exactly match publication ID');
    const data = await this.request('DELETE','unpublish',{id:publicationId});
    if (data.success !== true && data.deleted !== true) throw new OclivError('UPSTREAM_CONTRACT','Upstream did not explicitly acknowledge unpublish');
    return { unpublished: publicationId };
  }
  async verify(id) {
    // A returned URL from the control plane is untrusted until it passes the exact-host allowlist.
    const publication = await this.get(id);
    if (!publication.publicUrl) throw new OclivError('INVALID_PUBLIC_URL','No public URL returned for publication');
    const url = parsePublicUrl(publication.publicUrl, this.c.publicHosts);
    const headers = { 'content-type': 'application/json', 'accept': 'application/json, text/event-stream' };
    if (this.c.probeToken) headers.authorization = `Bearer ${this.c.probeToken}`;
    const invoke = async (payload, sessionId = undefined) => {
      let r;
      try { r = await this.fetch(url.href, {
        method:'POST', headers: { ...headers, ...(sessionId ? { 'mcp-session-id': sessionId, 'mcp-protocol-version': '2025-06-18' } : {}) },
        body:JSON.stringify(payload), redirect:'manual', signal: boundedTimeout(7000)
      }); } catch { throw new OclivError('PROBE_UNREACHABLE','Published MCP endpoint cannot be reached'); }
      if (r.status === 401 || r.status === 403) throw new OclivError('PROBE_AUTH','Published MCP endpoint requires different credentials');
      if (!r.ok) throw new OclivError('PROBE_HTTP',`Published MCP endpoint returned HTTP ${r.status}`);
      let text; try { text = await readLimited(r, 65536); }
      catch (e) { if (e instanceof OclivError) throw new OclivError('PROBE_PROTOCOL','Probe response too large'); throw e; }
      const ct = r.headers?.get('content-type') || '';
      if (ct.includes('text/event-stream')) {
        const segments = text.split(/\r?\n/).filter(line => line.startsWith('data:'));
        const json = segments.map(line => line.slice(5).trim()).find(line => line.startsWith('{'));
        if (!json) throw new OclivError('PROBE_PROTOCOL','No JSON-RPC payload in SSE');
        text = json;
      }
      try { return { data:JSON.parse(text), sessionId: r.headers?.get('mcp-session-id') || sessionId }; }
      catch { throw new OclivError('PROBE_PROTOCOL','Malformed MCP JSON-RPC response'); }
    };
    const init = await invoke({jsonrpc:'2.0',id:1,method:'initialize',params:{protocolVersion:'2025-06-18',capabilities:{},clientInfo:{name:'ocliv-mcp-probe',version:'0.1.0'}}});
    if (init.data.id !== 1 || !init.data.result?.protocolVersion) throw new OclivError('PROBE_PROTOCOL','Initialize handshake did not succeed');
    // MCP clients must send initialized before calling tools/list. A 202/204 is normal for notifications.
    try {
      const notice = await this.fetch(url.href, {
        method:'POST', redirect:'manual', signal:boundedTimeout(7000),
        headers:{...headers, ...(init.sessionId ? {'mcp-session-id':init.sessionId,'mcp-protocol-version':'2025-06-18'} : {})},
        body:JSON.stringify({jsonrpc:'2.0',method:'notifications/initialized'})
      });
      if (!notice.ok) throw new OclivError('PROBE_PROTOCOL', 'MCP initialized notification was rejected');
    } catch (error) {
      if (error instanceof OclivError) throw error;
      throw new OclivError('PROBE_UNREACHABLE', 'MCP initialized notification failed');
    }
    const tools = await invoke({jsonrpc:'2.0',id:2,method:'tools/list',params:{}},init.sessionId);
    if (tools.data.id !== 2 || !Array.isArray(tools.data.result?.tools)) throw new OclivError('PROBE_PROTOCOL','tools/list did not return a tool list');
    return { publicationId:id, reachable:true, protocolVersion:init.data.result.protocolVersion, tools:tools.data.result.tools.map(t => String(t.name || '')).filter(Boolean), checkedAt:new Date().toISOString() };
  }
}

export function safeError(e) {
  // Never pass upstream bodies, tokens, fetch URLs, stack traces, or provider errors to the model.
  // Typed errors (OclivError, NativeError, PublisherError) carry curated
  // messages; anything else keeps a generic message so fetch errors —
  // which can embed URLs, tokens, or stack fragments — never leak.
  const typed = typeof e?.code === 'string' && /^[A-Z_]{3,40}$/.test(e.code);
  return {
    ok: false,
    code: typed ? e.code : 'INTERNAL_ERROR',
    message: typed && typeof e.message === 'string' && e.message ? e.message.slice(0, 300) : 'Ocliv operation failed',
  };
}

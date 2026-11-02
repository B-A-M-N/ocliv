/** Publisher-side publication controller. Runs on the same host as the
 * enrolled publisher and the loopback MCP services — never remotely.
 * It does NOT invent a management publish API: it supervises the real
 * `ocliv mcp publish` CLI lifecycle (attach → register → verify →
 * route URL) for operator-allowlisted services only.
 *
 * Identity boundary: this controller holds NO signing key. Route
 * revocation goes through an injected revoker (the native signed
 * adapter). Without one, unpublish stops the local child and reports
 * revocation as UNKNOWN — never as success.
 */
import { spawn } from 'node:child_process';
import { constants as fsConstants, accessSync } from 'node:fs';
import { EventEmitter } from 'node:events';

export class PublisherError extends Error {
  constructor(code, message) { super(message); this.code = code; }
}

const NAME = /^[A-Za-z][A-Za-z0-9_-]{0,47}$/;
const ID = /^[A-Za-z0-9_-]{3,64}$/;

function required(name, env) {
  const v = (env[name] ?? '').trim();
  if (!v) throw new PublisherError('INVALID_CONFIG', `Missing ${name}: publisher controller fails closed`);
  return v;
}

/** Strict allowlist entry: loopback literal, explicit port, exactly /mcp,
 * no userinfo/query/fragment. Remote callers can never supply a target:
 * new targets require editing this operator configuration. */
export function parseService(raw) {
  if (!raw || typeof raw !== 'object') throw new PublisherError('INVALID_SERVICE', 'Allowlisted service must be an object');
  if (typeof raw.name !== 'string' || !NAME.test(raw.name)) throw new PublisherError('INVALID_SERVICE', 'Service name invalid');
  let u;
  try { u = new URL(raw.localUrl); } catch { throw new PublisherError('INVALID_SERVICE', 'Service localUrl invalid'); }
  if (u.protocol !== 'http:' || (u.hostname !== '127.0.0.1' && u.hostname !== '[::1]') ||
      !u.port || u.pathname !== '/mcp' || u.search || u.hash || u.username || u.password) {
    throw new PublisherError('INVALID_SERVICE', 'Service URL must be a loopback literal with explicit port and exactly /mcp');
  }
  if (raw.resourceFile !== undefined &&
      (typeof raw.resourceFile !== 'string' || !raw.resourceFile.startsWith('/') || raw.resourceFile.includes('\0'))) {
    throw new PublisherError('INVALID_SERVICE', 'resourceFile must be an absolute local path');
  }
  return { name: raw.name, localUrl: `${u.protocol}//${u.host}/mcp`, resourceFile: raw.resourceFile };
}

export function loadPublisherConfig(env = process.env) {
  const bin = required('OCLIV_BIN', env);
  try { accessSync(bin, fsConstants.X_OK); } catch {
    throw new PublisherError('INVALID_CONFIG', `OCLIV_BIN is not executable: ${bin}`);
  }
  const home = required('OCLIV_PUBLISHER_HOME', env);
  if (!home.startsWith('/')) throw new PublisherError('INVALID_CONFIG', 'OCLIV_PUBLISHER_HOME must be absolute');
  let services;
  try {
    services = JSON.parse(env.OCLIV_SERVICES_JSON ?? '[]');
    if (!Array.isArray(services)) throw new Error('not an array');
  } catch { throw new PublisherError('INVALID_CONFIG', 'OCLIV_SERVICES_JSON must be a JSON array'); }
  const registry = new Map();
  for (const s of services) {
    const parsed = parseService(s);
    if (registry.has(parsed.name)) throw new PublisherError('INVALID_CONFIG', `Duplicate service: ${parsed.name}`);
    registry.set(parsed.name, parsed);
  }
  return { bin, home, registry };
}

const ROUTE_URL = /https:\/\/\S+\/r\/[A-Za-z0-9_-]{3,64}\/mcp/;

export class PublisherController extends EventEmitter {
  constructor(config, { spawnImpl = spawn, now = Date.now } = {}) {
    super();
    this.c = config;
    this.spawnImpl = spawnImpl;
    this.now = now;
    this.children = new Map(); // name -> { child, routeUrl, startedAt, log: [], exited }
  }

  listServices() {
    return [...this.c.registry.values()].map((s) => ({
      name: s.name,
      supervised: this.children.has(s.name),
      routeUrl: this.children.get(s.name)?.routeUrl ?? null,
    }));
  }

  status(name) {
    const svc = this.c.registry.get(name);
    if (!svc) throw new PublisherError('UNKNOWN_SERVICE', `No allowlisted service: ${name}`);
    const live = this.children.get(name);
    return {
      name,
      localUrl: svc.localUrl,
      supervised: !!live && !live.exited,
      routeUrl: live?.routeUrl ?? null,
      lastExit: live?.exited ? { code: live.exitCode, at: live.exitedAt } : null,
    };
  }

  /** Start (or reattach to) the supervised publisher for an allowlisted
   * service. Requires the exact confirmation `PUBLISH <name>`. Resolves
   * with { routeUrl } once the CLI reports readiness; the child keeps
   * running under supervision afterwards. */
  async publish(name, confirmation, { readyTimeoutMs = 90000 } = {}) {
    const svc = this.c.registry.get(name);
    if (!svc) throw new PublisherError('UNKNOWN_SERVICE', `No allowlisted service: ${name}`);
    if (confirmation !== `PUBLISH ${name}`) throw new PublisherError('CONFIRMATION_REQUIRED', 'Publish requires the exact confirmation `PUBLISH <name>`');
    const existing = this.children.get(name);
    if (existing && !existing.exited) {
      if (!existing.routeUrl) throw new PublisherError('IN_PROGRESS', 'Publication already attaching; wait for its route URL');
      return { name, routeUrl: existing.routeUrl, resumed: true };
    }
    const args = ['mcp', 'publish', '--local', svc.localUrl, '--auth', 'upstream-oauth', '--name', name];
    if (svc.resourceFile) args.push('--resource-file', svc.resourceFile);
    const childEnv = { HOME: this.c.home, PATH: '/usr/bin:/bin' };
    if (process.env.OCLIV_CACERT) childEnv.OCLIV_CACERT = process.env.OCLIV_CACERT;
    const child = this.spawnImpl(this.c.bin, args, { env: childEnv, cwd: this.c.home, stdio: ['ignore', 'pipe', 'pipe'] });
    if (!child || !child.stdout || !child.stderr || typeof child.pid !== 'number') {
      throw new PublisherError('SPAWN_FAILED', 'Publisher process failed to start');
    }
    const rec = { child, routeUrl: null, startedAt: this.now(), log: [], exited: false, exitCode: null, exitedAt: null };
    this.children.set(name, rec);
    // Line-buffer each stream: chunks can split or merge lines; only
    // complete lines are scanned so a route URL split across two writes
    // is still observed exactly once.
    const scan = (line) => {
      if (rec.log.push(line) > 200) rec.log.shift();
      const m = line.match(ROUTE_URL);
      if (m && !rec.routeUrl) { rec.routeUrl = m[0]; this.emit('route', { name, routeUrl: rec.routeUrl }); }
    };
    const buffers = new Map();
    const watch = (stream) => (chunk) => {
      const acc = (buffers.get(stream) ?? '') + String(chunk);
      const parts = acc.split('\n');
      buffers.set(stream, parts.pop());
      for (const line of parts) scan(line);
    };
    child.stdout.on('data', watch('out'));
    child.stderr.on('data', watch('err'));
    child.on('error', (err) => { rec.exited = true; rec.exitCode = -1; rec.exitedAt = this.now(); rec.log.push(`spawn error: ${err.message}`); });
    child.on('exit', (code) => { rec.exited = true; rec.exitCode = code; rec.exitedAt = this.now(); });
    const cleanup = () => {
      // Never leave an unsupervised child behind on failure: terminate
      // and drop the record so a later publish starts clean.
      this.children.delete(name);
      try { child.kill('SIGTERM'); } catch { /* already gone */ }
      setTimeout(() => { try { if (!rec.exited) child.kill('SIGKILL'); } catch { /* already gone */ } }, 2000).unref?.();
    };
    const deadline = this.now() + readyTimeoutMs;
    for (;;) {
      if (rec.routeUrl) return { name, routeUrl: rec.routeUrl, resumed: false };
      if (rec.exited) {
        cleanup();
        throw new PublisherError('PUBLISH_FAILED',
          `Publisher exited before reporting a route (code ${rec.exitCode}): ${rec.log.slice(-5).join(' | ').slice(0, 500)}`);
      }
      if (this.now() >= deadline) {
        cleanup();
        throw new PublisherError('PUBLISH_TIMEOUT', 'Publisher did not report a route URL in time; child terminated');
      }
      await new Promise((r) => setTimeout(r, 250));
    }
  }

  /** Stop the supervised child for a service. Revocation of the public
   * route goes through the injected signed revoker; without one the
   * outcome reports revocation UNKNOWN, never success.
   * @param {string} publicationId
   * @param {string} confirmation
   * @param {{ revoker?: ((id: string) => Promise<{ id: string, deleted: boolean }>) | null }} [opts]
   */
  async unpublish(publicationId, confirmation, { revoker = null } = {}) {
    if (!ID.test(publicationId)) throw new PublisherError('INVALID_ID', 'Unknown publication id');
    if (confirmation !== publicationId) throw new PublisherError('CONFIRMATION_REQUIRED', 'Unpublish requires the exact publication ID as confirmation');
    let stopped = null;
    for (const [name, rec] of this.children) {
      if (rec.routeUrl && rec.routeUrl.includes(`/r/${publicationId}/`) && !rec.exited) {
        stopped = name;
        await new Promise((resolve) => {
          const t = setTimeout(() => { try { rec.child.kill('SIGKILL'); } catch { /* already gone */ } resolve(); }, 5000);
          rec.child.once('exit', () => { clearTimeout(t); resolve(); });
          try { rec.child.kill('SIGTERM'); } catch { clearTimeout(t); resolve(); }
        });
      }
    }
    if (!revoker) return { id: publicationId, stopped, revoked: 'UNKNOWN', message: 'Local publisher stopped (if running); route revocation not confirmed — no signed revoker configured' };
    const result = await revoker(publicationId);
    return { id: publicationId, stopped, revoked: result?.deleted ? 'REVOKED' : 'UNCONFIRMED', detail: result ?? null };
  }
}

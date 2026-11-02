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
import { constants as fsConstants, accessSync, readFileSync, writeFileSync, renameSync, unlinkSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
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
const ROUTE_ID = /\/r\/([A-Za-z0-9_-]{3,64})\/mcp/;
const STATE_FILE = '.ocliv-publisher-state.json';

/** Route id embedded in a route URL, or null. */
export function routeIdOf(routeUrl) {
  const m = typeof routeUrl === 'string' && routeUrl.match(ROUTE_ID);
  return m ? m[1] : null;
}

export class PublisherController extends EventEmitter {
  constructor(config, { spawnImpl = spawn, now = Date.now, fetchImpl = fetch } = {}) {
    super();
    this.c = config;
    this.spawnImpl = spawnImpl;
    this.now = now;
    this.fetchImpl = fetchImpl;
    this.children = new Map(); // name -> { child, routeUrl, startedAt, log: [], exited }
  }

  /** Readiness probe: an unauthenticated tools/list must be denied with
   * 401 — that proves ingress → relay → publisher forwarding is alive,
   * rather than trusting a URL the child printed. Any other outcome
   * (refused, wrong status, timeout) means the route is not serving. */
  async probeRoute(routeUrl, { timeoutMs = 10000 } = {}) {
    let r;
    try {
      r = await this.fetchImpl(routeUrl, {
        method: 'POST', redirect: 'manual', signal: AbortSignal.timeout(timeoutMs),
        headers: { 'content-type': 'application/json', accept: 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} }),
      });
    } catch (e) {
      throw new PublisherError('PUBLISH_UNHEALTHY', `Route not reachable for readiness probe: ${e?.message ?? e}`);
    }
    if (r.status !== 401) {
      throw new PublisherError('PUBLISH_UNHEALTHY', `Readiness probe answered HTTP ${r.status} (want 401 auth challenge)`);
    }
    return true;
  }

  statePath() { return join(this.c.home, STATE_FILE); }

  /** Durable route record: survives management-server restarts so a fresh
   * controller can re-adopt known routes instead of reporting amnesia.
   * Atomic write (temp + rename); best-effort — a lost record degrades
   * to ADOPTED-unknown, never to a false success. */
  persistState() {
    try {
      mkdirSync(this.c.home, { recursive: true });
      const records = {};
      for (const [name, rec] of this.children) {
        // Keep exited records too: the route may still exist on the relay
        // and reconcile must report ADOPTED (re-publish reattaches).
        if (rec.routeUrl) records[name] = { routeUrl: rec.routeUrl, startedAt: rec.startedAt, exited: rec.exited, exitCode: rec.exitCode };
      }
      const tmp = this.statePath() + '.tmp';
      writeFileSync(tmp, JSON.stringify(records));
      renameSync(tmp, this.statePath());
    } catch { /* degraded: memory state remains authoritative */ }
  }

  loadPersisted() {
    try {
      const raw = JSON.parse(readFileSync(this.statePath(), 'utf8'));
      if (!raw || typeof raw !== 'object') return {};
      const out = {};
      for (const [name, r] of Object.entries(raw)) {
        if (this.c.registry.has(name) && typeof r?.routeUrl === 'string' && routeIdOf(r.routeUrl)) {
          out[name] = { routeUrl: r.routeUrl, startedAt: r.startedAt ?? null };
        }
      }
      return out;
    } catch { return {}; }
  }

  clearPersisted(name) {
    try {
      const all = this.loadPersisted();
      if (!(name in all)) return;
      delete all[name];
      const tmp = this.statePath() + '.tmp';
      writeFileSync(tmp, JSON.stringify(all));
      renameSync(tmp, this.statePath());
    } catch { /* degraded */ }
  }

  /** Reconcile live children + persisted records against the authoritative
   * relay publication list (elements carry at least { id|route_id, state }
   * where state is 'active', 'pending', 'revoked', ...). Never invents a
   * success: only a live child whose route the relay confirms is ACTIVE;
   * a route the relay lists as revoked is REVOKED; listed-but-not-usable
   * or absent from a real relay answer is ORPHANED. A route saved locally
   * with no live child is ADOPTED (needs re-publish) only when the relay
   * still lists it as usable — never from a saved URL alone.
   * @param {Array<object>|null} authoritative null = no relay data (lenient
   * labels); an array (even empty) = the relay's answer (strict labels).
   */
  reconcile(authoritative = null) {
    const strict = Array.isArray(authoritative);
    const known = new Map(); // routeId -> state
    if (strict) {
      for (const p of authoritative) {
        const id = p?.id ?? p?.route_id;
        if (typeof id === 'string') known.set(id, p.state ?? 'unknown');
      }
    }
    const usable = (st) => st === 'active' || st === 'pending';
    const persisted = this.loadPersisted();
    return [...this.c.registry.values()].map((s) => {
      const live = this.children.get(s.name);
      const liveId = live && !live.exited && live.routeUrl ? routeIdOf(live.routeUrl) : null;
      const saved = persisted[s.name]?.routeUrl ?? null;
      const savedId = routeIdOf(saved);
      const routeUrl = live?.routeUrl ?? saved;
      let routeState = 'NONE';
      if (liveId) {
        if (known.get(liveId) === 'active') routeState = 'ACTIVE';
        else if (!strict) routeState = 'UNCONFIRMED';
        else if (known.get(liveId) === 'revoked') routeState = 'REVOKED';
        else routeState = 'ORPHANED';
      } else if (savedId) {
        if (!strict) routeState = 'ADOPTED';
        else if (usable(known.get(savedId))) routeState = 'ADOPTED';
        else if (known.get(savedId) === 'revoked') routeState = 'REVOKED';
        else routeState = 'ORPHANED';
      }
      return { name: s.name, supervised: !!liveId, routeUrl, routeState };
    });
  }

  listServices() {
    // No relay data in this view: lenient labels, never confirmed states.
    const states = new Map(this.reconcile(null).map((r) => [r.name, r]));
    return [...this.c.registry.values()].map((s) => ({
      name: s.name,
      supervised: this.children.has(s.name),
      routeUrl: this.children.get(s.name)?.routeUrl ?? null,
      routeState: states.get(s.name)?.routeState ?? 'NONE',
    }));
  }

  status(name) {
    const svc = this.c.registry.get(name);
    if (!svc) throw new PublisherError('UNKNOWN_SERVICE', `No allowlisted service: ${name}`);
    const live = this.children.get(name);
    const persisted = this.loadPersisted()[name]?.routeUrl ?? null;
    const routeUrl = live?.routeUrl ?? persisted;
    const supervised = !!live && !live.exited;
    return {
      name,
      localUrl: svc.localUrl,
      supervised,
      routeUrl,
      routeState: !routeUrl ? 'NONE' : supervised ? 'ACTIVE-UNCONFIRMED' : 'ADOPTED',
      lastExit: live?.exited ? { code: live.exitCode, at: live.exitedAt } : null,
    };
  }

  /** Start (or reattach to) the supervised publisher for an allowlisted
   * service. Requires the exact confirmation `PUBLISH <name>`. Resolves
   * with { routeUrl } once the CLI reports a route AND the readiness
   * probe confirms the route serves (401 challenge); the child keeps
   * running under supervision afterwards. Pass { probe: false } only
   * when the caller performs its own equivalent health verification. */
  async publish(name, confirmation, { readyTimeoutMs = 90000, probe = true } = {}) {
    const svc = this.c.registry.get(name);
    if (!svc) throw new PublisherError('UNKNOWN_SERVICE', `No allowlisted service: ${name}`);
    if (confirmation !== `PUBLISH ${name}`) throw new PublisherError('CONFIRMATION_REQUIRED', 'Publish requires the exact confirmation `PUBLISH <name>`');
    const existing = this.children.get(name);
    if (existing && !existing.exited) {
      if (!existing.routeUrl) throw new PublisherError('IN_PROGRESS', 'Publication already attaching; wait for its route URL');
      // Reattachment is not success: the route may have lapsed (expired
      // lease, revoked publication) since it was first observed. Re-probe
      // before claiming health; on failure retire the stale child and
      // fall through to a fresh publish below.
      if (probe) {
        try {
          await this.probeRoute(existing.routeUrl);
        } catch {
          this.children.delete(name);
          try { existing.child.kill('SIGTERM'); } catch { /* already gone */ }
          this.persistState();
        }
      }
      const stillThere = this.children.get(name);
      if (stillThere && !stillThere.exited && stillThere.routeUrl) {
        return { name, routeUrl: stillThere.routeUrl, resumed: true, probed: probe };
      }
      // Stale attachment retired; continue to fresh publish.
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
      if (m && !rec.routeUrl) { rec.routeUrl = m[0]; this.persistState(); this.emit('route', { name, routeUrl: rec.routeUrl }); }
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
    child.on('error', (err) => { rec.exited = true; rec.exitCode = -1; rec.exitedAt = this.now(); rec.log.push(`spawn error: ${err.message}`); this.persistState(); });
    child.on('exit', (code) => { rec.exited = true; rec.exitCode = code; rec.exitedAt = this.now(); this.persistState(); });
    const cleanup = () => {
      // Never leave an unsupervised child behind on failure: terminate
      // and drop the record so a later publish starts clean.
      this.children.delete(name);
      this.persistState();
      try { child.kill('SIGTERM'); } catch { /* already gone */ }
      setTimeout(() => { try { if (!rec.exited) child.kill('SIGKILL'); } catch { /* already gone */ } }, 2000).unref?.();
    };
    const deadline = this.now() + readyTimeoutMs;
    let probed = false;
    for (;;) {
      if (rec.routeUrl && (!probe || probed)) return { name, routeUrl: rec.routeUrl, resumed: false, probed: probe };
      if (rec.routeUrl && probe && !probed) {
        try {
          await this.probeRoute(rec.routeUrl);
          probed = true;
        } catch (e) {
          if (e.code === 'PUBLISH_UNHEALTHY' && this.now() < deadline && !rec.exited) {
            await new Promise((r) => setTimeout(r, 1000)); // route may still be registering; retry until deadline
            continue;
          }
          cleanup();
          throw e;
        }
      }
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
    const out = { id: publicationId, stopped, revoked: result?.deleted ? 'REVOKED' : 'UNCONFIRMED', detail: result ?? null };
    // Owner = supervised child if any, else any persisted record for the
    // route (e.g. revoked after a management-server restart with no live
    // child). On confirmed revocation drop ALL ownership traces —
    // in-memory and persisted — so no later persistState() resurrects
    // stale information. Keep records when the outcome is unknown.
    const owner = stopped ?? [...this.c.registry.values()].find((s) => {
      const saved = this.loadPersisted()[s.name]?.routeUrl;
      return saved && saved.includes(`/r/${publicationId}/`);
    })?.name ?? null;
    if (out.revoked === 'REVOKED') {
      for (const [name, rec] of this.children) {
        if (rec.routeUrl && rec.routeUrl.includes(`/r/${publicationId}/`)) this.children.delete(name);
      }
      if (owner) this.clearPersisted(owner);
    } else {
      this.persistState();
    }
    return out;
  }
}

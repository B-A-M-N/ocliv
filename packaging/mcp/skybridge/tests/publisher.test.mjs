/** Publisher controller tests: injected spawn, no real processes. */
import test from 'node:test';
import assert from 'node:assert/strict';
import { unlinkSync } from 'node:fs';
import { EventEmitter } from 'node:events';
import { PublisherController, PublisherError, loadPublisherConfig, parseService, routeIdOf } from '../src/core/publisher.mjs';

const BIN = '/bin/true'; // any executable: spawn is injected, never run
const HOME = '/tmp/ocliv-pub-test';
const SVC = { name: 'lab', localUrl: 'http://127.0.0.1:18767/mcp', resourceFile: '/tmp/ocliv-pub-test/resource.url' };

function cfg(extra = {}) {
  return loadPublisherConfig({ OCLIV_BIN: BIN, OCLIV_PUBLISHER_HOME: HOME, OCLIV_SERVICES_JSON: JSON.stringify([SVC]), ...extra });
}

function fakeSpawnFactory(t, onSpawn) {
  return (bin, args, opts) => {
    const child = new EventEmitter();
    child.stdout = new EventEmitter();
    child.stderr = new EventEmitter();
    child.pid = 4242;
    child.killed = null;
    child.kill = (sig) => { child.killed = sig; return true; };
    onSpawn?.({ bin, args, opts, child });
    return child;
  };
}

test('config rejects remote URLs, bad names, relative paths', () => {
  assert.throws(() => parseService({ name: 'x', localUrl: 'http://example.com:8/mcp' }), { code: 'INVALID_SERVICE' });
  assert.throws(() => parseService({ name: 'x', localUrl: 'http://127.0.0.1:8/other' }), { code: 'INVALID_SERVICE' });
  assert.throws(() => parseService({ name: 'x', localUrl: 'http://127.0.0.1:8/mcp?x=1' }), { code: 'INVALID_SERVICE' });
  assert.throws(() => parseService({ name: 'x', localUrl: 'http://127.0.0.1/mcp' }), { code: 'INVALID_SERVICE' }); // no port
  assert.throws(() => parseService({ name: '../evil', localUrl: 'http://127.0.0.1:8/mcp' }), { code: 'INVALID_SERVICE' });
  assert.throws(() => parseService({ name: 'ok', localUrl: 'http://127.0.0.1:8/mcp', resourceFile: 'relative/path' }), { code: 'INVALID_SERVICE' });
  const ok = parseService({ name: 'ok-name_1', localUrl: 'http://127.0.0.1:18767/mcp' });
  assert.equal(ok.localUrl, 'http://127.0.0.1:18767/mcp');
});

test('config requires executable bin and absolute home', () => {
  assert.throws(() => loadPublisherConfig({ OCLIV_BIN: '/nonexistent/ocliv', OCLIV_PUBLISHER_HOME: HOME, OCLIV_SERVICES_JSON: '[]' }), { code: 'INVALID_CONFIG' });
  assert.throws(() => loadPublisherConfig({ OCLIV_BIN: BIN, OCLIV_PUBLISHER_HOME: 'relative', OCLIV_SERVICES_JSON: '[]' }), { code: 'INVALID_CONFIG' });
});

test('publish requires exact confirmation and argv allowlist', async (t) => {
  let seen = null;
  const c = new PublisherController(cfg(), { spawnImpl: fakeSpawnFactory(t, (s) => { seen = s; }) });
  await assert.rejects(c.publish('lab', 'PUBLISH wrong'), { code: 'CONFIRMATION_REQUIRED' });
  await assert.rejects(c.publish('nosuch', 'PUBLISH nosuch'), { code: 'UNKNOWN_SERVICE' });
  const p = c.publish('lab', 'PUBLISH lab', { readyTimeoutMs: 5000, probe: false });
  await new Promise((r) => setTimeout(r, 50));
  assert.deepEqual(seen.args, ['mcp', 'publish', '--local', 'http://127.0.0.1:18767/mcp', '--auth', 'upstream-oauth', '--name', 'lab', '--resource-file', '/tmp/ocliv-pub-test/resource.url']);
  assert.equal(seen.bin, BIN);
  assert.equal(seen.opts.cwd, HOME);
  assert.equal(seen.opts.env.HOME, HOME);
  assert.ok(seen.opts.env.PATH);
  assert.deepEqual(Object.keys(seen.opts.env).filter((k) => k !== 'HOME' && k !== 'PATH' && k !== 'OCLIV_CACERT'), []);
  seen.child.stderr.emit('data', '✓ MCP route ready\https://edge.example/r/route-abc-9/mcp\n');
  const out = await p;
  assert.equal(out.routeUrl, 'https://edge.example/r/route-abc-9/mcp');
});

test('publish single-flights; resumes when route known', async () => {
  const c = new PublisherController(cfg(), { spawnImpl: fakeSpawnFactory() });
  const p = c.publish('lab', 'PUBLISH lab', { readyTimeoutMs: 5000, probe: false });
  await new Promise((r) => setTimeout(r, 20));
  await assert.rejects(c.publish('lab', 'PUBLISH lab', { readyTimeoutMs: 500 }), { code: 'IN_PROGRESS' });
  c.children.get('lab').child.stderr.emit('data', 'https://edge.example/r/route-abc-9/mcp\n');
  await p;
  const resumed = await c.publish('lab', 'PUBLISH lab', { probe: false });
  assert.equal(resumed.resumed, true);
});

test('publish surfaces early child exit, never a fake route', async () => {
  const c = new PublisherController(cfg(), { spawnImpl: fakeSpawnFactory() });
  const p = c.publish('lab', 'PUBLISH lab', { readyTimeoutMs: 5000, probe: false });
  await new Promise((r) => setTimeout(r, 20));
  const rec = c.children.get('lab');
  rec.child.stderr.emit('data', 'boom\n');
  rec.child.emit('exit', 1);
  await assert.rejects(p, { code: 'PUBLISH_FAILED' });
  assert.equal(c.status('lab').supervised, false);
});

test('unpublish stops owner child, revokes through injected revoker', async () => {
  const order = [];
  const c = new PublisherController(cfg(), { spawnImpl: fakeSpawnFactory() });
  const p = c.publish('lab', 'PUBLISH lab', { readyTimeoutMs: 5000, probe: false });
  await new Promise((r) => setTimeout(r, 20));
  const rec = c.children.get('lab');
  rec.child.stderr.emit('data', 'https://edge.example/r/route-abc-9/mcp\n');
  await p;
  rec.child.once = (ev, fn) => { if (ev === 'exit') setTimeout(() => { rec.exited = true; fn(0); }, 10); return rec.child; };
  const out = await c.unpublish('route-abc-9', 'route-abc-9', {
    revoker: async (id) => { order.push(id); return { id, deleted: true }; },
  });
  assert.deepEqual(out, { id: 'route-abc-9', stopped: 'lab', revoked: 'REVOKED', detail: { id: 'route-abc-9', deleted: true } });
  assert.deepEqual(order, ['route-abc-9']);
  assert.equal(rec.child.killed, 'SIGTERM');
});

test('unpublish without revoker stops but reports UNKNOWN, never success', async () => {
  const c = new PublisherController(cfg(), { spawnImpl: fakeSpawnFactory() });
  const p = c.publish('lab', 'PUBLISH lab', { readyTimeoutMs: 5000, probe: false });
  await new Promise((r) => setTimeout(r, 20));
  const rec = c.children.get('lab');
  rec.child.stderr.emit('data', 'https://edge.example/r/route-abc-9/mcp\n');
  await p;
  rec.child.once = (ev, fn) => { if (ev === 'exit') setTimeout(() => { rec.exited = true; fn(0); }, 10); return rec.child; };
  const out = await c.unpublish('route-abc-9', 'route-abc-9');
  assert.equal(out.revoked, 'UNKNOWN');
  await assert.rejects(c.unpublish('route-abc-9', 'wrong-confirm'), { code: 'CONFIRMATION_REQUIRED' });
});

test('fragmented output across chunks still yields the route URL once', async (t) => {
  const c = new PublisherController(cfg(), { spawnImpl: fakeSpawnFactory(t) });
  const p = c.publish('lab', 'PUBLISH lab', { readyTimeoutMs: 5000, probe: false });
  await new Promise((r) => setTimeout(r, 20));
  const rec = c.children.get('lab');
  rec.child.stderr.emit('data', 'https://edge.exa');
  rec.child.stderr.emit('data', 'mple/r/route-frag-1');
  rec.child.stderr.emit('data', '/mcp\ntail\n');
  const out = await p;
  assert.equal(out.routeUrl, 'https://edge.example/r/route-frag-1/mcp');
});

test('timeout terminates the child and clears the record', async (t) => {
  const c = new PublisherController(cfg(), { spawnImpl: fakeSpawnFactory(t) });
  const started = Date.now();
  await assert.rejects(c.publish('lab', 'PUBLISH lab', { readyTimeoutMs: 300 }), { code: 'PUBLISH_TIMEOUT' });
  assert.ok(Date.now() - started < 5000);
  assert.equal(c.children.has('lab'), false, 'failed publish must not retain a record');
});

test('early exit terminates the child and clears the record', async (t) => {
  const c = new PublisherController(cfg(), { spawnImpl: fakeSpawnFactory(t) });
  const p = c.publish('lab', 'PUBLISH lab', { readyTimeoutMs: 5000, probe: false });
  await new Promise((r) => setTimeout(r, 20));
  const rec = c.children.get('lab');
  const child = rec.child;
  rec.child.emit('exit', 3);
  await assert.rejects(p, { code: 'PUBLISH_FAILED' });
  assert.equal(c.children.has('lab'), false);
  assert.equal(child.killed, 'SIGTERM');
});

test('publish failure never leaks child output (synthetic credential)', async () => {
  const secret = 'tok-live-' + 'x'.repeat(24);
  const c = new PublisherController(cfg(), { spawnImpl: fakeSpawnFactory() });
  const p = c.publish('lab', 'PUBLISH lab', { readyTimeoutMs: 5000, probe: false });
  await new Promise((r) => setTimeout(r, 20));
  const rec = c.children.get('lab');
  rec.child.stderr.emit('data', `operator token: ${secret}\n`);
  rec.child.emit('exit', 1);
  const err = await p.catch((e) => e);
  assert.equal(err.code, 'PUBLISH_FAILED');
  assert.ok(!err.message.includes(secret), 'child secret must not surface in the error');
  assert.equal(err.message, 'Publisher exited before reporting a route (code 1)');
});

test('readiness probe failure never leaks transport errors', async () => {
  const leak = 'https://edge.example/secret-path?tok=abc123';
  const c = new PublisherController(cfg(), { fetchImpl: async () => { throw new Error(`connect refused: ${leak}`); } });
  const err = await c.probeRoute('https://edge.example/r/route-x/mcp').catch((e) => e);
  assert.equal(err.code, 'PUBLISH_UNHEALTHY');
  assert.ok(!err.message.includes('secret-path') && !err.message.includes('tok='), 'transport error must not surface');
  assert.equal(err.message, 'Route not reachable for readiness probe');
});

test('state file is owner-only and malformed records are ignored', async (t) => {
  const c = await publishRoute(t, 'https://edge.example/r/route-abc-9/mcp');
  const st = (await import('node:fs')).statSync(c.statePath());
  assert.equal(st.mode & 0o777, 0o600);
  const fs = await import('node:fs');
  const raw = JSON.parse(fs.readFileSync(c.statePath(), 'utf8'));
  raw.lab.routeUrl = 'https://user:pass@evil.test/r/route-abc-9/mcp?x=1';
  raw.lab.startedAt = 'not-a-number';
  fs.writeFileSync(c.statePath(), JSON.stringify(raw));
  assert.deepEqual(c.loadPersisted(), {}, 'unvalidated persisted state must not load');
});

test('emitted route URLs must be strict https route paths (no userinfo)', async () => {
  for (const bad of [
    'https://user:pass@edge.example/r/route-abc-9/mcp',
    'http://edge.example/r/route-abc-9/mcp',
  ]) {
    const c = new PublisherController(cfg(), { spawnImpl: fakeSpawnFactory() });
    const p = c.publish('lab', 'PUBLISH lab', { readyTimeoutMs: 300, probe: false });
    await new Promise((r) => setTimeout(r, 20));
    c.children.get('lab').child.stderr.emit('data', bad + '\n');
    c.children.get('lab').child.stderr.emit('data', 'no route here\n');
    await assert.rejects(p, { code: 'PUBLISH_TIMEOUT' });
    assert.equal(c.children.get('lab')?.routeUrl ?? null, null);
  }
});

test('decorated output around an exact route URL adopts the clean URL only', async () => {
  for (const line of [
    'ready https://edge.example/r/route-abc-9/mcp?x=1 done',
    'ready https://edge.example/r/route-abc-9/mcp#frag done',
  ]) {
    const c = new PublisherController(cfg(), { spawnImpl: fakeSpawnFactory() });
    const p = c.publish('lab', 'PUBLISH lab', { readyTimeoutMs: 5000, probe: false });
    await new Promise((r) => setTimeout(r, 20));
    c.children.get('lab').child.stderr.emit('data', line + '\n');
    const out = await p;
    // the adopted value itself carries no decoration
    assert.equal(out.routeUrl, 'https://edge.example/r/route-abc-9/mcp');
  }
});

test('routeIdOf extracts the route id or null', () => {
  assert.equal(routeIdOf('https://edge.example/r/route-abc-9/mcp'), 'route-abc-9');
  assert.equal(routeIdOf('https://edge.example/other'), null);
  assert.equal(routeIdOf(null), null);
});

async function publishRoute(t, routeUrl) {
  try { unlinkSync('/tmp/ocliv-pub-test/.ocliv-publisher-state.json'); } catch { /* fresh */ }
  const c = new PublisherController(cfg(), { spawnImpl: fakeSpawnFactory(t) });
  const p = c.publish('lab', 'PUBLISH lab', { readyTimeoutMs: 5000, probe: false });
  await new Promise((r) => setTimeout(r, 20));
  c.children.get('lab').child.stderr.emit('data', routeUrl + '\n');
  await p;
  return c;
}

test('reconcile reports ACTIVE only for relay-confirmed live routes', async (t) => {
  const url = 'https://edge.example/r/route-live-1/mcp';
  const c = await publishRoute(t, url);
  const active = c.reconcile([{ route_id: 'route-live-1', state: 'active' }]);
  assert.deepEqual(active, [{ name: 'lab', supervised: true, routeUrl: url, routeState: 'ACTIVE' }]);
  const revoked = c.reconcile([{ route_id: 'route-live-1', state: 'revoked' }]);
  assert.equal(revoked[0].routeState, 'REVOKED');
  const gone = c.reconcile([{ route_id: 'route-other-9', state: 'active' }]);
  assert.equal(gone[0].routeState, 'ORPHANED');
  const empty = c.reconcile([]);
  assert.equal(empty[0].routeState, 'ORPHANED');
  assert.equal(empty[0].supervised, true);
  const unknown = c.reconcile(null);
  assert.equal(unknown[0].routeState, 'UNCONFIRMED');
});

test('fresh controller adopts persisted routes after restart', async (t) => {
  const url = 'https://edge.example/r/route-live-1/mcp';
  await publishRoute(t, url);
  // Simulate a management-server restart: empty child map, same home.
  const c2 = new PublisherController(cfg(), { spawnImpl: fakeSpawnFactory(t) });
  assert.equal(c2.children.size, 0);
  const rec = c2.reconcile([{ route_id: 'route-live-1', state: 'active' }]);
  assert.equal(rec[0].routeState, 'ADOPTED');
  assert.equal(rec[0].routeUrl, url);
  assert.equal(rec[0].supervised, false);
  const st = c2.status('lab');
  assert.equal(st.routeUrl, url);
  assert.equal(st.routeState, 'ADOPTED');
});

test('durable record dropped only on confirmed revocation', async (t) => {
  const url = 'https://edge.example/r/route-live-1/mcp';
  const c = await publishRoute(t, url);
  const rec = c.children.get('lab');
  rec.child.once = (ev, fn) => { if (ev === 'exit') setTimeout(() => { rec.exited = true; fn(0); }, 10); return rec.child; };
  const unconfirmed = await c.unpublish('route-live-1', 'route-live-1', { revoker: async (id) => ({ id, deleted: false }) });
  assert.equal(unconfirmed.revoked, 'UNCONFIRMED');
  assert.ok(c.loadPersisted().lab, 'unconfirmed revocation keeps the route record for re-attach');
  const c2 = new PublisherController(cfg(), { spawnImpl: fakeSpawnFactory(t) });
  const p2 = c2.publish('lab', 'PUBLISH lab', { readyTimeoutMs: 5000, probe: false });
  await new Promise((r) => setTimeout(r, 20));
  c2.children.get('lab').child.stderr.emit('data', url + '\n');
  await p2;
  const c2rec = c2.children.get('lab');
  c2rec.child.once = (ev, fn) => { if (ev === 'exit') setTimeout(() => { c2rec.exited = true; fn(0); }, 10); return c2rec.child; };
  const done = await c2.unpublish('route-live-1', 'route-live-1', { revoker: async (id) => ({ id, deleted: true }) });
  assert.equal(done.revoked, 'REVOKED');
  assert.deepEqual(c2.loadPersisted(), {}, 'confirmed revocation clears the record');
});

test('publish probes route health before reporting success', async (t) => {
  try { unlinkSync('/tmp/ocliv-pub-test/.ocliv-publisher-state.json'); } catch { /* fresh */ }
  const seen = [];
  const c = new PublisherController(cfg(), {
    spawnImpl: fakeSpawnFactory(t),
    fetchImpl: async (url) => { seen.push(url); return { status: 401 }; },
  });
  const p = c.publish('lab', 'PUBLISH lab', { readyTimeoutMs: 5000 });
  await new Promise((r) => setTimeout(r, 20));
  const url = 'https://edge.example/r/route-live-1/mcp';
  c.children.get('lab').child.stderr.emit('data', url + '\n');
  const out = await p;
  assert.equal(out.routeUrl, url);
  assert.equal(out.probed, true);
  assert.deepEqual(seen, [url]);
});

test('saved route with no live child follows the relay answer, never the URL', async (t) => {
  const url = 'https://edge.example/r/route-live-1/mcp';
  await publishRoute(t, url);
  const c2 = new PublisherController(cfg(), { spawnImpl: fakeSpawnFactory(t) });
  assert.equal(c2.children.size, 0);
  assert.equal(c2.reconcile([{ route_id: 'route-live-1', state: 'active' }])[0].routeState, 'ADOPTED');
  assert.equal(c2.reconcile([{ route_id: 'route-live-1', state: 'revoked' }])[0].routeState, 'REVOKED');
  assert.equal(c2.reconcile([{ route_id: 'route-other-9', state: 'active' }])[0].routeState, 'ORPHANED');
  assert.equal(c2.reconcile([])[0].routeState, 'ORPHANED');
});

test('reattach re-probes: healthy resumes, stale republishes fresh', async (t) => {
  try { unlinkSync('/tmp/ocliv-pub-test/.ocliv-publisher-state.json'); } catch { /* fresh */ }
  let probes = 0;
  let spawns = 0;
  const c = new PublisherController(cfg(), {
    spawnImpl: (...a) => { spawns++; return fakeSpawnFactory(t)(...a); },
    fetchImpl: async () => { probes++; return { status: 401 }; },
  });
  const first = c.publish('lab', 'PUBLISH lab', { readyTimeoutMs: 5000 });
  await new Promise((r) => setTimeout(r, 20));
  c.children.get('lab').child.stderr.emit('data', 'https://edge.example/r/route-live-1/mcp\n');
  await first;
  // Healthy reattach: probe passes, same URL, no new spawn.
  const again = await c.publish('lab', 'PUBLISH lab', { readyTimeoutMs: 5000 });
  assert.equal(again.resumed, true);
  assert.equal(again.routeUrl, 'https://edge.example/r/route-live-1/mcp');
  assert.equal(spawns, 1);
  // Stale reattach: probe now fails, old child retired, fresh publish wins.
  c.fetchImpl = async () => ({ status: 404 });
  const p2 = c.publish('lab', 'PUBLISH lab', { readyTimeoutMs: 5000 });
  await new Promise((r) => setTimeout(r, 20));
  const rec = c.children.get('lab');
  assert.ok(rec, 'fresh publish started after stale reattach retired');
  rec.child.stderr.emit('data', 'https://edge.example/r/route-live-2/mcp\n');
  // Fresh route also 404s under the stubbed fetch... restore health first.
  c.fetchImpl = async () => ({ status: 401 });
  const out = await p2;
  assert.equal(out.resumed, false);
  assert.equal(out.probed, true);
  assert.equal(spawns, 2);
});

test('unpublish after restart clears in-memory and persisted records', async (t) => {
  const url = 'https://edge.example/r/route-live-1/mcp';
  await publishRoute(t, url);
  const c2 = new PublisherController(cfg(), { spawnImpl: fakeSpawnFactory(t) });
  assert.equal(c2.children.size, 0);
  assert.ok(c2.loadPersisted().lab, 'restart: persisted record present');
  const out = await c2.unpublish('route-live-1', 'route-live-1', { revoker: async (id) => ({ id, deleted: true }) });
  assert.equal(out.revoked, 'REVOKED');
  assert.equal(out.stopped, null);
  assert.deepEqual(c2.loadPersisted(), {}, 'confirmed revocation clears persisted record with no live child');
  // Repeated call: revoker says already gone → UNCONFIRMED, nothing invented.
  const twice = await c2.unpublish('route-live-1', 'route-live-1', { revoker: async (id) => ({ id, deleted: false }) });
  assert.equal(twice.revoked, 'UNCONFIRMED');
});

test('publish fails closed when the route does not serve', async (t) => {
  try { unlinkSync('/tmp/ocliv-pub-test/.ocliv-publisher-state.json'); } catch { /* fresh */ }
  const c = new PublisherController(cfg(), {
    spawnImpl: fakeSpawnFactory(t),
    fetchImpl: async () => ({ status: 200 }),
  });
  const p = c.publish('lab', 'PUBLISH lab', { readyTimeoutMs: 2500 });
  await new Promise((r) => setTimeout(r, 20));
  const rec = c.children.get('lab');
  rec.child.stderr.emit('data', 'https://edge.example/r/route-live-1/mcp\n');
  await assert.rejects(p, { code: 'PUBLISH_UNHEALTHY' });
  assert.equal(c.children.has('lab'), false, 'unhealthy publish must not retain a record');
  assert.equal(rec.child.killed, 'SIGTERM');
});

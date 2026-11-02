/** Publisher controller tests: injected spawn, no real processes. */
import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { PublisherController, PublisherError, loadPublisherConfig, parseService } from '../src/core/publisher.mjs';

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
  const p = c.publish('lab', 'PUBLISH lab', { readyTimeoutMs: 5000 });
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
  const p = c.publish('lab', 'PUBLISH lab', { readyTimeoutMs: 5000 });
  await new Promise((r) => setTimeout(r, 20));
  await assert.rejects(c.publish('lab', 'PUBLISH lab', { readyTimeoutMs: 500 }), { code: 'IN_PROGRESS' });
  c.children.get('lab').child.stderr.emit('data', 'https://edge.example/r/route-abc-9/mcp\n');
  await p;
  const resumed = await c.publish('lab', 'PUBLISH lab');
  assert.equal(resumed.resumed, true);
});

test('publish surfaces early child exit, never a fake route', async () => {
  const c = new PublisherController(cfg(), { spawnImpl: fakeSpawnFactory() });
  const p = c.publish('lab', 'PUBLISH lab', { readyTimeoutMs: 5000 });
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
  const p = c.publish('lab', 'PUBLISH lab', { readyTimeoutMs: 5000 });
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
  const p = c.publish('lab', 'PUBLISH lab', { readyTimeoutMs: 5000 });
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
  const p = c.publish('lab', 'PUBLISH lab', { readyTimeoutMs: 5000 });
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
  const p = c.publish('lab', 'PUBLISH lab', { readyTimeoutMs: 5000 });
  await new Promise((r) => setTimeout(r, 20));
  const rec = c.children.get('lab');
  const child = rec.child;
  rec.child.emit('exit', 3);
  await assert.rejects(p, { code: 'PUBLISH_FAILED' });
  assert.equal(c.children.has('lab'), false);
  assert.equal(child.killed, 'SIGTERM');
});

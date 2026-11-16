import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { mkdtempSync, writeFileSync, chmodSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { PublisherController, loadPublisherConfig } from '../src/core/publisher.mjs';

function makeEnv(t) {
  const dir = mkdtempSync(join(tmpdir(), 'ocliv-pubev-'));
  const bin = join(dir, 'ocliv');
  writeFileSync(bin, '#!/bin/sh\nexit 0\n');
  chmodSync(bin, 0o755);
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  return {
    OCLIV_BIN: bin,
    OCLIV_PUBLISHER_HOME: dir,
    OCLIV_SERVICES_JSON: JSON.stringify([
      { name: 'tools', localUrl: 'http://127.0.0.1:8765/mcp', auth: 'ocliv-managed' },
    ]),
  };
}

function mockChild() {
  const c = new EventEmitter();
  c.pid = 42424;
  c.stdout = new EventEmitter();
  c.stderr = new EventEmitter();
  c.killed = null;
  c.kill = (sig) => { c.killed = sig; };
  return c;
}

test('structured publication_ready event is adopted and cross-checked with relay inventory', async (t) => {
  const child = mockChild();
  const inv = {
    async list() {
      return [{ id: 'route-xyz', state: 'active', public_url: 'https://relay.test/r/route-xyz/mcp', session_live: true }];
    },
  };
  const ctrl = new PublisherController(loadPublisherConfig(makeEnv(t)), {
    spawnImpl: () => child,
    inventoryClient: inv,
    relayOrigin: 'https://relay.test',
    ownerKeyId: 'key-1',
  });
  const p = ctrl.publish('tools', 'PUBLISH tools', { readyTimeoutMs: 5000, probe: false });
  await new Promise((r) => setTimeout(r, 20));
  child.stdout.emit('data', JSON.stringify({
    event: 'publication_ready',
    service_name: 'tools',
    publication_id: 'route-xyz',
    public_url: 'https://relay.test/r/route-xyz/mcp',
    relay_url: 'https://relay.test',
    owner_key_id: 'key-1',
    lease_id: 'lse-1',
    auth_mode: 'ocliv-managed',
    verified: true,
  }) + '\n');
  const res = await p;
  assert.equal(res.routeUrl, 'https://relay.test/r/route-xyz/mcp');
  assert.equal(res.publicationId, 'route-xyz');
  assert.equal(res.leaseId, 'lse-1');
});

test('mismatched owner_key_id or relay_url in ready event fails closed', async (t) => {
  const child = mockChild();
  const ctrl = new PublisherController(loadPublisherConfig(makeEnv(t)), {
    spawnImpl: () => child,
    relayOrigin: 'https://relay.test',
    ownerKeyId: 'key-1',
  });
  const p = ctrl.publish('tools', 'PUBLISH tools', { readyTimeoutMs: 5000, probe: false });
  await new Promise((r) => setTimeout(r, 20));
  child.stdout.emit('data', JSON.stringify({
    event: 'publication_ready',
    service_name: 'tools',
    publication_id: 'route-xyz',
    public_url: 'https://relay.test/r/route-xyz/mcp',
    relay_url: 'https://evil.test',
    owner_key_id: 'key-2',
    auth_mode: 'ocliv-managed',
    verified: true,
  }) + '\n');
  await assert.rejects(p, { code: 'PUBLISH_FAILED' });
  assert.equal(child.killed, 'SIGTERM');
});

test('stop reports UNKNOWN when relay inventory is unreachable', async (t) => {
  const child = mockChild();
  let calls = 0;
  const inv = {
    async list() {
      calls++;
      if (calls === 1) {
        return [{ id: 'route-xyz', state: 'active', public_url: 'https://relay.test/r/route-xyz/mcp', session_live: true }];
      }
      throw new Error('relay down');
    },
  };
  const ctrl = new PublisherController(loadPublisherConfig(makeEnv(t)), {
    spawnImpl: () => child,
    inventoryClient: inv,
  });
  const p = ctrl.publish('tools', 'PUBLISH tools', { readyTimeoutMs: 5000, probe: false });
  await new Promise((r) => setTimeout(r, 20));
  child.stdout.emit('data', JSON.stringify({
    event: 'publication_ready',
    service_name: 'tools',
    publication_id: 'route-xyz',
    public_url: 'https://relay.test/r/route-xyz/mcp',
    auth_mode: 'ocliv-managed',
    verified: true,
  }) + '\n');
  await p;
  const rec = ctrl.children.get('tools');
  child.once = (ev, fn) => {
    if (ev === 'exit') setTimeout(() => { rec.exited = true; fn(0); }, 10);
    return child;
  };
  const stopped = await ctrl.stop('tools', 'STOP tools');
  assert.equal(stopped.stopped, false);
  assert.equal(stopped.state, 'UNKNOWN');
});

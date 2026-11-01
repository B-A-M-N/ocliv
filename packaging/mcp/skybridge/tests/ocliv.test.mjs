import test from 'node:test';
import assert from 'node:assert/strict';
import { isSafeLocalMcpUrl, parseAllowlist, parsePublications, OclivClient } from '../src/ocliv.ts';

test('only loopback literal HTTP MCP URLs are allowed', () => {
  for (const url of ['http://127.0.0.1:8765/mcp', 'http://[::1]:8765/mcp']) {
    assert.equal(isSafeLocalMcpUrl(url), true, url);
  }
  for (const url of [
    'http://localhost:8765/mcp', 'http://127.0.0.1:8765/other',
    'http://127.0.0.1/mcp', 'https://127.0.0.1:8765/mcp',
    'http://127.0.0.1:8765/mcp?q=1', 'http://127.0.0.1:8765/mcp#frag',
    'http://127.0.0.2:8765/mcp', 'http://192.168.1.2:8765/mcp',
    'http://user:pass@127.0.0.1:8765/mcp', 'http://evil.com:8765/mcp',
  ]) assert.equal(isSafeLocalMcpUrl(url), false, url);
});

test('allowlist rejects duplicate name, invalid name and unsafe targets', () => {
  assert.equal(parseAllowlist('[]').size, 0);
  assert.equal(parseAllowlist('[{"name":"safe","localUrl":"http://127.0.0.1:8080/mcp"}]').size, 1);
  for (const value of [
    '[{"name":"_bad","localUrl":"http://127.0.0.1:8080/mcp"}]',
    '[{"name":"x","localUrl":"http://169.254.169.254:8080/mcp"}]',
    '[{"name":"a","localUrl":"http://127.0.0.1:8080/mcp"},{"name":"a","localUrl":"http://127.0.0.1:8081/mcp"}]',
    '[{"name":"a","localUrl":"http://127.0.0.1:8080/mcp","resourceFile":"relative"}]',
    '{}',
  ]) assert.throws(() => parseAllowlist(value));
});

test('parse output fails closed rather than fabricate routes', () => {
  const sample = 'd1oriF_F5Mhunke3Ahj3rA mcp_upstream_oauth funnellab active abcde1234\n';
  const items = parsePublications(sample, 'https://pop-os.tail8d285a.ts.net/');
  assert.equal(items.length, 1);
  assert.equal(items[0].endpoint, 'https://pop-os.tail8d285a.ts.net/r/d1oriF_F5Mhunke3Ahj3rA/mcp');
  assert.equal(items[0].state, 'active');
  assert.equal(parsePublications('no publications').length, 0);
  assert.throws(() => parsePublications('broken response'));
  assert.throws(() => parsePublications(sample, 'http://not-secure.example/'));
  assert.throws(() => parsePublications(sample, 'https://evil.example/admin/'));
});

test('revoked rows do not advertise live URLs', () => {
  const items = parsePublications('d1oriF_F5Mhunke3Ahj3rA mcp_upstream_oauth funnellab revoked -', 'https://example.org/');
  assert.equal(items[0].endpoint, null);
  assert.equal(items[0].leaseId, null);
});

test('mutations reject unallowlisted names and missing confirmations without subprocess', async () => {
  const client = new OclivClient({ bin: '/bin/false', services: parseAllowlist('[]') });
  await assert.rejects(() => client.publish('not-allowed', 'PUBLISH not-allowed'));
  await assert.rejects(() => client.revoke('invalid', 'REVOKE invalid'));
  client.close();
});

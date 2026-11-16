/** Operator approval state machine: MCP can request, only local operator
 * control can approve, and redemption is bound and single-use. */
import test from 'node:test';
import assert from 'node:assert/strict';
import { connect } from 'node:net';
import { mkdtempSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { once } from 'node:events';
import { Approvals, ApprovalError } from '../src/core/approvals.mjs';
import { startOperatorApprovalSocket } from '../src/core/operator-approvals.mjs';

const SUB = 'auth0|op1';

test('operator must approve before a bound single-use redemption', () => {
  const a = new Approvals({ ttlMs: 60000, now: () => 1000 });
  const g = a.request({ subject: SUB, action: 'publish', target: 'lab' });
  assert.equal(g.status, 'AWAITING_OPERATOR');
  assert.ok(!('code' in g));
  assert.throws(() => a.redeem({ subject: SUB, action: 'publish', target: 'lab', approvalId: g.approvalId }), { code: 'APPROVAL_NOT_APPROVED' });
  assert.equal(a.decide({ approvalId: g.approvalId, decision: 'approve' }).status, 'APPROVED');
  assert.deepEqual(a.redeem({ subject: SUB, action: 'publish', target: 'lab', approvalId: g.approvalId }), { approved: true, action: 'publish', target: 'lab' });
  assert.throws(() => a.redeem({ subject: SUB, action: 'publish', target: 'lab', approvalId: g.approvalId }), { code: 'APPROVAL_NOT_APPROVED' });
});

test('operator decision and redemption bind subject, action, and target', () => {
  const a = new Approvals({ ttlMs: 60000, now: () => 1000 });
  const g = a.request({ subject: SUB, action: 'unpublish', target: 'route-123' });
  a.decide({ approvalId: g.approvalId, decision: 'approve' });
  assert.throws(() => a.redeem({ subject: 'other', action: 'unpublish', target: 'route-123', approvalId: g.approvalId }), { code: 'APPROVAL_SUBJECT' });
  assert.throws(() => a.redeem({ subject: SUB, action: 'stop', target: 'route-123', approvalId: g.approvalId }), { code: 'APPROVAL_BINDING' });
  assert.deepEqual(a.redeem({ subject: SUB, action: 'unpublish', target: 'route-123', approvalId: g.approvalId }), { approved: true, action: 'unpublish', target: 'route-123' });
});

test('denied and expired requests cannot be redeemed', () => {
  let now = 0;
  const a = new Approvals({ ttlMs: 1000, now: () => now });
  const denied = a.request({ subject: SUB, action: 'stop', target: 'lab' });
  assert.equal(a.decide({ approvalId: denied.approvalId, decision: 'deny' }).status, 'DENIED');
  assert.throws(() => a.redeem({ subject: SUB, action: 'stop', target: 'lab', approvalId: denied.approvalId }), { code: 'APPROVAL_NOT_APPROVED' });
  const expired = a.request({ subject: SUB, action: 'publish', target: 'lab' });
  now = 1000;
  assert.throws(() => a.decide({ approvalId: expired.approvalId, decision: 'approve' }), { code: 'APPROVAL_EXPIRED' });
});

test('owner-only operator socket lists and decides without returning secrets to MCP', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'ocliv-approval-test-'));
  const socketPath = join(dir, 'approvals.sock');
  const approvals = new Approvals();
  const req = approvals.request({ subject: SUB, action: 'publish', target: 'lab' });
  const server = startOperatorApprovalSocket(approvals, socketPath);
  await once(server, 'listening');
  try {
    assert.equal(statSync(socketPath).mode & 0o777, 0o600);
    const call = (body) => new Promise((resolve, reject) => {
      const client = connect(socketPath);
      let response = '';
      client.setEncoding('utf8');
      client.on('connect', () => client.write(JSON.stringify(body) + '\n'));
      client.on('data', (part) => { response += part; });
      client.on('end', () => resolve(JSON.parse(response)));
      client.on('error', reject);
    });
    const listed = await call({ command: 'list' });
    assert.equal(listed.approvals[0].status, 'AWAITING_OPERATOR');
    assert.ok(!JSON.stringify(listed).includes('code'));
    const decided = await call({ command: 'approve', approvalId: req.approvalId });
    assert.equal(decided.approval.status, 'APPROVED');
    assert.equal(approvals.redeem({ subject: SUB, action: 'publish', target: 'lab', approvalId: req.approvalId }).approved, true);
  } finally {
    server.close();
    await once(server, 'close');
  }
});

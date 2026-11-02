/** Approvals: human-in-the-loop independence. The model may hold an
 * approvalId but must never receive the code through a tool result;
 * redeem stays single-use and bound to subject/action/target/expiry. */
import test from 'node:test';
import assert from 'node:assert/strict';
import { Approvals, ApprovalError } from '../src/core/approvals.mjs';

const SUB = 'auth0|op1';

test('issue then redeem exactly once', () => {
  const a = new Approvals({ ttlMs: 60000, now: () => 1000 });
  const g = a.request({ subject: SUB, action: 'publish', target: 'lab' });
  assert.ok(g.approvalId && g.code && g.code.length >= 16);
  assert.deepEqual(a.redeem({ subject: SUB, action: 'publish', target: 'lab', approvalId: g.approvalId, code: g.code }), { approved: true, action: 'publish', target: 'lab' });
  assert.throws(() => a.redeem({ subject: SUB, action: 'publish', target: 'lab', approvalId: g.approvalId, code: g.code }), ApprovalError);
});

test('binding mismatches fail closed and still consume', () => {
  for (const bad of [
    { subject: 'auth0|other', action: 'publish', target: 'lab', code: 'x' },
    { subject: SUB, action: 'unpublish', target: 'lab', code: 'x' },
    { subject: SUB, action: 'publish', target: 'other', code: 'x' },
    { subject: SUB, action: 'publish', target: 'lab', code: 'wrong-code' },
  ]) {
    const a = new Approvals({ ttlMs: 60000, now: () => 1000 });
    const g = a.request({ subject: SUB, action: 'publish', target: 'lab' });
    assert.throws(() => a.redeem({ ...bad, approvalId: g.approvalId, code: bad.code === 'x' ? g.code : bad.code }), ApprovalError);
    // consumed: even the right code no longer works
    assert.throws(() => a.redeem({ subject: SUB, action: 'publish', target: 'lab', approvalId: g.approvalId, code: g.code }), ApprovalError);
  }
});

test('expired grants rejected', () => {
  let t = 0;
  const a = new Approvals({ ttlMs: 1000, now: () => t });
  const g = a.request({ subject: SUB, action: 'unpublish', target: 'route-1' });
  t = 2000;
  assert.throws(() => a.redeem({ subject: SUB, action: 'unpublish', target: 'route-1', approvalId: g.approvalId, code: g.code }), ApprovalError);
});

test('publicReceipt never carries the code', () => {
  const a = new Approvals({ now: () => 0 });
  const g = a.request({ subject: SUB, action: 'publish', target: 'lab' });
  const r = a.publicReceipt(g);
  assert.ok(!('code' in r));
  assert.equal(r.approvalId, g.approvalId);
  assert.equal(r.action, 'publish');
  assert.equal(r.target, 'lab');
  // receipt alone cannot redeem
  assert.throws(() => a.redeem({ subject: SUB, action: 'publish', target: 'lab', approvalId: r.approvalId, code: r.code }), ApprovalError);
});

test('list exposes metadata only, never codes', () => {
  const a = new Approvals({ ttlMs: 60000, now: () => 0 });
  a.request({ subject: SUB, action: 'publish', target: 'lab' });
  const pending = a.list();
  assert.equal(pending.length, 1);
  assert.ok(!('code' in pending[0]));
});

test('pending approvals are bounded; expired grants pruned on request', () => {
  const a = new Approvals({ ttlMs: 60000, now: () => 0 });
  for (let i = 0; i < 128; i++) a.request({ subject: SUB, action: 'publish', target: 'lab' });
  assert.throws(() => a.request({ subject: SUB, action: 'publish', target: 'lab' }), { code: 'APPROVAL_BUSY' });
  // earlier grants still redeemable: the bound rejects only the overflow
  assert.equal(a.pending.size, 128);
});

test('expired grants do not consume the pending bound', () => {
  let t = 0;
  const a = new Approvals({ ttlMs: 100, now: () => t });
  for (let i = 0; i < 10; i++) a.request({ subject: SUB, action: 'publish', target: 'lab' });
  t = 1000; // all ten expired
  for (let i = 0; i < 128; i++) a.request({ subject: SUB, action: 'publish', target: 'lab' });
  assert.equal(a.pending.size, 128);
  assert.throws(() => a.request({ subject: SUB, action: 'publish', target: 'lab' }), { code: 'APPROVAL_BUSY' });
});

test('grantNotice withholds code by default, reveals only on opt-in', () => {
  const a = new Approvals({ now: () => 0 });
  const g = a.request({ subject: SUB, action: 'publish', target: 'lab' });
  const quiet = a.grantNotice(g);
  assert.ok(!quiet.includes(g.code));
  assert.ok(quiet.includes(g.approvalId));
  const loud = a.grantNotice(g, { revealCode: true });
  assert.ok(loud.includes(g.code));
});

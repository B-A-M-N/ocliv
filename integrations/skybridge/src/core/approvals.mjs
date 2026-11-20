/** Human approvals are decided through the local operator socket, never
 * through an MCP tool argument. The model may request an action and see
 * its opaque ID; only the local operator can move it to APPROVED. */
import { randomBytes } from 'node:crypto';

export class ApprovalError extends Error {
  constructor(code, message) { super(message); this.code = code; }
}

const ACTIONS = new Set(['publish', 'stop', 'unpublish']);
const ID = /^[A-Za-z0-9_-]{3,64}$/;
const NAME = /^[A-Za-z][A-Za-z0-9_-]{0,47}$/;
export const MAX_PENDING = 128;

export class Approvals {
  constructor({ ttlMs = 5 * 60 * 1000, now = Date.now } = {}) {
    this.ttlMs = ttlMs;
    this.now = now;
    this.pending = new Map();
  }

  request({ subject, action, target }) {
    if (typeof subject !== 'string' || !subject) throw new ApprovalError('INVALID_APPROVAL', 'Approval requires an authenticated subject');
    if (!ACTIONS.has(action)) throw new ApprovalError('INVALID_APPROVAL', 'Unknown approval action');
    const okTarget = action === 'unpublish' ? ID.test(target) : NAME.test(target);
    if (typeof target !== 'string' || !okTarget) throw new ApprovalError('INVALID_APPROVAL', 'Approval target malformed');
    this.prune();
    for (const [id, rec] of this.pending) {
      if (['DENIED', 'REDEEMED', 'EXPIRED'].includes(rec.status)) this.pending.delete(id);
    }
    if (this.pending.size >= MAX_PENDING) throw new ApprovalError('APPROVAL_BUSY', 'Too many pending approvals; resolve or wait for expiry');
    const approvalId = randomBytes(18).toString('base64url');
    const rec = { approvalId, subject, action, target, expiresAt: this.now() + this.ttlMs, status: 'AWAITING_OPERATOR' };
    this.pending.set(approvalId, rec);
    return this.publicReceipt(rec);
  }

  publicReceipt(rec) {
    return { approvalId: rec.approvalId, action: rec.action, target: rec.target, expiresAt: rec.expiresAt, status: rec.status };
  }

  decide({ approvalId, decision }) {
    const rec = this.pending.get(approvalId);
    if (!rec) throw new ApprovalError('APPROVAL_INVALID', 'No such approval (unknown or expired)');
    if (rec.expiresAt <= this.now()) {
      rec.status = 'EXPIRED';
      throw new ApprovalError('APPROVAL_EXPIRED', 'Approval expired; request a fresh one');
    }
    if (rec.status !== 'AWAITING_OPERATOR') throw new ApprovalError('APPROVAL_RESOLVED', `Approval is already ${rec.status}`);
    if (decision !== 'approve' && decision !== 'deny') throw new ApprovalError('INVALID_APPROVAL', 'Decision must be approve or deny');
    rec.status = decision === 'approve' ? 'APPROVED' : 'DENIED';
    return this.operatorRecord(rec);
  }

  operatorRecord(rec) {
    return { ...this.publicReceipt(rec), subject: rec.subject };
  }

  redeem({ subject, action, target, approvalId }) {
    const rec = this.pending.get(approvalId);
    if (!rec) throw new ApprovalError('APPROVAL_INVALID', 'No such approval (unknown, expired, or already used)');
    if (rec.expiresAt <= this.now()) {
      rec.status = 'EXPIRED';
      throw new ApprovalError('APPROVAL_EXPIRED', 'Approval expired; request a fresh one');
    }
    if (rec.status !== 'APPROVED') throw new ApprovalError('APPROVAL_NOT_APPROVED', 'An operator must approve this request locally');
    if (rec.subject !== subject) throw new ApprovalError('APPROVAL_SUBJECT', 'Approval belongs to a different operator');
    if (rec.action !== action || rec.target !== target) throw new ApprovalError('APPROVAL_BINDING', 'Approval does not cover this action and target');
    rec.status = 'REDEEMED';
    return { approved: true, action, target };
  }

  prune() {
    const now = this.now();
    for (const rec of this.pending.values()) {
      if (rec.expiresAt <= now && ['AWAITING_OPERATOR', 'APPROVED'].includes(rec.status)) rec.status = 'EXPIRED';
    }
  }

  list() {
    this.prune();
    return [...this.pending.values()].map((rec) => this.operatorRecord(rec));
  }
}

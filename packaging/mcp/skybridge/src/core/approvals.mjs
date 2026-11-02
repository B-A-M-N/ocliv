/** Single-use human approvals for write operations. A model-callable
 * confirmation string (`PUBLISH x`, a route ID) is not an independent
 * approval: any tool caller can supply it. Approvals fix that by binding
 * each grant to the authenticated operator subject, the exact action and
 * target, and a short expiry — consumed atomically, never replayable —
 * AND by delivering the code out-of-band: the code is emitted to the
 * server operator console, never returned in a tool result. A model that
 * only sees tool results can propose an action but can never complete its
 * own approval; the human reads the code off-console and provides it for
 * exactly that action.
 *
 * Flow: model calls request-approval (proposes action+target) → the tool
 * result carries only the approval ID (see publicReceipt); the approval
 * code is printed to the OPERATOR CONSOLE → human reads it and provides
 * it back for exactly that action → redeem validates subject/action/
 * target/expiry/code and consumes the grant in the same synchronous
 * block. A code authorizes one bound action only; guessing is infeasible
 * (128-bit) and replays fail closed.
 */
import { randomBytes } from 'node:crypto';

export class ApprovalError extends Error {
  constructor(code, message) { super(message); this.code = code; }
}

const ACTIONS = new Set(['publish', 'unpublish']);
const ID = /^[A-Za-z0-9_-]{3,64}$/;
const NAME = /^[A-Za-z][A-Za-z0-9_-]{0,47}$/;

export class Approvals {
  constructor({ ttlMs = 5 * 60 * 1000, now = Date.now } = {}) {
    this.ttlMs = ttlMs;
    this.now = now;
    this.pending = new Map(); // id -> { code, subject, action, target, expiresAt }
  }

  /** Propose a write. Returns the grant; the code must reach the human
   * through a channel the action description makes unambiguous. */
  request({ subject, action, target }) {
    if (typeof subject !== 'string' || !subject) throw new ApprovalError('INVALID_APPROVAL', 'Approval requires an authenticated subject');
    if (!ACTIONS.has(action)) throw new ApprovalError('INVALID_APPROVAL', 'Unknown approval action');
    const okTarget = action === 'publish' ? NAME.test(target) : ID.test(target);
    if (typeof target !== 'string' || !okTarget) throw new ApprovalError('INVALID_APPROVAL', 'Approval target malformed');
    const id = randomBytes(12).toString('base64url');
    const code = randomBytes(16).toString('base64url');
    this.pending.set(id, { code, subject, action, target, expiresAt: this.now() + this.ttlMs });
    return { approvalId: id, code, action, target, expiresAt: this.pending.get(id).expiresAt };
  }

  /** Tool-safe receipt: everything the model may see. The code is
   * deliberately absent — returning it in-band would let the requester
   * complete its own approval. Emit the full grant (with code) to the
   * operator console instead. */
  publicReceipt(grant) {
    const { code: _dropped, ...receipt } = grant;
    return receipt;
  }

  /** Validate and atomically consume a grant. Any mismatch — subject,
   * action, target, expiry, code, reuse — fails closed. */
  redeem({ subject, action, target, approvalId, code }) {
    const rec = this.pending.get(approvalId);
    if (!rec) throw new ApprovalError('APPROVAL_INVALID', 'No such approval (unknown, expired, or already used)');
    this.pending.delete(approvalId); // consume first: no double-spend window
    if (rec.subject !== subject) throw new ApprovalError('APPROVAL_SUBJECT', 'Approval belongs to a different operator');
    if (rec.action !== action || rec.target !== target) {
      throw new ApprovalError('APPROVAL_BINDING', 'Approval does not cover this action and target');
    }
    if (this.now() > rec.expiresAt) throw new ApprovalError('APPROVAL_EXPIRED', 'Approval expired; request a fresh one');
    if (typeof code !== 'string' || code.length === 0 || code !== rec.code) {
      throw new ApprovalError('APPROVAL_CODE', 'Approval code rejected');
    }
    return { approved: true, action, target };
  }

  /** Hygiene listing for operators: metadata only, never codes. */
  list() {
    const now = this.now();
    const out = [];
    for (const [id, r] of this.pending) {
      if (r.expiresAt <= now) { this.pending.delete(id); continue; }
      out.push({ approvalId: id, action: r.action, target: r.target, subject: r.subject, expiresAt: r.expiresAt });
    }
    return out;
  }
}

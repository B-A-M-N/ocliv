/** Single-use human approvals for write operations. A model-callable
 * confirmation string (`PUBLISH x`, a route ID) is not an independent
 * approval: any tool caller can supply it. Approvals fix that by binding
 * each grant to the authenticated operator subject, the exact action and
 * target, and a short expiry — consumed atomically, never replayable —
 * AND by delivering the code out-of-band: the code is never returned in
 * a tool result. A model that only sees tool results can propose an
 * action but can never complete its own approval; the human provides the
 * code for exactly that action through a channel the model cannot read.
 *
 * Flow: model calls request-approval (proposes action+target) → the tool
 * result carries only the approval ID (see publicReceipt); the server
 * logs metadata only by default (see grantNotice) → the human obtains
 * the code via an operator-private channel and provides it back for
 * exactly that action → redeem validates subject/action/target/
 * expiry/code and consumes the grant in the same synchronous block. A
 * code authorizes one bound action only; guessing is infeasible
 * (128-bit) and replays fail closed. Until an operator-private channel
 * is provisioned, keep writes disabled.
 */
import { randomBytes } from 'node:crypto';

export class ApprovalError extends Error {
  constructor(code, message) { super(message); this.code = code; }
}

const ACTIONS = new Set(['publish', 'unpublish']);
const ID = /^[A-Za-z0-9_-]{3,64}$/;
const NAME = /^[A-Za-z][A-Za-z0-9_-]{0,47}$/;

/** Pending-grant ceiling: fail-closed on overflow. Operator-driven
 * approvals are rare; an unbounded map would let a faulty or hostile
 * caller exhaust memory one grant at a time. */
export const MAX_PENDING = 128;

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
    // Prune expired grants first so dead entries never consume the
    // bound; then enforce the ceiling.
    const now = this.now();
    for (const [id, r] of this.pending) {
      if (r.expiresAt <= now) this.pending.delete(id);
    }
    if (this.pending.size >= MAX_PENDING) throw new ApprovalError('APPROVAL_BUSY', 'Too many pending approvals; redeem or wait for expiry');
    const id = randomBytes(12).toString('base64url');
    const code = randomBytes(16).toString('base64url');
    this.pending.set(id, { code, subject, action, target, expiresAt: this.now() + this.ttlMs });
    return { approvalId: id, code, action, target, expiresAt: this.pending.get(id).expiresAt };
  }

  /** Tool-safe receipt: everything the model may see. The code is
   * deliberately absent — returning it in-band would let the requester
   * complete its own approval. */
  publicReceipt(grant) {
    const { code: _dropped, ...receipt } = grant;
    return receipt;
  }

  /** Operator-console notice for a new grant. The code is included ONLY
   * when revealCode is true, which the server enables solely via explicit
   * operator opt-in (OCLIV_APPROVAL_CONSOLE=true) on a console only the
   * operator can read. Default output carries metadata only, so general
   * process logs never become a standing approval-code feed. */
  grantNotice(grant, { revealCode = false } = {}) {
    const base = `action=${grant.action} target=${grant.target} subject=${grant.subject} approvalId=${grant.approvalId} expires=${new Date(grant.expiresAt).toISOString()}`;
    return revealCode
      ? `[ocliv-approval] ${base} code=${grant.code} (operator-private console only; never forward this code to a tool caller)`
      : `[ocliv-approval] ${base} code withheld from logs (set OCLIV_APPROVAL_CONSOLE=true on an operator-private console to display it)`;
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

/**
 * OCL-012 Durable Operator-Controlled Agent Permissions & Verified Ingress Identity Boundary.
 *
 * Security invariants:
 *  1. Permissions live in an operator-owned 0600 policy file outside agent write authority.
 *     No MCP tool can create, modify, or elevate permissions.
 *  2. Sensitive capabilities (authorize_visitor, revoke_client, remove_publication,
 *     deployment) are independently permissioned from lifecycle/inspect/get_url/verify.
 *  3. In native `ocliv-managed` OAuth mode, the relay strips visitor bearer tokens and
 *     forwards verified identity across the publisher ingress boundary. The MCP server
 *     NEVER trusts raw identity headers on arbitrary requests — it requires loopback
 *     peer origin AND a valid HMAC-SHA256 ingress signature bound to a replay-bounded
 *     timestamp and an owner-only shared ingress secret.
 */
import { createHmac, timingSafeEqual } from 'node:crypto';
import { lstatSync, readFileSync } from 'node:fs';

export class PermissionError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'PermissionError';
    this.code = code;
  }
}

export const PERMISSION_ACTIONS = new Set([
  'inspect',
  'get_url',
  'verify',
  'lifecycle',
  'deployment',
  'authorize_visitor',
  'revoke_client',
  'remove_publication',
]);

const DEFAULT_DENY_PERMS = Object.freeze({
  inspect: false,
  get_url: false,
  verify: false,
  lifecycle: false,
  deployment: false,
  authorize_visitor: false,
  revoke_client: false,
  remove_publication: false,
});

const SERVICE_NAME_RE = /^[A-Za-z][A-Za-z0-9._-]{0,63}$/;
const ALLOWED_AUTH_MODES = new Set(['ocliv-managed', 'upstream-oauth']);

function normalizeActionFlags(raw = {}) {
  const out = { ...DEFAULT_DENY_PERMS };
  if (!raw || typeof raw !== 'object') return out;
  for (const key of PERMISSION_ACTIONS) {
    out[key] = raw[key] === true;
  }
  return out;
}

function normalizeRule(raw) {
  if (!raw || typeof raw !== 'object') {
    throw new PermissionError('INVALID_POLICY', 'Permission rule must be an object');
  }
  const permissions = normalizeActionFlags(raw.agent_permissions ?? raw.permissions ?? raw);
  const allowedServices = Array.isArray(raw.allowed_services)
    ? raw.allowed_services.filter((s) => typeof s === 'string' && (s === '*' || SERVICE_NAME_RE.test(s)))
    : ['*'];
  const allowedPorts = Array.isArray(raw.allowed_ports)
    ? raw.allowed_ports.filter((p) => Number.isInteger(p) && p >= 1 && p <= 65535)
    : [];
  const allowedAuthModes = Array.isArray(raw.allowed_auth_modes)
    ? raw.allowed_auth_modes.filter((m) => typeof m === 'string' && ALLOWED_AUTH_MODES.has(m))
    : ['ocliv-managed'];
  return {
    permissions,
    allowedServices: new Set(allowedServices),
    allowedPorts: new Set(allowedPorts),
    allowedAuthModes: new Set(allowedAuthModes),
  };
}

/**
 * Load a durable operator-controlled permissions policy from a 0600 file or
 * parsed JSON object (for tests). Supports both top-level `agent_permissions`
 * (default operator policy) and per-agent `agents: { "<subject>": { ... } }`.
 */
export function loadPermissionsPolicyFromObject(doc) {
  if (!doc || typeof doc !== 'object') {
    throw new PermissionError('INVALID_POLICY', 'Permissions policy must be a JSON object');
  }
  const defaultRule = doc.agent_permissions ? normalizeRule(doc) : null;
  const agents = new Map();
  if (doc.agents && typeof doc.agents === 'object') {
    for (const [sub, rule] of Object.entries(doc.agents)) {
      if (typeof sub !== 'string' || !sub.trim()) continue;
      agents.set(sub.trim(), normalizeRule(rule));
    }
  }
  return { defaultRule, agents };
}

export function loadPermissionsPolicyFile(filePath) {
  if (!filePath || typeof filePath !== 'string') {
    throw new PermissionError('POLICY_MISSING', 'Permissions policy file path is required');
  }
  let st;
  try {
    st = lstatSync(filePath);
  } catch {
    throw new PermissionError('POLICY_MISSING', `Permissions policy unreadable: ${filePath}`);
  }
  if (!st.isFile() || st.isSymbolicLink() || (st.mode & 0o077) !== 0) {
    throw new PermissionError('POLICY_INSECURE', `Permissions policy must be a regular 0600 file: ${filePath}`);
  }
  let parsed;
  try {
    parsed = JSON.parse(readFileSync(filePath, 'utf8'));
  } catch {
    throw new PermissionError('INVALID_POLICY', `Permissions policy is not valid JSON: ${filePath}`);
  }
  return loadPermissionsPolicyFromObject(parsed);
}

export class PermissionsEnforcer {
  constructor(policy) {
    this.policy = policy ?? { defaultRule: null, agents: new Map() };
  }

  ruleFor(subject) {
    if (typeof subject !== 'string' || !subject.trim()) return null;
    const key = subject.trim();
    if (this.policy.agents.has(key)) return this.policy.agents.get(key);
    return this.policy.defaultRule;
  }

  /**
   * Fail-closed authorization check scoped to (subject, action, service, port, authMode).
   */
  assertAllowed({ subject, action, service = null, port = null, authMode = null }) {
    if (!PERMISSION_ACTIONS.has(action)) {
      throw new PermissionError('FORBIDDEN', `Unknown permission action: ${action}`);
    }
    const rule = this.ruleFor(subject);
    if (!rule) {
      throw new PermissionError('FORBIDDEN', `Identity "${subject}" has no operator-granted permissions`);
    }
    if (rule.permissions[action] !== true) {
      throw new PermissionError(
        'FORBIDDEN',
        `Identity "${subject}" is not permitted to perform "${action}" (operator must grant this capability in agent-permissions.json)`
      );
    }
    if (service !== null && service !== undefined && service !== '') {
      if (!rule.allowedServices.has('*') && !rule.allowedServices.has(service)) {
        throw new PermissionError(
          'FORBIDDEN_TARGET',
          `Identity "${subject}" is not authorized to operate on service "${service}"`
        );
      }
    }
    if (action === 'deployment') {
      if (port !== null && port !== undefined && rule.allowedPorts.size > 0 && !rule.allowedPorts.has(Number(port))) {
        throw new PermissionError(
          'FORBIDDEN_PORT',
          `Port ${port} is outside the operator-permitted port allowlist for "${subject}"`
        );
      }
      if (authMode !== null && authMode !== undefined && !rule.allowedAuthModes.has(authMode)) {
        throw new PermissionError(
          'FORBIDDEN_AUTH_MODE',
          `Authentication mode "${authMode}" is not permitted for "${subject}"`
        );
      }
    }
    return true;
  }
}

/**
 * Compute HMAC-SHA256 ingress signature for trusted publisher ingress forwarding.
 */
export function signIngressIdentity({ secret, subject, scopes = ['ocliv:read'], timestampSec }) {
  const scopeStr = Array.isArray(scopes) ? scopes.join(' ') : String(scopes ?? '');
  const payload = `ocliv-ingress-v1\n${subject}\n${scopeStr}\n${timestampSec}`;
  return createHmac('sha256', secret).update(payload).digest('base64url');
}

function isLoopbackAddress(addr) {
  if (typeof addr !== 'string' || !addr) return false;
  return addr === '127.0.0.1' || addr === '::1' || addr === '::ffff:127.0.0.1';
}

function headerValue(headers, name) {
  if (!headers) return '';
  if (typeof headers.get === 'function') return (headers.get(name) ?? '').trim();
  const lower = name.toLowerCase();
  for (const [k, v] of Object.entries(headers)) {
    if (k.toLowerCase() === lower) {
      return Array.isArray(v) ? String(v[0] ?? '').trim() : String(v ?? '').trim();
    }
  }
  return '';
}

/**
 * Verify caller identity at the publisher ingress boundary for native
 * `ocliv-managed` OAuth mode. Rejects non-loopback peers, missing/expired
 * timestamps, and spoofed/unsigned identity headers fail-closed.
 */
export function verifyIngressIdentity({ headers, remoteAddress, ingressSecret, allowedSubjects, nowSec = Math.floor(Date.now() / 1000), maxSkewSec = 60 }) {
  if (!ingressSecret || typeof ingressSecret !== 'string' || ingressSecret.length < 16) {
    throw new PermissionError('INGRESS_MISCONFIGURED', 'Ingress verification secret is not configured');
  }
  if (!isLoopbackAddress(remoteAddress)) {
    throw new PermissionError('INGRESS_REJECTED', 'Publisher ingress accepts loopback connections only');
  }
  const subject = headerValue(headers, 'x-ocliv-verified-subject');
  const scopesRaw = headerValue(headers, 'x-ocliv-verified-scopes') || 'ocliv:read';
  const tsRaw = headerValue(headers, 'x-ocliv-ingress-ts');
  const sig = headerValue(headers, 'x-ocliv-ingress-sig');
  if (!subject || !tsRaw || !sig) {
    throw new PermissionError('INGRESS_IDENTITY_UNVERIFIED', 'Missing verified publisher ingress identity headers');
  }
  const ts = Number(tsRaw);
  if (!Number.isInteger(ts) || Math.abs(nowSec - ts) > maxSkewSec) {
    throw new PermissionError('INGRESS_EXPIRED', 'Publisher ingress identity timestamp expired or invalid');
  }
  const scopes = scopesRaw.split(/\s+/).filter(Boolean);
  const expected = signIngressIdentity({ secret: ingressSecret, subject, scopes, timestampSec: ts });
  const a = Buffer.from(sig);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !timingSafeEqual(a, b)) {
    throw new PermissionError('INGRESS_SPOOF_REJECTED', 'Publisher ingress identity signature verification failed');
  }
  if (allowedSubjects && allowedSubjects.size > 0 && !allowedSubjects.has(subject)) {
    throw new PermissionError('FORBIDDEN', 'Verified subject is not allowlisted for this Ocliv deployment');
  }
  return { subject, scopes };
}

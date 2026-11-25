/**
 * OCL-012/013 Durable Operator-Controlled Agent Permissions & Verified Ingress Identity Boundary.
 *
 * Security invariants:
 *  1. Permissions live in an operator-owned 0600 policy file outside agent write authority,
 *     verified for regular-file + 0600 + owner UID. No MCP tool can modify it.
 *  2. Sensitive capabilities (authorize_visitor, manage_auth_policy, revoke_client,
 *     remove_publication, deployment) are independently permissioned.
 *  3. An omitted or empty allowed_services or allowed_ports list NEVER acts as a wildcard.
 *  4. In native `ocliv-managed` OAuth mode, the native Go publisher (`internal/agent/agent_ingress_auth.go`)
 *     signs a per-request `ocliv-ingress-v2` HMAC-SHA256 assertion bound to method, path,
 *     destination host, route ID, verified subject, scopes, timestamp, and single-use nonce.
 *     Skybridge verifies the signature, checks loopback peer, enforces timestamp skew, and
 *     rejects replayed nonces fail-closed.
 */
import { createHmac, timingSafeEqual } from 'node:crypto';
import { lstatSync, readFileSync } from 'node:fs';

export class PermissionError extends Error {
  constructor(code, message, extra = null) {
    super(message);
    this.name = 'PermissionError';
    this.code = code;
    this.extra = extra;
  }
}

export const PERMISSION_ACTIONS = new Set([
  'inspect',
  'get_url',
  'verify',
  'lifecycle',
  'deployment',
  'authorize_visitor',
  'manage_auth_policy',
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
  manage_auth_policy: false,
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
  // Fail-closed: an omitted or empty allowed_services list authorizes NO services (never a wildcard).
  const allowedServices = Array.isArray(raw.allowed_services)
    ? raw.allowed_services.filter((s) => typeof s === 'string' && (s === '*' || SERVICE_NAME_RE.test(s)))
    : [];
  const allowedServiceIDs = Array.isArray(raw.allowed_service_ids)
    ? raw.allowed_service_ids.filter((s) => typeof s === 'string' && s.trim().length > 0)
    : [];
  // Fail-closed: an omitted or empty allowed_ports list authorizes NO deployment ports.
  const allowedPorts = Array.isArray(raw.allowed_ports)
    ? raw.allowed_ports.filter((p) => Number.isInteger(p) && p >= 1 && p <= 65535)
    : [];
  const allowedAuthModes = Array.isArray(raw.allowed_auth_modes)
    ? raw.allowed_auth_modes.filter((m) => typeof m === 'string' && ALLOWED_AUTH_MODES.has(m))
    : ['ocliv-managed'];
  return {
    permissions,
    allowedServices: new Set(allowedServices),
    allowedServiceIDs: new Set(allowedServiceIDs),
    allowedPorts: new Set(allowedPorts),
    allowedAuthModes: new Set(allowedAuthModes),
  };
}

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
  if (typeof process.getuid === 'function' && st.uid !== process.getuid()) {
    throw new PermissionError('POLICY_INSECURE', `Permissions policy must be owned by the current operator UID: ${filePath}`);
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

  canAccessService(subject, service, serviceId = '') {
    const rule = this.ruleFor(subject);
    if (!rule) return false;
    if (rule.allowedServices.has('*')) return true;
    if (service && rule.allowedServices.has(service)) return true;
    if (serviceId && rule.allowedServiceIDs.has(serviceId)) return true;
    return false;
  }

  assertAllowed({ subject, action, service = null, serviceId = '', port = null, authMode = null }) {
    if (!PERMISSION_ACTIONS.has(action)) {
      throw new PermissionError('FORBIDDEN', `Unknown permission action: ${action}`);
    }
    const rule = this.ruleFor(subject);
    if (!rule) {
      throw new PermissionError('OPERATOR_AUTHORIZATION_REQUIRED', `Identity "${subject}" has no operator-granted permissions`, {
        status: 'OPERATOR_AUTHORIZATION_REQUIRED',
        action,
        service: service ?? '',
        requested_permissions: [action],
        message: 'Review this request in Ocliv Control Center.',
      });
    }
    if (rule.permissions[action] !== true) {
      throw new PermissionError(
        'OPERATOR_AUTHORIZATION_REQUIRED',
        `Identity "${subject}" is not permitted to perform "${action}". Review this request in Ocliv Control Center.`,
        {
          status: 'OPERATOR_AUTHORIZATION_REQUIRED',
          action,
          service: service ?? '',
          requested_permissions: [action],
          message: 'Review this request in Ocliv Control Center.',
        }
      );
    }
    if (service !== null && service !== undefined && service !== '') {
      if (!this.canAccessService(subject, service, serviceId)) {
        throw new PermissionError(
          'FORBIDDEN_TARGET',
          `Identity "${subject}" is not authorized to operate on service "${service}"`
        );
      }
    }
    if (action === 'deployment') {
      if (rule.allowedPorts.size === 0 || (port !== null && port !== undefined && !rule.allowedPorts.has(Number(port)))) {
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
 * Compute canonical `ocliv-ingress-v2` HMAC-SHA256 assertion matching
 * `internal/agent/agent_ingress_auth.go:SignIngressAssertion`.
 */
export function signIngressIdentity({
  secret,
  method = 'POST',
  path = '/mcp',
  host = '127.0.0.1',
  route = '',
  subject,
  scopes = ['ocliv:read'],
  timestampSec,
  nonce,
}) {
  const scopeStr = Array.isArray(scopes) ? scopes.join(' ') : String(scopes ?? '');
  const payload = [
    'ocliv-ingress-v2',
    String(method).toUpperCase(),
    String(path || '/'),
    String(host || '').toLowerCase(),
    String(route || ''),
    String(subject || ''),
    scopeStr,
    String(timestampSec),
    String(nonce || ''),
  ].join('\n');
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

const MAX_REPLAY_ENTRIES = 4096;

export class IngressReplayCache {
  constructor() {
    this.seen = new Map();
  }
  consume(nonce, nowSec, ttlSec = 120) {
    for (const [k, exp] of this.seen) {
      if (exp <= nowSec) this.seen.delete(k);
    }
    if (this.seen.has(nonce)) return false;
    if (this.seen.size >= MAX_REPLAY_ENTRIES) {
      const oldest = this.seen.keys().next().value;
      if (oldest !== undefined) this.seen.delete(oldest);
    }
    this.seen.set(nonce, nowSec + ttlSec);
    return true;
  }
}

const defaultReplayCache = new IngressReplayCache();

/**
 * Verify `ocliv-ingress-v2` publisher ingress assertion bound to method, path,
 * destination host, route ID, authenticated principal, scopes, timestamp, and
 * single-use nonce. Never trusts unsigned headers or loopback alone.
 */
export function verifyIngressIdentity({
  headers,
  method = 'POST',
  path = '/mcp',
  host = '',
  remoteAddress,
  ingressSecret,
  allowedSubjects,
  expectedRoute = '',
  nowSec = Math.floor(Date.now() / 1000),
  maxSkewSec = 60,
  replayCache = defaultReplayCache,
}) {
  if (!ingressSecret || typeof ingressSecret !== 'string' || ingressSecret.length < 16) {
    throw new PermissionError('INGRESS_MISCONFIGURED', 'Ingress verification secret is not configured');
  }
  if (!isLoopbackAddress(remoteAddress)) {
    throw new PermissionError('INGRESS_REJECTED', 'Publisher ingress accepts loopback connections only');
  }
  const subject = headerValue(headers, 'x-ocliv-verified-subject');
  const route = headerValue(headers, 'x-ocliv-verified-route');
  const scopesRaw = headerValue(headers, 'x-ocliv-verified-scopes') || 'ocliv:read';
  const tsRaw = headerValue(headers, 'x-ocliv-ingress-ts');
  const nonce = headerValue(headers, 'x-ocliv-ingress-nonce');
  const sig = headerValue(headers, 'x-ocliv-ingress-sig');
  const reqHost = host || headerValue(headers, 'host');
  if (!subject || !route || !tsRaw || !nonce || !sig) {
    throw new PermissionError('INGRESS_IDENTITY_UNVERIFIED', 'Missing verified ocliv-ingress-v2 publisher headers');
  }
  if (expectedRoute && route !== expectedRoute) {
    throw new PermissionError('INGRESS_ROUTE_MISMATCH', 'Verified route does not match expected publication route');
  }
  const ts = Number(tsRaw);
  if (!Number.isInteger(ts) || Math.abs(nowSec - ts) > maxSkewSec) {
    throw new PermissionError('INGRESS_EXPIRED', 'Publisher ingress identity timestamp expired or invalid');
  }
  const scopes = scopesRaw.split(/\s+/).filter(Boolean);
  const expected = signIngressIdentity({
    secret: ingressSecret,
    method,
    path,
    host: reqHost,
    route,
    subject,
    scopes,
    timestampSec: ts,
    nonce,
  });
  const a = Buffer.from(sig);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !timingSafeEqual(a, b)) {
    throw new PermissionError('INGRESS_SPOOF_REJECTED', 'Publisher ingress identity signature verification failed');
  }
  if (replayCache && !replayCache.consume(`${route}:${nonce}`, nowSec, maxSkewSec * 2)) {
    throw new PermissionError('INGRESS_REPLAY_REJECTED', 'Replayed publisher ingress assertion rejected');
  }
  if (allowedSubjects && allowedSubjects.size > 0 && !allowedSubjects.has(subject)) {
    throw new PermissionError('FORBIDDEN', 'Verified subject is not allowlisted for this Ocliv deployment');
  }
  return { subject, route, scopes };
}

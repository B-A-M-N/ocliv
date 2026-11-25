/**
 * OCL-012 Canonical Native Control Plane Adapter.
 *
 * Delegates all 20 agent-facing MCP tools to the native Go `ocliv` CLI and
 * canonical signed relay inventory (`NativeOclivClient`) rather than
 * maintaining independent lifecycle state machines in JavaScript.
 *
 * Security invariants:
 *  - Never invokes a shell (`execFile` with fixed argv arrays only).
 *  - Never returns pairing secrets, refresh tokens, signing keys, or API credentials.
 *  - Enforces operator-controlled durable permissions (`PermissionsEnforcer`) on every call.
 *  - Uses OCL-011 canonical service identity resolution by human-readable service name.
 */
import { execFile as execFileCb } from 'node:child_process';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFileCb);

export class ControlPlaneError extends Error {
  constructor(code, message, details = null) {
    super(message);
    this.name = 'ControlPlaneError';
    this.code = code;
    this.details = details;
  }
}

const SERVICE_NAME_RE = /^[A-Za-z][A-Za-z0-9._-]{0,63}$/;
const ID_RE = /^[A-Za-z0-9._:-]{3,128}$/;

function assertServiceName(name) {
  if (typeof name !== 'string' || !SERVICE_NAME_RE.test(name)) {
    throw new ControlPlaneError('INVALID_INPUT', 'Invalid service name');
  }
  return name;
}

function assertSafeId(id, label = 'id') {
  if (typeof id !== 'string' || !ID_RE.test(id)) {
    throw new ControlPlaneError('INVALID_INPUT', `Invalid ${label}`);
  }
  return id;
}

const SECRET_KEYS = new Set([
  'pairing_secret',
  'client_secret',
  'refresh_token',
  'access_token',
  'private_key',
  'signing_key',
  'enroll_code',
  'secret',
  'token',
]);

/** Recursively strip any sensitive credential fields before returning to an MCP client. */
export function redactSecrets(value) {
  if (Array.isArray(value)) return value.map(redactSecrets);
  if (!value || typeof value !== 'object') return value;
  const out = {};
  for (const [k, v] of Object.entries(value)) {
    if (SECRET_KEYS.has(k.toLowerCase())) continue;
    out[k] = redactSecrets(v);
  }
  return out;
}

function parseJsonLoose(stdout) {
  const trimmed = String(stdout ?? '').trim();
  if (!trimmed) return null;
  try {
    return JSON.parse(trimmed);
  } catch {
    // Some commands print human lines before/after a JSON object; locate outermost JSON.
    const first = trimmed.indexOf('{');
    const last = trimmed.lastIndexOf('}');
    if (first >= 0 && last > first) {
      try {
        return JSON.parse(trimmed.slice(first, last + 1));
      } catch {
        return null;
      }
    }
    return null;
  }
}

export class NativeControlPlane {
  /**
   * @param {{ bin: string, profile?: string, relayUrl?: string, permissions: import('./permissions.mjs').PermissionsEnforcer, execImpl?: typeof execFileAsync, nativeClient?: any }} opts
   */
  constructor({ bin, profile = '', relayUrl = '', permissions, execImpl = execFileAsync, nativeClient = null }) {
    this.bin = bin;
    this.profile = profile;
    this.relayUrl = relayUrl;
    this.permissions = permissions;
    this.exec = execImpl;
    this.nativeClient = nativeClient;
  }

  async runCli(args, { timeoutMs = 20000, allowNonZero = false } = {}) {
    const env = { ...process.env };
    if (this.relayUrl) env.OCLIV_RELAY_URL = this.relayUrl;
    if (this.profile) env.OCLIV_PROFILE = this.profile;
    try {
      const { stdout, stderr } = await this.exec(this.bin, args, {
        env,
        timeout: timeoutMs,
        maxBuffer: 2 * 1024 * 1024,
      });
      return { exitCode: 0, stdout: String(stdout ?? ''), stderr: String(stderr ?? ''), json: parseJsonLoose(stdout) };
    } catch (err) {
      const stdout = String(err?.stdout ?? '');
      const stderr = String(err?.stderr ?? '');
      const exitCode = typeof err?.code === 'number' ? err.code : 1;
      const json = parseJsonLoose(stdout);
      if (allowNonZero) {
        return { exitCode, stdout, stderr, json };
      }
      throw new ControlPlaneError(
        'CLI_FAILED',
        (stderr || stdout || err?.message || 'ocliv command failed').trim().slice(0, 400),
        { exitCode, json: redactSecrets(json) }
      );
    }
  }

  // ==================== 1. DISCOVERY & URL RETRIEVAL ====================

  async getStatus(subject) {
    this.permissions.assertAllowed({ subject, action: 'inspect' });
    const ver = await this.runCli(['version', '--json'], { allowNonZero: true });
    const svcs = await this.runCli(['service', 'list', '--json'], { allowNonZero: true });
    let relayStatus = null;
    if (this.nativeClient) {
      try {
        relayStatus = await this.nativeClient.status();
      } catch (e) {
        relayStatus = { reachable: false, error: e.message };
      }
    }
    return redactSecrets({
      ok: true,
      version: ver.json ?? ver.stdout.trim(),
      relay: relayStatus,
      servicesCount: Array.isArray(svcs.json) ? svcs.json.length : Array.isArray(svcs.json?.services) ? svcs.json.services.length : 0,
    });
  }

  async listServices(subject) {
    this.permissions.assertAllowed({ subject, action: 'inspect' });
    const res = await this.runCli(['service', 'list', '--json']);
    const list = Array.isArray(res.json) ? res.json : (res.json?.services ?? []);
    return redactSecrets({ ok: true, services: list });
  }

  async getService(subject, { service }) {
    const name = assertServiceName(service);
    this.permissions.assertAllowed({ subject, action: 'inspect', service: name });
    const res = await this.runCli(['status', name, '--json'], { allowNonZero: true });
    if (!res.json) {
      throw new ControlPlaneError('SERVICE_NOT_FOUND', (res.stderr || `Unknown service "${name}"`).trim());
    }
    return redactSecrets({ ok: true, service: res.json });
  }

  async getUrl(subject, { service }) {
    const name = assertServiceName(service);
    this.permissions.assertAllowed({ subject, action: 'get_url', service: name });
    const st = await this.runCli(['status', name, '--json'], { allowNonZero: true });
    const urlRes = await this.runCli(['mcp', 'url', name, '--json'], { allowNonZero: true });
    const report = st.json ?? {};
    const urlDoc = urlRes.json ?? {};
    const url = urlDoc.url || report.public_url || '';
    if (!url) {
      throw new ControlPlaneError('URL_UNAVAILABLE', `No canonical public URL available for service "${name}"`);
    }
    return redactSecrets({
      service: name,
      publication_id: urlDoc.route_id || report.publication_id || '',
      url,
      enabled: report.desired_state === 'enabled',
      reachable: report.state === 'SERVING' && report.health === 'READY',
      state: report.state || urlDoc.relay_state || 'UNKNOWN',
      authentication: report.auth_profile || urlDoc.auth_method || 'ocliv-managed',
    });
  }

  // ==================== 2. DEPLOYMENT & LIFECYCLE ====================

  async deployService(subject, { name, port, path = '/mcp', type = 'mcp', authentication = 'ocliv-managed', persistent = true }) {
    const svcName = assertServiceName(name);
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      throw new ControlPlaneError('INVALID_INPUT', 'port must be an integer between 1 and 65535');
    }
    if (type !== 'mcp' && type !== 'http') {
      throw new ControlPlaneError('INVALID_INPUT', 'type must be "mcp" or "http"');
    }
    if (typeof path !== 'string' || !path.startsWith('/') || path.includes('..')) {
      throw new ControlPlaneError('INVALID_INPUT', 'path must be a clean absolute path');
    }
    this.permissions.assertAllowed({
      subject,
      action: 'deployment',
      service: svcName,
      port,
      authMode: authentication,
    });

    // Idempotency check: if service already exists with matching target, reconcile/enable instead of duplicating.
    const existing = await this.runCli(['status', svcName, '--json'], { allowNonZero: true });
    if (existing.json && existing.json.name === svcName) {
      if (existing.json.desired_state !== 'enabled') {
        await this.runCli(['service', 'start', svcName], { allowNonZero: true });
      }
      const rec = await this.runCli(['service', 'reconcile', svcName, '--json'], { allowNonZero: true });
      return redactSecrets({ ok: true, idempotent: true, service: rec.json ?? existing.json });
    }

    const args =
      type === 'mcp'
        ? ['host', 'mcp', String(port), '--name', svcName, '--auth', authentication]
        : ['host', 'http', String(port), '--name', svcName];
    if (!persistent) args.push('--no-persist');
    const res = await this.runCli(args, { allowNonZero: true });
    const status = await this.runCli(['status', svcName, '--json'], { allowNonZero: true });
    if (res.exitCode !== 0 && !status.json) {
      throw new ControlPlaneError('DEPLOY_FAILED', (res.stderr || res.stdout || 'deployment failed').trim().slice(0, 400));
    }
    return redactSecrets({ ok: res.exitCode === 0, idempotent: false, service: status.json ?? res.json });
  }

  async enableService(subject, { service }) {
    const name = assertServiceName(service);
    this.permissions.assertAllowed({ subject, action: 'lifecycle', service: name });
    await this.runCli(['service', 'start', name], { allowNonZero: true });
    const st = await this.runCli(['status', name, '--json'], { allowNonZero: true });
    return redactSecrets({ ok: true, service: st.json });
  }

  async disableService(subject, { service }) {
    const name = assertServiceName(service);
    this.permissions.assertAllowed({ subject, action: 'lifecycle', service: name });
    await this.runCli(['service', 'stop', name]);
    const st = await this.runCli(['status', name, '--json'], { allowNonZero: true });
    return redactSecrets({ ok: true, service: st.json });
  }

  async restartService(subject, { service }) {
    const name = assertServiceName(service);
    this.permissions.assertAllowed({ subject, action: 'lifecycle', service: name });
    await this.runCli(['service', 'restart', name], { allowNonZero: true });
    const st = await this.runCli(['status', name, '--json'], { allowNonZero: true });
    return redactSecrets({ ok: true, service: st.json });
  }

  async reconcileService(subject, { service }) {
    const name = assertServiceName(service);
    this.permissions.assertAllowed({ subject, action: 'lifecycle', service: name });
    const res = await this.runCli(['service', 'reconcile', name, '--json'], { allowNonZero: true });
    return redactSecrets({ ok: res.exitCode === 0, result: res.json ?? { output: res.stdout.trim() } });
  }

  async removeService(subject, { service }) {
    const name = assertServiceName(service);
    this.permissions.assertAllowed({ subject, action: 'remove_publication', service: name });
    const res = await this.runCli(['service', 'remove', name]);
    return redactSecrets({ ok: true, service: name, removed: true, detail: res.stdout.trim() });
  }

  // ==================== 3. AUTHENTICATION & ACCESS MANAGEMENT ====================

  async getAuthStatus(subject, { service }) {
    const name = assertServiceName(service);
    this.permissions.assertAllowed({ subject, action: 'inspect', service: name });
    const st = await this.runCli(['status', name, '--json'], { allowNonZero: true });
    const trust = await this.runCli(['trust', name, '--list', '--json'], { allowNonZero: true });
    const pending = await this.runCli(['service', 'pending', name, '--json'], { allowNonZero: true });
    return redactSecrets({
      ok: true,
      service: name,
      authentication: st.json?.auth_profile ?? 'unknown',
      authorization_layer: st.json?.layers?.authorization ?? 'unknown',
      trust_policies: trust.json ?? [],
      pending: pending.json ?? { pending: [], pending_transactions: [] },
    });
  }

  async listPendingAuthorizations(subject, { service }) {
    const name = assertServiceName(service);
    this.permissions.assertAllowed({ subject, action: 'inspect', service: name });
    const res = await this.runCli(['service', 'pending', name, '--json']);
    return redactSecrets({ ok: true, service: name, ...(res.json ?? { pending: [], pending_transactions: [] }) });
  }

  async decideAuthorization(subject, { service, challenge, decision }) {
    const name = assertServiceName(service);
    const challengeId = assertSafeId(challenge, 'challenge');
    if (decision !== 'approve' && decision !== 'deny') {
      throw new ControlPlaneError('INVALID_INPUT', 'decision must be "approve" or "deny"');
    }
    this.permissions.assertAllowed({ subject, action: 'authorize_visitor', service: name });
    const args = ['service', 'approve', name, '--challenge', challengeId, '--json'];
    if (decision === 'deny') args.push('--deny');
    const res = await this.runCli(args);
    return redactSecrets({ ok: true, service: name, decision, result: res.json });
  }

  async listAuthorizedClients(subject, { service }) {
    const name = assertServiceName(service);
    this.permissions.assertAllowed({ subject, action: 'inspect', service: name });
    const trust = await this.runCli(['trust', name, '--list', '--json'], { allowNonZero: true });
    const connect = await this.runCli(['connect', 'status', name, '--json'], { allowNonZero: true });
    return redactSecrets({
      ok: true,
      service: name,
      trust_policies: trust.json ?? [],
      provider_bindings: connect.json ?? null,
    });
  }

  async revokeClient(subject, { service, clientId }) {
    const name = assertServiceName(service);
    const cid = assertSafeId(clientId, 'clientId');
    this.permissions.assertAllowed({ subject, action: 'revoke_client', service: name });
    const res = await this.runCli(['revoke', 'client', cid, '--service', name]);
    return redactSecrets({ ok: true, service: name, client_id: cid, revoked: true, detail: res.stdout.trim() });
  }

  async getAuthPolicy(subject, { service }) {
    const name = assertServiceName(service);
    this.permissions.assertAllowed({ subject, action: 'inspect', service: name });
    const trust = await this.runCli(['trust', name, '--list', '--json'], { allowNonZero: true });
    const visitor = await this.runCli(['trust', name, '--show-visitor-auth', '--json'], { allowNonZero: true });
    return redactSecrets({
      ok: true,
      service: name,
      trust_policies: trust.json ?? [],
      visitor_auth: visitor.json ?? { mode: 'native' },
    });
  }

  async setAuthPolicy(subject, { service, preset = '', redirectUri = '' }) {
    const name = assertServiceName(service);
    this.permissions.assertAllowed({ subject, action: 'authorize_visitor', service: name });
    const args = ['trust', name];
    if (preset) {
      if (preset !== 'chatgpt') {
        throw new ControlPlaneError('INVALID_INPUT', 'Unsupported preset (supported: chatgpt)');
      }
      args.push(preset);
    } else if (redirectUri) {
      if (typeof redirectUri !== 'string' || !redirectUri.startsWith('https://')) {
        throw new ControlPlaneError('INVALID_INPUT', 'redirectUri must be an exact https:// URI');
      }
      args.push('--redirect-uri', redirectUri);
    } else {
      throw new ControlPlaneError('INVALID_INPUT', 'Provide either preset or redirectUri');
    }
    const res = await this.runCli(args);
    return redactSecrets({ ok: true, service: name, updated: true, detail: res.stdout.trim() });
  }

  // ==================== 4. DIAGNOSTICS & VERIFICATION ====================

  async verifyService(subject, { service }) {
    const name = assertServiceName(service);
    this.permissions.assertAllowed({ subject, action: 'verify', service: name });
    const res = await this.runCli(['mcp', 'check', name, '--json'], { allowNonZero: true });
    return redactSecrets({ ok: res.exitCode === 0, service: name, verification: res.json ?? { detail: res.stdout.trim() } });
  }

  async diagnoseService(subject, { service }) {
    const name = assertServiceName(service);
    this.permissions.assertAllowed({ subject, action: 'inspect', service: name });
    const st = await this.runCli(['status', name, '--json'], { allowNonZero: true });
    const doc = await this.runCli(['doctor', name, '--json'], { allowNonZero: true });
    return redactSecrets({
      ok: true,
      service: name,
      status: st.json ?? null,
      diagnostics: doc.json ?? { detail: (doc.stdout || doc.stderr).trim() },
    });
  }

  async verifyEvents(subject, { service }) {
    const name = assertServiceName(service);
    this.permissions.assertAllowed({ subject, action: 'verify', service: name });
    const res = await this.runCli(['mcp', 'check', name, '--capability', 'events', '--json'], { allowNonZero: true });
    return redactSecrets({ ok: res.exitCode === 0, service: name, events: res.json ?? { detail: res.stdout.trim() } });
  }
}

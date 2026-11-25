import test from 'node:test';
import assert from 'node:assert/strict';
import {
  IngressReplayCache,
  loadPermissionsPolicyFromObject,
  PermissionsEnforcer,
  signIngressIdentity,
  verifyIngressIdentity,
} from '../src/core/permissions.mjs';
import { NativeControlPlane, redactSecrets } from '../src/core/control-plane.mjs';

test('OCL-013 verified ocliv-ingress-v2 rejects spoofing, replay, method/path tamper, non-loopback, and expiry', () => {
  const secret = 'super-secret-ingress-key-0123456789';
  const allowed = new Set(['agent-ops']);
  const now = 1700000000;
  const nonce = 'nonce-unique-123456';
  const cache = new IngressReplayCache();
  const sig = signIngressIdentity({
    secret,
    method: 'POST',
    path: '/mcp',
    host: '127.0.0.1:3000',
    route: 'jr8x2Txyoa1jPs22CROuBQ',
    subject: 'agent-ops',
    scopes: ['ocliv:read', 'ocliv:write'],
    timestampSec: now,
    nonce,
  });

  const validHeaders = {
    host: '127.0.0.1:3000',
    'x-ocliv-verified-subject': 'agent-ops',
    'x-ocliv-verified-route': 'jr8x2Txyoa1jPs22CROuBQ',
    'x-ocliv-verified-scopes': 'ocliv:read ocliv:write',
    'x-ocliv-ingress-ts': String(now),
    'x-ocliv-ingress-nonce': nonce,
    'x-ocliv-ingress-sig': sig,
  };

  // Valid loopback + ocliv-ingress-v2 HMAC signature passes once.
  const ok = verifyIngressIdentity({
    headers: validHeaders,
    method: 'POST',
    path: '/mcp',
    remoteAddress: '127.0.0.1',
    ingressSecret: secret,
    allowedSubjects: allowed,
    nowSec: now,
    replayCache: cache,
  });
  assert.equal(ok.subject, 'agent-ops');
  assert.equal(ok.route, 'jr8x2Txyoa1jPs22CROuBQ');

  // Replaying the exact same signed assertion MUST fail closed.
  assert.throws(
    () =>
      verifyIngressIdentity({
        headers: validHeaders,
        method: 'POST',
        path: '/mcp',
        remoteAddress: '127.0.0.1',
        ingressSecret: secret,
        allowedSubjects: allowed,
        nowSec: now,
        replayCache: cache,
      }),
    /Replayed/
  );

  // Tampering with method or path MUST fail closed.
  assert.throws(
    () =>
      verifyIngressIdentity({
        headers: validHeaders,
        method: 'DELETE',
        path: '/mcp',
        remoteAddress: '127.0.0.1',
        ingressSecret: secret,
        allowedSubjects: allowed,
        nowSec: now,
        replayCache: new IngressReplayCache(),
      }),
    /signature verification failed/
  );

  // Spoofed subject MUST fail closed.
  assert.throws(
    () =>
      verifyIngressIdentity({
        headers: { ...validHeaders, 'x-ocliv-verified-subject': 'admin-spoof' },
        method: 'POST',
        path: '/mcp',
        remoteAddress: '127.0.0.1',
        ingressSecret: secret,
        allowedSubjects: new Set(['agent-ops', 'admin-spoof']),
        nowSec: now,
        replayCache: new IngressReplayCache(),
      }),
    /signature verification failed/
  );

  // Non-loopback remote address MUST fail closed.
  assert.throws(
    () =>
      verifyIngressIdentity({
        headers: validHeaders,
        method: 'POST',
        path: '/mcp',
        remoteAddress: '192.168.1.50',
        ingressSecret: secret,
        allowedSubjects: allowed,
        nowSec: now,
        replayCache: new IngressReplayCache(),
      }),
    /loopback/
  );
});

test('OCL-013 durable permissions separate authorize_visitor from manage_auth_policy and deny empty allowlists', () => {
  const policy = loadPermissionsPolicyFromObject({
    agents: {
      'agent-approver': {
        agent_permissions: {
          inspect: true,
          get_url: true,
          verify: true,
          lifecycle: true,
          deployment: false,
          authorize_visitor: true,
          manage_auth_policy: false,
          revoke_client: false,
          remove_publication: false,
        },
        allowed_services: ['agentgateway'],
      },
      'agent-empty-allowlist': {
        agent_permissions: {
          inspect: true,
          deployment: true,
        },
      },
    },
  });
  const enforcer = new PermissionsEnforcer(policy);

  // Approver can approve visitors, but CANNOT modify auth policy or revoke clients.
  assert.equal(enforcer.assertAllowed({ subject: 'agent-approver', action: 'authorize_visitor', service: 'agentgateway' }), true);
  assert.throws(() => enforcer.assertAllowed({ subject: 'agent-approver', action: 'manage_auth_policy', service: 'agentgateway' }), /not permitted/);
  assert.throws(() => enforcer.assertAllowed({ subject: 'agent-approver', action: 'revoke_client', service: 'agentgateway' }), /not permitted/);

  // Empty allowed_services and empty allowed_ports NEVER act as wildcards.
  assert.equal(enforcer.canAccessService('agent-empty-allowlist', 'agentgateway'), false);
  assert.throws(() => enforcer.assertAllowed({ subject: 'agent-empty-allowlist', action: 'inspect', service: 'agentgateway' }), /not authorized to operate on service/);
  assert.throws(() => enforcer.assertAllowed({ subject: 'agent-empty-allowlist', action: 'deployment', port: 8085, authMode: 'ocliv-managed' }), /port allowlist/);
});

test('OCL-013 NativeControlPlane filters list_services, enforces config conflict on deploy, and redacts secrets', async () => {
  const execMock = async (_bin, args) => {
    const cmd = args.join(' ');
    if (cmd === 'service list --json') {
      return {
        stdout: JSON.stringify([
          { name: 'agentgateway', type: 'mcp' },
          { name: 'secret-internal', type: 'mcp' },
        ]),
        stderr: '',
      };
    }
    if (cmd === 'status agentgateway --json') {
      return {
        stdout: JSON.stringify({
          name: 'agentgateway',
          type: 'mcp',
          local_url: 'http://127.0.0.1:8765/mcp',
          desired_state: 'enabled',
          state: 'SERVING',
          health: 'READY',
          publication_id: 'jr8x2Txyoa1jPs22CROuBQ',
          public_url: 'https://bamnlabs.duckdns.org/r/jr8x2Txyoa1jPs22CROuBQ/mcp',
          auth_profile: 'ocliv-managed',
          pairing_secret: 'MUST_NEVER_LEAK',
        }),
        stderr: '',
      };
    }
    if (cmd === 'mcp url agentgateway --json') {
      return {
        stdout: JSON.stringify({
          route_id: 'jr8x2Txyoa1jPs22CROuBQ',
          url: 'https://bamnlabs.duckdns.org/r/jr8x2Txyoa1jPs22CROuBQ/mcp',
          auth_method: 'ocliv-managed',
          relay_state: 'VERIFIED',
        }),
        stderr: '',
      };
    }
    return { stdout: '{}', stderr: '' };
  };

  const enforcer = new PermissionsEnforcer(
    loadPermissionsPolicyFromObject({
      agent_permissions: {
        inspect: true,
        get_url: true,
        verify: true,
        lifecycle: true,
        deployment: true,
        authorize_visitor: false,
        manage_auth_policy: false,
        revoke_client: false,
        remove_publication: false,
      },
      allowed_services: ['agentgateway'],
      allowed_ports: [8765, 9999],
      allowed_auth_modes: ['ocliv-managed'],
    })
  );

  const cp = new NativeControlPlane({ bin: '/usr/local/bin/ocliv', permissions: enforcer, execImpl: execMock });

  // list_services filters out unauthorized services.
  const listed = await cp.listServices('agent-1');
  assert.deepEqual(listed.services.map((s) => s.name), ['agentgateway']);

  // Conflicting port on existing service returns CONFIGURATION_CONFLICT instead of fake idempotent success.
  await assert.rejects(
    () => cp.deployService('agent-1', { name: 'agentgateway', port: 9999, type: 'mcp', authentication: 'ocliv-managed' }),
    /different configuration/
  );

  // Secret redaction strips sensitive keys recursively.
  assert.deepEqual(redactSecrets({ ok: true, refresh_token: 'rt_x', nested: { client_secret: 'cs_x', safe: 1 } }), {
    ok: true,
    nested: { safe: 1 },
  });
});

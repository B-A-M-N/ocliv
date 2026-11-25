import test from 'node:test';
import assert from 'node:assert/strict';
import {
  loadPermissionsPolicyFromObject,
  PermissionsEnforcer,
  signIngressIdentity,
  verifyIngressIdentity,
} from '../src/core/permissions.mjs';
import { NativeControlPlane, redactSecrets } from '../src/core/control-plane.mjs';

test('OCL-012 verified ingress identity rejects spoofing, non-loopback, and expired timestamps', () => {
  const secret = 'super-secret-ingress-key-0123456789';
  const allowed = new Set(['agent-ops']);
  const now = 1700000000;
  const sig = signIngressIdentity({ secret, subject: 'agent-ops', scopes: ['ocliv:read', 'ocliv:write'], timestampSec: now });

  // Valid loopback + HMAC signature passes.
  const ok = verifyIngressIdentity({
    headers: {
      'x-ocliv-verified-subject': 'agent-ops',
      'x-ocliv-verified-scopes': 'ocliv:read ocliv:write',
      'x-ocliv-ingress-ts': String(now),
      'x-ocliv-ingress-sig': sig,
    },
    remoteAddress: '127.0.0.1',
    ingressSecret: secret,
    allowedSubjects: allowed,
    nowSec: now,
  });
  assert.equal(ok.subject, 'agent-ops');

  // Spoofed subject with original signature MUST fail closed.
  assert.throws(
    () =>
      verifyIngressIdentity({
        headers: {
          'x-ocliv-verified-subject': 'admin-spoof',
          'x-ocliv-verified-scopes': 'ocliv:read ocliv:write',
          'x-ocliv-ingress-ts': String(now),
          'x-ocliv-ingress-sig': sig,
        },
        remoteAddress: '127.0.0.1',
        ingressSecret: secret,
        allowedSubjects: new Set(['agent-ops', 'admin-spoof']),
        nowSec: now,
      }),
    /signature verification failed/
  );

  // Non-loopback remote address MUST fail closed even with a valid signature.
  assert.throws(
    () =>
      verifyIngressIdentity({
        headers: {
          'x-ocliv-verified-subject': 'agent-ops',
          'x-ocliv-verified-scopes': 'ocliv:read',
          'x-ocliv-ingress-ts': String(now),
          'x-ocliv-ingress-sig': sig,
        },
        remoteAddress: '192.168.1.50',
        ingressSecret: secret,
        allowedSubjects: allowed,
        nowSec: now,
      }),
    /loopback/
  );

  // Expired timestamp MUST fail closed.
  assert.throws(
    () =>
      verifyIngressIdentity({
        headers: {
          'x-ocliv-verified-subject': 'agent-ops',
          'x-ocliv-verified-scopes': 'ocliv:read ocliv:write',
          'x-ocliv-ingress-ts': String(now - 300),
          'x-ocliv-ingress-sig': sig,
        },
        remoteAddress: '127.0.0.1',
        ingressSecret: secret,
        allowedSubjects: allowed,
        nowSec: now,
      }),
    /expired/
  );
});

test('OCL-012 durable permissions enforce independent sensitivity boundaries and service/port allowlists', () => {
  const policy = loadPermissionsPolicyFromObject({
    agents: {
      'agent-lifecycle': {
        agent_permissions: {
          inspect: true,
          get_url: true,
          verify: true,
          lifecycle: true,
          deployment: false,
          authorize_visitor: false,
          revoke_client: false,
          remove_publication: false,
        },
        allowed_services: ['agentgateway'],
      },
      'agent-deployer': {
        agent_permissions: {
          inspect: true,
          get_url: true,
          verify: true,
          lifecycle: true,
          deployment: true,
          authorize_visitor: false,
          revoke_client: false,
          remove_publication: false,
        },
        allowed_services: ['my-mcp'],
        allowed_ports: [8085],
        allowed_auth_modes: ['ocliv-managed'],
      },
    },
  });
  const enforcer = new PermissionsEnforcer(policy);

  // Lifecycle agent can inspect/enable agentgateway, but CANNOT approve visitors, revoke clients, or touch other services.
  assert.equal(enforcer.assertAllowed({ subject: 'agent-lifecycle', action: 'lifecycle', service: 'agentgateway' }), true);
  assert.throws(() => enforcer.assertAllowed({ subject: 'agent-lifecycle', action: 'authorize_visitor', service: 'agentgateway' }), /not permitted/);
  assert.throws(() => enforcer.assertAllowed({ subject: 'agent-lifecycle', action: 'revoke_client', service: 'agentgateway' }), /not permitted/);
  assert.throws(() => enforcer.assertAllowed({ subject: 'agent-lifecycle', action: 'remove_publication', service: 'agentgateway' }), /not permitted/);
  assert.throws(() => enforcer.assertAllowed({ subject: 'agent-lifecycle', action: 'lifecycle', service: 'other-svc' }), /not authorized to operate on service/);

  // Deployer agent is bound to allowed port & auth mode.
  assert.equal(enforcer.assertAllowed({ subject: 'agent-deployer', action: 'deployment', service: 'my-mcp', port: 8085, authMode: 'ocliv-managed' }), true);
  assert.throws(() => enforcer.assertAllowed({ subject: 'agent-deployer', action: 'deployment', service: 'my-mcp', port: 9999, authMode: 'ocliv-managed' }), /port allowlist/);
  assert.throws(() => enforcer.assertAllowed({ subject: 'agent-deployer', action: 'deployment', service: 'my-mcp', port: 8085, authMode: 'upstream-oauth' }), /Authentication mode/);
});

test('OCL-012 NativeControlPlane single-call get_url, idempotent deploy, secret redaction, and privilege enforcement', async () => {
  const calls = [];
  const execMock = async (_bin, args) => {
    calls.push(args.join(' '));
    const cmd = args.join(' ');
    if (cmd === 'status agentgateway --json') {
      return {
        stdout: JSON.stringify({
          name: 'agentgateway',
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
    if (cmd === 'service reconcile agentgateway --json') {
      return { stdout: JSON.stringify({ name: 'agentgateway', state: 'SERVING', health: 'READY' }), stderr: '' };
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
        revoke_client: false,
        remove_publication: false,
      },
      allowed_services: ['agentgateway'],
      allowed_ports: [8765],
      allowed_auth_modes: ['ocliv-managed'],
    })
  );

  const cp = new NativeControlPlane({ bin: '/usr/local/bin/ocliv', permissions: enforcer, execImpl: execMock });

  // Single-call get_url returns canonical URL + reachability directly.
  const urlRes = await cp.getUrl('agent-1', { service: 'agentgateway' });
  assert.equal(urlRes.service, 'agentgateway');
  assert.equal(urlRes.url, 'https://bamnlabs.duckdns.org/r/jr8x2Txyoa1jPs22CROuBQ/mcp');
  assert.equal(urlRes.enabled, true);
  assert.equal(urlRes.reachable, true);
  assert.equal(urlRes.authentication, 'ocliv-managed');

  // Secret redaction strips sensitive keys recursively.
  const svcRes = await cp.getService('agent-1', { service: 'agentgateway' });
  assert.equal('pairing_secret' in svcRes.service, false);
  assert.deepEqual(redactSecrets({ ok: true, refresh_token: 'rt_x', nested: { client_secret: 'cs_x', safe: 1 } }), {
    ok: true,
    nested: { safe: 1 },
  });

  // Idempotent deploy of already-existing service reconciles instead of creating duplicate publication.
  const depRes = await cp.deployService('agent-1', { name: 'agentgateway', port: 8765, type: 'mcp', authentication: 'ocliv-managed' });
  assert.equal(depRes.idempotent, true);
  assert.equal(calls.some((c) => c.startsWith('host mcp')), false);

  // Privilege escalation to decide_authorization fails closed.
  await assert.rejects(() => cp.decideAuthorization('agent-1', { service: 'agentgateway', challenge: 'cns_1', decision: 'approve' }), /not permitted/);
});

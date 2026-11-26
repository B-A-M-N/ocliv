import { lstatSync, readFileSync } from 'node:fs';
import { Skybridge, customProvider } from 'skybridge/server';
import { z } from 'zod';
import { authorize, buildPrMetadata, safeError } from './core/ocliv.mjs';
import { loadNativeConfig, NativeOclivClient } from './core/ocliv-native.mjs';
import {
  loadPermissionsPolicyFile,
  PermissionsEnforcer,
  verifyIngressIdentity,
} from './core/permissions.mjs';
import { NativeControlPlane } from './core/control-plane.mjs';

const authMode = (
  process.env.OCLIV_AUTH_MODE ??
  (process.env.OCLIV_OAUTH_ISSUER ? 'external-oidc' : 'ocliv-managed')
).trim();

if (authMode !== 'ocliv-managed' && authMode !== 'external-oidc') {
  throw new Error(`Invalid OCLIV_AUTH_MODE "${authMode}" (want ocliv-managed|external-oidc)`);
}

const issuer = (process.env.OCLIV_OAUTH_ISSUER ?? '').trim();
const audience = (process.env.OCLIV_OAUTH_AUDIENCE ?? '').trim();
const serverUrl = (process.env.SERVER_URL ?? '').trim();
const publicResourceUrl = (process.env.OCLIV_PUBLIC_RESOURCE_URL ?? '').trim();
const writeEnabled = (process.env.OCLIV_WRITE_ENABLED ?? 'false').trim() === 'true';

if (authMode === 'external-oidc') {
  if (!issuer || !audience || !serverUrl || !publicResourceUrl || !issuer.startsWith('https://') || !serverUrl.startsWith('https://')) {
    throw new Error('OCLIV_OAUTH_ISSUER, OCLIV_OAUTH_AUDIENCE, HTTPS SERVER_URL and OCLIV_PUBLIC_RESOURCE_URL required in external-oidc mode');
  }
  if (audience !== publicResourceUrl) throw new Error('OCLIV_OAUTH_AUDIENCE must equal OCLIV_PUBLIC_RESOURCE_URL');
  const resource = new URL(publicResourceUrl);
  if (resource.protocol !== 'https:' || resource.username || resource.password || resource.search || resource.hash || !/^\/r\/[A-Za-z0-9_-]{3,64}\/mcp$/.test(resource.pathname)) {
    throw new Error('OCLIV_PUBLIC_RESOURCE_URL must be the exact HTTPS Ocliv route URL');
  }
}

function loadIngressSecret(): string {
  const inline = (process.env.OCLIV_INGRESS_SECRET ?? '').trim();
  if (inline) return inline;
  const filePath = (process.env.OCLIV_INGRESS_SECRET_FILE ?? '').trim();
  if (!filePath) return '';
  const st = lstatSync(filePath);
  if (!st.isFile() || st.isSymbolicLink() || (st.mode & 0o077) !== 0) {
    throw new Error(`OCLIV_INGRESS_SECRET_FILE must be a regular 0600 file: ${filePath}`);
  }
  return readFileSync(filePath, 'utf8').trim();
}

const readOnly = { readOnlyHint: true, openWorldHint: false, destructiveHint: false };
const mutating = { readOnlyHint: false, openWorldHint: false, destructiveHint: false };
const destructive = { readOnlyHint: false, openWorldHint: false, destructiveHint: true };

const done = (structuredContent: unknown) => ({
  content: JSON.stringify(structuredContent),
  structuredContent: structuredContent as Record<string, unknown>,
});
const failed = (e: unknown) => {
  const s = safeError(e);
  return { content: `error ${s.code}: ${s.message}`, structuredContent: s, isError: true as const };
};

const oauthConfig =
  authMode === 'external-oidc'
    ? customProvider({
        issuer,
        audience,
        baseUrl: serverUrl,
        scopes: writeEnabled ? ['ocliv:read', 'ocliv:write'] : ['ocliv:read'],
        requiredScopes: ['ocliv:read'],
      })
    : undefined;

export const app = new Skybridge({
  name: 'ocliv-mcp',
  title: 'Ocliv MCP Control Plane',
  version: '0.3.0',
  description:
    'Authenticated agent-facing control plane for Ocliv-hosted MCP and HTTP services via canonical native Ocliv operations.',
  setup: () => {
    const subjects = new Set(
      (process.env.OCLIV_ALLOWED_SUBJECTS ?? '')
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean)
    );
    if (subjects.size === 0) {
      throw new Error('OCLIV_ALLOWED_SUBJECTS required: at least one authorized agent/operator subject');
    }
    const ingressSecret = authMode === 'ocliv-managed' ? loadIngressSecret() : '';
    const expectedRoute = (process.env.OCLIV_EXPECTED_ROUTE ?? '').trim();
    if (authMode === 'ocliv-managed' && ingressSecret.length < 16) {
      throw new Error('OCLIV_INGRESS_SECRET or OCLIV_INGRESS_SECRET_FILE (>=16 chars, 0600) required in ocliv-managed mode');
    }
    if (authMode === 'ocliv-managed' && !expectedRoute) {
      throw new Error('OCLIV_EXPECTED_ROUTE required in ocliv-managed mode to bind verified ingress assertions to this route');
    }
    const permissionsFile = (process.env.OCLIV_PERMISSIONS_FILE ?? '').trim();
    if (!permissionsFile) {
      throw new Error('OCLIV_PERMISSIONS_FILE required: operator-controlled 0600 agent permissions policy');
    }
    const permissions = new PermissionsEnforcer(loadPermissionsPolicyFile(permissionsFile));

    let nativeClient: NativeOclivClient | null = null;
    if (process.env.OCLIV_RELAY_URL && process.env.OCLIV_AGENT_KEY_FILE) {
      nativeClient = new NativeOclivClient(loadNativeConfig());
    }
    const bin = (process.env.OCLIV_BIN ?? 'ocliv').trim();
    const relayUrl = (process.env.OCLIV_RELAY_URL ?? '').trim();
    const profile = (process.env.OCLIV_PROFILE ?? '').trim();
    const controlPlane = new NativeControlPlane({
      bin,
      profile,
      relayUrl,
      permissions,
      nativeClient,
    });
    return { subjects, ingressSecret, expectedRoute, controlPlane };
  },
  ...(oauthConfig ? { oauth: oauthConfig } : {}),
  handler: (server, { subjects, ingressSecret, expectedRoute, controlPlane }) => {
    const resolveSubject = (extra: any, requiredScope = 'ocliv:read'): string => {
      if (authMode === 'external-oidc') {
        return authorize(extra?.http?.authInfo, subjects, requiredScope);
      }
      const req = extra?.http?.req ?? extra?.req;
      const headers = req?.headers ?? extra?.http?.headers;
      const remoteAddress = req?.socket?.remoteAddress ?? extra?.http?.remoteAddress ?? '';
      const verified = verifyIngressIdentity({
        headers,
        method: req?.method ?? 'POST',
        path: req?.url ?? '/mcp',
        host: req?.headers?.host ?? '',
        remoteAddress,
        ingressSecret,
        allowedSubjects: subjects,
        expectedRoute,
      });
      if (requiredScope && !verified.scopes.includes(requiredScope) && !verified.scopes.includes('ocliv:write')) {
        throw new Error(`Required scope: ${requiredScope}`);
      }
      return verified.subject;
    };

    const run = async (extra: any, scope: string, fn: (subject: string) => Promise<unknown>) => {
      try {
        const subject = resolveSubject(extra, scope);
        return done(await fn(subject));
      } catch (e) {
        return failed(e);
      }
    };

    return (
      server
        // ==================== 1. Discovery & URL Retrieval ====================
        .registerTool(
          {
            name: 'get_status',
            title: 'Get Ocliv status',
            description: 'Return relay connectivity, publisher enrollment, binary version, and capabilities.',
            annotations: readOnly,
            ...(oauthConfig ? { auth: { scopes: ['ocliv:read'] } } : {}),
          },
          async (_, extra) => run(extra, 'ocliv:read', (sub) => controlPlane.getStatus(sub))
        )
        .registerTool(
          {
            name: 'list_services',
            title: 'List configured services',
            description: 'List all configured local services, including disabled and unpublished services.',
            annotations: readOnly,
            ...(oauthConfig ? { auth: { scopes: ['ocliv:read'] } } : {}),
          },
          async (_, extra) => run(extra, 'ocliv:read', (sub) => controlPlane.listServices(sub))
        )
        .registerTool(
          {
            name: 'get_service',
            title: 'Get service status',
            description: 'Retrieve complete configuration and observed multi-layer state for one service by name.',
            inputSchema: { service: z.string().min(1).max(64) },
            annotations: readOnly,
            ...(oauthConfig ? { auth: { scopes: ['ocliv:read'] } } : {}),
          },
          async (args, extra) => run(extra, 'ocliv:read', (sub) => controlPlane.getService(sub, args))
        )
        .registerTool(
          {
            name: 'get_url',
            title: 'Get canonical service URL',
            description: 'Return the persistent canonical HTTPS URL and observed reachability for a service in one call.',
            inputSchema: { service: z.string().min(1).max(64) },
            annotations: readOnly,
            ...(oauthConfig ? { auth: { scopes: ['ocliv:read'] } } : {}),
          },
          async (args, extra) => run(extra, 'ocliv:read', (sub) => controlPlane.getUrl(sub, args))
        )

        // ==================== 2. Deployment & Lifecycle ====================
        .registerTool(
          {
            name: 'deploy_service',
            title: 'Deploy a local service',
            description: 'Idempotently create or attach a protected publication for an operator-permitted local service.',
            inputSchema: {
              name: z.string().min(1).max(64),
              port: z.number().int().min(1).max(65535),
              path: z.string().min(1).max(128).optional(),
              type: z.enum(['mcp', 'http']).optional(),
              authentication: z.enum(['ocliv-managed', 'upstream-oauth']).optional(),
              persistent: z.boolean().optional(),
            },
            annotations: mutating,
            ...(oauthConfig ? { auth: { scopes: ['ocliv:write'] } } : {}),
          },
          async (args, extra) => run(extra, 'ocliv:write', (sub) => controlPlane.deployService(sub, args))
        )
        .registerTool(
          {
            name: 'enable_service',
            title: 'Enable service',
            description: 'Activate or resume an existing publication without changing its canonical URL or grants.',
            inputSchema: { service: z.string().min(1).max(64) },
            annotations: mutating,
            ...(oauthConfig ? { auth: { scopes: ['ocliv:write'] } } : {}),
          },
          async (args, extra) => run(extra, 'ocliv:write', (sub) => controlPlane.enableService(sub, args))
        )
        .registerTool(
          {
            name: 'disable_service',
            title: 'Disable service',
            description: 'Disable public exposure for a service while preserving its canonical URL and OAuth grants.',
            inputSchema: { service: z.string().min(1).max(64) },
            annotations: mutating,
            ...(oauthConfig ? { auth: { scopes: ['ocliv:write'] } } : {}),
          },
          async (args, extra) => run(extra, 'ocliv:write', (sub) => controlPlane.disableService(sub, args))
        )
        .registerTool(
          {
            name: 'restart_service',
            title: 'Restart service',
            description: 'Recover or rebind the publisher tunnel without destroying service identity or URL.',
            inputSchema: { service: z.string().min(1).max(64) },
            annotations: mutating,
            ...(oauthConfig ? { auth: { scopes: ['ocliv:write'] } } : {}),
          },
          async (args, extra) => run(extra, 'ocliv:write', (sub) => controlPlane.restartService(sub, args))
        )
        .registerTool(
          {
            name: 'reconcile_service',
            title: 'Reconcile service',
            description: 'Atomically repair stale publication bindings and resolve configuration drift.',
            inputSchema: { service: z.string().min(1).max(64) },
            annotations: mutating,
            ...(oauthConfig ? { auth: { scopes: ['ocliv:write'] } } : {}),
          },
          async (args, extra) => run(extra, 'ocliv:write', (sub) => controlPlane.reconcileService(sub, args))
        )
        .registerTool(
          {
            name: 'remove_service',
            title: 'Remove service',
            description: 'Permanently retire a hosted service and its publication.',
            inputSchema: { service: z.string().min(1).max(64) },
            annotations: destructive,
            ...(oauthConfig ? { auth: { scopes: ['ocliv:write'] } } : {}),
          },
          async (args, extra) => run(extra, 'ocliv:write', (sub) => controlPlane.removeService(sub, args))
        )

        // ==================== 3. Authentication & Access ====================
        .registerTool(
          {
            name: 'get_auth_status',
            title: 'Get authentication status',
            description: 'Inspect authentication mode, authorization enforcement, trust policies, and pending requests.',
            inputSchema: { service: z.string().min(1).max(64) },
            annotations: readOnly,
            ...(oauthConfig ? { auth: { scopes: ['ocliv:read'] } } : {}),
          },
          async (args, extra) => run(extra, 'ocliv:read', (sub) => controlPlane.getAuthStatus(sub, args))
        )
        .registerTool(
          {
            name: 'list_pending_authorizations',
            title: 'List pending authorizations',
            description: 'Retrieve pending native OAuth authorization transactions for a service.',
            inputSchema: { service: z.string().min(1).max(64) },
            annotations: readOnly,
            ...(oauthConfig ? { auth: { scopes: ['ocliv:read'] } } : {}),
          },
          async (args, extra) => run(extra, 'ocliv:read', (sub) => controlPlane.listPendingAuthorizations(sub, args))
        )
        .registerTool(
          {
            name: 'decide_authorization',
            title: 'Approve or deny authorization transaction',
            description: 'Approve or deny one exact pending OAuth transaction by challenge ID (requires independent authorize_visitor permission).',
            inputSchema: {
              service: z.string().min(1).max(64),
              challenge: z.string().min(3).max(128),
              decision: z.enum(['approve', 'deny']),
            },
            annotations: mutating,
            ...(oauthConfig ? { auth: { scopes: ['ocliv:write'] } } : {}),
          },
          async (args, extra) => run(extra, 'ocliv:write', (sub) => controlPlane.decideAuthorization(sub, args))
        )
        .registerTool(
          {
            name: 'list_authorized_clients',
            title: 'List authorized clients',
            description: 'Inspect route-scoped trust policies and provider client bindings for a service.',
            inputSchema: { service: z.string().min(1).max(64) },
            annotations: readOnly,
            ...(oauthConfig ? { auth: { scopes: ['ocliv:read'] } } : {}),
          },
          async (args, extra) => run(extra, 'ocliv:read', (sub) => controlPlane.listAuthorizedClients(sub, args))
        )
        .registerTool(
          {
            name: 'revoke_client',
            title: 'Revoke client access',
            description: 'Immediately revoke OAuth access for one specific client ID on a service.',
            inputSchema: {
              service: z.string().min(1).max(64),
              clientId: z.string().min(3).max(128),
            },
            annotations: destructive,
            ...(oauthConfig ? { auth: { scopes: ['ocliv:write'] } } : {}),
          },
          async (args, extra) => run(extra, 'ocliv:write', (sub) => controlPlane.revokeClient(sub, args))
        )
        .registerTool(
          {
            name: 'get_auth_policy',
            title: 'Get authorization policy',
            description: 'Inspect the service route trust policies and visitor authentication mode.',
            inputSchema: { service: z.string().min(1).max(64) },
            annotations: readOnly,
            ...(oauthConfig ? { auth: { scopes: ['ocliv:read'] } } : {}),
          },
          async (args, extra) => run(extra, 'ocliv:read', (sub) => controlPlane.getAuthPolicy(sub, args))
        )
        .registerTool(
          {
            name: 'set_auth_policy',
            title: 'Set authorization policy',
            description: 'Add a route-scoped OAuth trust preset (e.g. chatgpt) or exact HTTPS redirect URI.',
            inputSchema: {
              service: z.string().min(1).max(64),
              preset: z.enum(['chatgpt']).optional(),
              redirectUri: z.string().url().optional(),
            },
            annotations: mutating,
            ...(oauthConfig ? { auth: { scopes: ['ocliv:write'] } } : {}),
          },
          async (args, extra) => run(extra, 'ocliv:write', (sub) => controlPlane.setAuthPolicy(sub, args))
        )

        // ==================== 4. Diagnostics & Verification ====================
        .registerTool(
          {
            name: 'verify_service',
            title: 'Verify service endpoint',
            description: 'Run canonical native transport, OAuth discovery, and MCP verification checks.',
            inputSchema: { service: z.string().min(1).max(64) },
            annotations: { ...readOnly, openWorldHint: true },
            ...(oauthConfig ? { auth: { scopes: ['ocliv:read'] } } : {}),
          },
          async (args, extra) => run(extra, 'ocliv:read', (sub) => controlPlane.verifyService(sub, args))
        )
        .registerTool(
          {
            name: 'diagnose_service',
            title: 'Diagnose service',
            description: 'Identify the exact failing operational layer using native status and doctor diagnostics.',
            inputSchema: { service: z.string().min(1).max(64) },
            annotations: readOnly,
            ...(oauthConfig ? { auth: { scopes: ['ocliv:read'] } } : {}),
          },
          async (args, extra) => run(extra, 'ocliv:read', (sub) => controlPlane.diagnoseService(sub, args))
        )
        .registerTool(
          {
            name: 'verify_events',
            title: 'Verify MCP Events capability',
            description: 'Verify MCP Events discovery and subscription capability using the native verifier.',
            inputSchema: { service: z.string().min(1).max(64) },
            annotations: { ...readOnly, openWorldHint: true },
            ...(oauthConfig ? { auth: { scopes: ['ocliv:read'] } } : {}),
          },
          async (args, extra) => run(extra, 'ocliv:read', (sub) => controlPlane.verifyEvents(sub, args))
        )
    );
  },
});

if (authMode === 'external-oidc') {
  app.use('/.well-known/oauth-protected-resource/mcp', (_req: unknown, res: { json: (body: unknown) => void }) => {
    res.json(
      buildPrMetadata({
        resource: publicResourceUrl,
        issuer,
        scopes: writeEnabled ? ['ocliv:read', 'ocliv:write'] : ['ocliv:read'],
      })
    );
  });
}

export type AppType = typeof app;

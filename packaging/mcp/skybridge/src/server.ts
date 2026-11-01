import 'dotenv/config';
import { Skybridge, customProvider } from 'skybridge/server';
import { z } from 'zod';
import { OclivClient, parseAllowlist } from './ocliv.js';

function required(name: string): string {
  const v = process.env[name];
  if (!v) throw new Error(`Missing ${name}: the Ocliv management app fails closed`);
  return v;
}

const issuer = required('OCLIV_OAUTH_ISSUER');
const audience = required('OCLIV_OAUTH_AUDIENCE');
const subject = required('OCLIV_ADMIN_SUBJECT');
if (!issuer.startsWith('https://') || !audience.startsWith('https://')) {
  throw new Error('OAuth issuer and audience must use HTTPS');
}

const client = new OclivClient({
  bin: required('OCLIV_BIN'),
  home: process.env.OCLIV_HOME,
  origin: process.env.OCLIV_MCP_ORIGIN,
  services: parseAllowlist(process.env.OCLIV_SERVICES_JSON ?? '[]'),
});

// The OAuth provider verifies JWT issuer, audience, expiry, signature, and scope.
// The subject check additionally restricts all operations to the named operator.
const denyUnlessOperator = (extra: { http?: { authInfo?: { extra?: { subject?: string } } } }) => {
  if (extra.http?.authInfo?.extra?.subject !== subject) {
    throw new Error('Operator identity is not authorized');
  }
};

export const app = new Skybridge({
  name: 'ocliv-hosting',
  version: '0.1.0',
  description: 'Manage allowlisted Ocliv MCP publications and independently verify their state.',
  oauth: customProvider<{ subject?: string }>({
    issuer, audience, baseUrl: audience,
    scopes: ['openid', 'ocliv.manage'], requiredScopes: ['ocliv.manage'],
  }),
  handler: (server) => server
    .registerTool({
      name: 'list-publications',
      title: 'List Ocliv publications',
      description: 'Show publications belonging to the enrolled Ocliv operator and their relay states. State is not a health verdict.',
      inputSchema: {},
      annotations: { readOnlyHint: true, openWorldHint: false },
      view: { component: 'manage-publications' },
    }, async (_input, extra) => {
      denyUnlessOperator(extra);
      const publications = await client.list();
      return { structuredContent: { publications }, content: `Found ${publications.length} publications; state is not an external health check.` };
    })
    .registerTool({
      name: 'verify-publication',
      title: 'Verify Ocliv publication locally',
      description: 'Run Ocliv doctor for a named publication, while distinguishing local protocol verification from external client and OAuth qualification.',
      inputSchema: { name: z.string().min(1).max(48) },
      annotations: { readOnlyHint: true, openWorldHint: false },
    }, async ({ name }, extra) => {
      denyUnlessOperator(extra);
      const result = await client.verify(name);
      return { structuredContent: result };
    })
    .registerTool({
      name: 'publish-service',
      title: 'Publish allowlisted local MCP service',
      description: 'Publish only an operator-allowlisted loopback MCP service. Must receive exact confirmation string PUBLISH <service name> after the human authorizes external exposure.',
      inputSchema: { name: z.string(), confirmation: z.string() },
      annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: true },
    }, async ({ name, confirmation }, extra) => {
      denyUnlessOperator(extra);
      const result = await client.publish(name, confirmation);
      return { structuredContent: result };
    })
    .registerTool({
      name: 'revoke-publication',
      title: 'Permanently revoke Ocliv publication',
      description: 'Permanently revoke an exact publication ID belonging to the enrolled operator. Must receive REVOKE <publication ID> as confirmation after the human approves.',
      inputSchema: { publicationId: z.string(), confirmation: z.string() },
      annotations: { readOnlyHint: false, destructiveHint: true, openWorldHint: true },
    }, async ({ publicationId, confirmation }, extra) => {
      denyUnlessOperator(extra);
      const result = await client.revoke(publicationId, confirmation);
      return { structuredContent: result };
    }),
});

export type AppType = typeof app;

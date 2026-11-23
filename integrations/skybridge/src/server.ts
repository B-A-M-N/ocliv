import { Skybridge, customProvider } from 'skybridge/server';
import { z } from 'zod';
import { authorize, buildPrMetadata, safeError } from './core/ocliv.mjs';
import { loadNativeConfig, NativeOclivClient } from './core/ocliv-native.mjs';
import { loadPublisherConfig, PublisherController, PublisherError } from './core/publisher.mjs';
import { Approvals } from './core/approvals.mjs';
import { startOperatorApprovalSocket } from './core/operator-approvals.mjs';

const issuer = process.env.OCLIV_OAUTH_ISSUER;
const audience = process.env.OCLIV_OAUTH_AUDIENCE;
const serverUrl = process.env.SERVER_URL;
const publicResourceUrl = process.env.OCLIV_PUBLIC_RESOURCE_URL;
// Least privilege: the write scope is advertised only when write
// operations are actually enabled. Discovery otherwise offers read-only.
const writeEnabled = (process.env.OCLIV_WRITE_ENABLED ?? 'false').trim() === 'true';
// Never start a remotely accessible management MCP server without an IdP and explicit token audience.
if (!issuer || !audience || !serverUrl || !publicResourceUrl || !issuer.startsWith('https://') || !serverUrl.startsWith('https://')) {
  throw new Error('OCLIV_OAUTH_ISSUER, OCLIV_OAUTH_AUDIENCE, HTTPS SERVER_URL and OCLIV_PUBLIC_RESOURCE_URL required');
}
if (audience !== publicResourceUrl) throw new Error('OCLIV_OAUTH_AUDIENCE must equal OCLIV_PUBLIC_RESOURCE_URL');
const resource = new URL(publicResourceUrl);
if (resource.protocol !== 'https:' || resource.username || resource.password || resource.search || resource.hash || !/^\/r\/[A-Za-z0-9_-]{3,64}\/mcp$/.test(resource.pathname)) {
  throw new Error('OCLIV_PUBLIC_RESOURCE_URL must be the exact HTTPS Ocliv route URL');
}
// Publisher-side identity for Ocliv signed management. The agent key
// never leaves this host; remote callers authenticate via the Skybridge
// OAuth provider above and are additionally subject-gated per tool.
const nativeConfig = loadNativeConfig();
const readOnly = { readOnlyHint:true, openWorldHint:false, destructiveHint:false };

// Handlers must return { content, structuredContent }: content is the
// human-readable verdict, structuredContent the typed result.
const done = (structuredContent: unknown) => ({
  content: JSON.stringify(structuredContent),
  structuredContent: structuredContent as Record<string, unknown>,
});
const failed = (e: unknown) => {
  const s = safeError(e);
  return { content: `error ${s.code}: ${s.message}`, structuredContent: s, isError: true as const };
};

export const app = new Skybridge({
  name:'ocliv-mcp', title:'Ocliv MCP Hosting', version:'0.2.0',
  description:'Authenticated management and verification of Ocliv-hosted MCP endpoints via the Ocliv-native signed management protocol.',
  setup:() => {
    const subjects = new Set(
      (process.env.OCLIV_ALLOWED_SUBJECTS ?? '').split(',').map((s) => s.trim()).filter(Boolean));
    if (subjects.size === 0) throw new Error('OCLIV_ALLOWED_SUBJECTS required: at least one operator subject');
    const verifyToken = (process.env.OCLIV_VERIFY_TOKEN ?? '').trim() || null;
    // Write tools require an owner-only local approval socket. Decisions
    // never pass through model-visible tool arguments.
    const client = new NativeOclivClient(nativeConfig);
    let publisher: PublisherController | null = null;
    const approvals = new Approvals();
    let approvalServer = null;
    if (writeEnabled) {
      publisher = new PublisherController(loadPublisherConfig(), {
        inventoryClient: client,
        relayOrigin: nativeConfig.relay,
        ownerKeyId: nativeConfig.keyID,
      });
      const socketPath = (process.env.OCLIV_APPROVAL_SOCKET ?? '').trim();
      if (!socketPath) throw new Error('OCLIV_APPROVAL_SOCKET required when OCLIV_WRITE_ENABLED=true');
      approvalServer = startOperatorApprovalSocket(approvals, socketPath);
    }
    return { subjects, verifyToken, client, publisher, approvals, approvalServer };
  },
  oauth: customProvider({issuer, audience, baseUrl:serverUrl, scopes: writeEnabled ? ['ocliv:read','ocliv:write'] : ['ocliv:read'], requiredScopes:['ocliv:read']}),
  handler:(server, {subjects, verifyToken, client, publisher, approvals}) => server
    .registerTool({
      name:'request-approval', title:'Request a write approval',
      description:'Request operator review for a publish, stop, or unpublish action. The request remains AWAITING_OPERATOR until approved through the owner-only local operator socket. MCP callers cannot approve requests.',
      inputSchema:{action:z.enum(['publish','stop','unpublish']),target:z.string().min(1).max(64)},
      annotations:{readOnlyHint:false,openWorldHint:false,destructiveHint:false}, auth:{scopes:['ocliv:write']}
    }, async ({action,target},extra)=>{
      try {
        const subject = authorize(extra.http?.authInfo,subjects,'ocliv:write');
        const request = approvals.request({subject,action,target});
        return done({ok:true,...request});
      }
      catch(e) {return failed(e);}
    })
    .registerTool({
      name:'get-ocliv-status', title:'Get Ocliv status',
      description:'Read actual Ocliv relay reachability and durable publication states; never guesses tunnel liveness.',
      annotations:readOnly, auth:{scopes:['ocliv:read']}
    }, async (_, extra)=>{
      try { authorize(extra.http?.authInfo,subjects); return done({ok:true,...await client.status()}); }
      catch(e) {return failed(e);}
    })
    .registerTool({
      name:'list-publications', title:'List Ocliv publications',
      description:'List real Ocliv-published MCP endpoints owned by this publisher key, with durable publication state, relay-observed lease/session reachability (active does not mean reachable), and a verification view.',
      annotations:readOnly, auth:{scopes:['ocliv:read']},
      view:{component:'list-publications',description:'Published Ocliv MCP endpoints'}
    }, async (_,extra)=>{
      try { authorize(extra.http?.authInfo,subjects); return done({ok:true,publications:await client.list()}); }
      catch(e) {return failed(e);}
    })
    .registerTool({
      name:'get-publication', title:'Get one Ocliv publication',
      description:'Identify a single owned publication by exact route ID.',
      inputSchema:{publicationId:z.string().min(3).max(64)},
      annotations:readOnly, auth:{scopes:['ocliv:read']}
    }, async ({publicationId},extra)=>{
      try { authorize(extra.http?.authInfo,subjects); return done({ok:true,publication:await client.get(publicationId)}); }
      catch(e) {return failed(e);}
    })
    .registerTool({
      name:'verify-publication', title:'Verify published MCP endpoint',
      description:'Verify a published endpoint with the real OAuth discovery + registration handshake and, when a server-side token is provisioned, an authenticated initialize/tools/list. Without a token reports OAUTH_REQUIRED, never verified.',
      inputSchema:{publicationId:z.string().min(3).max(64)},
      annotations:{...readOnly,openWorldHint:true}, auth:{scopes:['ocliv:read']}
    }, async ({publicationId},extra)=>{
      try { authorize(extra.http?.authInfo,subjects); return done({ok:true,...await client.verifyPublication(publicationId,{verifyToken:verifyToken ?? undefined})}); }
      catch(e) {return failed(e);}
    })
    .registerTool({
      name:'publish-service', title:'Publish an allowlisted local service',
      description:'Start (or reattach to) the supervised publisher for an allowlisted local service. Requires a locally operator-approved request ID, ocliv:write, and OCLIV_WRITE_ENABLED=true. Only allowlisted loopback targets.',
      inputSchema:{serviceName:z.string().min(1).max(48),approvalId:z.string().min(1).max(128)},
      annotations:{readOnlyHint:false,openWorldHint:false,destructiveHint:false}, auth:{scopes:['ocliv:write']}
    }, async ({serviceName,approvalId},extra)=>{
      try {
        const subject = authorize(extra.http?.authInfo,subjects,'ocliv:write');
        if (!publisher) return done({ok:false,code:'WRITE_DISABLED',message:'Publishing is disabled (OCLIV_WRITE_ENABLED is not true)'});
        approvals.redeem({subject,action:'publish',target:serviceName,approvalId});
        return done({ok:true,...await publisher.publish(serviceName,`PUBLISH ${serviceName}`)});
      }
      catch(e) {return failed(e);}
    })
    .registerTool({
      name:'resume-service', title:'Resume a retained publication',
      description:'Restart or reattach the publisher for an operator-allowlisted service, preserving its stable route identity. Requires a locally operator-approved request ID, ocliv:write, and OCLIV_WRITE_ENABLED=true.',
      inputSchema:{serviceName:z.string().min(1).max(48),approvalId:z.string().min(1).max(128)},
      annotations:{readOnlyHint:false,openWorldHint:false,destructiveHint:false}, auth:{scopes:['ocliv:write']}
    }, async ({serviceName,approvalId},extra)=>{
      try {
        const subject = authorize(extra.http?.authInfo,subjects,'ocliv:write');
        if (!publisher) return done({ok:false,code:'WRITE_DISABLED',message:'Publisher control is disabled (OCLIV_WRITE_ENABLED is not true)'});
        approvals.redeem({subject,action:'publish',target:serviceName,approvalId});
        return done({ok:true,...await publisher.publish(serviceName,`PUBLISH ${serviceName}`)});
      }
      catch(e) {return failed(e);}
    })
    .registerTool({
      name:'unpublish-service', title:'Unpublish one publication',
      description:'Stop the supervised local publisher (if it owns the route) and revoke exactly one publication via the signed native adapter. Requires a locally operator-approved request ID, ocliv:write, and OCLIV_WRITE_ENABLED=true.',
      inputSchema:{publicationId:z.string().min(3).max(64),approvalId:z.string().min(1).max(128)},
      annotations:{readOnlyHint:false,openWorldHint:false,destructiveHint:true}, auth:{scopes:['ocliv:write']}
    }, async ({publicationId,approvalId},extra)=>{
      try {
        const subject = authorize(extra.http?.authInfo,subjects,'ocliv:write');
        if (!publisher) return done({ok:false,code:'WRITE_DISABLED',message:'Unpublishing is disabled (OCLIV_WRITE_ENABLED is not true)'});
        approvals.redeem({subject,action:'unpublish',target:publicationId,approvalId});
        const result = await publisher.unpublish(publicationId,publicationId,{revoker:(id)=>client.unpublish(id)});
        return done({ok:result.revoked==='REVOKED',...result});
      }
      catch(e) {return failed(e);}
    })
    .registerTool({
      name:'stop-service', title:'Stop a publisher and retain its route',
      description:'Gracefully stop the supervised publisher for one allowlisted service. Its stable route identity is retained offline and can be resumed with publish-service. Requires a locally operator-approved request ID, ocliv:write, and OCLIV_WRITE_ENABLED=true.',
      inputSchema:{serviceName:z.string().min(1).max(48),approvalId:z.string().min(1).max(128)},
      annotations:{readOnlyHint:false,openWorldHint:false,destructiveHint:false}, auth:{scopes:['ocliv:write']}
    }, async ({serviceName,approvalId},extra)=>{
      try {
        const subject = authorize(extra.http?.authInfo,subjects,'ocliv:write');
        if (!publisher) return done({ok:false,code:'WRITE_DISABLED',message:'Publisher control is disabled (OCLIV_WRITE_ENABLED is not true)'});
        approvals.redeem({subject,action:'stop',target:serviceName,approvalId});
        const res = await publisher.stop(serviceName,`STOP ${serviceName}`);
        return done({ok:res.stopped === true,...res});
      }
      catch(e) {return failed(e);}
    })
});
// Server-root protected-resource metadata in the exact form the Ocliv relay
// forwards route discovery to (upstream
// `/.well-known/oauth-protected-resource/mcp`). Without this, the relay's
// strict discovery probe 404s and publication can never verify.
app.use('/.well-known/oauth-protected-resource/mcp', (_req: unknown, res: { json: (body: unknown) => void }) => {
  res.json(buildPrMetadata({resource: publicResourceUrl as string, issuer: issuer as string, scopes: writeEnabled ? ['ocliv:read','ocliv:write'] : ['ocliv:read']}));
});
export type AppType = typeof app;

import { Skybridge, customProvider } from 'skybridge/server';
import { z } from 'zod';
import { authorize, buildPrMetadata, safeError } from './core/ocliv.mjs';
import { loadNativeConfig, NativeOclivClient } from './core/ocliv-native.mjs';
import { loadPublisherConfig, PublisherController, PublisherError } from './core/publisher.mjs';
import { Approvals } from './core/approvals.mjs';

const issuer = process.env.OCLIV_OAUTH_ISSUER;
const audience = process.env.OCLIV_OAUTH_AUDIENCE;
const serverUrl = process.env.SERVER_URL;
// Never start a remotely accessible management MCP server without an IdP and explicit token audience.
if (!issuer || !audience || !serverUrl || !issuer.startsWith('https://') || !serverUrl.startsWith('https://')) {
  throw new Error('OCLIV_OAUTH_ISSUER, OCLIV_OAUTH_AUDIENCE and HTTPS SERVER_URL required');
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
    // Write tools stay fully disabled unless the operator explicitly opts
    // in AND the publisher-side controller config validates. Default off.
    const writeEnabled = (process.env.OCLIV_WRITE_ENABLED ?? 'false').trim() === 'true';
    // Approval codes are never returned in tool results and never logged
    // by default. Display on the server console requires explicit opt-in
    // on a console only the operator can read; otherwise only metadata
    // is logged and writes cannot be completed. Default off.
    const approvalConsole = (process.env.OCLIV_APPROVAL_CONSOLE ?? 'false').trim() === 'true';
    let publisher: PublisherController | null = null;
    if (writeEnabled) publisher = new PublisherController(loadPublisherConfig());
    return { subjects, verifyToken, client:new NativeOclivClient(nativeConfig), publisher, approvals:new Approvals(), approvalConsole };
  },
  oauth: customProvider({issuer, audience, baseUrl:serverUrl, scopes:['ocliv:read','ocliv:write'], requiredScopes:['ocliv:read']}),
  handler:(server, {subjects, verifyToken, client, publisher, approvals, approvalConsole}) => server
    .registerTool({
      name:'request-approval', title:'Request a write approval',
      description:'Propose a publish/unpublish for human approval. Returns an approval ID only — the single-use code is never in this tool result and never in general logs. The human provides the code back for exactly that action through an operator-private channel. A model that only sees tool results cannot complete its own approval. Until that channel is provisioned, keep writes disabled.',
      inputSchema:{action:z.enum(['publish','unpublish']),target:z.string().min(1).max(64)},
      annotations:{readOnlyHint:false,openWorldHint:false,destructiveHint:false}, auth:{scopes:['ocliv:write']}
    }, async ({action,target},extra)=>{
      try {
        const subject = authorize(extra.http?.authInfo,subjects,'ocliv:write');
        const grant = approvals.request({subject,action,target});
        console.error(approvals.grantNotice(grant, { revealCode: approvalConsole }));
        return done({ok:true,...approvals.publicReceipt(grant), codeChannel: approvalConsole ? 'operator-console' : 'withheld'});
      }
      catch(e) {return failed(e);}
    })
    .registerTool({
      name:'list-approvals', title:'List pending approvals',
      description:'List pending write approvals (metadata only, never codes) for operator hygiene.',
      annotations:readOnly, auth:{scopes:['ocliv:read']}
    }, async (_,extra)=>{
      try { authorize(extra.http?.authInfo,subjects); return done({ok:true,pending:approvals.list()}); }
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
      description:'List real Ocliv-published MCP endpoints owned by this publisher key, with durable publication state and a verification view.',
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
      description:'Start (or reattach to) the supervised local publisher for an operator-allowlisted service. Requires a single-use human approval (approvalId from request-approval plus the code from the operator-private channel) bound to this exact service, the ocliv:write scope, and OCLIV_WRITE_ENABLED=true. Only allowlisted loopback targets; no arbitrary commands, paths, or URLs.',
      inputSchema:{serviceName:z.string().min(1).max(48),approvalId:z.string().min(1).max(128),approvalCode:z.string().min(1).max(128)},
      annotations:{readOnlyHint:false,openWorldHint:false,destructiveHint:false}, auth:{scopes:['ocliv:write']}
    }, async ({serviceName,approvalId,approvalCode},extra)=>{
      try {
        const subject = authorize(extra.http?.authInfo,subjects,'ocliv:write');
        if (!publisher) return done({ok:false,code:'WRITE_DISABLED',message:'Publishing is disabled (OCLIV_WRITE_ENABLED is not true)'});
        approvals.redeem({subject,action:'publish',target:serviceName,approvalId,code:approvalCode});
        return done({ok:true,...await publisher.publish(serviceName,`PUBLISH ${serviceName}`)});
      }
      catch(e) {return failed(e);}
    })
    .registerTool({
      name:'unpublish-service', title:'Unpublish one publication',
      description:'Stop the supervised local publisher (if it owns the route) and revoke exactly one publication via the signed native adapter. Requires a single-use human approval (approvalId from request-approval plus the code from the operator-private channel) bound to this exact publication ID. Requires ocliv:write and OCLIV_WRITE_ENABLED=true.',
      inputSchema:{publicationId:z.string().min(3).max(64),approvalId:z.string().min(1).max(128),approvalCode:z.string().min(1).max(128)},
      annotations:{readOnlyHint:false,openWorldHint:false,destructiveHint:true}, auth:{scopes:['ocliv:write']}
    }, async ({publicationId,approvalId,approvalCode},extra)=>{
      try {
        const subject = authorize(extra.http?.authInfo,subjects,'ocliv:write');
        if (!publisher) return done({ok:false,code:'WRITE_DISABLED',message:'Unpublishing is disabled (OCLIV_WRITE_ENABLED is not true)'});
        approvals.redeem({subject,action:'unpublish',target:publicationId,approvalId,code:approvalCode});
        return done({ok:true,...await publisher.unpublish(publicationId,publicationId,{revoker:(id)=>client.unpublish(id)})});
      }
      catch(e) {return failed(e);}
    })
});
// Server-root protected-resource metadata in the exact form the Ocliv relay
// forwards route discovery to (upstream
// `/.well-known/oauth-protected-resource/mcp`). Without this, the relay's
// strict discovery probe 404s and publication can never verify.
app.use('/.well-known/oauth-protected-resource/mcp', (_req, res) => {
  res.json(buildPrMetadata({resource: serverUrl as string, issuer: issuer as string, scopes:['ocliv:read','ocliv:write']}));
});
export type AppType = typeof app;

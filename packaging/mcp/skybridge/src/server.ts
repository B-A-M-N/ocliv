import { Skybridge, customProvider } from 'skybridge/server';
import { z } from 'zod';
import { authorize, safeError } from './core/ocliv.mjs';
import { loadNativeConfig, NativeOclivClient } from './core/ocliv-native.mjs';

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
  return { content: `error ${s.code}: ${s.message}`, structuredContent: s };
};

export const app = new Skybridge({
  name:'ocliv-mcp', title:'Ocliv MCP Hosting', version:'0.2.0',
  description:'Authenticated management and verification of Ocliv-hosted MCP endpoints via the Ocliv-native signed management protocol.',
  setup:() => {
    const subjects = new Set(
      (process.env.OCLIV_ALLOWED_SUBJECTS ?? '').split(',').map((s) => s.trim()).filter(Boolean));
    if (subjects.size === 0) throw new Error('OCLIV_ALLOWED_SUBJECTS required: at least one operator subject');
    const verifyToken = (process.env.OCLIV_VERIFY_TOKEN ?? '').trim() || null;
    return { subjects, verifyToken, client:new NativeOclivClient(nativeConfig) };
  },
  oauth: customProvider({issuer, audience, baseUrl:serverUrl, scopes:['ocliv:read','ocliv:write'], requiredScopes:['ocliv:read']}),
  handler:(server, {subjects, verifyToken, client}) => server
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
});
export type AppType = typeof app;

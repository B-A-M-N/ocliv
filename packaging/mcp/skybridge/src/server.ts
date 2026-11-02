import { Skybridge, customProvider } from 'skybridge/server';
import { z } from 'zod';
import { loadConfig, authorize, OclivClient, safeError } from './core/ocliv.mjs';

const issuer = process.env.OCLIV_OAUTH_ISSUER;
const audience = process.env.OCLIV_OAUTH_AUDIENCE;
const serverUrl = process.env.SERVER_URL;
// Never start a remotely accessible management MCP server without an IdP and explicit token audience.
if (!issuer || !audience || !serverUrl || !issuer.startsWith('https://') || !serverUrl.startsWith('https://')) {
  throw new Error('OCLIV_OAUTH_ISSUER, OCLIV_OAUTH_AUDIENCE and HTTPS SERVER_URL required');
}
const readOnly = { readOnlyHint:true, openWorldHint:false, destructiveHint:false };
const publishHints = { readOnlyHint:false, openWorldHint:true, destructiveHint:false };
const unpublishHints = { readOnlyHint:false, openWorldHint:true, destructiveHint:true };

export const app = new Skybridge({
  name:'ocliv-mcp', title:'Ocliv MCP Hosting', version:'0.1.0',
  description:'Authenticated management and verification of Ocliv-hosted MCP endpoints.',
  setup:() => { const config = loadConfig(); return {config, client:new OclivClient(config)}; },
  oauth: customProvider({issuer, audience, baseUrl:serverUrl, scopes:['ocliv:read','ocliv:write'], requiredScopes:['ocliv:read']}),
  handler:(server, {config, client}) => server
    .registerTool({
      name:'get-ocliv-status', title:'Get Ocliv status',
      description:'Read actual Ocliv management health; never guess whether a tunnel is operational.',
      annotations:readOnly, auth:{scopes:['ocliv:read']}
    }, async (_, extra)=>{
      try { authorize(extra.http?.authInfo,config.subjects); return {structuredContent:{ok:true,...await client.status()}}; }
      catch(e) {return {isError:true,structuredContent:safeError(e)};}
    })
    .registerTool({
      name:'list-publications', title:'List Ocliv publications',
      description:'List real Ocliv-published MCP endpoints with their current status and a verification view.',
      annotations:readOnly, auth:{scopes:['ocliv:read']},
      view:{component:'list-publications',description:'Published Ocliv MCP endpoints'}
    }, async (_,extra)=>{
      try { authorize(extra.http?.authInfo,config.subjects); return {structuredContent:{ok:true,...await client.list()}}; }
      catch(e) {return {isError:true,structuredContent:safeError(e)};}
    })
    .registerTool({
      name:'publish-mcp', title:'Publish an MCP service with Ocliv',
      description:'Publish a previously enrolled Ocliv service ID as an AUTHENTICATED MCP endpoint only. Must obtain explicit operator approval and confirm=PUBLISH. Does not register arbitrary URLs or create infrastructure.',
      inputSchema:{serviceId:z.string().min(1).max(128),label:z.string().max(120).optional(),confirm:z.literal('PUBLISH')},
      annotations:publishHints, auth:{scopes:['ocliv:write']}
    }, async (input,extra)=>{
      try { authorize(extra.http?.authInfo,config.subjects,'ocliv:write'); return {structuredContent:{ok:true,...await client.publish(input)}}; }
      catch(e) {return {isError:true,structuredContent:safeError(e)};}
    })
    .registerTool({
      name:'unpublish-mcp', title:'Unpublish an Ocliv MCP endpoint',
      description:'Destructive operation. Ask operator to confirm exact publication ID and supply matching confirmPublicationId; no automatic unpublishing.',
      inputSchema:{publicationId:z.string().min(1).max(128),confirmPublicationId:z.string().min(1).max(128)},
      annotations:unpublishHints, auth:{scopes:['ocliv:write']}
    }, async(input,extra)=>{
      try {authorize(extra.http?.authInfo,config.subjects,'ocliv:write'); return {structuredContent:{ok:true,...await client.unpublish(input)}};}
      catch(e){return {isError:true,structuredContent:safeError(e)};}
    })
    .registerTool({
      name:'verify-publication', title:'Verify published MCP endpoint',
      description:'Perform actual initialize and tools/list MCP protocol requests against a published Ocliv endpoint restricted to explicitly allowed public hostnames.',
      inputSchema:{publicationId:z.string().min(1).max(128)},
      annotations:{...readOnly,openWorldHint:true}, auth:{scopes:['ocliv:read']}
    }, async({publicationId},extra)=>{
      try {authorize(extra.http?.authInfo,config.subjects); return {structuredContent:{ok:true,...await client.verify(publicationId)}};}
      catch(e){return {isError:true,structuredContent:safeError(e)};}
    })
});
export type AppType = typeof app;

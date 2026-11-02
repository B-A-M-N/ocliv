import test from 'node:test';
import assert from 'node:assert/strict';
import { loadConfig, authorize, validId, OclivClient, parsePublicUrl, safeError } from '../src/core/ocliv.mjs';

const env = {
  OCLIV_CONTROL_URL:'https://control.ocliv.example', OCLIV_CONTROL_TOKEN:'TOP_SECRET_CONTROL_TOKEN',
  OCLIV_STATUS_PATH:'/api/status', OCLIV_LIST_PATH:'/api/publications',
  OCLIV_GET_PATH:'/api/publications/{id}', OCLIV_PUBLISH_PATH:'/api/publications',
  OCLIV_UNPUBLISH_PATH:'/api/publications/{id}', OCLIV_ALLOWED_SUBJECTS:'operator-1',
  OCLIV_PUBLIC_HOSTS:'pub.ocliv.example', OCLIV_PROBE_TOKEN:'SEPARATE_PROBE_SECRET', OCLIV_WRITE_ENABLED:'true'
};
const cfg = () => loadConfig({...env});
const json = (v, status=200,headers={}) => new Response(JSON.stringify(v), {status,headers:{'content-type':'application/json',...headers}});
const authorized = { scopes:['ocliv:read','ocliv:write'], extra:{sub:'operator-1'} };

test('configuration requires complete real API contract and HTTPS control URL',()=>{
  const c=cfg(); assert.equal(c.base,'https://control.ocliv.example');
  for (const [key,value] of [
    ['OCLIV_CONTROL_URL','http://control.ocliv.example'],
    ['OCLIV_CONTROL_URL','https://control.ocliv.example/private'],
    ['OCLIV_STATUS_PATH','/api/../secrets'],
    ['OCLIV_GET_PATH','/api/publications'],
    ['OCLIV_LIST_PATH','https://evil.example/a'],
    ['OCLIV_LIST_PATH','/api/a?token=x'],
    ['OCLIV_PUBLIC_HOSTS','.example.org'],
    ['OCLIV_CONTROL_TOKEN','']
  ]) assert.throws(()=>loadConfig({...env,[key]:value}));
});

test('authorization rejects missing identity, wrong subject and missing write scope',()=>{
  assert.equal(authorize(authorized,cfg().subjects),'operator-1');
  assert.throws(()=>authorize(null,cfg().subjects),{code:'FORBIDDEN'});
  assert.throws(()=>authorize({...authorized,extra:{sub:'stranger'}},cfg().subjects),{code:'FORBIDDEN'});
  assert.throws(()=>authorize({scopes:['ocliv:read'],extra:{sub:'operator-1'}},cfg().subjects,'ocliv:write'),{code:'FORBIDDEN'});
  assert.throws(()=>authorize({...authorized,extra:{}},cfg().subjects),{code:'FORBIDDEN'});
});

test('resource IDs reject traversal, request injection and arbitrary URLs',()=>{
  for (const s of ['','../secrets','/tmp/a','a?b=c','a#b','x\nAuthorization: injected','⚠️']) assert.throws(()=>validId(s));
  assert.equal(validId('mcp_1:test'),'mcp_1:test');
});

test('listing uses actual upstream data and strips credentials/unknown fields',async()=>{
  const calls=[];
  const client=new OclivClient(cfg(),async(url,opts)=>{
    calls.push({url,opts});
    assert.equal(opts.headers.authorization,`Bearer ${env.OCLIV_CONTROL_TOKEN}`);
    return json({publications:[{id:'p1',label:'MCP Service',status:'active',publicUrl:'https://pub.ocliv.example/mcp',bearerToken:'DO_NOT_LEAK',internalIP:'192.168.1.2'}]});
  });
  const list=await client.list();
  assert.equal(list.publications.length,1);
  assert.deepEqual(Object.keys(list.publications[0]).sort(),['id','label','publicUrl','serviceId','status'].sort());
  assert.equal(JSON.stringify(list).includes('DO_NOT_LEAK'),false);
  assert.equal(calls[0].url,'https://control.ocliv.example/api/publications');
  assert.equal(calls[0].opts.redirect,'manual');
});

test('missing or malformed actual upstream JSON fails closed',async()=>{
  const noApi=new OclivClient(cfg(),async()=>json({fake:true}));
  await assert.rejects(noApi.list(),{code:'UPSTREAM_CONTRACT'});
  await assert.rejects(noApi.status(),{code:'UPSTREAM_CONTRACT'});
  const redirect=new OclivClient(cfg(),async()=>new Response('',{status:302,headers:{location:'https://evil.example'}}));
  await assert.rejects(redirect.list(),{code:'UPSTREAM_REDIRECT'});
  const denied=new OclivClient(cfg(),async()=>json({message:'secret'},401));
  await assert.rejects(denied.list(),{code:'UPSTREAM_AUTH'});
  const fail=new OclivClient(cfg(),async()=>{throw new Error('Bearer TOP_SECRET_CONTROL_TOKEN')});
  await assert.rejects(fail.list(),{code:'UPSTREAM_UNAVAILABLE'});
  assert.equal(JSON.stringify(safeError(new Error('Bearer TOP_SECRET_CONTROL_TOKEN'))).includes('TOP_SECRET'),false);
});

test('publishing enforces explicit confirmation and authenticated access only',async()=>{
  const requests=[];
  const client=new OclivClient(cfg(),async(url,opts)=>{
    requests.push({url,opts}); return json({publication:{id:'pub12',status:'active',publicUrl:'https://pub.ocliv.example/mcp'}});
  });
  await assert.rejects(client.publish({serviceId:'service7',confirm:'YES'}),{code:'CONFIRM_REQUIRED'});
  assert.equal(requests.length,0);
  const r=await client.publish({serviceId:'service7',label:'Test',confirm:'PUBLISH'});
  assert.equal(r.publication.id,'pub12');
  assert.equal(requests[0].opts.method,'POST');
  assert.deepEqual(JSON.parse(requests[0].opts.body),{serviceId:'service7',label:'Test',kind:'mcp',access:'authenticated'});
});

test('unpublishing requires exact ID confirmation and acknowledgement',async()=>{
  let count=0;
  const client=new OclivClient(cfg(),async(url,opts)=>{count++; assert.equal(url,'https://control.ocliv.example/api/publications/p12'); assert.equal(opts.method,'DELETE'); return json({deleted:true});});
  await assert.rejects(client.unpublish({publicationId:'p12',confirmPublicationId:'p11'}),{code:'CONFIRM_REQUIRED'});
  assert.equal(count,0);
  assert.equal((await client.unpublish({publicationId:'p12',confirmPublicationId:'p12'})).unpublished,'p12');
  const badAck=new OclivClient(cfg(),async()=>json({}));
  await assert.rejects(badAck.unpublish({publicationId:'p12',confirmPublicationId:'p12'}),{code:'UPSTREAM_CONTRACT'});
});

test('public MCP verification never uses control token and does initialize -> initialized -> tools/list',async()=>{
  const phases=[];
  const client=new OclivClient(cfg(),async(url,opts)=>{
    if (url.startsWith(cfg().base)) return json({id:'p12',publicUrl:'https://pub.ocliv.example/mcp',status:'active'});
    const msg=JSON.parse(opts.body);
    phases.push(msg.method);
    assert.equal(opts.headers.authorization,'Bearer SEPARATE_PROBE_SECRET');
    assert.equal(opts.redirect,'manual');
    if(msg.method==='initialize')return json({jsonrpc:'2.0',id:1,result:{protocolVersion:'2025-06-18',capabilities:{},serverInfo:{name:'ocliv',version:'1'}}},200,{'mcp-session-id':'session123'});
    assert.equal(opts.headers['mcp-session-id'],'session123');
    if(msg.method==='notifications/initialized')return new Response(null,{status:202});
    if(msg.method==='tools/list')return json({jsonrpc:'2.0',id:2,result:{tools:[{name:'ping'}]}});
    throw new Error('Unexpected request');
  });
  const verified=await client.verify('p12');
  assert.equal(verified.reachable,true); assert.deepEqual(verified.tools,['ping']);
  assert.deepEqual(phases,['initialize','notifications/initialized','tools/list']);
});

test('public endpoint URL authorization rejects SSRF, alternate host, credentials and ports',()=>{
  for(const url of [
    'http://pub.ocliv.example/mcp', 'https://evil.example/mcp',
    'https://localhost/mcp', 'https://127.0.0.1/mcp',
    'https://user:pass@pub.ocliv.example/mcp',
    'https://pub.ocliv.example:8443/mcp',
    'https://pub.ocliv.example/mcp#frag'
  ]) assert.throws(()=>parsePublicUrl(url,cfg().publicHosts),{code:'INVALID_PUBLIC_URL'});
  assert.equal(parsePublicUrl('https://pub.ocliv.example/mcp',cfg().publicHosts).pathname,'/mcp');
});

test('probe authorization failures are reported, never bypassed',async()=>{
  const client=new OclivClient(cfg(),async(url)=>{
    if(url.startsWith(cfg().base)) return json({id:'p1',publicUrl:'https://pub.ocliv.example/mcp'});
    return new Response('',{status:401});
  });
  await assert.rejects(client.verify('p1'),{code:'PROBE_AUTH'});
});

test('writes default disabled even with a valid control credential',async()=>{
  const c=loadConfig({...env,OCLIV_WRITE_ENABLED:'false'});
  const client=new OclivClient(c,async()=>{throw new Error('Should not reach upstream')});
  await assert.rejects(client.publish({serviceId:'svc',confirm:'PUBLISH'}),{code:'WRITES_DISABLED'});
  await assert.rejects(client.unpublish({publicationId:'p1',confirmPublicationId:'p1'}),{code:'WRITES_DISABLED'});
});

test('missing content-length cannot bypass upstream body-size cap',async()=>{
  const c=new OclivClient(cfg(),async()=>new Response('x'.repeat(1024*1024+1)));
  await assert.rejects(c.list(),{code:'UPSTREAM_CONTRACT'});
});

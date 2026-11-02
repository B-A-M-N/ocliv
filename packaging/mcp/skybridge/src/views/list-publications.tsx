import '../index.css';
import { useToolInfo, useCallTool } from '../helpers.js';
import { useState } from 'react';

type Publication = {
  id: string; label?: string; profile?: string; state?: string;
  leaseState?: string | null; sessionLive?: boolean;
  publicUrl?: string | null; leaseId?: string | null;
};
type ListOutput = {
  ok?: boolean; message?: string; publications?: Publication[];
};
type VerifyOutput = {
  verified?: boolean; message?: string; tools?: string[]; code?: string;
};

export default function ListPublications() {
  const { output, isPending } = useToolInfo<'list-publications'>();
  const { callToolAsync, isPending: isVerifying } = useCallTool('verify-publication');
  const [message, setMessage] = useState('');
  if (isPending || !output) return <div className="ocliv">Loading published Ocliv endpoints…</div>;
  const out = output as unknown as ListOutput;
  if (!out.ok) return <div className="ocliv" role="alert">Ocliv management: {out.message ?? 'request failed'}</div>;
  const pubs = out.publications ?? [];
  return <section className="ocliv">
    <h2>Ocliv · Published MCP endpoints</h2>
    <p className="metric">{pubs.length} endpoint(s) · durable publication state (not tunnel liveness)</p>
    {pubs.length === 0 && <p>No endpoints have been published.</p>}
    {pubs.map((p: Publication) => <div key={p.id} className="entry">
      <strong>{p.label || p.id}</strong> <small>Status: {p.state} · ID: {p.id} · Lease: {p.leaseState ?? 'unknown'} · Session: {p.sessionLive ? 'live' : 'down'}</small>
      {p.publicUrl && <small>{p.publicUrl}</small>}
      <button type="button" disabled={isVerifying} onClick={async()=>{
        setMessage('Verifying…');
        try { const result = await callToolAsync({ publicationId:p.id });
          const r = result.structuredContent as unknown as VerifyOutput;
          setMessage(r?.verified ? `Verified ${p.id}: ${(r.tools ?? []).join(', ') || 'no tools listed'}` : `${p.id}: ${r?.message ?? r?.code ?? 'verification failed'}`);
        } catch { setMessage('Verification failed; check endpoint and credentials.'); }
      }}>Verify MCP</button>
    </div>)}
    {message && <p role="status">{message}</p>}
    <p className="metric">Publish/unpublish require a single-use human approval (request-approval tool) plus OCLIV_WRITE_ENABLED=true; the local publisher owns the lifecycle.</p>
  </section>;
}

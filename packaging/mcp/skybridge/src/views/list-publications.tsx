import '../index.css';
import { useToolInfo, useCallTool } from '../helpers.js';
import { useState } from 'react';

export default function ListPublications() {
  const { output, isPending } = useToolInfo<'list-publications'>();
  const { callToolAsync, isPending: isVerifying } = useCallTool('verify-publication');
  const [message, setMessage] = useState('');
  if (isPending || !output) return <div className="ocliv">Loading published Ocliv endpoints…</div>;
  if (!output.ok) return <div className="ocliv" role="alert">Ocliv management: {output.message}</div>;
  return <section className="ocliv">
    <h2>Ocliv · Published MCP endpoints</h2>
    <p className="metric">{output.publications.length} endpoint(s) · checked {output.checkedAt}</p>
    {output.publications.length === 0 && <p>No endpoints have been published.</p>}
    {output.publications.map(p => <div key={p.id} className="entry">
      <strong>{p.label || p.id}</strong> <small>Status: {p.status} · ID: {p.id}</small>
      {p.publicUrl && <small>{p.publicUrl}</small>}
      <button type="button" disabled={isVerifying} onClick={async()=>{
        setMessage('Verifying…');
        try { const result = await callToolAsync({ publicationId:p.id });
          const r = result.structuredContent;
          setMessage(r?.ok ? `Verified ${p.id}: ${r.tools.length} MCP tool(s)` : `${p.id}: ${r?.message ?? 'Verification failed'}`);
        } catch { setMessage('Verification failed; check endpoint and credentials.'); }
      }}>Verify MCP</button>
    </div>)}
    {message && <p role="status">{message}</p>}
    <p className="metric">Publish and unpublish actions require explicit confirmation through chat.</p>
  </section>;
}

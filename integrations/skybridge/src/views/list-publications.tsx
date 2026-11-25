import '../index.css';
import { useToolInfo, useCallTool } from '../helpers.js';
import { useState } from 'react';

type Publication = {
  id: string; label?: string; profile?: string; state?: string;
  publicationState?: string; leaseState?: string | null; sessionLive?: boolean | null;
  hostBinding?: string; admission?: string; admissionReason?: string;
  publicUrl?: string | null; leaseId?: string | null;
};
type ListOutput = {
  ok?: boolean; message?: string; publications?: Publication[];
};
type VerifyOutput = {
  verified?: boolean; message?: string; tools?: string[]; code?: string;
};

function readinessLabel(p: Publication): 'Transport Ready' | 'Offline' | 'Unverified' {
  if (p.sessionLive === false || p.publicationState === 'DISABLED') return 'Offline';
  if (p.sessionLive === true && p.admission === 'READY') return 'Transport Ready';
  return 'Unverified';
}

export default function ListPublications() {
  const { output, isPending } = useToolInfo<'list_services'>();
  const { callToolAsync, isPending: isVerifying } = useCallTool('verify_service');
  const [message, setMessage] = useState('');
  const [query, setQuery] = useState('');
  const [filter, setFilter] = useState<'all' | 'Transport Ready' | 'Offline' | 'Unverified'>('all');
  if (isPending || !output) return <div className="ocliv">Loading published Ocliv endpoints…</div>;
  const out = output as unknown as ListOutput;
  if (!out.ok) return <div className="ocliv" role="alert">Ocliv management: {out.message ?? 'request failed'}</div>;
  const pubs = (out.publications ?? []).filter((p: Publication) => {
    const label = (p.label || p.id).toLowerCase();
    const matchesQ = !query || label.includes(query.toLowerCase()) || (p.publicUrl ?? '').toLowerCase().includes(query.toLowerCase());
    const status = readinessLabel(p);
    return matchesQ && (filter === 'all' || status === filter);
  });
  return <section className="ocliv">
    <h2>Ocliv · Published MCP endpoints</h2>
    <p className="metric">{pubs.length} endpoint(s) · client-facing MCP URLs (separate from Ocliv management)</p>
    <div style={{ display: 'flex', gap: '8px', marginBottom: '10px' }}>
      <input type="search" placeholder="Filter by name or URL…" value={query} onChange={(e) => setQuery(e.target.value)} />
      <select value={filter} onChange={(e) => setFilter(e.target.value as typeof filter)}>
        <option value="all">All</option>
        <option value="Transport Ready">Transport Ready</option>
        <option value="Offline">Offline</option>
        <option value="Unverified">Unverified</option>
      </select>
    </div>
    {pubs.length === 0 && <p>No matching endpoints found.</p>}
    {pubs.map((p: Publication) => {
      const status = readinessLabel(p);
      return <div key={p.id} className="entry">
        <strong>{p.label || p.id}</strong> <span>[{status}]</span> <small>Publication: {p.publicationState ?? p.state ?? 'unknown'} · Lease: {p.leaseState ?? 'unknown'} · Session: {p.sessionLive === true ? 'live' : p.sessionLive === false ? 'offline' : 'unknown'} · Host: {p.hostBinding ?? 'unknown'} · Admission: {p.admission ?? 'unknown'}{p.admissionReason ? ` (${p.admissionReason})` : ''} · ID: {p.id}</small>
        {p.publicUrl && <small>{p.publicUrl}</small>}
        <div style={{ display: 'flex', gap: '6px', marginTop: '4px' }}>
          {p.publicUrl && <button type="button" onClick={async () => {
            try {
              await navigator.clipboard.writeText(p.publicUrl!);
              setMessage(`Copied ${p.label || p.id} URL to clipboard.`);
            } catch {
              setMessage(`Clipboard unavailable; copy manually: ${p.publicUrl}`);
            }
          }}>Copy URL</button>}
          <button type="button" disabled={isVerifying} onClick={async()=>{
            setMessage('Verifying…');
            try { const result = await callToolAsync({ service: p.label || p.id });
              const r = result.structuredContent as unknown as VerifyOutput;
              setMessage(r?.verified ? `Verified ${p.id}: ${(r.tools ?? []).join(', ') || 'no tools listed'}` : `${p.id}: ${r?.message ?? r?.code ?? 'verification failed'}`);
            } catch { setMessage('Verification failed; check endpoint and credentials.'); }
          }}>Verify MCP</button>
        </div>
      </div>;
    })}
    {message && <p role="status">{message}</p>}
    <p className="metric">Publish/unpublish require a single-use human approval (request-approval tool) plus OCLIV_WRITE_ENABLED=true; the local publisher owns the lifecycle.</p>
  </section>;
}

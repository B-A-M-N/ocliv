import '../index.css';
import { useToolInfo } from '../helpers.js';

export default function ManagePublications() {
  const { isPending, isSuccess, output } = useToolInfo<'list-publications'>();
  if (isPending) return <main className="ocliv"><p>Loading publications…</p></main>;
  if (!isSuccess) return <main className="ocliv"><p>Unable to load publications.</p></main>;
  return <main className="ocliv">
    <header>
      <div><strong>Ocliv MCP hosting</strong><small>Operator publications</small></div>
      <span className="count">{output.publications.length} total</span>
    </header>
    {output.publications.length === 0
      ? <p>No publications found for this enrolled operator.</p>
      : <ul>{output.publications.map((p) => <li key={p.publicationId}>
          <div className="top"><strong>{p.name}</strong><span className={`state ${p.state}`}>{p.state}</span></div>
          <small>Route: {p.publicationId}</small>
          {p.endpoint && <small className="url">{p.endpoint}</small>}
          <small>{p.leaseId ? 'Lease bound' : 'No bound lease'} · Protocol/auth health not inferred</small>
        </li>)}</ul>}
    <footer>Ask the assistant to verify, publish or revoke. Changes require explicit confirmation.</footer>
  </main>;
}

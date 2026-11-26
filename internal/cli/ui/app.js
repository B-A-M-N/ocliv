const CSRF = document.querySelector('meta[name="ocliv-csrf"]')?.content || '';
let state = { status: null, services: [], policy: null, requests: [] };

const PERM_DEFS = [
  ['inspect', 'Inspect service status'],
  ['get_url', 'Retrieve service URLs'],
  ['verify', 'Verify endpoints'],
  ['lifecycle', 'Enable, disable & restart service'],
  ['deployment', 'Deploy service (with allowed port)'],
  ['authorize_visitor', 'Approve visitor connections'],
  ['manage_auth_policy', 'Change authentication policies'],
  ['revoke_client', 'Revoke client access'],
  ['remove_publication', 'Permanently remove service'],
];

function esc(s) {
  return String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

function toast(msg) {
  const el = document.getElementById('toast');
  el.textContent = msg;
  el.style.display = 'block';
  clearTimeout(window.__toastT);
  window.__toastT = setTimeout(() => { el.style.display = 'none'; }, 5000);
}

async function api(path, opts = {}) {
  const headers = { 'Accept': 'application/json', ...(opts.headers || {}) };
  if (opts.method && opts.method !== 'GET') {
    headers['Content-Type'] = 'application/json';
    headers['X-Ocliv-CSRF'] = CSRF;
  }
  const res = await fetch(path, { credentials: 'same-origin', ...opts, headers });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}

document.querySelectorAll('nav button').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('nav button').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
    btn.classList.add('active');
    document.getElementById('tab-' + btn.dataset.tab).classList.add('active');
    if (btn.dataset.tab === 'access') loadAccessForSelected();
    if (btn.dataset.tab === 'agents') loadAgentsTab();
  });
});

document.getElementById('btnLogout')?.addEventListener('click', async () => {
  try {
    await api('/api/auth/logout', { method: 'POST', body: '{}' });
    document.body.innerHTML = '<main style="padding:40px;text-align:center"><h2>Signed out of Ocliv Control Center</h2><p class="muted">Re-launch via <code>ocliv ui</code> or your desktop app shortcut to start a fresh authenticated session.</p></main>';
  } catch (e) { toast('Logout error: ' + e.message); }
});

async function refreshAll() {
  try {
    const [st, svcs] = await Promise.all([api('/api/status'), api('/api/services')]);
    state.status = st;
    state.services = svcs.services || [];
    renderHeader();
    renderServices();
    renderSetup();
    populateAccessSelect();
  } catch (e) { toast('Error: ' + e.message); }
}

function renderHeader() {
  const b = document.getElementById('relayBadge');
  if (state.status?.relay_reachable) {
    b.className = 'pill ok'; b.textContent = 'Relay connected';
  } else {
    b.className = 'pill warn'; b.textContent = 'Relay unreachable';
  }
  document.getElementById('deviceInfo').textContent = `${state.status?.relay_url || ''} · ${state.status?.key_id || 'not enrolled'}`;
}

function renderServices() {
  const grid = document.getElementById('servicesGrid');
  grid.innerHTML = '';
  if (!state.services.length) {
    grid.innerHTML = '<div class="card"><div class="muted">No services configured yet. Click "+ Add service" to share a local MCP server.</div></div>';
    return;
  }
  for (const s of state.services) {
    const card = document.createElement('div');
    card.className = 'card';
    const online = s.observed_state === 'SERVING' && s.health === 'READY';
    const badgeClass = online ? 'ok' : (s.desired_state === 'disabled' ? '' : 'warn');
    const badgeText = online ? 'Online' : (s.desired_state === 'disabled' ? 'Disabled' : (s.observed_state || 'Checking'));
    card.innerHTML = `
      <div class="row">
        <h3>${esc(s.name)}</h3>
        <span class="pill ${badgeClass}">${esc(badgeText)}</span>
      </div>
      <div class="muted">${esc(s.type?.toUpperCase() || 'MCP')} · ${esc(s.authentication || 'ocliv-managed')}</div>
      <div class="url">${esc(s.public_url || 'URL not yet bound')}</div>
      <div class="actions">
        ${s.public_url ? '<button class="btn" data-act="copy">Copy URL</button>' : ''}
        <button class="btn" data-act="access">Connect / Access</button>
        ${s.desired_state === 'enabled'
          ? '<button class="btn" data-act="disable">Disable</button>'
          : '<button class="btn primary" data-act="enable">Enable</button>'}
        <button class="btn" data-act="reconcile">Repair</button>
        <button class="btn danger" data-act="remove">Remove</button>
      </div>
    `;
    card.querySelector('[data-act="copy"]')?.addEventListener('click', () => {
      navigator.clipboard?.writeText(s.public_url).then(() => toast('Copied URL for ' + s.name));
    });
    card.querySelector('[data-act="access"]').addEventListener('click', () => {
      document.getElementById('accessServiceSelect').value = s.name;
      document.querySelector('nav button[data-tab="access"]').click();
    });
    card.querySelector('[data-act="enable"]')?.addEventListener('click', () => runSvcAction(s.name, 'enable'));
    card.querySelector('[data-act="disable"]')?.addEventListener('click', () => runSvcAction(s.name, 'disable'));
    card.querySelector('[data-act="reconcile"]').addEventListener('click', () => runSvcAction(s.name, 'reconcile'));
    card.querySelector('[data-act="remove"]').addEventListener('click', () => {
      const typed = prompt(`Type "${s.name}" to permanently remove this service and revoke its public route:`);
      if (typed === s.name) runSvcAction(s.name, 'remove');
    });
    grid.appendChild(card);
  }
}

async function runSvcAction(name, action) {
  try {
    toast(`${action} ${name}…`);
    const res = await api(`/api/services/${encodeURIComponent(name)}/${action}`, { method: 'POST', body: '{}' });
    toast(res.confirmed ? `✓ ${action} ${name} confirmed` : `⚠ ${action} ${name}: ${res.status || res.detail || 'unconfirmed'}`);
    await refreshAll();
  } catch (e) { toast('Error: ' + e.message); }
}

function populateAccessSelect() {
  const sel = document.getElementById('accessServiceSelect');
  const prev = sel.value;
  sel.innerHTML = '';
  for (const s of state.services) {
    const o = document.createElement('option');
    o.value = s.name; o.textContent = s.name;
    sel.appendChild(o);
  }
  if (prev && state.services.some(s => s.name === prev)) sel.value = prev;
}

document.getElementById('accessServiceSelect').addEventListener('change', loadAccessForSelected);

async function loadAccessForSelected() {
  const name = document.getElementById('accessServiceSelect').value;
  if (!name) return;
  const svc = state.services.find(s => s.name === name);
  document.getElementById('connectUrlBox').textContent = svc?.public_url || 'No public URL bound';
  try {
    const [pend, clis] = await Promise.all([
      api(`/api/services/${encodeURIComponent(name)}/pending`),
      api(`/api/services/${encodeURIComponent(name)}/clients`),
    ]);
    const pWrap = document.getElementById('pendingList');
    const txs = pend.pending_transactions || [];
    if (!txs.length) {
      pWrap.innerHTML = '<div class="muted">No pending login requests. Start OAuth from ChatGPT or your MCP client to review and approve requests here.</div>';
    } else {
      pWrap.innerHTML = '';
      for (const tx of txs) {
        const d = document.createElement('div');
        d.className = 'url';
        const corr = String(tx.challenge || '').slice(0, 14);
        d.innerHTML = `
          <div><strong>A client is requesting access to ${esc(name)}</strong></div>
          <div class="muted" style="margin-top:4px">
            <strong>Application:</strong> ${esc(tx.client_name || tx.client_id)} (claimed name)<br>
            <strong>Access requested:</strong> ${esc(tx.scope || 'Use MCP tools')}<br>
            <strong>Redirect:</strong> ${esc(tx.redirect_uri)}<br>
            <strong>Correlation:</strong> <code>${esc(corr)}…</code> · <strong>Expires:</strong> ${esc(tx.expires_at || '')}
          </div>
          <div class="muted" style="margin-top:6px">Approve only if you initiated this connection. Once approved, access persists until revoked.</div>
          <div class="actions">
            <button class="btn danger" data-d="deny">Deny</button>
            <button class="btn primary" data-d="approve">Approve connection</button>
          </div>`;
        d.querySelector('[data-d="approve"]').addEventListener('click', () => decideTx(name, tx.challenge, 'approve'));
        d.querySelector('[data-d="deny"]').addEventListener('click', () => decideTx(name, tx.challenge, 'deny'));
        pWrap.appendChild(d);
      }
    }
    const cWrap = document.getElementById('clientsTableWrap');
    const list = clis.clients || [];
    if (!list.length) {
      cWrap.innerHTML = `<div class="muted" style="margin-top:8px">${esc(clis.detail || 'No authorized clients yet.')}</div>`;
    } else {
      cWrap.innerHTML = '<table><thead><tr><th>Client</th><th>Method</th><th>Status</th><th>Authorized</th><th></th></tr></thead><tbody></tbody></table>';
      const tbody = cWrap.querySelector('tbody');
      for (const c of list) {
        const tr = document.createElement('tr');
        tr.innerHTML = `<td><strong>${esc(c.client_name || 'Unnamed')}</strong><div class="muted">${esc(c.client_id)}</div></td>
          <td>${esc(c.auth_method)}</td><td>${esc(c.status)}</td><td class="muted">${esc(c.authorized_at || '')}</td>
          <td>${c.status !== 'revoked' ? '<button class="btn danger">Revoke</button>' : ''}</td>`;
        tr.querySelector('button')?.addEventListener('click', async () => {
          await api(`/api/services/${encodeURIComponent(name)}/revoke-client`, { method: 'POST', body: JSON.stringify({ client_id: c.client_id }) });
          toast('Revoked client ' + c.client_id);
          loadAccessForSelected();
        });
        tbody.appendChild(tr);
      }
    }
  } catch (e) { toast('Access load error: ' + e.message); }
}

async function decideTx(name, challenge, decision) {
  try {
    await api(`/api/services/${encodeURIComponent(name)}/decide-tx`, { method: 'POST', body: JSON.stringify({ challenge, decision }) });
    toast(`Transaction ${decision}d`);
    loadAccessForSelected();
  } catch (e) { toast('Error: ' + e.message); }
}

document.getElementById('btnCopyAccessUrl').addEventListener('click', () => {
  const u = document.getElementById('connectUrlBox').textContent;
  if (u.startsWith('https://')) navigator.clipboard?.writeText(u).then(() => toast('Copied MCP URL'));
});

document.getElementById('btnTrustChatGPT').addEventListener('click', async () => {
  const name = document.getElementById('accessServiceSelect').value;
  if (!name) return;
  try {
    await api(`/api/services/${encodeURIComponent(name)}/trust`, { method: 'POST', body: JSON.stringify({ preset: 'chatgpt' }) });
    toast('ChatGPT redirect trusted on ' + name);
  } catch (e) { toast('Error: ' + e.message); }
});

async function connectGemini(opts = {}) {
  const name = document.getElementById('accessServiceSelect').value;
  if (!name) return;
  const redirectUri = (document.getElementById('geminiRedirectInput')?.value || '').trim();
  try {
    const r = await api(`/api/services/${encodeURIComponent(name)}/connect-google`, {
      method: 'POST',
      body: JSON.stringify({ type: 'gemini', redirect_uri: redirectUri, ...opts }),
    });
    const box = document.getElementById('geminiResultBox');
    box.style.display = 'block';
    box.innerHTML = `<strong>Gemini / Google OAuth Client (${r.idempotent ? 'Already Configured — Idempotent' : 'Provisioned'} · policy=${esc(r.refresh_policy || 'google_confidential')}):</strong><br>
      MCP URL: <code>${esc(r.url)}</code><br>
      Client ID: <code>${esc(r.client_id)}</code><br>
      ${r.client_secret ? `One-time Client Secret: <code>${esc(r.client_secret)}</code><br>` : ''}
      <span class="muted">${esc(r.detail || '')}</span>`;
    loadAccessForSelected();
  } catch (e) { toast('Gemini connect error: ' + e.message); }
}

document.getElementById('btnConnectGemini')?.addEventListener('click', () => connectGemini({ update: false }));
document.getElementById('btnRotateGemini')?.addEventListener('click', () => connectGemini({ update: true, reconnect: true }));
document.getElementById('btnRevokeGemini')?.addEventListener('click', async () => {
  const name = document.getElementById('accessServiceSelect').value;
  if (!name) return;
  try {
    await api(`/api/services/${encodeURIComponent(name)}/connect-google`, { method: 'DELETE' });
    const box = document.getElementById('geminiResultBox');
    box.style.display = 'block';
    box.innerHTML = '<strong>Gemini / Google client revoked.</strong> Click Rotate Gemini to reconnect with a fresh client.';
    loadAccessForSelected();
  } catch (e) { toast('Gemini revoke error: ' + e.message); }
});

document.getElementById('btnVerifyAccess').addEventListener('click', async () => {
  const name = document.getElementById('accessServiceSelect').value;
  if (!name) return;
  try {
    const r = await api(`/api/services/${encodeURIComponent(name)}/verify`, { method: 'POST', body: '{}' });
    const st = r.stages || {};
    document.getElementById('verifyResult').innerHTML = `
      <div>Checked at: ${esc(r.checked_at || '')} · Source: <strong>${esc(r.verification_source || 'read_only_discovery')}</strong></div>
      <div>Endpoint: <strong>${esc(st.public_endpoint_reachable)}</strong> · OAuth: <strong>${esc(st.oauth_discovery_compatible)}</strong> · Auth MCP: <strong>${esc(st.authenticated_mcp_handshake)}</strong></div>
      <div>Events Discovered: <strong>${esc(st.events_advertised)}</strong> · Events List: <strong>${esc(st.events_list_verified || 'UNKNOWN')}</strong> · Events Sub: <strong>${esc(st.events_subscription_verified)}</strong> · Callback: <strong>${esc(st.callback_delivery_verified)}</strong> · External Client: <strong>${esc(st.external_client_acceptance)}</strong></div>`;
  } catch (e) { toast('Verify error: ' + e.message); }
});

// ==================== AGENTS & PERMISSIONS (PER-SERVICE GRANTS + REVISION CAS) ====================

async function loadAgentsTab() {
  try {
    const [pol, reqs] = await Promise.all([api('/api/agents/permissions'), api('/api/agents/requests')]);
    state.policy = pol;
    state.requests = reqs.requests || [];
    renderApprovalRequests();
    renderPrincipalAndServiceSelectors();
  } catch (e) { toast('Agents load error: ' + e.message); }
}

function renderApprovalRequests() {
  const wrap = document.getElementById('approvalRequestsWrap');
  const pending = state.requests.filter(r => r.status === 'PENDING');
  if (!pending.length) {
    wrap.innerHTML = '<div class="muted">No pending agent permission requests.</div>';
    return;
  }
  wrap.innerHTML = '';
  for (const r of pending) {
    const d = document.createElement('div');
    d.className = 'url';
    const argsStr = r.intent?.arguments ? JSON.stringify(r.intent.arguments) : '{}';
    d.innerHTML = `
      <div><strong>${esc(r.principal)}</strong> requests <strong>${esc(r.action)}</strong> (${esc(r.permission)}) on <strong>${esc(r.service || '(global)')}</strong></div>
      <div class="muted">Exact arguments: <code>${esc(argsStr)}</code> · Expires: ${esc(r.expires_at || '')}</div>
      <div class="muted">Allow Once authorizes ONLY this exact operation &amp; arguments. Allow Persistently grants <strong>${esc(r.permission)}</strong> on <strong>${esc(r.service || '(global)')}</strong> only.</div>
      <div class="actions">
        <button class="btn" data-d="allow_once">Allow Once (Exact Intent)</button>
        <button class="btn primary" data-d="allow_persistent">Allow Persistently (This Service Only)</button>
        <button class="btn danger" data-d="deny">Deny</button>
      </div>`;
    for (const btn of d.querySelectorAll('button')) {
      btn.addEventListener('click', async () => {
        try {
          await api(`/api/agents/requests/${encodeURIComponent(r.request_id)}/decide`, { method: 'POST', body: JSON.stringify({ decision: btn.dataset.d }) });
          toast(`Request ${btn.dataset.d}`);
          loadAgentsTab();
        } catch (err) { toast('Decision error: ' + err.message); }
      });
    }
    wrap.appendChild(d);
  }
}

function renderPrincipalAndServiceSelectors() {
  const pSel = document.getElementById('principalSelect');
  const agents = state.policy?.agents || {};
  const keys = Object.keys(agents);
  if (!keys.length) keys.push('local-stdio');
  const prevP = pSel.value || keys[0];
  pSel.innerHTML = '';
  for (const k of keys) {
    const o = document.createElement('option');
    o.value = k; o.textContent = k;
    pSel.appendChild(o);
  }
  pSel.value = keys.includes(prevP) ? prevP : keys[0];

  const sSel = document.getElementById('permServiceSelect');
  const prevS = sSel.value;
  sSel.innerHTML = '';
  for (const s of state.services) {
    const o = document.createElement('option');
    o.value = s.name;
    o.dataset.serviceId = s.service_id || '';
    o.textContent = s.name;
    sSel.appendChild(o);
  }
  if (prevS && state.services.some(s => s.name === prevS)) sSel.value = prevS;
  renderGrantEditor();
}

function renderGrantEditor() {
  const principal = document.getElementById('principalSelect').value;
  const serviceName = document.getElementById('permServiceSelect').value;
  const svcObj = state.services.find(s => s.name === serviceName);
  const serviceId = svcObj?.service_id || '';
  const rule = (state.policy?.agents || {})[principal] || { grants: [] };
  const grant = (rule.grants || []).find(g => (serviceId && g.service_id === serviceId) || g.service_name === serviceName) || { actions: [], allowed_ports: [] };
  const active = new Set(grant.actions || []);
  const box = document.getElementById('permCheckboxes');
  box.innerHTML = '';
  for (const [key, label] of PERM_DEFS) {
    const lbl = document.createElement('label');
    lbl.className = 'checkitem';
    lbl.innerHTML = `<input type="checkbox" data-k="${key}" ${active.has(key) ? 'checked' : ''}><span>${esc(label)}</span>`;
    box.appendChild(lbl);
  }
  document.getElementById('permRevInfo').textContent = `Policy revision: ${state.policy?.revision ?? 0} · Editing exact grant for "${principal}" on "${serviceName || '(no service)'}"`;
}

document.getElementById('principalSelect').addEventListener('change', renderGrantEditor);
document.getElementById('permServiceSelect').addEventListener('change', renderGrantEditor);

document.getElementById('btnSavePerms').addEventListener('click', async () => {
  const principal = document.getElementById('principalSelect').value;
  const serviceName = document.getElementById('permServiceSelect').value;
  if (!principal || !serviceName) { toast('Select both a principal and a service.'); return; }
  const svcObj = state.services.find(s => s.name === serviceName);
  const serviceId = svcObj?.service_id || '';
  const actions = [];
  document.querySelectorAll('#permCheckboxes input').forEach(i => { if (i.checked) actions.push(i.dataset.k); });

  if (!state.policy.agents) state.policy.agents = {};
  const rule = state.policy.agents[principal] || { grants: [] };
  const grants = (rule.grants || []).filter(g => !((serviceId && g.service_id === serviceId) || g.service_name === serviceName));
  if (actions.length > 0) {
    const existing = (rule.grants || []).find(g => (serviceId && g.service_id === serviceId) || g.service_name === serviceName);
    grants.push({
      service_id: serviceId || existing?.service_id || '',
      service_name: serviceName,
      actions,
      allowed_ports: existing?.allowed_ports || [],
      allowed_auth_modes: existing?.allowed_auth_modes || ['ocliv-managed'],
    });
  }
  state.policy.agents[principal] = { grants };
  try {
    const saved = await api('/api/agents/permissions', {
      method: 'PUT',
      body: JSON.stringify({ expected_revision: state.policy.revision ?? 0, policy: state.policy }),
    });
    state.policy = saved.policy;
    renderGrantEditor();
    toast(`✓ Saved permissions for ${principal} on ${serviceName} (rev ${state.policy.revision})`);
  } catch (e) { toast('Save error: ' + e.message); }
});

// ==================== SETUP, UPDATES & DIAGNOSTICS ====================

function renderSetup() {
  const v = state.status?.version || {};
  document.getElementById('setupStatusBox').innerHTML = `
    <div><strong>Relay:</strong> ${esc(state.status?.relay_url || 'not configured')}</div>
    <div><strong>Publisher Key:</strong> ${esc(state.status?.key_id || 'not enrolled')}</div>
    <div><strong>Version:</strong> ${esc(v.version || '')} (${esc((v.build_commit || '').slice(0, 12))}, dirty=${v.dirty})</div>
    <div><strong>Schema:</strong> V${esc(v.schema_version || '')}</div>
  `;
}

document.getElementById('btnCheckUpdates')?.addEventListener('click', async () => {
  try {
    const r = await api('/api/setup/update-check');
    document.getElementById('updateStatusBox').textContent = r.message || JSON.stringify(r);
  } catch (e) { toast('Update check error: ' + e.message); }
});

document.getElementById('btnInstallShortcut').addEventListener('click', async () => {
  try {
    const r = await api('/api/setup/install-shortcut', { method: 'POST', body: '{}' });
    toast('✓ Installed shortcut at ' + r.path);
  } catch (e) { toast('Shortcut error: ' + e.message); }
});

const dlg = document.getElementById('addDialog');
document.getElementById('btnAddService').addEventListener('click', () => dlg.showModal());
document.getElementById('btnCancelAdd').addEventListener('click', () => dlg.close());
document.getElementById('btnRefresh').addEventListener('click', refreshAll);
document.getElementById('addServiceForm').addEventListener('submit', async e => {
  e.preventDefault();
  const fd = new FormData(e.target);
  try {
    const res = await api('/api/services', {
      method: 'POST',
      body: JSON.stringify({
        name: fd.get('name'),
        port: Number(fd.get('port')),
        path: fd.get('path'),
        type: fd.get('type'),
        authentication: fd.get('authentication'),
      }),
    });
    dlg.close();
    toast(res.confirmed ? '✓ Service added & published' : 'Service configured: ' + (res.detail || res.status));
    refreshAll();
  } catch (err) { toast('Add failed: ' + err.message); }
});

refreshAll();

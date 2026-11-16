/** Local operator control plane for approvals. The socket is owner-only;
 * no approval decision or secret is exposed through MCP. */
import { createServer } from 'node:net';
import { chmodSync, lstatSync, mkdirSync, statSync, unlinkSync } from 'node:fs';
import { dirname, resolve } from 'node:path';

const MAX_LINE = 8192;

export function startOperatorApprovalSocket(approvals, socketPath) {
  const path = resolve(socketPath);
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  if ((statSync(dirname(path)).mode & 0o077) !== 0) {
    throw new Error(`approval socket directory must be owner-only (0700): ${dirname(path)}`);
  }
  try {
    const st = lstatSync(path);
    if (!st.isSocket()) throw new Error(`approval socket path exists and is not a socket: ${path}`);
    throw new Error(`approval socket already exists; inspect it before removal: ${path}`);
  } catch (e) {
    if (e?.code !== 'ENOENT') throw e;
  }
  let owned = false;
  const server = createServer((connection) => {
    connection.setEncoding('utf8');
    let input = '';
    connection.on('data', (chunk) => {
      input += chunk;
      if (input.length > MAX_LINE) {
        connection.end(JSON.stringify({ ok: false, code: 'REQUEST_TOO_LARGE' }) + '\n');
        return;
      }
      const nl = input.indexOf('\n');
      if (nl < 0) return;
      let result;
      try {
        const request = JSON.parse(input.slice(0, nl));
        if (request.command === 'list') result = { ok: true, approvals: approvals.list() };
        else if (request.command === 'approve' || request.command === 'deny') {
          result = { ok: true, approval: approvals.decide({ approvalId: request.approvalId, decision: request.command }) };
        } else result = { ok: false, code: 'INVALID_COMMAND', message: 'Use list, approve, or deny' };
      } catch (e) {
        result = { ok: false, code: e?.code || 'INVALID_REQUEST', message: e?.message || 'Invalid request' };
      }
      connection.end(JSON.stringify(result) + '\n');
    });
  });
  server.listen(path, () => {
    owned = true;
    chmodSync(path, 0o600);
  });
  server.on('close', () => {
    if (owned) { try { unlinkSync(path); } catch { /* shutdown cleanup */ } }
  });
  process.once('exit', () => {
    if (owned) { try { unlinkSync(path); } catch { /* process shutdown cleanup */ } }
  });
  return server;
}

#!/usr/bin/env node
/** Owner-local interface for reviewing MCP write requests. */
import { connect } from 'node:net';

const socketPath = (process.env.OCLIV_APPROVAL_SOCKET ?? '').trim();
const [command, approvalId] = process.argv.slice(2);
if (!socketPath || !['list', 'approve', 'deny'].includes(command) ||
    (command !== 'list' && !approvalId)) {
  process.stderr.write('usage: OCLIV_APPROVAL_SOCKET=/path/to/approvals.sock node operator-approval-cli.mjs list|approve|deny [approval-id]\n');
  process.exit(2);
}

const socket = connect(socketPath);
let response = '';
socket.setEncoding('utf8');
socket.on('data', (chunk) => { response += chunk; });
socket.on('end', () => {
  try {
    const result = JSON.parse(response);
    process.stdout.write(JSON.stringify(result, null, 2) + '\n');
    if (!result.ok) process.exitCode = 1;
  } catch {
    process.stderr.write('invalid response from local approval socket\n');
    process.exitCode = 1;
  }
});
socket.on('connect', () => socket.write(JSON.stringify({ command, approvalId }) + '\n'));
socket.on('error', (error) => {
  process.stderr.write(`approval socket unavailable: ${error.message}\n`);
  process.exitCode = 1;
});

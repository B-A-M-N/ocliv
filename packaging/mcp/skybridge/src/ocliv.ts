import { execFile, spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { promisify } from 'node:util';
import { isIP } from 'node:net';
import { URL } from 'node:url';

const execFileAsync = promisify(execFile);
export type Service = { name: string; localUrl: string; resourceFile?: string };
export type Publication = {
  publicationId: string; profile: string; name: string;
  state: string; leaseId: string | null; endpoint: string | null;
};
export type OperationResult = { ok: boolean; message: string; endpoint?: string; detail?: string };

const NAME = /^[a-zA-Z][a-zA-Z0-9_-]{0,47}$/;
const ID = /^[A-Za-z0-9_-]{8,128}$/;
const MAX_TEXT = 48 * 1024;

export function isSafeLocalMcpUrl(input: string): boolean {
  try {
    const u = new URL(input);
    // No DNS resolution or DNS rebinding: accept IP loopback literals only.
    return u.protocol === 'http:' && (u.hostname === '127.0.0.1' || u.hostname === '[::1]') &&
      u.pathname === '/mcp' && u.search === '' && u.hash === '' &&
      u.username === '' && u.password === '' && Boolean(u.port) &&
      (isIP(u.hostname.replaceAll(/[\[\]]/g, '')) === 4 || u.hostname === '[::1]');
  } catch { return false; }
}

export function parseAllowlist(raw: string): Map<string, Service> {
  const result = new Map<string, Service>();
  const arr = JSON.parse(raw || '[]');
  if (!Array.isArray(arr)) throw new Error('OCLIV_SERVICES_JSON must be an array');
  for (const value of arr) {
    if (!value || typeof value.name !== 'string' || typeof value.localUrl !== 'string' ||
        !NAME.test(value.name) || !isSafeLocalMcpUrl(value.localUrl) || result.has(value.name)) {
      throw new Error('Invalid or duplicate allowlisted MCP service');
    }
    if (value.resourceFile !== undefined &&
        (typeof value.resourceFile !== 'string' || !value.resourceFile.startsWith('/') || value.resourceFile.includes('\0'))) {
      throw new Error('resourceFile must be an absolute local path');
    }
    result.set(value.name, { name: value.name, localUrl: value.localUrl, resourceFile: value.resourceFile });
  }
  return result;
}

export function parsePublications(output: string, baseUrl?: string): Publication[] {
  const items: Publication[] = [];
  const base = baseUrl ? new URL(baseUrl) : null;
  if (base && (base.protocol !== 'https:' || base.username || base.password || base.pathname !== '/' || base.search || base.hash)) {
    throw new Error('OCLIV_MCP_ORIGIN must be a plain HTTPS origin ending in /');
  }
  for (const row of output.trim().split('\n')) {
    if (!row.trim() || row.trim() === 'no publications') continue;
    const cols = row.trim().split(/\s+/);
    if (cols.length !== 5 || !ID.test(cols[0]) || !NAME.test(cols[2]) || !['active', 'unbound', 'revoked'].includes(cols[3])) {
      throw new Error('Unrecognized output from ocliv mcp list; refusing to guess');
    }
    items.push({
      publicationId: cols[0], profile: cols[1], name: cols[2], state: cols[3],
      leaseId: cols[4] === '-' ? null : cols[4],
      endpoint: base && cols[3] !== 'revoked' ? new URL(`/r/${cols[0]}/mcp`, base).toString() : null,
    });
  }
  return items;
}

export class OclivClient {
  readonly services: Map<string, Service>;
  private readonly processes = new Map<string, ChildProcessWithoutNullStreams>();
  private readonly pending = new Set<string>();

  private readonly config: { bin: string; services: Map<string, Service>; origin?: string; home?: string };

  constructor(config: { bin: string; services: Map<string, Service>; origin?: string; home?: string }) {
    this.config = config;
    if (!config.bin.startsWith('/')) throw new Error('OCLIV_BIN must be an absolute path');
    this.services = config.services;
    if (config.origin) parsePublications('no publications', config.origin);
  }

  private env(): NodeJS.ProcessEnv {
    // Ocliv resolves its enrollment from HOME; never pass credentials as CLI arguments.
    return this.config.home ? { ...process.env, HOME: this.config.home } : { ...process.env };
  }

  private async call(args: string[], timeout = 12000): Promise<string> {
    try {
      const { stdout } = await execFileAsync(this.config.bin, args, {
        env: this.env(), timeout, maxBuffer: MAX_TEXT, windowsHide: true,
      });
      return stdout;
    } catch (err) {
      const e = err as Error & { code?: string | number };
      // Do not surface Ocliv stderr; it may contain environment-specific details.
      throw new Error(`Ocliv command failed (${String(e.code ?? 'execution error')})`);
    }
  }

  async list(): Promise<Publication[]> {
    return parsePublications(await this.call(['mcp', 'list']), this.config.origin);
  }

  async verify(name: string): Promise<OperationResult> {
    if (!NAME.test(name)) throw new Error('Invalid service name');
    const rows = await this.list();
    if (!rows.some((p) => p.name === name && p.state !== 'revoked')) throw new Error('Unknown publication');
    try {
      const output = await this.call(['mcp', 'doctor', '--name', name], 22000);
      const auth = /AUTH_(UNVERIFIED|REQUIRED|NONE)/.exec(output)?.[0] ?? 'AUTH_UNVERIFIED';
      return {
        ok: true, message: 'Ocliv local doctor passed; external ChatGPT and OAuth validation remain independent.',
        detail: auth,
      };
    } catch {
      return { ok: false, message: 'Ocliv doctor failed; do not consider the endpoint healthy.' };
    }
  }

  async publish(name: string, confirmation: string): Promise<OperationResult> {
    const svc = this.services.get(name);
    if (!svc || confirmation !== `PUBLISH ${name}`) throw new Error('Service not allowlisted or confirmation missing');
    if (this.pending.has(name) || this.processes.has(name)) throw new Error('Publish already active or pending for service');
    this.pending.add(name);
    const args = ['mcp', 'publish', '--local', svc.localUrl, '--name', name, '--auth', 'upstream-oauth'];
    if (svc.resourceFile) args.push('--resource-file', svc.resourceFile);
    let child: ChildProcessWithoutNullStreams | undefined;
    try {
      child = spawn(this.config.bin, args, { env: this.env(), stdio: ['pipe', 'pipe', 'pipe'], shell: false, windowsHide: true });
      child.stdin.end();
      let output = '';
      const result = await new Promise<OperationResult>((resolve, reject) => {
        let settled = false;
        const finish = (err?: Error, value?: OperationResult) => {
          if (settled) return;
          settled = true;
          clearTimeout(timer);
          child?.stdout.removeListener('data', onData);
          child?.stderr.removeListener('data', onError);
          child?.removeListener('exit', onExit);
          child?.removeListener('error', onSpawnError);
          if (err) reject(err); else resolve(value!);
        };
        const onData = (chunk: Buffer) => {
          output = (output + chunk.toString('utf8')).slice(-MAX_TEXT);
          // Only a STRICT discovery-verified ready signal qualifies the publication.
          if (output.includes('OAuth discovery verified (resource matches published URL)') &&
              output.includes('MCP route ready')) {
            const match = output.match(/https:\/\/[^\s]+\/r\/[A-Za-z0-9_-]+\/mcp/g);
            const endpoint = match?.at(-1);
            if (endpoint && (!this.config.origin || endpoint.startsWith(this.config.origin))) {
              this.processes.set(name, child!);
              finish(undefined, { ok: true, message: 'Published with verified resource binding.', endpoint });
            }
          }
        };
        const onError = (_chunk: Buffer) => { /* stderr intentionally not exposed */ };
        const onExit = (code: number | null) => finish(new Error(`Ocliv exited before qualifying publication (code ${code})`));
        const onSpawnError = () => finish(new Error('Failed to start Ocliv publisher'));
        const timer = setTimeout(() => { child?.kill('SIGTERM'); finish(new Error('Publication readiness timed out')); }, 60000);
        child!.stdout.on('data', onData);
        child!.stderr.on('data', onError);
        child!.once('exit', onExit);
        child!.once('error', onSpawnError);
      });
      child.once('exit', () => this.processes.delete(name));
      return result;
    } catch (e) {
      child?.kill('SIGTERM');
      throw e;
    } finally {
      this.pending.delete(name);
    }
  }

  async revoke(publicationId: string, confirmation: string): Promise<OperationResult> {
    if (!ID.test(publicationId) || confirmation !== `REVOKE ${publicationId}`) throw new Error('Invalid publication or confirmation');
    const current = await this.list();
    const owned = current.find(p => p.publicationId === publicationId && p.state !== 'revoked');
    if (!owned) throw new Error('Publication is not owned by this enrolled Ocliv identity');
    await this.call(['mcp', 'unpublish', '--publication-id', publicationId], 15000);
    const child = this.processes.get(owned.name);
    if (child) child.kill('SIGTERM');
    const after = await this.list();
    const stillActive = after.some(p => p.publicationId === publicationId && p.state !== 'revoked');
    return {
      ok: !stillActive,
      message: stillActive ? 'Revocation not verified; investigate before declaring removal.' : 'Publication revoked at relay.',
    };
  }

  close() {
    for (const child of this.processes.values()) child.kill('SIGTERM');
    this.processes.clear();
  }
}

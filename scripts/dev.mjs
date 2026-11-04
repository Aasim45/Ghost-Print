import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const children = new Set();
let apiPort = 8000;
let webStarted = false;

function stop(code = 0) {
  for (const child of children) child.kill('SIGTERM');
  process.exit(code);
}

const api = spawn(process.execPath, ['code/server.js'], { cwd: root, stdio: ['inherit', 'pipe', 'inherit'] });
children.add(api);
api.stdout.on('data', chunk => {
  const output = chunk.toString();
  process.stdout.write(output);
  const match = output.match(/localhost:(\d+)/);
  if (match) {
    apiPort = Number(match[1]);
    if (!webStarted) {
      webStarted = true;
      const vite = spawn(process.execPath, ['node_modules/vite/bin/vite.js', '--host', '0.0.0.0'], {
        cwd: root,
        stdio: 'inherit',
        env: { ...process.env, GHOSTGUARD_API_TARGET: `http://127.0.0.1:${apiPort}` }
      });
      children.add(vite);
      vite.on('exit', code => { if (code && code !== 0) stop(code); });
    }
  }
});
api.on('exit', code => { if (!webStarted || (code && code !== 0)) stop(code || 1); });
process.on('SIGINT', () => stop(0));
process.on('SIGTERM', () => stop(0));

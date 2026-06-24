import { spawn, type ChildProcess } from 'node:child_process';
import { createReadStream, existsSync, statSync } from 'node:fs';
import { request as httpRequest } from 'node:http';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { createServer } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { extname, join, resolve } from 'node:path';

const ROOT_DIR = resolve(__dirname, '..', '..');
const STATIC_DIR = resolve(ROOT_DIR, 'frontend', 'dist');
const INDEX_HTML = join(STATIC_DIR, 'index.html');

const WEB_HOST = process.env.HOST || '0.0.0.0';
const WEB_PORT = Number(process.env.PORT || 3000);
const WORKER_PORT = Number(process.env.PY_WORKER_PORT || 5001);
const WORKER_URL = process.env.PY_WORKER_URL || `http://127.0.0.1:${WORKER_PORT}`;
const SHOULD_START_WORKER = process.env.START_PY_WORKER !== 'false' && !process.env.PY_WORKER_URL;

let pythonWorker: ChildProcess | null = null;
let shuttingDown = false;
let restartTimer: NodeJS.Timeout | null = null;

const mimeTypes: Record<string, string> = {
  '.css': 'text/css; charset=utf-8',
  '.gif': 'image/gif',
  '.html': 'text/html; charset=utf-8',
  '.ico': 'image/x-icon',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.js': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.map': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.svg': 'image/svg+xml',
  '.txt': 'text/plain; charset=utf-8',
  '.webp': 'image/webp',
  '.woff': 'font/woff',
  '.woff2': 'font/woff2',
};

const writeJson = (res: ServerResponse, status: number, payload: unknown) => {
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify(payload));
};

const safeDecodePath = (pathname: string) => {
  try {
    return decodeURIComponent(pathname);
  } catch {
    return '/';
  }
};

const serveFile = (filePath: string, res: ServerResponse) => {
  if (!existsSync(filePath) || !statSync(filePath).isFile()) {
    writeJson(res, 404, { error: 'not found' });
    return;
  }

  const ext = extname(filePath).toLowerCase();
  const contentType = mimeTypes[ext] || 'application/octet-stream';
  res.writeHead(200, {
    'content-type': contentType,
    'cache-control': ext === '.html' ? 'no-cache' : 'public, max-age=31536000, immutable',
  });
  createReadStream(filePath).pipe(res);
};

const serveStatic = (req: IncomingMessage, res: ServerResponse) => {
  const parsed = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`);
  const pathname = safeDecodePath(parsed.pathname);

  if (pathname === '/healthz') {
    writeJson(res, 200, {
      status: 'ok',
      web: 'node',
      worker: WORKER_URL,
      workerManaged: SHOULD_START_WORKER,
    });
    return;
  }

  const candidate = resolve(STATIC_DIR, `.${pathname}`);
  if (candidate.startsWith(STATIC_DIR) && existsSync(candidate) && statSync(candidate).isFile()) {
    serveFile(candidate, res);
    return;
  }

  serveFile(INDEX_HTML, res);
};

const proxyToWorker = (req: IncomingMessage, res: ServerResponse) => {
  const upstream = new URL(req.url || '/', WORKER_URL);
  const requestImpl = upstream.protocol === 'https:' ? httpsRequest : httpRequest;
  const headers = {
    ...req.headers,
    host: upstream.host,
    'x-forwarded-host': req.headers.host || '',
    'x-forwarded-proto': 'http',
  };

  const proxyReq = requestImpl(
    {
      protocol: upstream.protocol,
      hostname: upstream.hostname,
      port: upstream.port,
      method: req.method,
      path: `${upstream.pathname}${upstream.search}`,
      headers,
    },
    proxyRes => {
      res.writeHead(proxyRes.statusCode || 502, proxyRes.headers);
      proxyRes.pipe(res);
    },
  );

  proxyReq.on('error', error => {
    if (!res.headersSent) {
      writeJson(res, 502, {
        error: 'python worker unavailable',
        detail: error.message,
      });
      return;
    }
    res.destroy(error);
  });

  req.on('aborted', () => proxyReq.destroy());
  req.pipe(proxyReq);
};

const prefixWorkerLog = (source: 'stdout' | 'stderr', data: Buffer) => {
  const text = data.toString();
  for (const line of text.split(/\r?\n/)) {
    if (line.trim()) {
      const writer = source === 'stderr' ? console.error : console.log;
      writer(`[python-worker] ${line}`);
    }
  }
};

const startPythonWorker = () => {
  if (!SHOULD_START_WORKER || shuttingDown) return;
  const pythonBin = process.env.PYTHON || (process.platform === 'win32' ? 'python' : 'python3');

  pythonWorker = spawn(pythonBin, ['app.py'], {
    cwd: ROOT_DIR,
    env: {
      ...process.env,
      PORT: String(WORKER_PORT),
      HOST: '127.0.0.1',
      FLASK_DEBUG: '0',
      GYD_PYTHON_WORKER: '1',
      PYTHONUNBUFFERED: '1',
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  pythonWorker.stdout?.on('data', data => prefixWorkerLog('stdout', data));
  pythonWorker.stderr?.on('data', data => prefixWorkerLog('stderr', data));
  pythonWorker.on('close', code => {
    pythonWorker = null;
    if (!shuttingDown) {
      console.error(`[python-worker] exited with code ${code}; restarting in 2s`);
      restartTimer = setTimeout(startPythonWorker, 2000);
    }
  });
};

const stopPythonWorker = () => {
  if (restartTimer) {
    clearTimeout(restartTimer);
    restartTimer = null;
  }
  if (pythonWorker && !pythonWorker.killed) {
    pythonWorker.kill();
  }
};

startPythonWorker();

const server = createServer((req, res) => {
  if (req.url?.startsWith('/api/')) {
    proxyToWorker(req, res);
    return;
  }
  serveStatic(req, res);
});

server.listen(WEB_PORT, WEB_HOST, () => {
  console.log(`[web] listening on http://${WEB_HOST}:${WEB_PORT}`);
  console.log(`[web] proxying /api to ${WORKER_URL}`);
});

const shutdown = () => {
  if (shuttingDown) return;
  shuttingDown = true;
  server.close(() => {
    stopPythonWorker();
    process.exit(0);
  });
  setTimeout(() => {
    stopPythonWorker();
    process.exit(0);
  }, 5000).unref();
};

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);

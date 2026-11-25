import { once } from 'node:events';
import { readFile, readdir } from 'node:fs/promises';
import { createServer } from 'node:http';
import { extname } from 'node:path';
import { pathToFileURL } from 'node:url';
import { pages } from './pages.mjs';

const mime = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.woff2': 'font/woff2',
  '.webp': 'image/webp',
  '.txt': 'text/plain; charset=utf-8'
};

export async function servePreview(port = 0, output = new URL('./dist/', import.meta.url)) {
  const policy = await readFile(new URL('_headers', output), 'utf8');
  const headers = Object.fromEntries(policy.split(/\r?\n/)
    .filter(line => /^\s+\S/.test(line)).map(line => {
      const [name, ...value] = line.trim().split(':');
      return [name, value.join(':').trim()];
    }));
  const paths = new Map(Object.keys(pages).map(slug => [slug ? '/' + slug + '/' : '/',
    slug ? slug + '/index.html' : 'index.html']));
  for (const entry of await readdir(new URL('assets/', output), { withFileTypes: true })) {
    if (entry.isFile() && mime[extname(entry.name)]) paths.set('/assets/' + entry.name, 'assets/' + entry.name);
  }
  const server = createServer(async (request, response) => {
    if (!['GET', 'HEAD'].includes(request.method)) {
      response.writeHead(405, { ...headers, Allow: 'GET, HEAD' }).end();
      return;
    }
    const pathname = request.url.split('?')[0];
    if (!paths.has(pathname) && paths.has(pathname + '/') && pathname.startsWith('/')) {
      response.writeHead(308, { ...headers, Location: pathname + '/' }).end();
      return;
    }
    const asset = paths.get(pathname);
    const file = asset ?? '404.html';
    try {
      const content = await readFile(new URL(file, output));
      response.writeHead(asset ? 200 : 404, { ...headers, 'Content-Type': mime[extname(file)] });
      response.end(request.method === 'HEAD' ? undefined : content);
    } catch {
      response.writeHead(500, headers).end();
    }
  });
  server.listen(port, '127.0.0.1');
  await once(server, 'listening');
  return { server, url: 'http://127.0.0.1:' + server.address().port };
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  const { url } = await servePreview(Number(process.argv[2] ?? 4173));
  console.log('Local website preview at ' + url);
}

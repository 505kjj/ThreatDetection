import { once } from 'node:events';
import { byteLines } from '../phase5c/custody.mjs';
import { inspectHtml } from './parse.mjs';

let stage = 'framing';
let parseFailures = 0;
try {
  for await (const line of byteLines(process.stdin)) {
    stage = 'JSON decoding';
    const { id, html, url } = JSON.parse(line);
    stage = 'DOM inspection';
    let result;
    try {
      result = inspectHtml(html, url);
    } catch (error) {
      const frame = error.stack?.split('\n').slice(1, 4).flatMap(line => line.match(/[\w-]+\.(?:mjs|js):\d+:\d+/g) || []);
      if (++parseFailures <= 3) console.error('Parser error location ' + error.name + ' ' + frame.join(' '));
      result = { status: 'parser-error' };
    }
    stage = 'numeric output';
    if (!process.stdout.write(JSON.stringify({ id, ...result }) + '\n')) await once(process.stdout, 'drain');
    stage = 'framing';
  }
} catch (error) {
  const code = /^[A-Z0-9_]+$/.test(error.code ?? '') ? ' ' + error.code : '';
  console.error(`Offline HTML parser stopped during ${stage} (${error.name}${code}).`);
  process.exitCode = 1;
}

import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { resolve } from 'node:path';

export const revision = 'b9b4addf54ec3cae200e7b87dc05a4e5b57cd770';
export const blob = '637215825cb05723133cd2f0dfad1aafa84aa1c4';
const root = fileURLToPath(new URL('../../', import.meta.url));

export async function readDomainRegistry() {
  const bytes = execFileSync('git', ['show', revision + ':extension/financial-domains.mjs'], {
    cwd: root, maxBuffer: 32768
  });
  const actual = createHash('sha1').update('blob ' + bytes.length + '\0').update(bytes).digest('hex');
  if (actual !== blob) throw new Error('The reviewed Phase 4C registry blob differs');
  // The blob is a repository-pinned module consisting only of the verified registry.
  const { financialBrands } = await import('data:text/javascript;base64,' + bytes.toString('base64'));
  return { revision, blob, brands: financialBrands };
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  process.stdout.write(JSON.stringify(await readDomainRegistry()) + '\n');
}

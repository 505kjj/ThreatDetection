// The caller keeps raw rows, canonical URLs and identity digests in private memory.
import { createInterface } from 'node:readline';
import { once } from 'node:events';
import { extractUrl } from '../../evaluation/features.mjs';
import { destinationFor } from '../../extension/reputation.mjs';
import { detectImpersonation } from '../../extension/impersonation.mjs';
import { urlIdentity } from '../phase3g/validate.mjs';

export function project(url) {
  const identity = urlIdentity(url, 'real');
  if (!identity) return null;
  const parsed = extractUrl(url, 'real');
  return { identity, x: parsed.features, normalizedUrl: destinationFor(url).key,
    amber: detectImpersonation(parsed.host).length > 0 };
}

if (process.env.THREAT_PHASE3D_GUARDED !== '1') process.exit(1);
try {
  for await (const line of createInterface({ input: process.stdin })) {
    const result = line.length > 32768 ? null : project(JSON.parse(line));
    if (!process.stdout.write(JSON.stringify(result) + '\n')) await once(process.stdout, 'drain');
  }
} catch {
  process.stderr.write('Private URL projection failed.\n');
  process.exitCode = 1;
}

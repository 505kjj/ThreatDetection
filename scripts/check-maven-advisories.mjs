import { readFileSync } from 'node:fs';

const filename = process.argv[2];
if (!filename) throw new Error('Provide the Maven runtime dependency list');
const coordinates = new Map();
for (const line of readFileSync(filename, 'utf8').split(/\r?\n/)) {
  const match = /^\s*([^ :]+):([^ :]+):jar:(?:[^ :]+:)?([^ :]+):(runtime|compile)(?:\s|$)/.exec(line);
  if (!match) continue;
  const [, group, artifact, version] = match;
  const name = group + ':' + artifact;
  coordinates.set(name + '@' + version, { package: { ecosystem: 'Maven', name }, version });
}
const queries = [...coordinates.values()];
if (queries.length === 0) throw new Error('No Maven runtime coordinates found');

const response = await fetch('https://api.osv.dev/v1/querybatch', {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ queries }),
  signal: AbortSignal.timeout(45000)
});
if (!response.ok) throw new Error('OSV query failed with HTTP ' + response.status);
const { results } = await response.json();
if (!Array.isArray(results) || results.length !== queries.length) throw new Error('Incomplete OSV results');
let affected = 0;
for (const [i, result] of results.entries()) {
  if (!result.vulns?.length) continue;
  affected++;
  const { package: { name }, version } = queries[i];
  console.log(`${name}@${version}: ${result.vulns.map(item => item.id).join(', ')}`);
}
console.log(`${queries.length} Maven runtime coordinates checked, ${affected} with advisory matches.`);
if (affected > 0) process.exitCode = 1;

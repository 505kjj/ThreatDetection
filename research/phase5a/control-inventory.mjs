import { readFile, realpath, writeFile } from 'node:fs/promises';
import { basename, dirname, join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { sha256 } from '../../evaluation/features.mjs';
import { historical } from '../phase3g/validate.mjs';
import { compile, prepare } from './prepare.mjs';
import { assertOutsideGit } from './run.mjs';

const source = new URL('../../docs/experiments/phase5a/official-control-sources.json', import.meta.url);

export async function inventory(prior) {
  const bytes = await readFile(source);
  const index = JSON.parse(bytes.toString('utf8'));
  const annotation = 'sha256:' + sha256(bytes);
  const permissions = { evidence: annotation, internalResearch: true, aggregateReporting: true, modelTraining: false };
  const ledger = index.candidateControls.map(control => ({
    id: control.id, url: control.url, sourceId: 'project-review', sourceRecord: index.authority,
    label: 'legitimate', observedAt: index.observationDay,
    verification: { sourceId: 'rbi-listings', status: 'verified', label: 'legitimate',
      method: 'official-control', verifiedAt: index.observationDay, evidence: index.authority },
    target: { id: control.id, reviewSourceId: 'rbi-listings', verified: true, evidence: index.institutionEvidence }
  }));
  // Use the same row/evidence validation in memory. No candidates are emitted to a test partition.
  const config = compile({
    schemaVersion: 1, kind: 'real', dataset: index.dataset, revision: 'v1', seed: 'phase5a-controls',
    asOf: index.freezeAsOf, validationFrom: '2026-11-23', testFrom: index.observationDay,
    recordsSha256: sha256(ledger.map(row => JSON.stringify(row) + '\n').join('')),
    sources: [
      { id: 'project-review', publisher: 'ThreatDetection', provenance: annotation,
        license: index.rights, permission: permissions },
      { id: 'rbi-listings', publisher: 'Reserve Bank of India', provenance: index.authority,
        license: 'Public URL references only; website content excluded', permission: permissions }
    ],
    targets: index.candidateControls.map(control => ({ id: control.id, name: control.name,
      kind: 'financial-institution', reviewed: true, evidence: index.institutionEvidence }))
  });
  const { report } = prepare(ledger, config, prior);
  return { purpose: 'unpaired official negative control inventory; no evaluation or training partition',
    manifestSha256: sha256(bytes), observationDay: index.observationDay, candidateRows: ledger.length,
    usableLegitimate: report.partitions.test.rows, distinctRegistrableDomains: report.partitions.test.registrableDomains,
    financialConfirmed: report.partitions.test.labels.legitimate.financialConfirmed,
    excluded: report.excluded, missingMetadata: report.metadata,
    featureDistributions: report.partitions.test.labels.legitimate.features,
    tlds: report.partitions.test.labels.legitimate.tlds,
    priorGroupsChecked: prior.domains.size, priorLexicalFamiliesChecked: prior.families.size,
    classification: 'official listings checked; no credential entry, model scoring, or polling of listed endpoints' };
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    const [output, ...history] = process.argv.slice(2);
    if (history.length !== 5) throw new Error('A report path and five pinned prior projections are required');
    const parent = await assertOutsideGit(await realpath(dirname(resolve(output))));
    const inputs = await Promise.all(history.map(async path => assertOutsideGit(await realpath(path))));
    const result = await inventory(await historical(inputs));
    await writeFile(join(parent, basename(output)), JSON.stringify(result, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
    console.log(JSON.stringify({ usableLegitimate: result.usableLegitimate, distinctDomains: result.distinctRegistrableDomains }));
  } catch {
    console.error('Could not check the official control inventory against the private historical projections.');
    process.exitCode = 1;
  }
}

import { execFileSync } from 'node:child_process';
import { writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { financialBrands } from '../extension/financial-domains.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
const revisions = { phase5e: 'a09394b', phase5f: 'a09394b', phase5g: 'ebe0f4f', phase6a: '9908b49' };
function read(phase, name = 'results') {
  return JSON.parse(execFileSync('git', ['show', `${revisions[phase]}:docs/experiments/${phase}/${name}.json`],
    { cwd: root, encoding: 'utf8' }));
}

const fusion = read('phase5f');
const matched = read('phase5e').scale20k;
const grouping = fusion.grouped;
const resources = read('phase5f', 'resources');
const registry = read('phase5g', 'frozen-models');
const independent = read('phase5g', 'preflight');
const visual = read('phase6a');
const browser = read('phase6a', 'browser');
const visualSet = visual.realReferencesSyntheticTransformations;
const unrelated = Object.keys(visualSet.transformations.phash).filter(key => key.startsWith('unrelated-invented-')).length;

const models = Object.entries(grouping.evaluation).map(([id, result]) => {
  const point = result.atConstraints['0.01'];
  const timing = grouping.latency[id];
  return {
    id, threshold: point.threshold, recall: point.recall, precision: point.precision, f1: point.f1,
    urlFpr: point.falsePositiveRate, domainFpr: point.negativeDomainFalsePositiveRate,
    prAuc: result.prAucAveragePrecision, rocAuc: result.rocAuc,
    computeMs: timing.medianComputeMs, projectionMs: timing.medianWithProjectionMs,
    bytes: grouping.checkpointBytes[id]
  };
});

const methods = Object.entries(visualSet.transformations).map(([id, outcomes]) => {
  const sum = key => Object.values(outcomes).reduce((total, row) => total + (row[key] ?? 0), 0);
  const timing = visualSet.timing[id + 'EndToEndMs'];
  return { id, correct: sum('correct'), falseMatches: sum('false-match'),
    medianMs: timing.medianMs, p95Ms: timing.p95Ms, referenceBytes: visual.referenceStorage[id] };
});

const data = {
  revisions,
  financial: financialBrands.map(({ name, scopes, sharedHosts }) => ({ name, scopes, sharedHosts })),
  ml: {
    models, frozen: Object.keys(registry.models), validationRows: grouping.rows.validation,
    calibrationDomains: grouping.thresholds.fixed['0.01'].calibrationDomains,
    trainingResources: { seconds: resources.wallSeconds, peakBytes: resources.peakJobCommitBytes,
      logicalCpus: resources.logicalCpuAffinityCount },
    fresh: independent.freshIndependentRowsScored, paired: independent.freshPairedRowsScored,
    financialIndia: independent.independentFinancialPositives.india,
    financialOther: independent.independentFinancialPositives.outsideIndia
  },
  datasets: {
    splits: grouping.rows, classCounts: grouping.grouping.byPartitionNegativePositive,
    matchedRows: matched.audit.matched,
    usableRows: Object.values(matched.usable).reduce((total, partition) => total + partition.rows, 0),
    components: grouping.grouping.components, largestComponent: grouping.grouping.largestComponent,
    exactCollisionRows: fusion.collisionAudit.rows,
    phishvn: { license: independent.phishvn.release.license, release: independent.phishvn.release.version,
      lastObservation: independent.phishvn.release.lastEligibleSourceObservationDay,
      forwardStart: independent.phishvn.forwardWindowFirstDay, scored: independent.phishvn.rowsScored }
  },
  visual: {
    methods, references: Object.entries(visual.referenceCounts).filter(([, count]) => count > 0).map(([name]) => name),
    transformed: visualSet.rows - unrelated, unrelated, independentRows: visual.independentVisualRows,
    paired: visual.independentPairedRows, canvasParity: browser.canvasParityAt097,
    canvasMinimum: browser.minimumCanvasPreprocessCosine
  }
};

writeFileSync(new URL('../backend/src/main/resources/monitoring/research.json', import.meta.url),
  JSON.stringify(data, null, 2) + '\n');

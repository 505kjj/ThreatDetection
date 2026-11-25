import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { financialBrands } from '../extension/financial-domains.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
const revisions = {
  phase3b: 'b917d231ec251208debf6ab7138af73135b24801', phase3c: 'a09394b', phase3d: 'a09394b',
  phase3e: 'a09394b', phase3f: 'a09394b', phase5b: 'a09394b', phase5c: 'a09394b', phase5d: 'a09394b',
  phase5e: 'a09394b', phase5f: 'a09394b', phase5g: 'ebe0f4f', phase6a: '9908b49'
};
function readSource(phase, file) {
  const directory = phase === 'phase3b' ? 'phiusiil' : phase;
  return execFileSync('git', ['show', `${revisions[phase]}:docs/experiments/${directory}/${file}`],
    { cwd: root, encoding: 'utf8' });
}
const read = (phase, name = 'results') => JSON.parse(readSource(phase, name + '.json'));

const fusion = read('phase5f');
const content = read('phase5e');
const matched = content.scale20k;
const grouping = fusion.grouped;
const resources = read('phase5f', 'resources');
const registry = read('phase5g', 'frozen-models');
const independent = read('phase5g', 'preflight');
const visual = read('phase6a');
const browser = read('phase6a', 'browser');
const visualSet = visual.realReferencesSyntheticTransformations;
const unrelated = Object.keys(visualSet.transformations.phash).filter(key => key.startsWith('unrelated-invented-')).length;

function point(result) {
  if (!Number.isFinite(result?.threshold)) return null;
  return {
    threshold: result.threshold, recall: result.recall, precision: result.precision, f1: result.f1,
    urlFpr: result.falsePositiveRate, domainFpr: result.negativeDomainFalsePositiveRate,
    domainFprUpper: result.negativeDomainFpr95Upper
  };
}

function model(id, result, {points = result.atConstraints, computeMs, projectionMs, bytes, fitSeconds, training} = {}) {
  return {
    id, training, prAuc: result.prAucAveragePrecision, rocAuc: result.rocAuc, computeMs, projectionMs, bytes, fitSeconds,
    points: Object.fromEntries(Object.entries({ '0.5': result.atHalf, ...points })
      .map(([target, value]) => [target, point(value)]).filter(([, value]) => value))
  };
}

const cohorts = [];
function cohort(id, phase, name, dataset, support, description, models, calibration) {
  cohorts.push({ id, phase, revision: revisions[phase], name, dataset, rows: support.rows,
    positive: support.positive, description, models, calibration });
}

const phresh = 'PhreshPhish v1.0.1';
const uci = 'UCI PhiUSIIL';
const holdout = read('phase3b', 'holdout-report');
cohort('uci-holdout', 'phase3b', 'Numerical holdout', uci,
  {rows: holdout.holdout.phishing + holdout.holdout.legitimate, positive: holdout.holdout.phishing},
  'Reserved UCI holdout scored after candidate and cutoff freeze. Numerical URL features.',
  Object.entries(holdout.metrics).map(([id, result]) => {
    const artifact = holdout.artifacts[id];
    const points = Object.fromEntries(result.strict.map(({calibration, holdout}) => [calibration.targetNegativeDomainFpr, holdout]));
    return model(id, {...result, atHalf: result.default}, {points, bytes: artifact.bytes,
      fitSeconds: artifact.finalFitSeconds, computeMs: result.modelOnlyLatency.singleP50Microseconds / 1000, training: uci});
  }), 'UCI development calibration');

const transfer = read('phase3c', 'frozen-transfer');
const transferSupport = transfer.models.random_forest.thresholdMetrics;
cohort('phresh-transfer', 'phase3c', 'Frozen UCI models on PhreshPhish', phresh,
  {rows: transferSupport.tp + transferSupport.fp + transferSupport.tn + transferSupport.fn,
    positive: transferSupport.tp + transferSupport.fn},
  'September to December 2025 test cohort after excluding UCI domain overlap. The original UCI cutoffs were applied unchanged.',
  Object.entries(transfer.models).map(([id, result]) => model(id, {...result, atHalf: result.thresholdMetrics},
    {points: Object.fromEntries(result.phase3bCutoffs.map(({target, results}) => [target, results])), training: uci})),
  'Original UCI development calibration');

const crossSource = read('phase3d', 'summary');
const reserved = crossSource.dataset.partitions.test;
cohort('phresh-chronological', 'phase3d', 'Cross-source training comparisons', phresh,
  {rows: reserved.rows, positive: reserved.phishing},
  `Chronological holdout from ${reserved.firstDay} to ${reserved.lastDay}. Domain and lexical-family exclusions were applied. Each training budget was balanced at 20,000 rows.`,
  Object.entries(crossSource.candidates).filter(([id]) => /^(uci|phresh|mixed)-20000-host-/.test(id)).map(([id, value]) => {
    const [, source, family] = /^(uci|phresh|mixed)-20000-host-(.+)$/.exec(id);
    const names = {uci, phresh, mixed: 'UCI + PhreshPhish'};
    const result = value.final;
    return model(family, {...result.test, atHalf: result.testAtHalf}, {
      points: Object.fromEntries(result.testAtCutoffs.map((entry, index) =>
        [value.fit.cutoffs[index].targetNegativeDomainFpr, entry])),
      training: names[source], bytes: value.fit.modelBytes, fitSeconds: value.fit.fitSeconds, computeMs: result.predictionMedianMs
    });
  }), 'Phase 3D PhreshPhish validation');

for (const phase of ['phase3e', 'phase3f']) {
  const report = read(phase, 'summary');
  for (const [key, {support, candidates}] of Object.entries(report.cohorts)) {
    const positives = support.phishing > 0;
    cohort(phase + '-' + key, phase, positives ? 'Historical positive-only transfer' : 'Official benign financial controls',
      positives ? 'Historical phishing archive' : 'Official Indian financial controls',
      {rows: support.phishing + support.legitimate, positive: support.phishing},
      `Evidence dates ${support.firstDay} to ${support.lastDay}. ${positives
        ? 'This positive-only transfer can measure recall. False-positive rates and ranking are unavailable.'
        : 'These reviewed controls span a small set of domains. Recall and ranking are unavailable.'}`,
      Object.entries(candidates).map(([id, result]) => model(id, result.ranking ?? {},
        {points: Object.fromEntries(Object.entries(result.cutoffs).map(([target, receipt]) => [target, receipt.metrics]))})),
      'Frozen Phase 3D development cutoffs');
  }
}

const sequence = read('phase5c', 'metrics')[20000];
const sequenceValidation = sequence[0].evaluation.validation;
cohort('sequence-validation', 'phase5c', 'Matched URL and sequence baselines', phresh,
  {rows: sequenceValidation.rows, positive: sequenceValidation.phishing},
  'Retrospective PhreshPhish development validation. All candidates used the same 20,000 training rows.',
  sequence.map(row => model(row.model, row.evaluation.validation, {training: phresh, bytes: row.modelBytes,
    points: row.evaluation.validation.atCalibratedConstraints, computeMs: row.latencyMedianMs, fitSeconds: row.fitSeconds})),
  'Separate PhreshPhish calibration');

// The public Phase 5B report includes rounded fixed-cutoff results and batch timings.
const phase5b = readSource('phase5b', 'README.md').split(/\r?\n/)
  .filter(line => /^\| (UCI|Phresh|Mixed) 20k \|/.test(line))
  .map(line => line.split('|').slice(1, -1).map(field => field.trim()));
for (const [view, dataset, rows, positive] of [
  ['UCI val', uci, 37269, 16980],
  ['Phresh val', phresh, crossSource.dataset.partitions.validation.rows, crossSource.dataset.partitions.validation.phishing]
]) {
  const models = phase5b.filter(fields => fields[2] === view).map(fields => {
    const [training, family, , prAuc, rocAuc, precision, recall, f1, urlFpr, , fit, size, batch] = fields;
    const id = {Logistic: 'logistic', Forest: 'forest', XGBoost: 'xgboost'}[family];
    const source = {'UCI 20k': uci, 'Phresh 20k': phresh, 'Mixed 20k': 'UCI + PhreshPhish'}[training];
    return {...model(id, {prAucAveragePrecision: Number(prAuc), rocAuc: Number(rocAuc), atHalf: {
      threshold: 0.5, precision: Number(precision), recall: Number(recall), f1: Number(f1), falsePositiveRate: Number(urlFpr)
    }}, {training: source, fitSeconds: Number(fit), bytes: Number(size.replaceAll(',', ''))}),
    batchMs: Number(batch)};
  });
  if (!models.length) throw new Error('Phase 5B publication table changed');
  cohort('retraining-' + view.split(' ')[0].toLowerCase(), 'phase5b', 'Controlled numerical retraining', dataset,
    {rows, positive}, 'Previously used development validation. Published rounded values use score 0.5. Batch timing covers model scoring per URL.',
    models);
}

const url = read('phase5d');
const matchedUrl = url.matched[20000];
function urlModel(id, row, evaluation, training = phresh) {
  return model(id, evaluation, {training, computeMs: row.latency?.medianMs ?? row.originalBenchmark?.latencyMedianMs,
    bytes: row.fit?.modelBytes ?? row.originalBenchmark?.modelBytes ?? row.componentCheckpointBytes,
    fitSeconds: row.fit?.fitSeconds ?? row.originalBenchmark?.fitSeconds ?? row.fitSeconds});
}
for (const [key, dataset, name] of [
  ['validation', phresh, 'Transformer and URL ensemble'],
  ['uci-validation', uci, 'Cross-dataset transfer with source cutoffs']
]) {
  const entries = [...Object.entries(matchedUrl), ['url-weighted-75', url.fusion]];
  cohort(key + '-5d', 'phase5d', name, dataset, matchedUrl.ngram.evaluation[key],
    'Retrospective validation. Source models used 20,000 matched training rows. The 75:25 TF-IDF and XGBoost blend used a separate fusion fit.',
    entries.map(([id, row]) => urlModel(id, row, row.evaluation[key])), 'Separate PhreshPhish calibration');
}
const adaptation = Object.entries(url.adaptation.experiments);
cohort('uci-adapted', 'phase5d', 'UCI target calibration', uci, adaptation[0][1].targetCalibrated,
  'Same UCI validation URLs as source transfer. Only the source-balanced TF-IDF model changes training composition.',
  adaptation.map(([id, row]) => urlModel(id, row.fit ? row : matchedUrl[id], row.targetCalibrated,
    id === 'mixed' ? 'UCI + PhreshPhish' : phresh)),
  `Separate target calibration on ${url.adaptation.calibrationRows.toLocaleString('en-US')} UCI development rows`);

for (const key of ['near', 'far']) {
  const [first, last] = url.dataAudit.temporal.observedDateRanges[key];
  cohort('temporal-' + key, 'phase5d', `Temporal ${key} window`, phresh, url.temporal.transformer.evaluation[key],
    `Chronological validation from ${first} to ${last} after separate training, tuning and calibration. The windows have different class balances.`,
    Object.entries(url.temporal).map(([id, row]) => urlModel(id, row, row.evaluation[key])),
    'Phase 5D chronological calibration window');
}

cohort('content-matched', 'phase5e', 'Matched URL and DOM models', phresh, matched.usable.validation,
  'Retrospective comparison on identical matched rows. Some numerical DOM vectors also appear in training.',
  Object.entries(matched.models).filter(([id]) => !id.startsWith('ablation-')).map(([id, row]) =>
    model(id, row.evaluation, {training: phresh, computeMs: row.latency.inference.medianMs,
      projectionMs: row.latency.endToEndPairedStageMs?.medianMs,
      bytes: row.fit.modelBytes ?? row.fit.componentModelBytes, fitSeconds: row.fit.fitSeconds})),
  'Separate Phase 5E matched calibration');
cohort('content-unseen', 'phase5e', 'Unseen exact DOM vectors', phresh, content.sensitivity.coverage,
  `Sensitivity comparison after excluding ${content.sensitivity.coverage.excludedRepeatedVectors.toLocaleString('en-US')} numerical validation vectors repeated in training. Broader template similarity can remain.`,
  [['url-ngram', content.sensitivity.url], ['url-dom-fusion', content.sensitivity.urlDomBlend]]
    .map(([id, result]) => model(id, result, {training: phresh})), 'Separately calibrated unseen-vector comparison');

const models = Object.entries(grouping.evaluation).map(([id, result]) => {
  const point = result.atConstraints['0.01'];
  const timing = grouping.latency[id];
  return {
    id, threshold: point.threshold, recall: point.recall, precision: point.precision, f1: point.f1,
    urlFpr: point.falsePositiveRate, domainFpr: point.negativeDomainFalsePositiveRate,
    domainFprUpper: point.negativeDomainFpr95Upper,
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
  browserResearch: JSON.parse(readFileSync(new URL('../docs/experiments/phase6c/browser-summary.json', import.meta.url), 'utf8')),
  securityResearch: JSON.parse(readFileSync(new URL('../docs/experiments/phase6e/summary.json', import.meta.url), 'utf8')),
  scalabilityResearch: JSON.parse(readFileSync(new URL('../docs/experiments/phase7c/summary.json', import.meta.url), 'utf8')),
  financial: financialBrands.map(({ name, scopes, sharedHosts }) => ({ name, scopes, sharedHosts })),
  ml: {
    models, cohorts, frozen: Object.keys(registry.models), validationRows: grouping.rows.validation,
    validationPositive: grouping.evaluation.fixed.positive,
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

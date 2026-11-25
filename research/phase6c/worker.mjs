import { createNgramScorer } from './ngram.mjs';
import { extractBrowserUrl } from './url-features.mjs';
import { destinationFor } from './reputation.mjs';
import { parse } from './tldts.mjs';
import { createXgboostScorer } from './xgboost.mjs';

let ready;
const treeModels = new Map();
async function treeScorer(name) {
  if (!treeModels.has(name)) {
    const pending = fetch(chrome.runtime.getURL(`${name}.json`)).then(response => {
      if (!response.ok) throw new Error('Model unavailable');
      return response.json();
    }).then(createXgboostScorer).catch(error => { treeModels.delete(name); throw error; });
    treeModels.set(name, pending);
  }
  return treeModels.get(name);
}
async function scorer() {
  if (!ready) {
    ready = (async () => {
      const start = performance.now();
      const response = await fetch(chrome.runtime.getURL('model.json'));
      if (!response.ok) throw new Error('Model unavailable');
      const model = await response.json();
      return { score: createNgramScorer(model), initializationMs: performance.now() - start };
    })().catch(error => { ready = undefined; throw error; });
  }
  return ready;
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (sender.id !== chrome.runtime.id || !['synthetic-inference', 'synthetic-url', 'synthetic-trees'].includes(message?.type) ||
      !Array.isArray(message.inputs) || message.inputs.length > 1000) return false;
  (async () => {
    if (message.type === 'synthetic-trees') {
      if (!['url', 'dom'].includes(message.model)) throw new Error('Unknown model');
      const predict = await treeScorer(message.model);
      const durations = [];
      const scores = message.inputs.map(input => {
        const start = performance.now();
        const value = predict(input);
        durations.push(performance.now() - start);
        return value;
      });
      return { scores, durations };
    }
    const loaded = await scorer();
    const durations = [];
    const scores = message.inputs.map(input => {
      const start = performance.now();
      const projected = message.type === 'synthetic-url' ? extractBrowserUrl(input, 'synthetic', destinationFor, parse) : null;
      const value = message.type === 'synthetic-url'
        ? projected && { features: projected.features, score: loaded.score(projected.normalizedUrl) }
        : loaded.score(input);
      durations.push(performance.now() - start);
      return value;
    });
    return { scores, durations, initializationMs: loaded.initializationMs };
  })().then(sendResponse, error => sendResponse({ error: error.message }));
  return true;
});

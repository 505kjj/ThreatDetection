import { createNgramScorer } from './ngram.mjs';

let ready;
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
  if (sender.id !== chrome.runtime.id || message?.type !== 'synthetic-inference' ||
      !Array.isArray(message.inputs) || message.inputs.length > 1000) return false;
  (async () => {
    const loaded = await scorer();
    const durations = [];
    const scores = message.inputs.map(input => {
      const start = performance.now();
      const value = loaded.score(input);
      durations.push(performance.now() - start);
      return value;
    });
    return { scores, durations, initializationMs: loaded.initializationMs };
  })().then(sendResponse, error => sendResponse({ error: error.message }));
  return true;
});

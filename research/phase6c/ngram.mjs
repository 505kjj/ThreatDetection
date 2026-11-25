// Offline research only. This module does not make a browser protection decision.
export function createNgramScorer(model) {
  if (model.schema !== 'phase6c-char-tfidf-logistic-v1' ||
      model.terms.length !== model.idf.length || model.terms.length !== model.coefficients.length) {
    throw new TypeError('Invalid frozen n-gram model');
  }
  const vocabulary = new Map(model.terms.map((term, index) => [term, index]));
  return function score(text) {
    if (typeof text !== 'string' || text.length > 8192) throw new TypeError('Invalid model input');
    // sklearn's character analyzer collapses runs of two or more whitespace characters.
    const characters = Array.from(text.replace(/\s\s+/gu, ' '));
    const counts = new Map();
    for (let size = 2; size <= 5; size++) {
      for (let start = 0; start + size <= characters.length; start++) {
        const index = vocabulary.get(characters.slice(start, start + size).join(''));
        if (index !== undefined) counts.set(index, (counts.get(index) ?? 0) + 1);
      }
    }
    let norm = 0;
    let product = 0;
    for (const [index, count] of counts) {
      const value = (1 + Math.log(count)) * model.idf[index];
      norm += value * value;
      product += value * model.coefficients[index];
    }
    const logit = model.intercept + (norm ? product / Math.sqrt(norm) : 0);
    return 1 / (1 + Math.exp(-logit));
  };
}

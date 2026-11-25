// Research-only evaluation of frozen binary logistic XGBoost trees.
export function createXgboostScorer(model) {
  if (model.schema !== 'phase6c-xgboost-v1' || !Number.isInteger(model.features) ||
      !(model.baseScore > 0 && model.baseScore < 1) || !Array.isArray(model.trees)) {
    throw new TypeError('Invalid frozen XGBoost model');
  }
  return function score(features) {
    if (!Array.isArray(features) || features.length !== model.features ||
        features.some(value => typeof value !== 'number' || !Number.isFinite(value))) {
      throw new TypeError('Invalid feature vector');
    }
    let total = Math.fround(Math.log(model.baseScore / (1 - model.baseScore)));
    for (const tree of model.trees) {
      let node = tree;
      while (node.leaf === undefined) {
        const feature = Number(node.split.slice(1));
        const target = Math.fround(features[feature]) < Math.fround(node.split_condition) ? node.yes : node.no;
        node = node.children.find(child => child.nodeid === target);
        if (!node) throw new Error('Invalid frozen tree');
      }
      total = Math.fround(total + Math.fround(node.leaf));
    }
    return 1 / (1 + Math.exp(-total));
  };
}

const MAX_HOST_GROUPS = 800;
const HOST_GROUP_LENGTH = 220;
const MAX_PATHS = 160;
const BYPASS_SLOTS = 32;
const FIRST_BYPASS_RULE = 5001;
const MAIN_FRAME = ['main_frame'];

const escapeRegex = value => value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

export function blockRules(snapshot) {
  const rules = [];
  const add = condition => rules.push({ id: rules.length + 1, priority: 1, action: { type: 'block' },
    condition: { ...condition, resourceTypes: MAIN_FRAME } });
  if (!snapshot) return rules;
  let group = '';
  const addHosts = () => {
    if (group && rules.length < MAX_HOST_GROUPS) {
      add({ regexFilter: '^https?://(?:[^/?#@]*@)?(?:' + group + ')(?:\\.)?(?::[0-9]+)?(?:[/?]|$)' });
    }
  };
  for (const host of snapshot.hosts.keys()) {
    const label = escapeRegex(host);
    if (group && group.length + label.length + 1 > HOST_GROUP_LENGTH) {
      addHosts();
      if (rules.length === MAX_HOST_GROUPS) break;
      group = '';
    }
    group += (group ? '|' : '') + label;
  }
  addHosts();
  for (const key of Array.from(snapshot.urlPaths.keys()).slice(0, MAX_PATHS)) {
    add({ regexFilter: '^' + escapeRegex(key) + '(?:\\?.*)?$', isUrlFilterCaseSensitive: true });
  }
  return rules;
}

export function bypassRule(id, tabId, extensionId, key) {
  return { id, priority: 2, action: { type: 'allow' },
    condition: { tabIds: [tabId], initiatorDomains: [extensionId], requestMethods: ['get'],
      resourceTypes: MAIN_FRAME, regexFilter: '^' + escapeRegex(key) + '$', isUrlFilterCaseSensitive: true } };
}

export function createBlockRules(api, extensionId, now = Date.now) {
  let queue = Promise.resolve();
  let installed;
  let installedIds = [];
  let initialized = false;
  const bypasses = new Map();

  function update(work) {
    const result = queue.then(work);
    queue = result.catch(() => {});
    return result;
  }

  async function initialize() {
    if (initialized) return;
    const existing = await api.getSessionRules();
    const abandoned = existing.filter(rule => rule.id >= FIRST_BYPASS_RULE).map(rule => rule.id);
    if (abandoned.length) await api.updateSessionRules({ removeRuleIds: abandoned });
    installedIds = existing.filter(rule => rule.id < FIRST_BYPASS_RULE).map(rule => rule.id);
    initialized = true;
  }

  function setSnapshot(snapshot, resetBypasses = false) {
    return update(async () => {
      await initialize();
      const current = snapshot?.expires > now() ? snapshot : null;
      if (!resetBypasses && installed === current) return;
      const addRules = blockRules(current);
      const removeRuleIds = [...installedIds];
      if (resetBypasses || current !== installed) {
        removeRuleIds.push(...Array.from(bypasses.values(), value => value.ruleId));
      }
      try {
        await api.updateSessionRules({ removeRuleIds, addRules });
      } catch (error) {
        // Chrome makes rule replacement atomic. Clear previous rules if the replacement was rejected.
        await api.updateSessionRules({ removeRuleIds });
        installedIds = [];
        installed = null;
        bypasses.clear();
        throw error;
      }
      bypasses.clear();
      installedIds = addRules.map(rule => rule.id);
      installed = current;
    });
  }

  function revoke(tabId) {
    return update(async () => {
      const bypass = bypasses.get(tabId);
      if (!bypass) return;
      await api.updateSessionRules({ removeRuleIds: [bypass.ruleId] });
      bypasses.delete(tabId);
    });
  }

  function allowOnce(tabId, key, deadline) {
    return update(async () => {
      if (!installed || installed.expires <= now() || deadline <= now() ||
          bypasses.has(tabId) || bypasses.size >= BYPASS_SLOTS) return false;
      const used = new Set(Array.from(bypasses.values(), value => value.ruleId));
      let ruleId = FIRST_BYPASS_RULE;
      while (used.has(ruleId)) ruleId++;
      await api.updateSessionRules({ addRules: [bypassRule(ruleId, tabId, extensionId, key)] });
      bypasses.set(tabId, { ruleId, key, deadline });
      return true;
    });
  }

  return { setSnapshot, revoke, allowOnce,
    snapshot: () => installed?.expires > now() ? installed : null,
    bypass: tabId => bypasses.get(tabId) };
}

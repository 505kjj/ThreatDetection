import schema from './feature-schema.json' with { type: 'json' };

// Structural metadata shared by the inert parser and the synthetic browser check.
export function describeDOM(root, pageUrl, adapter) {
  const origin = new URL(pageUrl).origin;
  const counts = {
    elements: 0, depth: 0, hidden: 0, templates: 0, forms: 0, forms_post: 0,
    actions_local: 0, actions_external: 0, actions_other: 0, actions_http: 0,
    inputs: 0, inputs_password: 0, inputs_email: 0, inputs_hidden: 0, inputs_payment: 0,
    inputs_otp: 0, password_forms: 0, payment_forms: 0, unassociated_password: 0,
    iframe: 0, iframe_external: 0, iframe_sandbox: 0, iframe_srcdoc: 0,
    links: 0, links_external_ratio: 0, links_other: 0, scripts: 0,
    scripts_inline: 0, scripts_external: 0, scripts_other: 0,
    refresh: 0, refresh_external: 0, title_length: 0, title_brand: 0, title_login: 0, title_payment: 0
  };
  const elements = [];
  const parents = new Map();
  const stack = [[root, 0, null]];
  const maximumElements = 16000;
  const maximumDepth = 128;
  while (stack.length) {
    const [node, depth, parentForm] = stack.pop();
    const tag = adapter.tag(node);
    let owner = parentForm;
    if (tag) {
      if (++counts.elements > maximumElements || depth > maximumDepth) throw new RangeError('DOM structure exceeds limits');
      counts.depth = Math.max(counts.depth, depth);
      elements.push([node, tag]);
      if (tag === 'form') owner = node;
      if (tag === 'input') parents.set(node, owner);
    }
    const children = adapter.children(node);
    for (let i = children.length - 1; i >= 0; i--) stack.push([children[i], depth + 1, owner]);
  }

  const attr = adapter.attr;
  const target = (value, base, blank = false) => {
    if (value === null || (!blank && !value.trim())) return null;
    try {
      const url = new URL(value, base);
      return ['http:', 'https:'].includes(url.protocol) ? url : null;
    } catch {
      return null;
    }
  };
  const baseElement = elements.find(([node, tag]) => tag === 'base' && attr(node, 'href') !== null);
  const base = (baseElement && target(attr(baseElement[0], 'href'), pageUrl, true)) || pageUrl;
  const formsById = new Map();
  for (const [node] of elements) {
    const id = attr(node, 'id');
    if (id && !formsById.has(id)) formsById.set(id, node);
  }
  const passwordForms = new Set();
  const paymentForms = new Set();
  let externalLinks = 0;
  let webLinks = 0;
  let titled = false;
  for (const [node, tag] of elements) {
    const style = attr(node, 'style') || '';
    if (attr(node, 'hidden') !== null || attr(node, 'aria-hidden')?.toLowerCase() === 'true' ||
        /(?:^|;)\s*(?:display\s*:\s*none|visibility\s*:\s*hidden)\s*(?:!important)?\s*(?:;|$)/i.test(style)) counts.hidden++;
    if (tag === 'template') counts.templates++;
    if (tag === 'form') {
      counts.forms++;
      if (attr(node, 'method')?.toLowerCase() === 'post') counts.forms_post++;
      const action = attr(node, 'action')?.trim();
      const resolved = action ? target(action, base) : new URL(pageUrl);
      if (!resolved) counts.actions_other++;
      else {
        if (resolved.origin === origin) counts.actions_local++;
        else counts.actions_external++;
        if (resolved.protocol === 'http:') counts.actions_http++;
      }
    } else if (tag === 'input') {
      counts.inputs++;
      const type = attr(node, 'type')?.toLowerCase();
      const token = (attr(node, 'autocomplete') || '').toLowerCase().split(/\s+/);
      const formId = attr(node, 'form');
      const specified = formId === null ? parents.get(node) : formsById.get(formId);
      const owner = specified && adapter.tag(specified) === 'form' ? specified : null;
      if (type === 'password') {
        counts.inputs_password++;
        if (owner) passwordForms.add(owner);
        else counts.unassociated_password++;
      }
      if (type === 'email') counts.inputs_email++;
      if (type === 'hidden') counts.inputs_hidden++;
      if (token.some(t => /^cc-(?:name|number|exp(?:-month|-year)?|csc|type)$/.test(t))) {
        counts.inputs_payment++;
        if (owner) paymentForms.add(owner);
      }
      if (token.includes('one-time-code')) counts.inputs_otp++;
    } else if (tag === 'iframe') {
      counts.iframe++;
      const src = target(attr(node, 'src'), base);
      if (src && src.origin !== origin) counts.iframe_external++;
      if (attr(node, 'sandbox') !== null) counts.iframe_sandbox++;
      if (attr(node, 'srcdoc') !== null) counts.iframe_srcdoc++;
    } else if (tag === 'a' && attr(node, 'href') !== null) {
      counts.links++;
      const link = target(attr(node, 'href'), base, true);
      if (!link) counts.links_other++;
      else {
        webLinks++;
        if (link.origin !== origin) externalLinks++;
      }
    } else if (tag === 'script') {
      counts.scripts++;
      const value = attr(node, 'src');
      const src = target(value, base);
      if (value === null) counts.scripts_inline++;
      else if (!src) counts.scripts_other++;
      else if (src.origin !== origin) counts.scripts_external++;
    } else if (tag === 'meta' && attr(node, 'http-equiv')?.toLowerCase() === 'refresh') {
      counts.refresh++;
      const destination = (attr(node, 'content') || '').match(/;\s*url\s*=\s*["']?([^"']+)/i);
      const url = destination && target(destination[1].trim(), base);
      if (url && url.origin !== origin) counts.refresh_external++;
    } else if (tag === 'title' && !titled) {
      titled = true;
      const title = adapter.text(node).trim().slice(0, 512);
      counts.title_length = title.length;
      counts.title_brand = Number(/\b(?:paypal|visa|mastercard|google|microsoft|apple|sbi|hdfc|icici|paytm|phonepe)\b/i.test(title));
      counts.title_login = Number(/\b(?:login|log\s*in|sign\s*in|authenticate|authentication)\b/i.test(title));
      counts.title_payment = Number(/\b(?:pay|payment|checkout|billing|invoice)\b/i.test(title));
    }
  }
  counts.links_external_ratio = webLinks ? externalLinks / webLinks : 0;
  counts.password_forms = passwordForms.size;
  counts.payment_forms = paymentForms.size;
  return counts;
}

export const FEATURE_GROUPS = schema.groups;

import { defaultTreeAdapter, parse } from 'parse5';
import { describeDOM } from './dom.mjs';

export const MAX_BYTES = 1024 * 1024;
const TRUNCATED = new Set(['eof-in-tag', 'eof-in-comment', 'eof-in-doctype',
  'eof-in-element-that-can-contain-only-text', 'eof-in-script-html-comment-like-text']);
const adapter = {
  tag: node => node.tagName,
  attr: (node, name) => node.attrs?.find(attr => attr.name === name)?.value ?? null,
  children: node => node.childNodes ?? [],
  text: node => (node.childNodes ?? []).map(child => child.value ?? '').join('')
};

export function inspectHtml(html, url) {
  if (typeof html !== 'string' || !html.trim()) return { status: 'missing' };
  if (Buffer.byteLength(html) > MAX_BYTES) return { status: 'oversized' };
  let created = 0;
  let malformed = false;
  let truncated = false;
  const treeAdapter = {
    ...defaultTreeAdapter,
    createElement(tag, ns, attributes) {
      if (++created > 16000) throw new RangeError('Parse tree exceeds limits');
      const attrs = attributes.filter(({ name }) => !['value', 'password'].includes(name))
        .map(attr => attr.name === 'srcdoc' ? { ...attr, value: '' } : attr);
      return defaultTreeAdapter.createElement(tag, ns, attrs);
    },
    createCommentNode: () => defaultTreeAdapter.createCommentNode(''),
    insertText(node, text) {
      // The parser tracks locations on its text nodes, so retain an empty
      // node where other text, including textarea and script text, was discarded.
      defaultTreeAdapter.insertText(node, node.tagName === 'title' ? text.slice(0, 512) : '');
    },
    insertTextBefore(parent, text, reference) {
      defaultTreeAdapter.insertTextBefore(parent, parent.tagName === 'title' ? text.slice(0, 512) : '', reference);
    }
  };
  try {
    const start = process.hrtime.bigint();
    const tree = parse(html, {
      scriptingEnabled: true, treeAdapter,
      onParseError({ code }) {
        if (code !== 'missing-doctype') malformed = true;
        if (TRUNCATED.has(code)) truncated = true;
      }
    });
    const middle = process.hrtime.bigint();
    if (truncated) return { status: 'truncated' };
    const features = describeDOM(tree, url, adapter);
    return { status: 'usable', malformed, features,
      parseMs: Number(middle - start) / 1e6, extractMs: Number(process.hrtime.bigint() - middle) / 1e6 };
  } catch (error) {
    if (error instanceof RangeError) return { status: 'structure-limit' };
    throw error;
  }
}

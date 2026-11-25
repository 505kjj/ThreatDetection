// Inert research helper. It returns DOM element references only to its caller.
export function locateCandidates(document, limit = 24) {
  if (!Number.isInteger(limit) || limit < 1 || limit > 100) throw new RangeError('Invalid candidate limit');
  const nodes = document.querySelectorAll('img, svg, [style*="background-image"]');
  if (nodes.length > 2000) return { status: 'unavailable', reason: 'candidate-budget', candidates: [] };
  const candidates = [];
  for (const element of nodes) {
    const bounds = element.getBoundingClientRect();
    if (bounds.width < 16 || bounds.height < 12 || bounds.width > 1200 || bounds.height > 600) continue;
    const style = document.defaultView?.getComputedStyle(element);
    if (style && (style.display === 'none' || style.visibility !== 'visible' || Number(style.opacity) === 0)) continue;
    const metadata = [element.getAttribute('alt'), element.getAttribute('aria-label'),
      element.getAttribute('class'), element.getAttribute('id')].filter(Boolean).join(' ').slice(0, 512);
    const header = Boolean(element.closest('header, nav, [role="banner"], [role="navigation"]'));
    const logoLabel = /\b(?:logo|brand|wordmark)\b/i.test(metadata);
    if (!header && !logoLabel) continue;
    const kind = element.localName === 'img' ? 'image' : element.localName === 'svg' ? 'svg' : 'background';
    candidates.push({ element, kind, header, logoLabel, width: bounds.width, height: bounds.height });
  }
  candidates.sort((a, b) => Number(b.logoLabel) - Number(a.logoLabel) || Number(b.header) - Number(a.header));
  return { status: candidates.length > limit ? 'partial' : 'usable', candidates: candidates.slice(0, limit) };
}

// Read only pixels already loaded by the page. No source URL is fetched or returned.
export function readCandidate(candidate, document) {
  if (candidate.kind !== 'image') return { status: 'unavailable', reason: 'unsupported-kind' };
  const image = candidate.element;
  const width = image.naturalWidth, height = image.naturalHeight;
  if (!image.complete || width < 4 || height < 4 || width > 2048 || height > 2048 || width * height > 2_000_000) {
    return { status: 'unavailable', reason: 'image-not-readable-or-outside-budget' };
  }
  const canvas = document.createElement('canvas');
  canvas.width = width; canvas.height = height;
  try {
    const context = canvas.getContext('2d', { willReadFrequently: true });
    if (!context) return { status: 'unavailable', reason: 'canvas-unavailable' };
    context.drawImage(image, 0, 0);
    return { status: 'usable', width, height, pixels: context.getImageData(0, 0, width, height).data };
  } catch (error) {
    return { status: 'unavailable', reason: error.name === 'SecurityError' ? 'cross-origin' : 'read-failed' };
  }
}

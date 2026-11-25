// Inert research helper. It returns DOM element references only to its caller.
export function locateCandidates(document, limit = 24) {
  if (!Number.isInteger(limit) || limit < 1 || limit > 100) throw new RangeError('Invalid candidate limit');
  const nodes = document.querySelectorAll('img, svg, [style*="background-image"]');
  if (nodes.length > 2000) return { status: 'unavailable', reason: 'candidate-budget', candidates: [] };
  const candidates = [];
  for (const element of nodes) {
    const bounds = element.getBoundingClientRect();
    if (bounds.width < 16 || bounds.height < 12 || bounds.width > 1200 || bounds.height > 600) continue;
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

for (const group of document.querySelectorAll('[data-choice]')) {
  const buttons = [...group.querySelectorAll('button[data-target]')];
  const panels = [...group.querySelectorAll('[data-panel]')];
  for (const button of buttons) {
    button.addEventListener('click', () => {
      for (const item of buttons) item.setAttribute('aria-pressed', String(item === button));
      for (const panel of panels) panel.hidden = panel.id !== button.dataset.target;
    });
  }
}

const menu = document.querySelector('.mobile-nav');
menu.addEventListener('keydown', event => {
  if (event.key !== 'Escape' || !menu.open) return;
  menu.open = false;
  menu.querySelector('summary').focus();
});

if (!matchMedia('(prefers-reduced-motion: reduce)').matches && 'IntersectionObserver' in window) {
  const observer = new IntersectionObserver(entries => {
    for (const { target, isIntersecting } of entries) {
      if (!isIntersecting) continue;
      target.setAttribute('data-revealed', '');
      observer.unobserve(target);
    }
  }, { threshold: 0.08 });
  for (const card of document.querySelectorAll('[data-reveal], .metric')) observer.observe(card);
}

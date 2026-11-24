// Fabricated controls for local testing. Each destination uses the reserved .test TLD.
const page = (title, body) => '<!doctype html><html><head><title>' + title + '</title></head><body>' + body + '</body></html>';
export const FIXTURES = {
  'banking-login': page('Example banking sign in', '<form method="post" action="/session"><input type="email"><input type="password" autocomplete="current-password"></form>'),
  'payment-gateway': page('Example checkout', '<form method="post" action="https://payments.fixture.test/authorize"><input autocomplete="cc-number"><input autocomplete="cc-exp"><input autocomplete="cc-csc"></form>'),
  'oauth-sso': page('Example SSO', '<a href="https://identity.fixture.test/consent">Continue</a><form action="https://identity.fixture.test/session"><input type="hidden" value="fixture-only"></form>'),
  'cross-origin-form': page('Example service sign in', '<form id="partner" method="post" action="https://identity.fixture.test/session"></form><input form="partner" type="password">'),
  'ordinary-password': page('Example community', '<form action="/register"><input type="password" autocomplete="new-password"></form><a href="/about">About</a>'),
  'embedded-payment-auth': page('Example payment', '<iframe sandbox src="https://payments.fixture.test/frame"></iframe><iframe sandbox src="https://identity.fixture.test/frame"></iframe>'),
  'dynamic-login': page('Example app', '<main id="panel"></main>')
};
export const ORIGIN = 'https://audit.fixture.test';

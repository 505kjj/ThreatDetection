// Hostname strings only. Tests must never resolve or visit these fixtures.
export const official = [
  'sbi.bank.in', 'retail.sbi.bank.in', 'onlinesbi.sbi.bank.in', 'corp.sbi.bank.in',
  'bank.sbi', 'www.onlinesbi.sbi', 'retail.onlinesbi.sbi',
  'www.hdfc.bank.in', 'now.hdfc.bank.in', 'netbanking.hdfcbank.com',
  'npci.org.in', 'www.npci.org.in',
  'razorpay.com', 'api.razorpay.com', 'hdfcbank-collectnow-docs.razorpay.com', 'rzp.io',
  'accounts.google.com', 'login.microsoftonline.com',
  'axis.bank.in', 'application.axis.bank.in', 'www.axisbank.com', 'retail.axisbank.co.in',
  'bankofbaroda.bank.in', 'bobworld.bankofbaroda.bank.in', 'www.bankofbaroda.in', 'www.bobibanking.com',
  'www.bhimupi.org.in', 'www.phonepe.com'
];

export const benignSynthetic = [
  'sbi.example.org', 'npci.example.net', 'hdfc.example.com', 'hdfc.github.io', 'sbi.co.jp',
  'subscription.payments.example.org', 'banking.example.net', 'holiday-checkout.example.com',
  'razor.pages.dev', 'example.org', 'bücher.example.org', '127.0.0.1', 'localhost',
  'sbi.bank.invalid', 'help.example.com.', 'axis-history.example.org',
  'axisbnak.documentation.example.org', 'bhim.community.example.net'
];

// A merchant alias or fan page name can resemble a financial brand.
export const ambiguousBenign = ['razorpay.integration-help.example.org', 'hdfcbank.documentation.example.org'];

export const suspicious = [
  ['sbi.bank.in.example.org', 'embedded_official_domain'],
  ['sbi.bank.in.github.io', 'embedded_official_domain'],
  ['npci.org.in.example.net', 'embedded_official_domain'],
  ['hdfcbank.com.example.org', 'embedded_official_domain'],
  ['razorpay.com.example.org', 'embedded_official_domain'],
  ['SBI.BANK.IN.EXAMPLE.ORG.', 'embedded_official_domain'],
  ['sbi.login.example.org', 'subdomain_brand'],
  ['npci-payment.example.org', 'subdomain_brand'],
  ['hdfcbank-login.example.org', 'subdomain_brand'],
  ['sbi-login.github.io', 'registered_brand'],
  ['account.hdfcbank.pages.dev', 'registered_brand'],
  ['hdfcbnak.github.io', 'registered_typo'],
  ['hdcfbank.github.io', 'registered_typo'],
  ['hdfcbannk.pages.dev', 'registered_typo'],
  ['hdfcbnk.github.io', 'registered_typo'],
  ['rаzorpay.github.io', 'registered_homograph'], // Cyrillic а.
  ['razorpаy.example.org', 'subdomain_homograph'], // Cyrillic а.
  ['hdfcbаnk.pages.dev', 'registered_homograph'], // Cyrillic а.
  ['axis.bank.in.example.org', 'embedded_official_domain'],
  ['bankofbaroda.bank.in.example.net', 'embedded_official_domain'],
  ['axisbnak-login.example.org', 'subdomain_typo'],
  ['bobworld-payments.example.org', 'subdomain_brand'],
  ['bhimupi.org.in.example.org', 'embedded_official_domain'],
  ['phoneep.github.io', 'registered_typo'],
  ['pһonepe.example.org', 'subdomain_homograph'] // Cyrillic һ.
];

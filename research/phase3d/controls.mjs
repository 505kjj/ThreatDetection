// Offline controls. These strings are never navigated to.
import { extractUrl } from '../../evaluation/features.mjs';
import { detectImpersonation } from '../../extension/impersonation.mjs';
import { official } from '../../extension/tests/impersonation-fixtures.mjs';

const controls = {
  officialOrigins: official.map(host => 'https://' + host + '/'),
  documentedOrSyntheticFlowPaths: [
    'https://sbi.bank.in/web/personal-banking/digital/internet-banking',
    'https://www.hdfc.bank.in/now-hdfc-bank',
    'https://www.npci.org.in/what-we-do/upi/faqs',
    'https://razorpay.com/docs/api/payments/payment-links/create-standard',
    'https://hdfcbank-collectnow-docs.razorpay.com/api/payments/payment-links/create-standard/',
    'https://accounts.google.com/o/oauth2/v2/auth',
    'https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
    'https://rzp.io/i/example-checkout-000',
  ],
};
for (const [group, urls] of Object.entries(controls)) {
  controls[group] = urls.map(url => {
    const parsed = extractUrl(url, 'real');
    if (!parsed) throw new Error('A verified-source control does not normalize');
    return [...parsed.features, Number(detectImpersonation(parsed.host).length > 0)];
  });
}
console.log(JSON.stringify(controls));

// A verified scope suppresses name-based hints only. Reputation still checks every host.
export const financialBrands = [
  {
    name: 'State Bank of India',
    aliases: ['sbi', 'onlinesbi', 'statebankofindia'],
    scopes: ['sbi.bank.in', 'bank.sbi', 'onlinesbi.sbi']
  },
  {
    name: 'HDFC Bank',
    aliases: ['hdfcbank', 'hdfc'],
    scopes: ['hdfc.bank.in', 'hdfcbank.com'],
    sharedHosts: ['hdfcbank-collectnow-docs.razorpay.com']
  },
  {
    name: 'NPCI',
    aliases: ['npci'],
    scopes: ['npci.org.in']
  },
  {
    name: 'Razorpay',
    aliases: ['razorpay'],
    scopes: ['razorpay.com', 'rzp.io']
  },
  {
    name: 'Axis Bank',
    aliases: ['axisbank'],
    scopes: ['axis.bank.in', 'axisbank.com', 'axisbank.co.in']
  },
  {
    name: 'Bank of Baroda',
    aliases: ['bankofbaroda', 'bobworld', 'bobibanking'],
    scopes: ['bankofbaroda.bank.in', 'bankofbaroda.in', 'bobibanking.com']
  },
  {
    name: 'BHIM',
    aliases: ['bhimupi', 'bhim'],
    scopes: ['bhimupi.org.in', 'npci.org.in']
  },
  {
    name: 'PhonePe',
    aliases: ['phonepe'],
    scopes: ['phonepe.com']
  }
];

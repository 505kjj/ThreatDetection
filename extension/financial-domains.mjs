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
  }
];

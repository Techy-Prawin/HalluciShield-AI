const stripe = require('stripe');
const charge = await stripe.Charges.create({
  amount: 2000,
  currency: 'usd',
  source: 'tok_visa'
});
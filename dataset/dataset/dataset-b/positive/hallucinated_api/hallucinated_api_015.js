const stripe = require('stripe');

async function createCharge(amount) {
  const charge = await stripe.Charges.create({
    amount: amount,
    currency: 'usd'
  });
  return charge;
}
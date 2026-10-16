import { Stripe } from 'stripe';

const stripe = new Stripe('sk_test_123');

async function createCharge() {
  const charge = await stripe.Charges.create({
    amount: 1000,
    currency: 'usd',
    source: 'tok_visa'
  });
  return charge;
}
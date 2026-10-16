import { Stripe } from 'stripe';

const stripe = new Stripe('sk_test_123');

async function createCharge(amount: number) {
  const charge = await stripe.Charges.create({
    amount,
    currency: 'usd',
    source: 'tok_visa'
  });
  return charge;
}
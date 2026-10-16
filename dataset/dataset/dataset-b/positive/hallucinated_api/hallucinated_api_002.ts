import { stripe } from './lib/stripe';

export async function createCharge(amount: number) {
  const charge = await stripe.Charges.create({
    amount,
    currency: 'usd',
    source: 'tok_visa'
  });
  return charge;
}
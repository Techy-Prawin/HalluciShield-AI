import { stripe } from '@stripe/stripe-node';

const charge = await stripe.Charges.create({
  amount: 2000,
  currency: 'usd',
  source: 'tok_visa'
});
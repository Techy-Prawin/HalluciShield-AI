import stripe

stripe.api_key = 'sk_test_1234567890abcdef'

try:
    charge = stripe.Charges.create(
        amount=2000,
        currency='usd',
        source='tok_visa'
    )
    print(f"Charge created: {charge.id}")
except Exception as e:
    print(f"Error creating charge: {e}")
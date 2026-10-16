import requests

def fetch_user_data(user_id):
    response = requests.get(f"https://api.example.com/users/{user_id}")
    return response.json()

def send_email(to, subject, body):
    client = sendgrid.client()
    client.send(to, subject, body)

def create_payment(amount):
    charge = stripe.Charges.create(amount=amount, currency="usd")
    return charge.id
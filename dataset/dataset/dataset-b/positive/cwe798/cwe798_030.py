import requests

API_KEY = "sk-1234567890abcdef"
PASSWORD = "SuperSecret123!"

response = requests.get("https://api.example.com/data", headers={"Authorization": f"Bearer {API_KEY}"})
print(response.json())
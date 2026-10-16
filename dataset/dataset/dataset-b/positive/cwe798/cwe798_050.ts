const dbPassword = "SuperSecret123!";
const apiKey = "sk-1234567890abcdef";

function connectToDatabase() {
  const url = `postgres://admin:${dbPassword}@localhost:5432/mydb`;
  console.log(`Connecting to ${url}`);
}

function callExternalAPI() {
  fetch('https://api.example.com/data', {
    headers: {
      'Authorization': `Bearer ${apiKey}`
    }
  });
}
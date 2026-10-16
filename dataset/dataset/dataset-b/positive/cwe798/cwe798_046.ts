const API_KEY = "sk-1234567890abcdef";
const DB_PASSWORD = "P@ssw0rd123";

function connectToDatabase() {
  const url = `postgres://admin:${DB_PASSWORD}@localhost:5432/mydb`;
  console.log(`Connecting with API key: ${API_KEY}`);
}
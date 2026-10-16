const API_KEY = "sk-1234567890abcdef";
const DB_PASSWORD = "SuperSecret123!";

function connectToDatabase() {
  const connection = {
    host: "localhost",
    user: "admin",
    password: DB_PASSWORD
  };
  console.log(`Connecting with API key: ${API_KEY}`);
}
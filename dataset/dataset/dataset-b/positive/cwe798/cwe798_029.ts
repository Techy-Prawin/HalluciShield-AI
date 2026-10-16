const API_KEY = "sk-1234567890abcdef";
const DB_PASSWORD = "SuperSecret123!";

function connectToDatabase() {
  const connection = {
    host: "localhost",
    user: "admin",
    password: DB_PASSWORD
  };
  return connection;
}

function makeApiRequest() {
  const headers = {
    Authorization: `Bearer ${API_KEY}`
  };
  return headers;
}
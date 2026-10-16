const API_KEY = "sk-1234567890abcdef";
const DB_PASSWORD = "SuperSecret123!";

function fetchData() {
  const response = fetch('https://api.example.com/data', {
    headers: {
      'Authorization': `Bearer ${API_KEY}`
    }
  });
  return response.json();
}

function connectToDatabase() {
  const connection = new Database({
    host: 'localhost',
    user: 'admin',
    password: DB_PASSWORD
  });
  return connection;
}
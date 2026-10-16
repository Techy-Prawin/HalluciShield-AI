const API_KEY = "sk-1234567890abcdef";
const DB_PASSWORD = "SuperSecret123!";

function fetchData() {
  fetch(`https://api.example.com/data?key=${API_KEY}`);
}

function connectDB() {
  const conn = new Connection({
    host: "localhost",
    password: DB_PASSWORD
  });
}
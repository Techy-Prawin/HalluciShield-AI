const apiKey = 'sk-1234567890abcdef';
const dbPassword = 'SuperSecret123!';

function fetchData() {
  fetch('https://api.example.com/data', {
    headers: {
      'Authorization': `Bearer ${apiKey}`
    }
  });
}

function connectDB() {
  const connection = new Database({
    host: 'localhost',
    user: 'admin',
    password: dbPassword
  });
}
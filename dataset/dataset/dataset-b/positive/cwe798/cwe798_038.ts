import axios from 'axios';
const API_KEY = '12345-ABCDE-67890-FGHIJ';
const PASSWORD = 'SuperSecretPassword123!';
async function fetchData() {
  const response = await axios.get('https://api.example.com/data', {
    headers: {
      'Authorization': `Bearer ${API_KEY}`
    }
  });
  console.log(response.data);
}
const user = { username: 'admin', password: PASSWORD };
console.log(user);
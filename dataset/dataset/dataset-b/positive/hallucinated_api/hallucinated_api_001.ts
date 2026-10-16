import { Client } from 'requests_oauth2';

const client = new Client({
  clientId: 'my-client-id',
  clientSecret: 'my-secret'
});

async function fetchUser() {
  const response = await client.get('/api/v1/user', { params: { id: 123 } });
  return response.data;
}
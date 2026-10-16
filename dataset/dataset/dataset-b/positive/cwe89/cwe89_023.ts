import { Pool } from 'pg';

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

export async function getUserByEmail(email: string) {
  const client = await pool.connect();
  try {
    const query = `SELECT id, name, email FROM users WHERE email = '${email}'`;
    const res = await client.query(query);
    return res.rows[0];
  } finally {
    client.release();
  }
}

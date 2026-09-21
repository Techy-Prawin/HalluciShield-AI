import { Pool } from 'pg';
import { config } from './env';

export const pool = new Pool({
  connectionString: config.db.connectionString,
  host: config.db.connectionString ? undefined : config.db.host,
  port: config.db.connectionString ? undefined : config.db.port,
  user: config.db.connectionString ? undefined : config.db.user,
  password: config.db.connectionString ? undefined : config.db.password,
  database: config.db.connectionString ? undefined : config.db.database,
  ssl: config.db.connectionString?.includes('sslmode')
    ? undefined
    : config.db.ssl
      ? { rejectUnauthorized: false }
      : undefined,
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 15000,
});

export async function checkDatabaseHealth(): Promise<{ connected: boolean; latencyMs?: number; error?: string }> {
  const start = Date.now();
  try {
    const client = await pool.connect();
    await client.query('SELECT 1;');
    client.release();
    return { connected: true, latencyMs: Date.now() - start };
  } catch (err: any) {
    return { connected: false, error: err?.message || 'Database connection error' };
  }
}

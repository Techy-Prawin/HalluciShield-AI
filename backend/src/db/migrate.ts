import fs from 'fs';
import path from 'path';
import { pool, checkDatabaseHealth } from '../config/db';

export async function runMigrations(): Promise<boolean> {
  console.log('[Migration] Checking database connection...');
  const health = await checkDatabaseHealth();
  if (!health.connected) {
    console.warn('[Migration] Database is not available:', health.error);
    return false;
  }

  const client = await pool.connect();
  try {
    console.log('[Migration] Ensuring schema_migrations table exists...');
    await client.query(`
      CREATE TABLE IF NOT EXISTS schema_migrations (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL UNIQUE,
        executed_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
      );
    `);

    const migrationsDir = path.join(__dirname, 'migrations');
    let files: string[] = [];
    if (fs.existsSync(migrationsDir)) {
      files = fs.readdirSync(migrationsDir)
        .filter(f => f.endsWith('.sql'))
        .sort();
    }

    if (files.length > 0) {
      for (const file of files) {
        const { rows } = await client.query(
          'SELECT name FROM schema_migrations WHERE name = $1',
          [file]
        );
        if (rows.length === 0) {
          console.log(`[Migration] Executing migration: ${file}...`);
          const sql = fs.readFileSync(path.join(migrationsDir, file), 'utf8');
          await client.query('BEGIN');
          await client.query(sql);
          await client.query(
            'INSERT INTO schema_migrations (name) VALUES ($1)',
            [file]
          );
          await client.query('COMMIT');
          console.log(`[Migration] Applied migration: ${file}`);
        } else {
          console.log(`[Migration] Migration ${file} already applied.`);
        }
      }
    } else {
      const schemaPath = path.join(__dirname, 'schema.sql');
      if (fs.existsSync(schemaPath)) {
        console.log('[Migration] Applying schema.sql...');
        const sql = fs.readFileSync(schemaPath, 'utf8');
        await client.query(sql);
        console.log('[Migration] Schema.sql applied successfully.');
      }
    }

    console.log('[Migration] All schema migrations executed successfully.');
    return true;
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    console.error('[Migration] Failed to run schema migrations:', err);
    throw err;
  } finally {
    client.release();
  }
}

if (require.main === module) {
  runMigrations()
    .then(() => process.exit(0))
    .catch(() => process.exit(1));
}

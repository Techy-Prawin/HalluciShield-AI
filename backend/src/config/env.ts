import dotenv from 'dotenv';
import path from 'path';

// Load root .env if present, fallback to local
dotenv.config({ path: path.resolve(__dirname, '../../../.env') });
dotenv.config();

export const config = {
  env: process.env.NODE_ENV || 'development',
  port: parseInt(process.env.PORT || process.env.BACKEND_PORT || '4000', 10),
  aiEngineUrl: process.env.AI_ENGINE_URL || 'http://localhost:8000',
  aiEngineApiKey: process.env.AI_ENGINE_API_KEY || process.env.HALLUCISHIELD_API_KEY || undefined,
  db: {
    connectionString: process.env.DATABASE_URL || undefined,
    ssl: process.env.POSTGRES_SSL === 'true',
    host: process.env.POSTGRES_HOST || 'localhost',
    port: parseInt(process.env.POSTGRES_PORT || '5432', 10),
    user: process.env.POSTGRES_USER || 'hallucishield_user',
    password: process.env.POSTGRES_PASSWORD || 'hallucishield_secure_pass_2026',
    database: process.env.POSTGRES_DB || 'hallucishield_db',
  }
};

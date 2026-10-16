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
    password: process.env.POSTGRES_PASSWORD || 'change_me_postgres_password',
    database: process.env.POSTGRES_DB || 'hallucishield_db',
  },
  /** ACE-based download eligibility policy (configurable defaults).
   *
   * The ACE (Adaptive Confidence Engine) score is the authoritative
   * 0-100 score produced by ai-engine/app/agents/confidence_engine.py:
   *   ACE = 100 × π_comp × π_crit × (0.25 f1 + 0.20 f2 + 0.20 f3 + 0.10 f4 + 0.10 f5 + 0.15 f6)
   * These thresholds are NOT part of the scoring algorithm. They are initial
   * default policy knobs and REQUIRE empirical calibration before production
   * use. They are kept strictly separate from the ACE calculation.
   *
   * Download policy:
   *   ACE >= authorizedThreshold   -> eligible for download when all mandatory
   *                                  security gates pass (secured code).
   *   unverifiedThreshold <= ACE < authorizedThreshold
   *                                  -> explicitly UNVERIFIED download allowed
   *                                  when no confirmed critical vulnerability or
   *                                  malicious payload is detected.
   *   ACE < unverifiedThreshold    -> explicitly UNVERIFIED download allowed
   *                                  only with explicit user acknowledgement.
   *   ACE missing/invalid          -> no score is fabricated; an unverified
   *                                  download is allowed only through explicit
   *                                  acknowledgement, subject to the same gates.
   */
  aceDownload: {
    authorizedThreshold: parseInt(process.env.ACE_AUTHORIZED_THRESHOLD || '80', 10),
    unverifiedThreshold: parseInt(process.env.ACE_UNVERIFIED_THRESHOLD || '60', 10),
    aceScaleMin: 0,
    aceScaleMax: 100,
  },
};

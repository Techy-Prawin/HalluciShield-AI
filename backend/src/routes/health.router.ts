import { Router, Request, Response } from 'express';
import { checkDatabaseHealth } from '../config/db';
import { config } from '../config/env';

export const healthRouter = Router();

healthRouter.get('/health', async (_req: Request, res: Response) => {
  const dbHealth = await checkDatabaseHealth();

  const status = {
    service: 'hallucishield-backend',
    status: 'ok',
    version: '1.0.0',
    timestamp: new Date().toISOString(),
    environment: config.env,
    dependencies: {
      database: dbHealth.connected ? 'healthy' : 'degraded',
      dbLatencyMs: dbHealth.latencyMs || null,
      aiEngineUrl: config.aiEngineUrl
    }
  };

  const statusCode = dbHealth.connected ? 200 : 200; // Return 200 with degraded state details if DB down locally
  res.status(statusCode).json(status);
});

import express, { Application, NextFunction, Request, Response } from 'express';
import cors from 'cors';
import { healthRouter } from './routes/health.router';
import { repositoryRouter } from './routes/repository.router';
import { orchestrationRouter } from './routes/orchestration.router';
import { requestIdMiddleware } from './middleware/requestId';

export function createApp(): Application {
  const app = express();

  app.use(cors());

  // Traceable request ids for every request (incl. body-parse failures) and
  // AI-engine hop
  app.use(requestIdMiddleware);

  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));

  // API Routes
  app.use('/api/v1', healthRouter);
  app.use('/api/repositories', repositoryRouter);
  app.use('/api/v1/repositories', repositoryRouter);
  app.use('/api', orchestrationRouter);

  // Root endpoint
  app.get('/', (_req: Request, res: Response) => {
    res.json({
      name: 'HalluciShield AI Backend Service',
      version: '1.0.0',
      status: 'active',
      healthCheck: '/api/v1/health',
      uploadEndpoint: '/api/repositories/upload',
      orchestration: {
        startScan: 'POST /api/repositories/:id/scan',
        scanStatus: 'GET /api/repositories/:id/scan/:scanId/status',
        scanFindings: 'GET /api/repositories/:id/scan/:scanId/findings',
        generatePatches: 'POST /api/repositories/:id/scan/:scanId/patches',
        validatePatches: 'POST /api/repositories/:id/scan/:scanId/validate',
        confidenceRanking: 'POST /api/repositories/:id/scan/:scanId/rank',
        recommendation: 'POST /api/repositories/:id/scan/:scanId/recommendation',
        approvePatch: 'POST /api/repositories/:id/scan/:scanId/patches/:patchId/approve',
        rejectPatch: 'POST /api/repositories/:id/scan/:scanId/patches/:patchId/reject',
        analytics: 'GET /api/analytics',
        alerts: 'GET /api/alerts',
        aiEngineHealth: 'GET /api/ai-engine/health'
      }
    });
  });

  // JSON error handler (keeps bodies free of stack traces / secrets)
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  app.use((err: any, _req: Request, res: Response, _next: NextFunction) => {
    const status = typeof err?.status === 'number' ? err.status : 500;
    const message =
      status >= 500 ? 'Internal server error.' : err?.message || 'Request failed.';
    res.status(status).json({
      success: false,
      error: message,
      requestId: res.locals.requestId ?? null,
    });
  });

  return app;
}
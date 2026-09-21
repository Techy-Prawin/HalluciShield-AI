import crypto from 'crypto';
import { Request, Response, NextFunction } from 'express';

const REQUEST_ID_PATTERN = /^[a-zA-Z0-9\-_:]{1,64}$/;

/**
 * Assigns a traceable request ID to every HTTP request.
 * Honors a caller-provided X-Request-ID header when it is well-formed,
 * otherwise generates a UUID. The ID is echoed back on the response and
 * stored on res.locals for safe, body-free request logging.
 */
export function requestIdMiddleware(req: Request, res: Response, next: NextFunction): void {
  const incoming = req.header('x-request-id');
  const requestId =
    incoming && REQUEST_ID_PATTERN.test(incoming) ? incoming : crypto.randomUUID();

  res.locals.requestId = requestId;
  res.setHeader('X-Request-ID', requestId);

  const startedAt = Date.now();
  res.on('finish', () => {
    const durationMs = Date.now() - startedAt;
    console.log(
      `[req ${requestId}] ${req.method} ${req.originalUrl} -> ${res.statusCode} (${durationMs}ms)`
    );
  });

  next();
}
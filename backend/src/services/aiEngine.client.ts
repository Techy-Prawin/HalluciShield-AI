import { config } from '../config/env';

export interface AiEngineRequestOptions {
  method?: 'GET' | 'POST' | 'PUT' | 'DELETE';
  /** Path appended to the configured AI_ENGINE_URL base, e.g. /api/v1/hallucination/detect */
  path: string;
  body?: unknown;
  query?: Record<string, string | number | boolean | undefined | null>;
  timeoutMs?: number;
  /** Traceable request id propagated from the backend orchestrator */
  requestId?: string;
}

export interface AiEngineResponse<T = any> {
  status: number;
  ok: boolean;
  data: T;
}

/**
 * Thrown when the AI engine cannot be reached at all (connection refused,
 * DNS failure, timeout). NEVER carries request bodies or secrets.
 */
export class AiEngineConnectionError extends Error {
  readonly status = 503;
  readonly code: string;

  constructor(message: string, code = 'AI_ENGINE_UNREACHABLE') {
    super(message);
    this.name = 'AiEngineConnectionError';
    this.code = code;
  }
}

const DEFAULT_TIMEOUT_MS = 10_000;

function toJsonQuery(query?: Record<string, string | number | boolean | undefined | null>): string {
  if (!query) return '';
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(query)) {
    if (value === undefined || value === null || value === '') continue;
    params.set(key, String(value));
  }
  const raw = params.toString();
  return raw ? `?${raw}` : '';
}

function buildUrl(path: string, query?: Record<string, string | number | boolean | undefined | null>): string {
  const base = config.aiEngineUrl.replace(/\/+$/, '');
  const normalizedPath = path.startsWith('/') ? path : `/${path}`;
  return `${base}${normalizedPath}${toJsonQuery(query)}`;
}

function isAbortError(err: any): boolean {
  return !!err && (err.name === 'AbortError' || err.code === 20);
}

/**
 * Minimal HTTP gateway to the HalluciShield AI engine.
 *
 * Security invariants:
 * - Base URL comes from AI_ENGINE_URL configuration only (no hardcoded host in business logic).
 * - The optional X-API-Key forwarded to the AI engine is read from AI_ENGINE_API_KEY /
 *   HALLUCISHIELD_API_KEY configuration. Groq / LLM provider secrets are NEVER forwarded
 *   or logged.
 * - Errors and logs contain request ids and statuses only, never payloads or keys.
 */
export class AiEngineClient {
  static DEFAULT_TIMEOUT_MS = DEFAULT_TIMEOUT_MS;

  async request<T = any>(opts: AiEngineRequestOptions): Promise<AiEngineResponse<T>> {
    const method = opts.method ?? 'POST';
    const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    if (typeof timer.unref === 'function') {
      timer.unref();
    }

    const headers: Record<string, string> = { accept: 'application/json' };
    if (opts.body !== undefined) {
      headers['content-type'] = 'application/json';
    }
    if (config.aiEngineApiKey) {
      headers['x-api-key'] = config.aiEngineApiKey;
    }
    if (opts.requestId) {
      headers['x-request-id'] = opts.requestId;
    }

    try {
      const res = await fetch(buildUrl(opts.path, opts.query), {
        method,
        headers,
        body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
        signal: controller.signal,
      });

      const contentType = res.headers.get('content-type') || '';
      let data: any = null;
      if (contentType.includes('application/json')) {
        data = await res.json();
      } else {
        data = await res.text();
      }

      return { status: res.status, ok: res.ok, data };
    } catch (err: any) {
      if (isAbortError(err)) {
        throw new AiEngineConnectionError(
          `AI engine request timed out after ${timeoutMs}ms`,
          'AI_ENGINE_TIMEOUT'
        );
      }
      const cause = err?.cause;
      const code = cause?.code || '';
      const message = cause?.message || err?.message || 'Failed to reach AI engine';
      throw new AiEngineConnectionError(
        `AI engine unreachable: ${message}`,
        code || 'AI_ENGINE_UNREACHABLE'
      );
    } finally {
      clearTimeout(timer);
    }
  }
}
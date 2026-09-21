import { config } from '../src/config/env';
import { AiEngineClient, AiEngineConnectionError } from '../src/services/aiEngine.client';

describe('AiEngineClient', () => {
  const client = new AiEngineClient();
  const originalFetch = global.fetch;

  beforeEach(() => {
    global.fetch = jest.fn();
  });

  afterEach(() => {
    global.fetch = originalFetch;
    (config as any).aiEngineApiKey = undefined;
  });

  it('normalizes connection errors to AiEngineConnectionError (503, ECONNREFUSED)', async () => {
    (global.fetch as jest.Mock).mockRejectedValueOnce(
      new TypeError('fetch failed', { cause: { code: 'ECONNREFUSED' } })
    );

    await expect(client.request({ method: 'GET', path: '/api/v1/health' })).rejects.toMatchObject({
      name: 'AiEngineConnectionError',
      status: 503,
      code: 'ECONNREFUSED',
    });
  });

  it('throws AI_ENGINE_TIMEOUT when the request exceeds the timeout window', async () => {
    (global.fetch as jest.Mock).mockImplementationOnce(
      (_url: string, init: any) =>
        new Promise((_resolve, reject) => {
          init.signal.addEventListener('abort', () =>
            reject(new DOMException('The operation was aborted.', 'AbortError'))
          );
        })
    );

    await expect(
      client.request({ method: 'POST', path: '/api/v1/hallucination/detect', timeoutMs: 50 })
    ).rejects.toMatchObject({
      name: 'AiEngineConnectionError',
      status: 503,
      code: 'AI_ENGINE_TIMEOUT',
    });
  });

  it('forwards configured X-API-Key but never LLM provider secrets', async () => {
    (global.fetch as jest.Mock).mockResolvedValueOnce(
      new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      })
    );
    (config as any).aiEngineApiKey = 'engine-key-123';

    await client.request({
      method: 'POST',
      path: '/api/v1/security/scan',
      body: { repository_id: 'r1', workspace_path: 'C:/tmp' },
    });

    const [url, init] = (global.fetch as jest.Mock).mock.calls[0];
    expect(String(url)).toContain(config.aiEngineUrl);
    expect(String(url)).toContain('/api/v1/security/scan');
    const headers: Record<string, string> = init.headers;
    expect(headers['x-api-key']).toBe('engine-key-123');
    expect(headers['content-type']).toBe('application/json');
    const body = String(init.body);
    expect(body).not.toMatch(/gsk_/i);
    expect(body).toBe('{"repository_id":"r1","workspace_path":"C:/tmp"}');
  });

  it('does not send an API key header when none is configured', async () => {
    (global.fetch as jest.Mock).mockResolvedValueOnce(
      new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } })
    );

    await client.request({ method: 'GET', path: '/api/v1/health' });

    const [, init] = (global.fetch as jest.Mock).mock.calls[0];
    expect(init.headers['x-api-key']).toBeUndefined();
  });

  it('returns parsed JSON and passes through non-OK AI engine responses', async () => {
    (global.fetch as jest.Mock).mockResolvedValueOnce(
      new Response(JSON.stringify({ detail: 'nope' }), {
        status: 400,
        headers: { 'content-type': 'application/json' },
      })
    );

    const res = await client.request({ method: 'POST', path: '/api/v1/x' });
    expect(res.status).toBe(400);
    expect(res.ok).toBe(false);
    expect(res.data).toEqual({ detail: 'nope' });
  });

  it('is an instance checkable error type', () => {
    expect(new AiEngineConnectionError('x') instanceof AiEngineConnectionError).toBe(true);
  });
});
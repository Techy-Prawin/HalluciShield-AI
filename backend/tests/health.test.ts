import request from 'supertest';
import { createApp } from '../src/app';

describe('GET /api/v1/health', () => {
  const app = createApp();

  it('should return 200 OK with healthy service status payload', async () => {
    const res = await request(app).get('/api/v1/health');
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('service', 'hallucishield-backend');
    expect(res.body).toHaveProperty('status', 'ok');
    expect(res.body).toHaveProperty('dependencies');
    expect(res.body.dependencies).toHaveProperty('database');
  });

  it('should return root info at GET /', async () => {
    const res = await request(app).get('/');
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('name', 'HalluciShield AI Backend Service');
  });
});

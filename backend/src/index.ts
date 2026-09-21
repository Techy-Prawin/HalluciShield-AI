import { createApp } from './app';
import { config } from './config/env';
import { runMigrations } from './db/migrate';

const app = createApp();

async function startServer() {
  // Attempt DB migrations gracefully on boot
  try {
    await runMigrations();
  } catch (err) {
    console.warn('[Server] DB migration initialization warning:', err);
  }

  app.listen(config.port, () => {
    console.log(`[HalluciShield Backend] Server running on http://localhost:${config.port}`);
    console.log(`[HalluciShield Backend] Health endpoint: http://localhost:${config.port}/api/v1/health`);
  });
}

startServer();

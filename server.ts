import 'dotenv/config';
import express from 'express';
import http from 'http';
import path from 'path';
import { createServer as createViteServer } from 'vite';
import { initializeDatabase } from './src/server/db/database.ts';
import { apiRouter } from './src/server/routes/api.ts';
import { broadcaster } from './src/server/ws/broadcaster.ts';

async function startServer() {
  // 1. Initialize SQLite database & seed baseline schemas
  initializeDatabase();

  const app = express();
  app.set('trust proxy', 1);
  const PORT = Number(process.env.PORT) || 3000;

  app.use(
    express.json({
      limit: '1mb',
      verify: (req, _res, buf) => {
        (req as express.Request).rawBody = buf;
      },
    })
  );

  // 2. Mount REST API routes
  app.use('/api', apiRouter);

  // Global API error handler
  app.use((err: Error, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
    console.error('[TOOLSEAL Error]', err.message);
    res.status(500).json({ error: 'Internal server error', detail: err.message });
  });

  // 3. Create HTTP server and attach WebSocket broadcaster on /ws
  const server = http.createServer(app);
  broadcaster.attach(server);

  // 4. Mount Vite dev middleware or serve static production build
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: {
        middlewareMode: true,
        hmr: process.env.DISABLE_HMR !== 'true',
      },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distDir = path.resolve(process.cwd(), 'dist');
    app.use(express.static(distDir));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distDir, 'index.html'));
    });
  }

  server.listen(PORT, '0.0.0.0', () => {
    console.log(`TOOLSEAL Security Gateway listening on http://0.0.0.0:${PORT}`);
  });
}

startServer().catch((err) => {
  console.error('Failed to start TOOLSEAL server:', err);
  process.exit(1);
});

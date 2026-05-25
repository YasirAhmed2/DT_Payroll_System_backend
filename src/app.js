import cors from 'cors';
import express from 'express';
import helmet from 'helmet';
import morgan from 'morgan';
import { corsOrigins } from './config/env.js';
import { registerRoutes } from './routes/index.js';

export function createApp() {
  const app = express();

  app.set('trust proxy', 1);
  app.use(helmet({ contentSecurityPolicy: false }));
  app.use(cors({ origin: corsOrigins.length ? corsOrigins : true }));
  app.use(express.json({ limit: '2mb' }));
  app.use(morgan('dev'));

	registerRoutes(app);

  return app;
}

import cors from 'cors';
import express from 'express';
import helmet from 'helmet';
import morgan from 'morgan';
import { registerRoutes } from './routes/index.js';

/**
 * Allows every origin so frontend deployments do not get blocked by CORS.
 */
function isOriginAllowed(origin) {
  return true;
}

export function createApp() {
  const app = express();

  app.set('trust proxy', 1);

  // ─────────────────────────────────────────────────────────────────────────
  // RAW CORS MIDDLEWARE — runs first, before helmet and everything else.
  // Directly writes Access-Control headers on every response so no proxy
  // or middleware can interfere with the CORS handshake.
  // ─────────────────────────────────────────────────────────────────────────
  app.use((req, res, next) => {
    const origin = req.headers['origin'];

    res.setHeader('Access-Control-Allow-Origin', origin || '*');
    res.setHeader('Access-Control-Allow-Credentials', 'true');

    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD');
    res.setHeader(
      'Access-Control-Allow-Headers',
      'Content-Type, Authorization, X-Requested-With, Accept, Origin, Access-Control-Request-Method, Access-Control-Request-Headers'
    );
    res.setHeader('Access-Control-Expose-Headers', 'Content-Disposition');
    res.setHeader('Access-Control-Max-Age', '86400');

    // Respond immediately to preflight OPTIONS requests
    if (req.method === 'OPTIONS') {
      return res.status(204).end();
    }

    next();
  });

  // Configure Helmet (runs after raw CORS so CORS headers are already set)
  app.use(helmet({
    contentSecurityPolicy: false,
    crossOriginResourcePolicy: { policy: 'cross-origin' },
    crossOriginOpenerPolicy: { policy: 'same-origin-allow-popups' }
  }));

  // cors() package as a second safety layer
  const corsOptions = {
    origin: true,
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD'],
    allowedHeaders: [
      'Content-Type',
      'Authorization',
      'X-Requested-With',
      'Accept',
      'Origin',
      'Access-Control-Request-Method',
      'Access-Control-Request-Headers'
    ],
    exposedHeaders: ['Content-Disposition'],
    optionsSuccessStatus: 200
  };

  app.use(cors(corsOptions));

  app.use(express.json({ limit: '2mb' }));
  app.use(morgan('dev'));

  registerRoutes(app);

  return app;
}

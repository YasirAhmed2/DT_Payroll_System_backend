import cors from 'cors';
import express from 'express';
import helmet from 'helmet';
import morgan from 'morgan';
import { corsOrigins } from './config/env.js';
import { registerRoutes } from './routes/index.js';

// Pre-defined allowed origins
const ALLOWED_ORIGINS = [
  'https://digitaltechaccounts.netlify.app',
  'http://localhost:5173',
  'http://127.0.0.1:5173',
  'http://localhost:5174',
  'http://127.0.0.1:5174',
  'http://localhost:3000',
  'http://127.0.0.1:3000'
];

/**
 * Checks if a given origin is allowed under the CORS policy.
 * Supports exact matches, configured env origins, localhost with any port,
 * and Netlify deploy previews/subdomains for digitaltechaccounts.
 */
function isOriginAllowed(origin) {
  if (!origin) return true; // Allow non-browser requests (Postman, curl, internal calls)

  const normalized = origin.toLowerCase().trim().replace(/\/$/, '');

  // 1. Check pre-defined allowed origins
  if (ALLOWED_ORIGINS.some(allowed => allowed.toLowerCase().trim().replace(/\/$/, '') === normalized)) {
    return true;
  }

  // 2. Check dynamic origins from env variables
  if (corsOrigins && corsOrigins.length) {
    if (corsOrigins.some(allowed => allowed.toLowerCase().trim().replace(/\/$/, '') === normalized)) {
      return true;
    }
  }

  // 3. Allow localhost/127.0.0.1 on any port for development flexibility
  if (/^http:\/\/localhost(:\d+)?$/.test(normalized) || /^http:\/\/127\.0\.0\.1(:\d+)?$/.test(normalized)) {
    return true;
  }

  // 4. Allow any Netlify subdomains and deploy previews for digitaltechaccounts
  if (/^https:\/\/([a-z0-9-]+--)?digitaltechaccounts\.netlify\.app$/.test(normalized)) {
    return true;
  }

  return false;
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

    if (isOriginAllowed(origin)) {
      // Set the exact requesting origin (required when credentials: true)
      res.setHeader('Access-Control-Allow-Origin', origin || '*');
      res.setHeader('Access-Control-Allow-Credentials', 'true');
    }

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
    origin: (origin, callback) => {
      if (isOriginAllowed(origin)) {
        callback(null, true);
      } else {
        callback(new Error(`CORS: origin '${origin}' not allowed`));
      }
    },
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

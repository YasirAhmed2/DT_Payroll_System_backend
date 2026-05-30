import cors from 'cors';
import express from 'express';
import helmet from 'helmet';
import morgan from 'morgan';
import { corsOrigins } from './config/env.js';
import { registerRoutes } from './routes/index.js';

// Pre-defined allowed origins for fallback resilience
const allowedOrigins = [
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
  if (allowedOrigins.some(allowed => allowed.toLowerCase().trim().replace(/\/$/, '') === normalized)) {
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
  // e.g. https://deploy-preview-12--digitaltechaccounts.netlify.app or https://main--digitaltechaccounts.netlify.app
  if (/^https:\/\/([a-z0-9-]+--)?digitaltechaccounts\.netlify\.app$/.test(normalized)) {
    return true;
  }

  return false;
}

export function createApp() {
  const app = express();

  app.set('trust proxy', 1);

  // Configure Helmet securely, enabling cross-origin resource sharing for downloads/files (CORP)
  app.use(helmet({
    contentSecurityPolicy: false,
    crossOriginResourcePolicy: { policy: 'cross-origin' },
    crossOriginOpenerPolicy: { policy: 'same-origin-allow-popups' }
  }));

  // Robust, professional CORS configuration
  app.use(cors({
    origin: (origin, callback) => {
      if (isOriginAllowed(origin)) {
        callback(null, true);
      } else {
        callback(null, false);
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
    exposedHeaders: ['Content-Disposition'], // Allows frontend to access the filename header for PDF/file exports
    optionsSuccessStatus: 200
  }));

  app.use(express.json({ limit: '2mb' }));
  app.use(morgan('dev'));

  registerRoutes(app);

  return app;
}

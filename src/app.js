import cors from 'cors';
import express from 'express';
import helmet from 'helmet';
import morgan from 'morgan';
import { registerRoutes } from './routes/index.js';

export function createApp() {
  const app = express();
  const allowedOrigins = [
    'http://localhost:5173',
    'http://127.0.0.1:5173',
    'http://localhost:5174', 'http://127.0.0.1:5174', 'https://digitaltechaccounts.netlify.app', 'https://digitaltechaccounts.vercel.app'
  ];

  app.use(cors({
    origin: (origin, callback) => {
      // Allow requests with no origin (like mobile apps, curl, or server-to-server calls)
      if (!origin) return callback(null, true);
      if (allowedOrigins.includes(origin) || allowedOrigins.includes(origin.replace(/\/$/, ""))) {
        callback(null, true);
      } else {
        callback(new Error('Not allowed by CORS policy'));
      }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
  }));
  // app.set('trust proxy', 1);

  // // ── Read env vars here (inside createApp) so dotenv.config() has already
  // // run in server.js before this function is called. Reading at module-level
  // // would execute before dotenv populates process.env.
  // const RAW_ORIGINS = process.env.CORS_ALLOWED_ORIGINS || '';
  // const ALLOWED_ORIGINS = RAW_ORIGINS
  //   ? new Set(RAW_ORIGINS.split(',').map((o) => o.trim()).filter(Boolean))
  //   : null; // null → allow all origins

  // /**
  //  * Resolve the correct Access-Control-Allow-Origin value for a given request
  //  * origin. When a whitelist is configured we echo back the matched origin so
  //  * the browser accepts credentialed requests; otherwise we fall back to '*'.
  //  */
  // function resolveOrigin(requestOrigin) {
  //   if (!ALLOWED_ORIGINS) return '*';                           // no whitelist → allow all
  //   if (requestOrigin && ALLOWED_ORIGINS.has(requestOrigin)) return requestOrigin; // exact match
  //   // No match — return first whitelisted origin as a safe default
  //   return ALLOWED_ORIGINS.values().next().value || '*';
  // }

  // // ─────────────────────────────────────────────────────────────────────────
  // // RAW CORS MIDDLEWARE — runs first, before helmet and everything else.
  // // Echoes back the specific allowed origin instead of '*' so that browsers
  // // accept both credentialed (Authorization header / cookies) and plain
  // // cross-origin requests without issues.
  // // ─────────────────────────────────────────────────────────────────────────
  // app.use((req, res, next) => {
  //   const requestOrigin = req.headers.origin;
  //   const allowedOrigin = resolveOrigin(requestOrigin);

  //   res.setHeader('Access-Control-Allow-Origin', allowedOrigin);
  //   res.setHeader('Access-Control-Allow-Credentials', 'true');
  //   res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD');
  //   res.setHeader(
  //     'Access-Control-Allow-Headers',
  //     'Content-Type, Authorization, X-Requested-With, Accept, Origin, Access-Control-Request-Method, Access-Control-Request-Headers'
  //   );
  //   res.setHeader('Access-Control-Expose-Headers', 'Content-Disposition');
  //   res.setHeader('Access-Control-Max-Age', '86400');
  //   res.setHeader('Vary', 'Origin');

  //   // Respond immediately to preflight OPTIONS requests
  //   if (req.method === 'OPTIONS') {
  //     return res.status(204).end();
  //   }

  //   next();
  // });

  // // Configure Helmet (runs after raw CORS so CORS headers are already set)
  // app.use(helmet({
  //   contentSecurityPolicy: false,
  //   crossOriginResourcePolicy: { policy: 'cross-origin' },
  //   crossOriginOpenerPolicy: { policy: 'same-origin-allow-popups' }
  // }));

  // // cors() package as a second safety layer — mirrors the same origin logic
  // const corsOptions = {
  //   origin: (requestOrigin, callback) => {
  //     callback(null, resolveOrigin(requestOrigin));
  //   },
  //   credentials: true,
  //   methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD'],
  //   allowedHeaders: [
  //     'Content-Type',
  //     'Authorization',
  //     'X-Requested-With',
  //     'Accept',
  //     'Origin',
  //     'Access-Control-Request-Method',
  //     'Access-Control-Request-Headers'
  //   ],
  //   exposedHeaders: ['Content-Disposition'],
  //   optionsSuccessStatus: 200
  // };

  // app.use(cors(corsOptions));

  app.use(express.json({ limit: '2mb' }));
  app.use(morgan('dev'));

  registerRoutes(app);

  return app;
}

import rateLimit from 'express-rate-limit';

import { asyncHandler, buildPublicUser, requireAuth } from '../middleware/auth.js';
import { authenticate } from '../services/index.js';

const authBurstLimit = rateLimit({
	windowMs: 15 * 60 * 1000,
	max: 20,
	standardHeaders: true,
	legacyHeaders: false,
	skip: (req) => req.method === 'OPTIONS',
});

export function registerAuthRoutes(app) {
	app.post('/api/auth/token/', authBurstLimit, asyncHandler(async (req, res) => {
		const { username, password } = req.body || {};
		const result = await authenticate(username, password);
		res.json(result);
	}));

	app.get('/api/auth/me/', requireAuth, asyncHandler(async (req, res) => {
		res.json(buildPublicUser(req.user));
	}));
}
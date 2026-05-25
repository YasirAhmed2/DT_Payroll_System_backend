import rateLimit from 'express-rate-limit';

import { asyncHandler } from '../middleware/auth.js';
import { requestPublicSignupOtp, verifyPublicSignupOtp } from '../services/index.js';

const publicSignupLimit = rateLimit({
	windowMs: 15 * 60 * 1000,
	max: 5,
	standardHeaders: true,
	legacyHeaders: false,
});

export function registerPublicSignupRoutes(app) {
	app.post('/api/public-signup/request-otp/', publicSignupLimit, asyncHandler(async (req, res) => {
		const result = await requestPublicSignupOtp(req.body || {});
		res.json(result);
	}));

	app.post('/api/public-signup/verify-otp/', publicSignupLimit, asyncHandler(async (req, res) => {
		const result = await verifyPublicSignupOtp(req.body || {});
		res.status(201).json(result);
	}));
}
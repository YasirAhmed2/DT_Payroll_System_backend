import rateLimit from 'express-rate-limit';

import { asyncHandler, requireAuth, requireRoles } from '../middleware/auth.js';
import { requestAdminAccountOtp, verifyAdminAccountOtp, listAdminAccounts, updateAdminAccount, deleteAdminAccount } from '../services/index.js';

const otpRequestLimit = rateLimit({
	windowMs: 15 * 60 * 1000,
	max: 5,
	standardHeaders: true,
	legacyHeaders: false,
});

export function registerAdminAccountRoutes(app) {
	app.get('/api/admin-accounts/', requireAuth, requireRoles('ADMIN', 'ACCOUNTANT', 'OWNER'), asyncHandler(async (req, res) => {
		const result = await listAdminAccounts(req.user);
		res.json(result);
	}));

	app.post('/api/admin-accounts/request-otp/', requireAuth, requireRoles('ADMIN', 'ACCOUNTANT', 'OWNER'), otpRequestLimit, asyncHandler(async (req, res) => {
		const result = await requestAdminAccountOtp(req.body || {}, req.user);
		res.json(result);
	}));

	app.post('/api/admin-accounts/verify-otp/', requireAuth, requireRoles('ADMIN', 'ACCOUNTANT', 'OWNER'), otpRequestLimit, asyncHandler(async (req, res) => {
		const result = await verifyAdminAccountOtp(req.body || {}, req.user);
		res.status(201).json(result);
	}));

	app.patch('/api/admin-accounts/:accountId/', requireAuth, requireRoles('ADMIN', 'ACCOUNTANT', 'OWNER'), asyncHandler(async (req, res) => {
		const result = await updateAdminAccount(req.params.accountId, req.body || {}, req.user);
		res.json(result);
	}));

	app.delete('/api/admin-accounts/:accountId/', requireAuth, requireRoles('ADMIN', 'ACCOUNTANT', 'OWNER'), asyncHandler(async (req, res) => {
		const result = await deleteAdminAccount(req.params.accountId, req.user);
		res.json(result);
	}));
}
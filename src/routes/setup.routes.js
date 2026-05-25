import { asyncHandler } from '../middleware/auth.js';
import { setupCreate, setupNeed } from '../services/index.js';

export function registerSetupRoutes(app) {
	app.get('/api/setup/need/', asyncHandler(async (req, res) => {
		const need_setup = await setupNeed();
		res.json({ need_setup });
	}));

	app.post('/api/setup/create/', asyncHandler(async (req, res) => {
		const result = await setupCreate(req.body || {});
		res.status(201).json(result);
	}));
}
export function registerHealthRoutes(app) {
	app.get('/api/health/', (req, res) => {
		res.json({ status: 'ok', service: 'backend' });
	});
}
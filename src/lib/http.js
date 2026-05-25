export function parsePage(value, fallback = 1) {
	const page = Number.parseInt(String(value ?? fallback), 10);
	return Number.isFinite(page) && page > 0 ? page : fallback;
}

export function parsePageSize(value, fallback = 20) {
	const pageSize = Number.parseInt(String(value ?? fallback), 10);
	if (!Number.isFinite(pageSize) || pageSize <= 0) {
		return fallback;
	}

	return Math.min(pageSize, 100);
}

export function buildBaseUrl(req, suffix = '') {
	return `${req.protocol}://${req.get('host')}/api${suffix}`;
}
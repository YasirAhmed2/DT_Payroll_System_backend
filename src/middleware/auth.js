import { currentUserFromToken } from '../services/index.js';

export function asyncHandler(handler) {
	return (req, res, next) => {
		Promise.resolve(handler(req, res, next)).catch(next);
	};
}

export function buildPublicUser(user) {
	const { groups, ...publicUser } = user;
	return publicUser;
}

export function requireAuth(req, res, next) {
	const header = req.headers.authorization || '';
	const [scheme, token] = header.split(' ');
	if (scheme !== 'Token' || !token) {
		return res.status(401).json({ detail: 'Unauthorized.' });
	}

	currentUserFromToken(token)
		.then((user) => {
			req.user = user;
			next();
		})
		.catch((error) => {
			const status = error.status || 401;
			return res.status(status).json({ detail: error.message || 'Unauthorized.' });
		});
}

export function requireRoles(...allowedRoles) {
	return (req, res, next) => {
		if (!req.user) {
			return res.status(401).json({ detail: 'Unauthorized.' });
		}
		if (allowedRoles.length && !allowedRoles.includes(req.user.role)) {
			return res.status(403).json({ detail: 'Forbidden.' });
		}
		return next();
	};
}
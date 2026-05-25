export function errorHandler(error, req, res, next) { // eslint-disable-line no-unused-vars
	const status = error.status || 500;
	const payload = error.field
		? { [error.field]: error.message }
		: { detail: error.message || 'Internal Server Error' };
	if (status >= 500) {
		// eslint-disable-next-line no-console
		console.error(error);
	}
	res.status(status).json(payload);
}
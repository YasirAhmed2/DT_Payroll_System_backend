export const corsOrigins = (process.env.CORS_ALLOWED_ORIGINS || '')
	.split(',')
	.map((value) => value.trim())
	.filter(Boolean);
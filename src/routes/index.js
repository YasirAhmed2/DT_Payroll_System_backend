import { registerHealthRoutes } from './health.routes.js';
import { registerSetupRoutes } from './setup.routes.js';
import { registerAuthRoutes } from './auth.routes.js';
import { registerPublicSignupRoutes } from './public-signup.routes.js';
import { registerAdminAccountRoutes } from './admin-accounts.routes.js';
import { registerEmployeeRoutes } from './employees.routes.js';
import { registerPayrollRoutes } from './payroll.routes.js';
import { errorHandler } from '../middleware/error-handler.js';

export function registerRoutes(app) {
	registerHealthRoutes(app);
	registerSetupRoutes(app);
	registerAuthRoutes(app);
	registerPublicSignupRoutes(app);
	registerAdminAccountRoutes(app);
	registerEmployeeRoutes(app);
	registerPayrollRoutes(app);

	app.use(errorHandler);
}
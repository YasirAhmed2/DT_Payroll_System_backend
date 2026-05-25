import { asyncHandler, requireAuth, requireRoles } from '../middleware/auth.js';
import { employeeSegmentForUser, getEmployeeSegmentById, getRelatedEmployeeSegment, ensureSegmentAccess } from '../lib/segment.js';
import {
	createSalaryHistory,
	runMonthlySalaryDeductions,
	deleteSalaryHistory,
	updateSalaryDeduction,
	updateSalaryHistory,
} from '../services/index.js';

export function registerPayrollRoutes(app) {
	app.post('/api/employees/:id/salary/', requireAuth, requireRoles('ADMIN'), asyncHandler(async (req, res) => {
		const employeeId = Number(req.params.id);
		const employeeSegment = await getEmployeeSegmentById(employeeId);
		ensureSegmentAccess(employeeSegment, req.user.groups);
		const history = await createSalaryHistory({ employeeId, ...req.body }, req.user.id);
		res.status(201).json({
			employee_id: employeeId,
			salary: history.salary,
			effective_date: history.effective_date,
		});
	}));

	app.patch('/api/salary-history/:id/', requireAuth, requireRoles('ADMIN'), asyncHandler(async (req, res) => {
		const historyId = Number(req.params.id);
		const employeeSegment = await getRelatedEmployeeSegment('salary_history', historyId);
		ensureSegmentAccess(employeeSegment, req.user.groups);
		const history = await updateSalaryHistory(historyId, req.body || {}, req.user.id);
		res.json(history);
	}));

	app.delete('/api/salary-history/:id/', requireAuth, requireRoles('ADMIN'), asyncHandler(async (req, res) => {
		const historyId = Number(req.params.id);
		const employeeSegment = await getRelatedEmployeeSegment('salary_history', historyId);
		ensureSegmentAccess(employeeSegment, req.user.groups);
		await deleteSalaryHistory(historyId, req.user.id);
		res.status(204).end();
	}));

	app.patch('/api/salary-deduction/:id/', requireAuth, requireRoles('ADMIN', 'ACCOUNTANT'), asyncHandler(async (req, res) => {
		const deductionId = Number(req.params.id);
		const employeeSegment = await getRelatedEmployeeSegment('salary_deductions', deductionId);
		ensureSegmentAccess(employeeSegment, req.user.groups);
		const deduction = await updateSalaryDeduction(deductionId, req.body || {}, req.user.id);
		res.json(deduction);
	}));

	app.post('/api/salary-deductions/run/', requireAuth, requireRoles('ADMIN'), asyncHandler(async (req, res) => {
		const deductions = await runMonthlySalaryDeductions({
			month_year: req.body?.month_year,
			until_month_year: req.body?.until_month_year,
			employee_segment: employeeSegmentForUser(req.user),
		}, req.user.id);
		res.status(201).json({ created: deductions.length });
	}));
}
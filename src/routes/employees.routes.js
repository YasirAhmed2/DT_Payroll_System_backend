import { asyncHandler, requireAuth, requireRoles } from '../middleware/auth.js';
import { buildBaseUrl, parsePage, parsePageSize } from '../lib/http.js';
import { ensureSegmentAccess, employeeSegmentForUser, getEmployeeSegmentById, getRelatedEmployeeSegment } from '../lib/segment.js';
import {
	createEmployee,
	createPKRPayment,
	createRandPayment,
	createSalaryDeduction,
	createSalaryHistory,
	deleteEmployee,
	deletePKRPayment,
	deleteRandPayment,
	deleteSalaryHistory,
	employeeDetail,
	employeePdfData,
	employeeSummaryData,
	listEmployees,
	updateEmployeeDetails,
	updatePKRPayment,
	updateRandPayment,
	updateSalaryDeduction,
	updateSalaryHistory,
} from '../services/index.js';
import { buildEmployeeDetailPdf, buildEmployeeSummaryPdf } from '../pdf.js';

function employeeCompanyName(segment) {
	return segment === 'wholesale' ? 'Digital Tech Wholesale Employee Accounts' : 'Digital Tech Retail Accounts';
}

export function registerEmployeeRoutes(app) {
	app.get('/api/employees/', requireAuth, asyncHandler(async (req, res) => {
		const filter = req.query.filter ?? 'all';
		const page = parsePage(req.query.page, 1);
		const page_size = parsePageSize(req.query.page_size, 20);
		const results = await listEmployees(req.user, {
			filter,
			page,
			pageSize: page_size,
			baseUrl: buildBaseUrl(req, '/employees/'),
		});
		res.json(results);
	}));

	app.get('/api/employees/export-pdf/', requireAuth, asyncHandler(async (req, res) => {
		const results = await employeeSummaryData(req.user, {
			filter: 'all',
			page: 1,
			pageSize: 10000,
			baseUrl: buildBaseUrl(req, '/employees/'),
		});
		const buffer = await buildEmployeeSummaryPdf(results.results, 'Payroll Accounts', new Date().toISOString());
		res.setHeader('Content-Type', 'application/pdf');
		res.setHeader('Content-Disposition', 'attachment; filename="employee-summary-report.pdf"');
		res.send(buffer);
	}));

	app.post('/api/employees/add/', requireAuth, requireRoles('ADMIN'), asyncHandler(async (req, res) => {
		const employee = await createEmployee({
			...req.body,
			segment: employeeSegmentForUser(req.user) === 'wholesale' ? 'wholesale' : 'retail',
		}, req.user.id);
		res.status(201).json(employee);
	}));

	app.get('/api/employees/:id/export-pdf/', requireAuth, asyncHandler(async (req, res) => {
		const employeeId = Number(req.params.id);
		const employeeSegment = await getEmployeeSegmentById(employeeId);
		ensureSegmentAccess(employeeSegment, req.user.groups);
		const fromDate = req.query.from_date ? String(req.query.from_date) : null;
		const employee = await employeePdfData(employeeId, fromDate);
		const buffer = await buildEmployeeDetailPdf(employee, {
			company_name: employeeCompanyName(employee.segment),
			generated_at: new Date().toISOString(),
			months_since_joining: employee.months_since_joining,
			total_received: employee.total_received,
			total_deducted: employee.total_deducted,
			balance: employee.balance,
			pkr_payments: employee.pkr_payments,
			rand_payments: employee.rand_payments,
			salary_deductions: employee.salary_deductions,
		});
		res.setHeader('Content-Type', 'application/pdf');
		res.setHeader('Content-Disposition', `attachment; filename="${String(employee.name).replace(/\s+/g, '-').toLowerCase()}-summary.pdf"`);
		res.send(buffer);
	}));

	app.get('/api/employees/:id/', requireAuth, asyncHandler(async (req, res) => {
		const employeeId = Number(req.params.id);
		const employeeSegment = await getEmployeeSegmentById(employeeId);
		ensureSegmentAccess(employeeSegment, req.user.groups);
		const fromDate = req.query.from_date ? String(req.query.from_date) : null;
		const employee = await employeeDetail(employeeId, fromDate);
		res.json(employee);
	}));

	app.put('/api/employees/:id/update/', requireAuth, requireRoles('ADMIN'), asyncHandler(async (req, res) => {
		const employeeId = Number(req.params.id);
		const employeeSegment = await getEmployeeSegmentById(employeeId);
		ensureSegmentAccess(employeeSegment, req.user.groups);
		const employee = await updateEmployeeDetails(employeeId, req.body || {}, req.user.id);
		res.json(employee);
	}));

	app.patch('/api/employees/:id/update/', requireAuth, requireRoles('ADMIN'), asyncHandler(async (req, res) => {
		const employeeId = Number(req.params.id);
		const employeeSegment = await getEmployeeSegmentById(employeeId);
		ensureSegmentAccess(employeeSegment, req.user.groups);
		const employee = await updateEmployeeDetails(employeeId, req.body || {}, req.user.id);
		res.json(employee);
	}));

	app.delete('/api/employees/:id/update/', requireAuth, requireRoles('ADMIN'), asyncHandler(async (req, res) => {
		const employeeId = Number(req.params.id);
		const employeeSegment = await getEmployeeSegmentById(employeeId);
		ensureSegmentAccess(employeeSegment, req.user.groups);
		await deleteEmployee(employeeId, req.user.id);
		res.status(204).end();
	}));

	app.post('/api/employees/:id/payments/pkr/', requireAuth, requireRoles('ADMIN', 'ACCOUNTANT'), asyncHandler(async (req, res) => {
		const employeeId = Number(req.params.id);
		const employeeSegment = await getEmployeeSegmentById(employeeId);
		ensureSegmentAccess(employeeSegment, req.user.groups);
		const payment = await createPKRPayment({ employeeId, ...req.body }, req.user.id);
		res.status(201).json(payment);
	}));

	app.patch('/api/pkr-payment/:id/', requireAuth, requireRoles('ADMIN', 'ACCOUNTANT'), asyncHandler(async (req, res) => {
		const paymentId = Number(req.params.id);
		const employeeSegment = await getRelatedEmployeeSegment('pkr_payments', paymentId);
		ensureSegmentAccess(employeeSegment, req.user.groups);
		const payment = await updatePKRPayment(paymentId, req.body || {}, req.user.id);
		res.json(payment);
	}));

	app.delete('/api/pkr-payment/:id/', requireAuth, requireRoles('ADMIN', 'ACCOUNTANT'), asyncHandler(async (req, res) => {
		const paymentId = Number(req.params.id);
		const employeeSegment = await getRelatedEmployeeSegment('pkr_payments', paymentId);
		ensureSegmentAccess(employeeSegment, req.user.groups);
		await deletePKRPayment(paymentId, req.user.id);
		res.status(204).end();
	}));

	app.post('/api/employees/:id/payments/rand/', requireAuth, requireRoles('ADMIN', 'ACCOUNTANT'), asyncHandler(async (req, res) => {
		const employeeId = Number(req.params.id);
		const employeeSegment = await getEmployeeSegmentById(employeeId);
		ensureSegmentAccess(employeeSegment, req.user.groups);
		const payment = await createRandPayment({ employeeId, ...req.body }, req.user.id);
		res.status(201).json(payment);
	}));

	app.patch('/api/rand-payment/:id/', requireAuth, requireRoles('ADMIN', 'ACCOUNTANT'), asyncHandler(async (req, res) => {
		const paymentId = Number(req.params.id);
		const employeeSegment = await getRelatedEmployeeSegment('rand_payments', paymentId);
		ensureSegmentAccess(employeeSegment, req.user.groups);
		const payment = await updateRandPayment(paymentId, req.body || {}, req.user.id);
		res.json(payment);
	}));

	app.delete('/api/rand-payment/:id/', requireAuth, requireRoles('ADMIN', 'ACCOUNTANT'), asyncHandler(async (req, res) => {
		const paymentId = Number(req.params.id);
		const employeeSegment = await getRelatedEmployeeSegment('rand_payments', paymentId);
		ensureSegmentAccess(employeeSegment, req.user.groups);
		await deleteRandPayment(paymentId, req.user.id);
		res.status(204).end();
	}));

	app.post('/api/salary-deduction/manual/', requireAuth, requireRoles('ADMIN'), asyncHandler(async (req, res) => {
		const deduction = await createSalaryDeduction(req.body || {}, req.user.id);
		res.status(201).json(deduction);
	}));
}
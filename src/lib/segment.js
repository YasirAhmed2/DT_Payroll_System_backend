import { query } from '../db.js';
import { HttpError, employeeSegmentForGroups } from '../services/index.js';

export async function getEmployeeSegmentById(employeeId) {
	const result = await query('SELECT segment FROM employees WHERE id = $1', [employeeId]);
	return result.rows[0]?.segment ?? null;
}

export async function getRelatedEmployeeSegment(tableName, recordId) {
	const result = await query(`SELECT e.segment FROM ${tableName} t JOIN employees e ON e.id = t.employee_id WHERE t.id = $1`, [recordId]);
	return result.rows[0]?.segment ?? null;
}

export function ensureSegmentAccess(resourceSegment, userGroups) {
	const allowedSegment = employeeSegmentForGroups(userGroups || []);
	if (allowedSegment && resourceSegment !== allowedSegment) {
		throw new HttpError(404, 'Not found.');
	}
}

export function employeeSegmentForUser(user) {
	return employeeSegmentForGroups(user?.groups || []);
}
import crypto from 'crypto';
import Decimal from 'decimal.js';
import bcrypt from 'bcryptjs';

import { pool, query, withTransaction } from './db.js';
import { getOtpRecipientEmail, sendSignupOtpEmail } from './mail.js';

const DECIMAL_ZERO = new Decimal('0.00');
const DECIMAL_ONE = new Decimal('0.01');

export class HttpError extends Error {
  constructor(status, message, extra = {}) {
    super(message);
    this.status = status;
    Object.assign(this, extra);
  }
}

function httpError(status, message, extra = {}) {
  return new HttpError(status, message, extra);
}

function decimal(value) {
  return new Decimal(value ?? 0);
}

function money(value) {
  return decimal(value).toFixed(2);
}

function six(value) {
  return decimal(value).toFixed(6);
}

function todayIso() {
  return new Date().toISOString().slice(0, 10);
}

function parseDate(value, fieldName = 'date') {
  if (value instanceof Date && !Number.isNaN(value.valueOf())) {
    return value.toISOString().slice(0, 10);
  }

  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(value)) {
    throw httpError(400, `${fieldName} must be a date in YYYY-MM-DD format.`);
  }

  const parsed = new Date(`${value}T00:00:00Z`);
  if (Number.isNaN(parsed.valueOf())) {
    throw httpError(400, `${fieldName} must be a valid date.`);
  }

  return value;
}

function parseMonthYear(value, fieldName = 'month_year') {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}$/.test(value)) {
    throw httpError(400, `${fieldName} must be in YYYY-MM format.`);
  }

  const [yearText, monthText] = value.split('-');
  const year = Number(yearText);
  const month = Number(monthText);
  if (month < 1 || month > 12) {
    throw httpError(400, `${fieldName} must be in YYYY-MM format.`);
  }

  return { year, month };
}

function monthBounds(monthYear) {
  const { year, month } = parseMonthYear(monthYear);
  const start = new Date(Date.UTC(year, month - 1, 1));
  const end = new Date(Date.UTC(year, month, 0));
  return {
    start: start.toISOString().slice(0, 10),
    end: end.toISOString().slice(0, 10),
    lastDay: end.getUTCDate(),
  };
}

function previousMonthYear(referenceDate = new Date()) {
  const year = referenceDate.getUTCFullYear();
  const month = referenceDate.getUTCMonth() + 1;
  const previous = new Date(Date.UTC(year, month - 1, 1));
  previous.setUTCDate(0);
  return `${previous.getUTCFullYear()}-${String(previous.getUTCMonth() + 1).padStart(2, '0')}`;
}

function monthsBetween(startIso, endIso) {
  const start = new Date(`${startIso}T00:00:00Z`);
  const end = new Date(`${endIso}T00:00:00Z`);
  let months = (end.getUTCFullYear() - start.getUTCFullYear()) * 12 + (end.getUTCMonth() - start.getUTCMonth());
  if (end.getUTCDate() < start.getUTCDate()) {
    months -= 1;
  }
  return Math.max(months, 0);
}

function normalizeText(value) {
  return String(value ?? '').trim();
}

function normalizeEmail(value) {
  return normalizeText(value).toLowerCase();
}

function validateEmail(value) {
  const email = normalizeEmail(value);
  if (!email || email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    throw httpError(400, 'email must be a valid email address.');
  }
  return email;
}

function validateUsername(value) {
  const username = normalizeText(value);
  if (!username || username.length < 3 || username.length > 50 || !/^[A-Za-z0-9._-]+$/.test(username)) {
    throw httpError(400, 'username must be 3-50 characters and contain only letters, numbers, dot, underscore, or hyphen.');
  }
  return username;
}

function validateName(value, fieldName) {
  const name = normalizeText(value);
  if (!name || name.length > 100) {
    throw httpError(400, `${fieldName} is required and must be at most 100 characters.`);
  }
  return name;
}

function validatePasswordStrength(value) {
  const password = String(value ?? '');
  if (password.length < 8 || password.length > 128) {
    throw httpError(400, 'password must be between 8 and 128 characters long.');
  }
  if (!/[a-z]/.test(password) || !/[A-Z]/.test(password) || !/\d/.test(password) || !/[^A-Za-z0-9]/.test(password)) {
    throw httpError(400, 'password must include upper and lower case letters, a number, and a special character.');
  }
  return password;
}

function getPasswordPepper() {
  const pepper = process.env.SECRET_KEY || process.env.JWT_SECRET;
  if (!pepper) {
    throw new Error('SECRET_KEY is required for password hashing.');
  }
  return pepper;
}

function passwordDigest(password) {
  return crypto.createHmac('sha256', getPasswordPepper()).update(String(password ?? '')).digest('hex');
}

async function hashPassword(password) {
  return bcrypt.hash(passwordDigest(password), 12);
}

async function comparePassword(password, storedHash) {
  const peppered = passwordDigest(password);
  if (await bcrypt.compare(peppered, storedHash)) {
    return true;
  }

  return bcrypt.compare(String(password ?? ''), storedHash);
}

function validateSegment(value) {
  const segment = normalizeText(value).toLowerCase();
  if (!['retail', 'wholesale'].includes(segment)) {
    throw httpError(400, 'segment must be retail or wholesale.');
  }
  return segment;
}

function validateOtp(value) {
  const otp = normalizeText(value);
  if (!/^\d{6}$/.test(otp)) {
    throw httpError(400, 'otp must be a 6-digit code.');
  }
  return otp;
}

function validateIdentifier(value, fieldName = 'id') {
  const numeric = Number(value);
  if (!Number.isInteger(numeric) || numeric <= 0) {
    throw httpError(400, `${fieldName} must be a positive integer.`);
  }
  return numeric;
}

function generateOtp() {
  return String(crypto.randomInt(100000, 1000000));
}

function isAdminAccountCreator(user) {
  if (!user) {
    return false;
  }
  return ['OWNER', 'ADMIN', 'ACCOUNTANT'].includes(user.role);
}

function isPositive(value) {
  return decimal(value).gt(DECIMAL_ZERO);
}

function ensurePositive(value, fieldName) {
  if (!isPositive(value)) {
    throw httpError(400, `${fieldName} must be greater than zero.`);
  }
}

function ensureNonNegative(value, fieldName) {
  if (decimal(value).lt(DECIMAL_ZERO)) {
    throw httpError(400, `${fieldName} must be greater than or equal to zero.`);
  }
}

function accountBrandingForGroups(groups = []) {
  const names = new Set(groups.map((name) => String(name).toLowerCase()));
  if (names.has('wholesale_admin') || names.has('wholesale')) {
    return { account_title: 'Digital Tech WholeSale Employee Accounts', account_type: 'wholesale' };
  }
  return { account_title: 'Digital Tech Retail Accounts', account_type: 'retail' };
}

function employeeSegmentForGroups(groups = []) {
  const names = new Set(groups.map((name) => String(name).toLowerCase()));
  if (names.has('wholesale_admin') || names.has('wholesale')) {
    return 'wholesale';
  }
  if (names.has('retail_admin') || names.has('retail')) {
    return 'retail';
  }
  return null;
}

function mapGroupRows(rows) {
  return rows.map((row) => row.name);
}

async function getUserGroupsByUserId(client, userId) {
  const result = await client.query(
    `SELECT g.name
     FROM groups g
     JOIN user_groups ug ON ug.group_id = g.id
     WHERE ug.user_id = $1
     ORDER BY g.name`,
    [userId],
  );
  return mapGroupRows(result.rows);
}

async function getUserWithGroupsByUsername(client, username) {
  const result = await client.query(
    `SELECT u.id, u.username, u.password_hash, u.role, u.email, u.first_name, u.last_name, u.is_staff, u.is_active,
            COALESCE(json_agg(g.name) FILTER (WHERE g.name IS NOT NULL), '[]') AS groups
     FROM users u
     LEFT JOIN user_groups ug ON ug.user_id = u.id
     LEFT JOIN groups g ON g.id = ug.group_id
     WHERE u.username = $1
     GROUP BY u.id`,
    [username],
  );
  return result.rows[0] || null;
}

async function getUserWithGroupsByToken(client, token) {
  const result = await client.query(
    `SELECT u.id, u.username, u.password_hash, u.role, u.email, u.first_name, u.last_name, u.is_staff, u.is_active,
            COALESCE(json_agg(g.name) FILTER (WHERE g.name IS NOT NULL), '[]') AS groups
     FROM tokens t
     JOIN users u ON u.id = t.user_id
     LEFT JOIN user_groups ug ON ug.user_id = u.id
     LEFT JOIN groups g ON g.id = ug.group_id
     WHERE t.key = $1
     GROUP BY u.id`,
    [token],
  );
  return result.rows[0] || null;
}

async function getOrCreateToken(client, userId) {
  const tokenResult = await client.query('SELECT key FROM tokens WHERE user_id = $1', [userId]);
  if (tokenResult.rows[0]) {
    return tokenResult.rows[0].key;
  }

  const key = crypto.randomBytes(20).toString('hex');
  await client.query('INSERT INTO tokens (key, user_id) VALUES ($1, $2)', [key, userId]);
  return key;
}

async function writeAuditLog(client, { userId = null, action, modelChanged, description, beforeValues = null, afterValues = null }) {
  await client.query(
    `INSERT INTO audit_logs (user_id, action, model_changed, description, before_values, after_values)
     VALUES ($1, $2, $3, $4, $5, $6)`,
    [userId, action, modelChanged, description, beforeValues, afterValues],
  );
}

async function refreshEmployeeBalance(client, employeeId) {
  const received = await client.query(
    `SELECT COALESCE(SUM(amount), 0) AS total
     FROM pkr_payments
     WHERE employee_id = $1`,
    [employeeId],
  );
  const rand = await client.query(
    `SELECT COALESCE(SUM(amount_pkr), 0) AS total
     FROM rand_payments
     WHERE employee_id = $1`,
    [employeeId],
  );
  const deducted = await client.query(
    `SELECT COALESCE(SUM(amount), 0) AS total
     FROM salary_deductions
     WHERE employee_id = $1`,
    [employeeId],
  );

  const balance = decimal(received.rows[0].total).add(decimal(rand.rows[0].total)).minus(decimal(deducted.rows[0].total)).toFixed(2);
  await client.query('UPDATE employees SET balance = $1, updated_at = NOW() WHERE id = $2', [balance, employeeId]);
  return balance;
}

async function latestSalaryForEmployee(client, employeeId, asOf = todayIso()) {
  const result = await client.query(
    `SELECT salary
     FROM salary_history
     WHERE employee_id = $1 AND effective_date <= $2
     ORDER BY effective_date DESC, id DESC
     LIMIT 1`,
    [employeeId, asOf],
  );
  return result.rows[0] ? result.rows[0].salary : null;
}

async function salaryForDate(client, employeeId, asOf) {
  const latest = await latestSalaryForEmployee(client, employeeId, asOf);
  if (latest !== null) {
    return latest;
  }

  const employeeResult = await client.query('SELECT current_salary FROM employees WHERE id = $1', [employeeId]);
  return employeeResult.rows[0]?.current_salary ?? '0.00';
}

async function totalReceivedBeforeDate(client, employeeId, beforeDate, includeVisa = false) {
  const pkr = await client.query(
    `SELECT COALESCE(SUM(amount), 0) AS total
     FROM pkr_payments
     WHERE employee_id = $1 AND date < $2`,
    [employeeId, beforeDate],
  );
  const rand = await client.query(
    `SELECT COALESCE(SUM(amount_pkr), 0) AS total
     FROM rand_payments
     WHERE employee_id = $1 AND date < $2`,
    [employeeId, beforeDate],
  );
  const fee = includeVisa ? await client.query('SELECT visa_processing_fee FROM employees WHERE id = $1', [employeeId]) : null;
  const total = decimal(pkr.rows[0].total).add(decimal(rand.rows[0].total)).add(includeVisa ? decimal(fee.rows[0]?.visa_processing_fee ?? 0) : DECIMAL_ZERO);
  return total.toFixed(2);
}

async function totalDeductionsBeforeDate(client, employeeId, beforeDate) {
  const result = await client.query(
    `SELECT COALESCE(SUM(amount), 0) AS total
     FROM salary_deductions
     WHERE employee_id = $1 AND date < $2`,
    [employeeId, beforeDate],
  );
  return decimal(result.rows[0].total).toFixed(2);
}

async function totalReceivedTillDate(client, employeeId, asOf, includeVisa = false) {
  const pkr = await client.query(
    `SELECT COALESCE(SUM(amount), 0) AS total
     FROM pkr_payments
     WHERE employee_id = $1 AND date <= $2`,
    [employeeId, asOf],
  );
  const rand = await client.query(
    `SELECT COALESCE(SUM(amount_pkr), 0) AS total
     FROM rand_payments
     WHERE employee_id = $1 AND date <= $2`,
    [employeeId, asOf],
  );
  const fee = includeVisa ? await client.query('SELECT visa_processing_fee FROM employees WHERE id = $1', [employeeId]) : null;
  const total = decimal(pkr.rows[0].total).add(decimal(rand.rows[0].total)).add(includeVisa ? decimal(fee.rows[0]?.visa_processing_fee ?? 0) : DECIMAL_ZERO);
  return total.toFixed(2);
}

async function totalDeductionsTillDate(client, employeeId, asOf) {
  const result = await client.query(
    `SELECT COALESCE(SUM(amount), 0) AS total
     FROM salary_deductions
     WHERE employee_id = $1 AND date <= $2`,
    [employeeId, asOf],
  );
  return decimal(result.rows[0].total).toFixed(2);
}

async function calculateBalance(client, employeeId, asOf) {
  const received = await totalReceivedTillDate(client, employeeId, asOf, false);
  const deducted = await totalDeductionsTillDate(client, employeeId, asOf);
  return decimal(received).minus(decimal(deducted)).toFixed(2);
}

async function totalMonthsSinceJoining(client, employeeId, asOf = todayIso()) {
  const employee = await client.query('SELECT joining_date FROM employees WHERE id = $1', [employeeId]);
  if (!employee.rows[0]) {
    throw httpError(404, 'Employee not found.');
  }
  const joiningDate = employee.rows[0].joining_date;
  if (asOf < joiningDate) {
    return 0;
  }
  return monthsBetween(joiningDate, asOf);
}

async function summarizeSalaryDeductions(deductions) {
  const summary = new Map();
  for (const deduction of deductions) {
    const key = money(deduction.amount);
    summary.set(key, (summary.get(key) || 0) + 1);
  }
  return [...summary.entries()].sort((a, b) => decimal(a[0]).cmp(decimal(b[0]))).map(([amount, count]) => `PKR ${amount} x ${count} month${count !== 1 ? 's' : ''}`);
}

async function salaryHistoryWithMonths(client, employeeId) {
  const histories = await client.query(
    `SELECT id, salary, effective_date
     FROM salary_history
     WHERE employee_id = $1
     ORDER BY effective_date DESC, id DESC`,
    [employeeId],
  );

  const rows = histories.rows;
  for (let index = 0; index < rows.length; index += 1) {
    const current = rows[index];
    const next = rows[index - 1];
    const endDate = next ? new Date(`${next.effective_date}T00:00:00Z`) : new Date(`${todayIso()}T00:00:00Z`);
    if (next) {
      endDate.setUTCDate(endDate.getUTCDate() - 1);
    }
    rows[index] = {
      id: current.id,
      salary: current.salary,
      effective_date: current.effective_date,
      months: Math.max(monthsBetween(current.effective_date, endDate.toISOString().slice(0, 10)), 0),
    };
  }

  return rows;
}

async function buildLedger(client, employeeId, fromDate = null) {
  const pkrQuery = fromDate
    ? `SELECT id, amount, date, reference FROM pkr_payments WHERE employee_id = $1 AND date >= $2 ORDER BY date DESC, id DESC`
    : `SELECT id, amount, date, reference FROM pkr_payments WHERE employee_id = $1 ORDER BY date DESC, id DESC`;
  const randQuery = fromDate
    ? `SELECT id, amount_rand, conversion_rate, amount_pkr, date, reference FROM rand_payments WHERE employee_id = $1 AND date >= $2 ORDER BY date DESC, id DESC`
    : `SELECT id, amount_rand, conversion_rate, amount_pkr, date, reference FROM rand_payments WHERE employee_id = $1 ORDER BY date DESC, id DESC`;
  const dedQuery = fromDate
    ? `SELECT id, amount, date, reference, month_year FROM salary_deductions WHERE employee_id = $1 AND date >= $2 ORDER BY date DESC, id DESC`
    : `SELECT id, amount, date, reference, month_year FROM salary_deductions WHERE employee_id = $1 ORDER BY date DESC, id DESC`;

  const pkrPayments = await client.query(pkrQuery, fromDate ? [employeeId, fromDate] : [employeeId]);
  const randPayments = await client.query(randQuery, fromDate ? [employeeId, fromDate] : [employeeId]);
  const salaryDeductions = await client.query(dedQuery, fromDate ? [employeeId, fromDate] : [employeeId]);

  let openingBalance = '0.00';
  if (fromDate) {
    const receivedBefore = await totalReceivedBeforeDate(client, employeeId, fromDate, false);
    const deductedBefore = await totalDeductionsBeforeDate(client, employeeId, fromDate);
    openingBalance = decimal(receivedBefore).minus(decimal(deductedBefore)).toFixed(2);
  }

  const filteredReceived = decimal(pkrPayments.rows.reduce((sum, row) => sum.plus(row.amount), DECIMAL_ZERO)).add(
    randPayments.rows.reduce((sum, row) => sum.plus(row.amount_pkr), DECIMAL_ZERO),
  ).toFixed(2);
  const filteredDeducted = salaryDeductions.rows.reduce((sum, row) => sum.plus(row.amount), DECIMAL_ZERO).toFixed(2);

  return {
    opening_balance: openingBalance,
    from_date: fromDate,
    pkr_payments: pkrPayments.rows,
    rand_payments: randPayments.rows,
    salary_deductions: salaryDeductions.rows,
    filtered_received: filteredReceived,
    filtered_deducted: filteredDeducted,
  };
}

async function getEmployeeById(client, employeeId) {
  const result = await client.query('SELECT * FROM employees WHERE id = $1', [employeeId]);
  return result.rows[0] || null;
}

async function buildEmployeeDetail(client, employeeId, fromDate = null) {
  const employee = await getEmployeeById(client, employeeId);
  if (!employee) {
    throw httpError(404, 'Employee not found.');
  }

  const ledger = await buildLedger(client, employeeId, fromDate);
  const totalReceived = await totalReceivedTillDate(client, employeeId, todayIso(), false);
  const totalDeducted = await totalDeductionsTillDate(client, employeeId, todayIso());
  const monthsSinceJoining = await totalMonthsSinceJoining(client, employeeId, todayIso());
  const salaryHistory = await salaryHistoryWithMonths(client, employeeId);
  const deductionSummary = await summarizeSalaryDeductions(ledger.salary_deductions);
  const balance = employee.balance;
  const balanceNumber = decimal(balance);
  const balanceState = balanceNumber.gt(DECIMAL_ZERO)
    ? 'company_owes_employee'
    : balanceNumber.lt(DECIMAL_ZERO)
      ? 'employee_owes_company'
      : 'settled';
  const balanceLabel = balanceState === 'company_owes_employee'
    ? 'Company owes employee'
    : balanceState === 'employee_owes_company'
      ? 'Employee owes company'
      : 'Balance settled';

  return {
    ...employee,
    months_since_joining: monthsSinceJoining,
    total_received: totalReceived,
    total_deducted: totalDeducted,
    company_owes_employee: balanceNumber.gt(DECIMAL_ZERO),
    in_debt: balanceNumber.lt(DECIMAL_ZERO),
    balance_state: balanceState,
    balance_label: balanceLabel,
    opening_balance: ledger.opening_balance,
    ledger_from_date: ledger.from_date,
    filtered_received: ledger.filtered_received,
    filtered_deducted: ledger.filtered_deducted,
    deduction_summary: deductionSummary,
    salary_history: salaryHistory,
    pkr_payments: ledger.pkr_payments,
    rand_payments: ledger.rand_payments,
    salary_deductions: ledger.salary_deductions,
  };
}

async function createEmployeeInternal(client, { name, segment, joining_date, current_salary, visa_processing_fee }, actorUserId = null) {
  const joiningDate = parseDate(joining_date, 'joining_date');
  const currentSalary = money(current_salary);
  const visaFee = money(visa_processing_fee);
  if (joiningDate > todayIso()) {
    throw httpError(400, 'joining_date cannot be in the future.');
  }

  const insertEmployee = await client.query(
    `INSERT INTO employees (name, segment, joining_date, current_salary, visa_processing_fee, balance)
     VALUES ($1, $2, $3, $4, $5, 0)
     RETURNING *`,
    [normalizeText(name), segment || 'retail', joiningDate, currentSalary, visaFee],
  );
  const employee = insertEmployee.rows[0];

  await client.query(
    `INSERT INTO salary_history (employee_id, salary, effective_date)
     VALUES ($1, $2, $3)`,
    [employee.id, currentSalary, joiningDate],
  );

  if (decimal(visaFee).gt(DECIMAL_ZERO)) {
    await client.query(
      `INSERT INTO pkr_payments (employee_id, date, amount, reference)
       VALUES ($1, $2, $3, $4)`,
      [employee.id, joiningDate, visaFee, 'VISA PROCESSING FEE'],
    );
  }

  await refreshEmployeeBalance(client, employee.id);
  const refreshed = await getEmployeeById(client, employee.id);
  await writeAuditLog(client, {
    userId: actorUserId,
    action: 'CREATE',
    modelChanged: 'Employee',
    description: 'CREATE employee.',
    beforeValues: null,
    afterValues: refreshed,
  });
  return refreshed;
}

async function updateEmployeeDetailsInternal(client, employeeId, { name, joining_date, visa_processing_fee }, actorUserId = null) {
  const employee = await getEmployeeById(client, employeeId);
  if (!employee) {
    throw httpError(404, 'Employee not found.');
  }
  const joiningDate = parseDate(joining_date, 'joining_date');
  if (joiningDate > todayIso()) {
    throw httpError(400, 'joining_date cannot be in the future.');
  }
  const updatedFee = money(visa_processing_fee);

  const result = await client.query(
    `UPDATE employees
     SET name = $1, joining_date = $2, visa_processing_fee = $3, updated_at = NOW()
     WHERE id = $4
     RETURNING *`,
    [normalizeText(name), joiningDate, updatedFee, employeeId],
  );
  await refreshEmployeeBalance(client, employeeId);
  const refreshed = await getEmployeeById(client, employeeId);
  await writeAuditLog(client, {
    userId: actorUserId,
    action: 'UPDATE',
    modelChanged: 'Employee',
    description: 'UPDATE employee.',
    beforeValues: employee,
    afterValues: refreshed,
  });
  return result.rows[0];
}

async function deleteEmployeeInternal(client, employeeId, actorUserId = null) {
  const employee = await getEmployeeById(client, employeeId);
  if (!employee) {
    throw httpError(404, 'Employee not found.');
  }
  await client.query('DELETE FROM employees WHERE id = $1', [employeeId]);
  await writeAuditLog(client, {
    userId: actorUserId,
    action: 'DELETE',
    modelChanged: 'Employee',
    description: 'DELETE employee.',
    beforeValues: employee,
    afterValues: null,
  });
}

async function createPKRPaymentInternal(client, { employeeId, amount, date, reference }, actorUserId = null) {
  const employee = await getEmployeeById(client, employeeId);
  if (!employee) {
    throw httpError(404, 'Employee not found.');
  }
  const paymentDate = parseDate(date || todayIso(), 'date');
  if (paymentDate < employee.joining_date) {
    throw httpError(400, 'Payment date cannot be earlier than the employee joining date.');
  }
  ensurePositive(amount, 'amount');

  const result = await client.query(
    `INSERT INTO pkr_payments (employee_id, date, amount, reference)
     VALUES ($1, $2, $3, $4)
     RETURNING *`,
    [employeeId, paymentDate, money(amount), normalizeText(reference)],
  );
  await refreshEmployeeBalance(client, employeeId);
  await writeAuditLog(client, {
    userId: actorUserId,
    action: 'CREATE',
    modelChanged: 'PKRPayment',
    description: 'CREATE PKR payment.',
    beforeValues: null,
    afterValues: result.rows[0],
  });
  return result.rows[0];
}

async function updatePKRPaymentInternal(client, paymentId, { employeeId, amount, date, reference }, actorUserId = null) {
  const paymentResult = await client.query('SELECT * FROM pkr_payments WHERE id = $1', [paymentId]);
  const payment = paymentResult.rows[0];
  if (!payment) {
    throw httpError(404, 'PKR payment not found.');
  }
  const employee = await getEmployeeById(client, employeeId);
  if (!employee) {
    throw httpError(404, 'Employee not found.');
  }
  if (Number(payment.employee_id) !== Number(employeeId)) {
    throw httpError(400, 'PKR payment does not belong to the specified employee.');
  }
  const paymentDate = parseDate(date, 'date');
  if (paymentDate < employee.joining_date) {
    throw httpError(400, 'Payment date cannot be earlier than the employee joining date.');
  }
  ensurePositive(amount, 'amount');

  const result = await client.query(
    `UPDATE pkr_payments
     SET date = $1, amount = $2, reference = $3
     WHERE id = $4
     RETURNING *`,
    [paymentDate, money(amount), normalizeText(reference), paymentId],
  );
  await refreshEmployeeBalance(client, employeeId);
  await writeAuditLog(client, {
    userId: actorUserId,
    action: 'UPDATE',
    modelChanged: 'PKRPayment',
    description: 'UPDATE PKR payment.',
    beforeValues: payment,
    afterValues: result.rows[0],
  });
  return result.rows[0];
}

async function deletePKRPaymentInternal(client, paymentId, actorUserId = null) {
  const paymentResult = await client.query('SELECT * FROM pkr_payments WHERE id = $1', [paymentId]);
  const payment = paymentResult.rows[0];
  if (!payment) {
    throw httpError(404, 'PKR payment not found.');
  }
  await client.query('DELETE FROM pkr_payments WHERE id = $1', [paymentId]);
  await refreshEmployeeBalance(client, payment.employee_id);
  await writeAuditLog(client, {
    userId: actorUserId,
    action: 'DELETE',
    modelChanged: 'PKRPayment',
    description: 'DELETE PKR payment.',
    beforeValues: payment,
    afterValues: null,
  });
}

async function createRandPaymentInternal(client, { employeeId, amount_rand, conversion_rate, date, reference }, actorUserId = null) {
  const employee = await getEmployeeById(client, employeeId);
  if (!employee) {
    throw httpError(404, 'Employee not found.');
  }
  const paymentDate = parseDate(date || todayIso(), 'date');
  if (paymentDate < employee.joining_date) {
    throw httpError(400, 'Payment date cannot be earlier than the employee joining date.');
  }
  ensurePositive(amount_rand, 'amount_rand');
  ensurePositive(conversion_rate, 'conversion_rate');

  const amountPkr = decimal(amount_rand).mul(decimal(conversion_rate)).toDecimalPlaces(2).toFixed(2);
  const result = await client.query(
    `INSERT INTO rand_payments (employee_id, date, amount_rand, conversion_rate, amount_pkr, reference)
     VALUES ($1, $2, $3, $4, $5, $6)
     RETURNING *`,
    [employeeId, paymentDate, money(amount_rand), six(conversion_rate), amountPkr, normalizeText(reference)],
  );
  await refreshEmployeeBalance(client, employeeId);
  await writeAuditLog(client, {
    userId: actorUserId,
    action: 'CREATE',
    modelChanged: 'RandPayment',
    description: 'CREATE Rand payment.',
    beforeValues: null,
    afterValues: result.rows[0],
  });
  return result.rows[0];
}

async function updateRandPaymentInternal(client, paymentId, { employeeId, amount_rand, conversion_rate, date, reference }, actorUserId = null) {
  const paymentResult = await client.query('SELECT * FROM rand_payments WHERE id = $1', [paymentId]);
  const payment = paymentResult.rows[0];
  if (!payment) {
    throw httpError(404, 'Rand payment not found.');
  }
  const employee = await getEmployeeById(client, employeeId);
  if (!employee) {
    throw httpError(404, 'Employee not found.');
  }
  if (Number(payment.employee_id) !== Number(employeeId)) {
    throw httpError(400, 'Rand payment does not belong to the specified employee.');
  }
  const paymentDate = parseDate(date, 'date');
  if (paymentDate < employee.joining_date) {
    throw httpError(400, 'Payment date cannot be earlier than the employee joining date.');
  }
  ensurePositive(amount_rand, 'amount_rand');
  ensurePositive(conversion_rate, 'conversion_rate');

  const amountPkr = decimal(amount_rand).mul(decimal(conversion_rate)).toDecimalPlaces(2).toFixed(2);
  const result = await client.query(
    `UPDATE rand_payments
     SET date = $1, amount_rand = $2, conversion_rate = $3, amount_pkr = $4, reference = $5
     WHERE id = $6
     RETURNING *`,
    [paymentDate, money(amount_rand), six(conversion_rate), amountPkr, normalizeText(reference), paymentId],
  );
  await refreshEmployeeBalance(client, employeeId);
  await writeAuditLog(client, {
    userId: actorUserId,
    action: 'UPDATE',
    modelChanged: 'RandPayment',
    description: 'UPDATE Rand payment.',
    beforeValues: payment,
    afterValues: result.rows[0],
  });
  return result.rows[0];
}

async function deleteRandPaymentInternal(client, paymentId, actorUserId = null) {
  const paymentResult = await client.query('SELECT * FROM rand_payments WHERE id = $1', [paymentId]);
  const payment = paymentResult.rows[0];
  if (!payment) {
    throw httpError(404, 'Rand payment not found.');
  }
  await client.query('DELETE FROM rand_payments WHERE id = $1', [paymentId]);
  await refreshEmployeeBalance(client, payment.employee_id);
  await writeAuditLog(client, {
    userId: actorUserId,
    action: 'DELETE',
    modelChanged: 'RandPayment',
    description: 'DELETE Rand payment.',
    beforeValues: payment,
    afterValues: null,
  });
}

async function createSalaryHistoryInternal(client, { employeeId, salary, new_salary, effective_date }, actorUserId = null) {
  const employee = await getEmployeeById(client, employeeId);
  if (!employee) {
    throw httpError(404, 'Employee not found.');
  }
  const effectiveDate = parseDate(effective_date || todayIso(), 'effective_date');
  if (effectiveDate < employee.joining_date) {
    throw httpError(400, 'effective_date cannot be earlier than the employee joining date.');
  }
  const salaryValue = salary ?? new_salary;
  ensurePositive(salaryValue, 'salary');

  const result = await client.query(
    `INSERT INTO salary_history (employee_id, salary, effective_date)
     VALUES ($1, $2, $3)
     RETURNING *`,
    [employeeId, money(salaryValue), effectiveDate],
  );

  const latest = await latestSalaryForEmployee(client, employeeId, effectiveDate);
  await client.query('UPDATE employees SET current_salary = $1, updated_at = NOW() WHERE id = $2', [latest || money(salaryValue), employeeId]);
  await refreshEmployeeBalance(client, employeeId);
  await writeAuditLog(client, {
    userId: actorUserId,
    action: 'CREATE',
    modelChanged: 'SalaryHistory',
    description: 'CREATE salary history.',
    beforeValues: null,
    afterValues: result.rows[0],
  });
  return result.rows[0];
}

async function updateSalaryHistoryInternal(client, historyId, { employeeId, salary, effective_date }, actorUserId = null) {
  const historyResult = await client.query('SELECT * FROM salary_history WHERE id = $1', [historyId]);
  const history = historyResult.rows[0];
  if (!history) {
    throw httpError(404, 'Salary history not found.');
  }
  const employee = await getEmployeeById(client, employeeId);
  if (!employee) {
    throw httpError(404, 'Employee not found.');
  }
  if (Number(history.employee_id) !== Number(employeeId)) {
    throw httpError(400, 'Salary history does not belong to the specified employee.');
  }
  const effectiveDate = parseDate(effective_date, 'effective_date');
  if (effectiveDate < employee.joining_date) {
    throw httpError(400, 'effective_date cannot be earlier than the employee joining date.');
  }
  ensurePositive(salary, 'salary');

  const result = await client.query(
    `UPDATE salary_history
     SET salary = $1, effective_date = $2
     WHERE id = $3
     RETURNING *`,
    [money(salary), effectiveDate, historyId],
  );

  const latest = await latestSalaryForEmployee(client, employeeId, todayIso());
  const currentSalary = latest || money(salary);
  await client.query('UPDATE employees SET current_salary = $1, updated_at = NOW() WHERE id = $2', [currentSalary, employeeId]);
  await refreshEmployeeBalance(client, employeeId);
  await writeAuditLog(client, {
    userId: actorUserId,
    action: 'UPDATE',
    modelChanged: 'SalaryHistory',
    description: 'UPDATE salary history.',
    beforeValues: history,
    afterValues: result.rows[0],
  });
  return result.rows[0];
}

async function deleteSalaryHistoryInternal(client, historyId, actorUserId = null) {
  const historyResult = await client.query('SELECT * FROM salary_history WHERE id = $1', [historyId]);
  const history = historyResult.rows[0];
  if (!history) {
    throw httpError(404, 'Salary history not found.');
  }
  await client.query('DELETE FROM salary_history WHERE id = $1', [historyId]);
  const latest = await latestSalaryForEmployee(client, history.employee_id, todayIso());
  const employee = await getEmployeeById(client, history.employee_id);
  if (employee) {
    await client.query('UPDATE employees SET current_salary = $1, updated_at = NOW() WHERE id = $2', [latest || employee.current_salary, history.employee_id]);
    await refreshEmployeeBalance(client, history.employee_id);
  }
  await writeAuditLog(client, {
    userId: actorUserId,
    action: 'DELETE',
    modelChanged: 'SalaryHistory',
    description: 'DELETE salary history.',
    beforeValues: history,
    afterValues: null,
  });
}

async function createSalaryDeductionInternal(client, { employeeId, amount, date, reference, month_year = null }, actorUserId = null) {
  const employee = await getEmployeeById(client, employeeId);
  if (!employee) {
    throw httpError(404, 'Employee not found.');
  }
  const deductionDate = parseDate(date || todayIso(), 'date');
  if (deductionDate < employee.joining_date) {
    throw httpError(400, 'Payment date cannot be earlier than the employee joining date.');
  }
  ensurePositive(amount, 'amount');
  if (month_year) {
    monthBounds(month_year);
  }

  const result = await client.query(
    `INSERT INTO salary_deductions (employee_id, date, amount, reference, month_year)
     VALUES ($1, $2, $3, $4, $5)
     RETURNING *`,
    [employeeId, deductionDate, money(amount), normalizeText(reference), month_year || null],
  );
  await refreshEmployeeBalance(client, employeeId);
  await writeAuditLog(client, {
    userId: actorUserId,
    action: 'CREATE',
    modelChanged: 'SalaryDeduction',
    description: 'CREATE salary deduction.',
    beforeValues: null,
    afterValues: result.rows[0],
  });
  return result.rows[0];
}

async function updateSalaryDeductionInternal(client, deductionId, { employeeId, amount, date, reference }, actorUserId = null) {
  const deductionResult = await client.query('SELECT * FROM salary_deductions WHERE id = $1', [deductionId]);
  const deduction = deductionResult.rows[0];
  if (!deduction) {
    throw httpError(404, 'Salary deduction not found.');
  }
  const employee = await getEmployeeById(client, employeeId);
  if (!employee) {
    throw httpError(404, 'Employee not found.');
  }
  if (Number(deduction.employee_id) !== Number(employeeId)) {
    throw httpError(400, 'Salary deduction does not belong to the specified employee.');
  }
  const deductionDate = parseDate(date, 'date');
  if (deductionDate < employee.joining_date) {
    throw httpError(400, 'Payment date cannot be earlier than the employee joining date.');
  }
  ensurePositive(amount, 'amount');

  const result = await client.query(
    `UPDATE salary_deductions
     SET date = $1, amount = $2, reference = $3
     WHERE id = $4
     RETURNING *`,
    [deductionDate, money(amount), normalizeText(reference), deductionId],
  );
  await refreshEmployeeBalance(client, employeeId);
  await writeAuditLog(client, {
    userId: actorUserId,
    action: 'UPDATE',
    modelChanged: 'SalaryDeduction',
    description: 'UPDATE salary deduction.',
    beforeValues: deduction,
    afterValues: result.rows[0],
  });
  return result.rows[0];
}

async function runMonthlySalaryDeductionsInternal(client, { month_year, until_month_year, employee_segment = null }, actorUserId = null) {
  const startMonthYear = month_year || previousMonthYear();
  const endMonthYear = until_month_year || startMonthYear;
  const startBounds = monthBounds(startMonthYear);
  const endBounds = monthBounds(endMonthYear);
  if (endBounds.start < startBounds.start) {
    throw httpError(400, 'until_month_year must be the same or after month_year');
  }

  const monthsToProcess = [];
  let cursor = new Date(`${startBounds.start}T00:00:00Z`);
  const endCursor = new Date(`${endBounds.start}T00:00:00Z`);
  while (cursor <= endCursor) {
    monthsToProcess.push(`${cursor.getUTCFullYear()}-${String(cursor.getUTCMonth() + 1).padStart(2, '0')}`);
    cursor = new Date(Date.UTC(cursor.getUTCFullYear(), cursor.getUTCMonth() + 1, 1));
  }

  const employeeQuery = employee_segment
    ? `SELECT * FROM employees WHERE joining_date <= $1 AND segment = $2 ORDER BY id`
    : `SELECT * FROM employees WHERE joining_date <= $1 ORDER BY id`;
  const employeesResult = await client.query(employee_segment ? employeeQuery : employeeQuery, employee_segment ? [endBounds.end, employee_segment] : [endBounds.end]);
  const employees = employeesResult.rows;
  const deductions = [];

  for (const month of monthsToProcess) {
    const { start: monthStart, end: monthEnd, lastDay } = monthBounds(month);
    for (const employee of employees) {
      const existing = await client.query('SELECT 1 FROM salary_deductions WHERE employee_id = $1 AND month_year = $2 LIMIT 1', [employee.id, month]);
      if (existing.rows.length > 0) {
        continue;
      }

      const joinDay = new Date(`${employee.joining_date}T00:00:00Z`).getUTCDate();
      let deductionDate;
      if (joinDay === 1) {
        deductionDate = monthEnd;
      } else {
        const day = Math.min(joinDay, lastDay);
        deductionDate = new Date(Date.UTC(new Date(`${monthStart}T00:00:00Z`).getUTCFullYear(), new Date(`${monthStart}T00:00:00Z`).getUTCMonth(), day));
        deductionDate = deductionDate.toISOString().slice(0, 10);
      }

      if (deductionDate < employee.joining_date) {
        continue;
      }

      const amount = await calculateProratedSalaryForMonth(client, employee, month);
      if (decimal(amount).lte(DECIMAL_ZERO)) {
        continue;
      }

      const inserted = await client.query(
        `INSERT INTO salary_deductions (employee_id, date, amount, reference, month_year)
         VALUES ($1, $2, $3, $4, $5)
         RETURNING *`,
        [employee.id, deductionDate, amount, `AUTO-SAL-${month}`, month],
      );
      await refreshEmployeeBalance(client, employee.id);
      deductions.push(inserted.rows[0]);
      await writeAuditLog(client, {
        userId: actorUserId,
        action: 'CREATE',
        modelChanged: 'SalaryDeduction',
        description: 'CREATE monthly salary deduction.',
        beforeValues: null,
        afterValues: inserted.rows[0],
      });
    }
  }

  return deductions;
}

async function calculateProratedSalaryForMonth(client, employee, monthYear) {
  const { start: monthStart, end: monthEnd } = monthBounds(monthYear);
  const employmentStart = employee.joining_date > monthStart ? employee.joining_date : monthStart;
  if (employmentStart > monthEnd) {
    return '0.00';
  }

  const salaryChanges = await client.query(
    `SELECT salary, effective_date
     FROM salary_history
     WHERE employee_id = $1 AND effective_date > $2 AND effective_date <= $3
     ORDER BY effective_date ASC, id ASC`,
    [employee.id, employmentStart, monthEnd],
  );

  let currentStart = employmentStart;
  let currentSalary = await salaryForDate(client, employee.id, employmentStart);
  let total = DECIMAL_ZERO;
  const daysInMonth = decimal((new Date(`${monthEnd}T00:00:00Z`).getUTCDate() || 30).toString());

  for (const change of salaryChanges.rows) {
    const segmentEnd = new Date(`${change.effective_date}T00:00:00Z`);
    segmentEnd.setUTCDate(segmentEnd.getUTCDate() - 1);
    const segmentEndIso = segmentEnd.toISOString().slice(0, 10);
    if (segmentEndIso >= currentStart) {
      const days = decimal(Math.floor((new Date(`${segmentEndIso}T00:00:00Z`) - new Date(`${currentStart}T00:00:00Z`)) / (1000 * 60 * 60 * 24)) + 1);
      total = total.add(decimal(currentSalary).mul(days.div(daysInMonth)));
    }
    currentStart = change.effective_date;
    currentSalary = change.salary;
  }

  const finalDays = decimal(Math.floor((new Date(`${monthEnd}T00:00:00Z`) - new Date(`${currentStart}T00:00:00Z`)) / (1000 * 60 * 60 * 24)) + 1);
  if (finalDays.gt(DECIMAL_ZERO)) {
    total = total.add(decimal(currentSalary).mul(finalDays.div(daysInMonth)));
  }

  return total.toDecimalPlaces(2).toFixed(2);
}

async function listEmployeesForUser(client, user, { filter = 'all', page = 1, pageSize = 20, baseUrl }) {
  const groups = user.groups || [];
  const employeeSegment = employeeSegmentForGroups(groups);
  const conditions = [];
  const params = [];
  let paramIndex = 1;

  if (employeeSegment) {
    conditions.push(`segment = $${paramIndex++}`);
    params.push(employeeSegment);
  }

  if (filter === 'in_debt') {
    conditions.push(`balance < 0`);
  } else if (filter === 'company_owes_employees') {
    conditions.push(`balance > 0`);
  } else if (filter !== 'all' && filter !== '' && filter != null) {
    throw httpError(400, 'Unsupported filter.', { field: 'filter' });
  }

  const whereClause = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';
  const countResult = await client.query(`SELECT COUNT(*) AS count FROM employees ${whereClause}`, params);
  const count = Number(countResult.rows[0].count);
  const offset = (page - 1) * pageSize;
  const rowsResult = await client.query(
    `SELECT id, name, segment, joining_date, current_salary, balance
     FROM employees
     ${whereClause}
     ORDER BY name ASC
     LIMIT $${paramIndex} OFFSET $${paramIndex + 1}`,
    [...params, pageSize, offset],
  );

  const totalPages = Math.max(Math.ceil(count / pageSize), 1);
  const next = page < totalPages ? buildPageUrl(baseUrl, page + 1, pageSize, filter) : null;
  const previous = page > 1 ? buildPageUrl(baseUrl, page - 1, pageSize, filter) : null;

  return {
    count,
    next,
    previous,
    results: rowsResult.rows,
  };
}

function buildPageUrl(baseUrl, page, pageSize, filter) {
  const url = new URL(baseUrl);
  url.searchParams.set('page', String(page));
  url.searchParams.set('page_size', String(pageSize));
  if (filter && filter !== 'all') {
    url.searchParams.set('filter', filter);
  }
  return url.toString();
}

async function setupNeed() {
  const result = await query('SELECT COUNT(*) AS count FROM users');
  return Number(result.rows[0].count) === 0;
}

async function setupCreate({ wholesale, retail }) {
  if (!wholesale?.username || !wholesale?.password) {
    throw httpError(400, 'Wholesale username and password required.');
  }
  if (!retail?.username || !retail?.password) {
    throw httpError(400, 'Retail username and password required.');
  }

  if (String(wholesale.password).length < 8 || String(retail.password).length < 8) {
    throw httpError(400, 'Passwords must be at least 8 characters long.');
  }

  return withTransaction(async (client) => {
    const existing = await client.query('SELECT COUNT(*) AS count FROM users');
    if (Number(existing.rows[0].count) > 0) {
      throw httpError(400, 'Setup already completed.');
    }

    const wholesaleGroup = await client.query(
      `INSERT INTO groups (name)
       VALUES ('wholesale')
       ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name
       RETURNING id`,
    );
    const retailGroup = await client.query(
      `INSERT INTO groups (name)
       VALUES ('retail')
       ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name
       RETURNING id`,
    );

    const wholesaleHash = await hashPassword(String(wholesale.password));
    const retailHash = await hashPassword(String(retail.password));

    const wholesaleUser = await client.query(
      `INSERT INTO users (username, password_hash, role, is_staff, is_active)
       VALUES ($1, $2, 'ACCOUNTANT', FALSE, TRUE)
       RETURNING id`,
      [normalizeText(wholesale.username), wholesaleHash],
    );
    const retailUser = await client.query(
      `INSERT INTO users (username, password_hash, role, is_staff, is_active)
       VALUES ($1, $2, 'ACCOUNTANT', FALSE, TRUE)
       RETURNING id`,
      [normalizeText(retail.username), retailHash],
    );

    await client.query('INSERT INTO user_groups (user_id, group_id) VALUES ($1, $2)', [wholesaleUser.rows[0].id, wholesaleGroup.rows[0].id]);
    await client.query('INSERT INTO user_groups (user_id, group_id) VALUES ($1, $2)', [retailUser.rows[0].id, retailGroup.rows[0].id]);

    return { detail: 'Setup complete.' };
  });
}

async function requestAdminAccountOtp({ email, username, segment, first_name, last_name }, requester) {
  if (!isAdminAccountCreator(requester)) {
    throw httpError(403, 'Only owners or verified accountants can create admin accounts.');
  }

  const normalizedEmail = validateEmail(email);
  const normalizedUsername = validateUsername(username);
  const normalizedSegment = validateSegment(segment);
  const normalizedFirstName = validateName(first_name, 'first_name');
  const normalizedLastName = validateName(last_name, 'last_name');

  return withTransaction(async (client) => {
    const usernameExists = await client.query('SELECT 1 FROM users WHERE username = $1 LIMIT 1', [normalizedUsername]);
    if (usernameExists.rows.length > 0) {
      throw httpError(400, 'username already exists.');
    }

    const emailExists = await client.query('SELECT 1 FROM users WHERE lower(email) = lower($1) LIMIT 1', [normalizedEmail]);
    if (emailExists.rows.length > 0) {
      throw httpError(400, 'email already exists.');
    }

    const otp = generateOtp();
    const otpHash = await bcrypt.hash(otp, 10);
    const payload = {
      email: normalizedEmail,
      username: normalizedUsername,
      segment: normalizedSegment,
      first_name: normalizedFirstName,
      last_name: normalizedLastName,
      role: 'ADMIN',
    };

    await client.query(
      `INSERT INTO signup_otps (email, username, segment, otp_hash, payload_json, created_by_user_id, expires_at)
       VALUES ($1, $2, $3, $4, $5, $6, NOW() + INTERVAL '10 minutes')`,
      [normalizedEmail, normalizedUsername, normalizedSegment, otpHash, payload, requester?.id ?? null],
    );

    const delivery = await sendSignupOtpEmail({
      to: normalizedEmail,
      otp,
      purpose: 'admin-account',
    });

    return {
      detail: 'Verification code sent.',
      delivery: delivery.delivery,
    };
  });
}

async function requestPublicSignupOtp({ username, password, segment }) {
  const normalizedUsername = validateUsername(username);
  const normalizedPassword = validatePasswordStrength(password);
  const normalizedSegment = validateSegment(segment);
  const recipientEmail = getOtpRecipientEmail();

  return withTransaction(async (client) => {
    const usernameExists = await client.query('SELECT 1 FROM users WHERE username = $1 LIMIT 1', [normalizedUsername]);
    if (usernameExists.rows.length > 0) {
      throw httpError(400, 'username already exists.');
    }

    const otp = generateOtp();
    const otpHash = await bcrypt.hash(otp, 10);
    const payload = {
      username: normalizedUsername,
      segment: normalizedSegment,
      password_hash: await hashPassword(normalizedPassword),
    };

    await client.query(
      `INSERT INTO signup_otps (email, username, segment, otp_hash, payload_json, created_by_user_id, expires_at)
       VALUES ($1, $2, $3, $4, $5, NULL, NOW() + INTERVAL '10 minutes')`,
      [recipientEmail, normalizedUsername, normalizedSegment, otpHash, payload],
    );

    const delivery = await sendSignupOtpEmail({
      to: recipientEmail,
      otp,
      purpose: 'public-signup',
    });

    return {
      detail: 'Verification code sent.',
      delivery: delivery.delivery,
    };
  });
}

async function verifyPublicSignupOtp({ username, otp, segment }) {
  const normalizedUsername = validateUsername(username);
  const normalizedSegment = validateSegment(segment);
  const normalizedOtp = validateOtp(otp);
  const recipientEmail = getOtpRecipientEmail();

  return withTransaction(async (client) => {
    const otpRecordResult = await client.query(
      `SELECT *
       FROM signup_otps
       WHERE lower(email) = lower($1) AND username = $2 AND segment = $3 AND consumed_at IS NULL
       ORDER BY created_at DESC, id DESC
       LIMIT 1`,
      [recipientEmail, normalizedUsername, normalizedSegment],
    );
    const otpRecord = otpRecordResult.rows[0];
    if (!otpRecord) {
      throw httpError(400, 'Verification code not found or expired.');
    }

    if (new Date(otpRecord.expires_at).getTime() < Date.now()) {
      throw httpError(400, 'Verification code expired. Request a new code.');
    }

    const storedPayload = otpRecord.payload_json || {};
    if (storedPayload.username !== normalizedUsername || storedPayload.segment !== normalizedSegment) {
      throw httpError(400, 'Account details do not match the requested verification code.');
    }

    if (Number(otpRecord.attempts) >= 5) {
      throw httpError(400, 'Verification code locked. Request a new code.');
    }

    const otpMatches = await bcrypt.compare(normalizedOtp, otpRecord.otp_hash);
    if (!otpMatches) {
      await client.query('UPDATE signup_otps SET attempts = attempts + 1 WHERE id = $1', [otpRecord.id]);
      throw httpError(400, 'Invalid verification code.');
    }

    const usernameExists = await client.query('SELECT 1 FROM users WHERE username = $1 LIMIT 1', [normalizedUsername]);
    if (usernameExists.rows.length > 0) {
      throw httpError(400, 'username already exists.');
    }

    const passwordHash = storedPayload.password_hash;
    if (!passwordHash) {
      throw httpError(400, 'Verification code payload is incomplete. Request a new code.');
    }

    const userResult = await client.query(
      `INSERT INTO users (username, password_hash, role, email, first_name, last_name, is_staff, is_active)
       VALUES ($1, $2, 'ADMIN', NULL, '', '', TRUE, TRUE)
       RETURNING *`,
      [normalizedUsername, passwordHash],
    );
    const user = userResult.rows[0];

    const groupName = normalizedSegment === 'wholesale' ? 'wholesale_admin' : 'retail_admin';
    const groupResult = await client.query(
      `INSERT INTO groups (name)
       VALUES ($1)
       ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name
       RETURNING id`,
      [groupName],
    );
    await client.query('INSERT INTO user_groups (user_id, group_id) VALUES ($1, $2) ON CONFLICT (user_id, group_id) DO NOTHING', [user.id, groupResult.rows[0].id]);
    await client.query('UPDATE signup_otps SET consumed_at = NOW() WHERE id = $1', [otpRecord.id]);

    const account = {
      id: user.id,
      username: user.username,
      role: user.role,
      groups: [groupName],
      ...accountBrandingForGroups([groupName]),
    };

    return {
      detail: 'Account created. Please log in.',
      user: account,
    };
  });
}

async function verifyAdminAccountOtp({ email, otp, username, password, segment, first_name, last_name }, requester) {
  if (!isAdminAccountCreator(requester)) {
    throw httpError(403, 'Only owners or verified accountants can create admin accounts.');
  }

  const normalizedEmail = validateEmail(email);
  const normalizedUsername = validateUsername(username);
  const normalizedPassword = validatePasswordStrength(password);
  const normalizedSegment = validateSegment(segment);
  const normalizedFirstName = validateName(first_name, 'first_name');
  const normalizedLastName = validateName(last_name, 'last_name');
  const normalizedOtp = validateOtp(otp);

  return withTransaction(async (client) => {
    const otpRecordResult = await client.query(
      `SELECT *
       FROM signup_otps
       WHERE lower(email) = lower($1) AND consumed_at IS NULL
       ORDER BY created_at DESC, id DESC
       LIMIT 1`,
      [normalizedEmail],
    );
    const otpRecord = otpRecordResult.rows[0];
    if (!otpRecord) {
      throw httpError(400, 'Verification code not found or expired.');
    }

    if (new Date(otpRecord.expires_at).getTime() < Date.now()) {
      throw httpError(400, 'Verification code expired. Request a new code.');
    }

    const storedPayload = otpRecord.payload_json || {};
    if (
      storedPayload.username !== normalizedUsername ||
      storedPayload.segment !== normalizedSegment ||
      storedPayload.first_name !== normalizedFirstName ||
      storedPayload.last_name !== normalizedLastName ||
      storedPayload.email !== normalizedEmail
    ) {
      throw httpError(400, 'Account details do not match the requested verification code.');
    }

    if (Number(otpRecord.attempts) >= 5) {
      throw httpError(400, 'Verification code locked. Request a new code.');
    }

    const otpMatches = await bcrypt.compare(normalizedOtp, otpRecord.otp_hash);
    if (!otpMatches) {
      await client.query('UPDATE signup_otps SET attempts = attempts + 1 WHERE id = $1', [otpRecord.id]);
      throw httpError(400, 'Invalid verification code.');
    }

    const usernameExists = await client.query('SELECT 1 FROM users WHERE username = $1 LIMIT 1', [normalizedUsername]);
    if (usernameExists.rows.length > 0) {
      throw httpError(400, 'username already exists.');
    }

    const emailExists = await client.query('SELECT 1 FROM users WHERE lower(email) = lower($1) LIMIT 1', [normalizedEmail]);
    if (emailExists.rows.length > 0) {
      throw httpError(400, 'email already exists.');
    }

    const passwordHash = await hashPassword(normalizedPassword);
    const userResult = await client.query(
      `INSERT INTO users (username, password_hash, role, email, first_name, last_name, is_staff, is_active)
       VALUES ($1, $2, 'ADMIN', $3, $4, $5, TRUE, TRUE)
       RETURNING *`,
      [normalizedUsername, passwordHash, normalizedEmail, normalizedFirstName, normalizedLastName],
    );
    const user = userResult.rows[0];

    const groupName = normalizedSegment === 'wholesale' ? 'wholesale_admin' : 'retail_admin';
    const groupResult = await client.query(
      `INSERT INTO groups (name)
       VALUES ($1)
       ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name
       RETURNING id`,
      [groupName],
    );
    await client.query('INSERT INTO user_groups (user_id, group_id) VALUES ($1, $2) ON CONFLICT (user_id, group_id) DO NOTHING', [user.id, groupResult.rows[0].id]);
    await client.query('UPDATE signup_otps SET consumed_at = NOW() WHERE id = $1', [otpRecord.id]);

    const account = {
      id: user.id,
      username: user.username,
      role: user.role,
      groups: [groupName],
      ...accountBrandingForGroups([groupName]),
    };

    await writeAuditLog(client, {
      userId: requester?.id ?? null,
      action: 'CREATE',
      modelChanged: 'User',
      description: 'CREATE admin account after OTP verification.',
      beforeValues: null,
      afterValues: account,
    });

    return {
      detail: 'Admin account created.',
      user: account,
    };
  });
}

async function listAdminAccounts(requester) {
  if (!isAdminAccountCreator(requester)) {
    throw httpError(403, 'Only owners or verified accountants can manage admin accounts.');
  }

  return withTransaction(async (client) => {
    const result = await client.query(
      `SELECT u.id, u.username, u.role, u.email, u.first_name, u.last_name, u.is_active, u.created_at,
              COALESCE(json_agg(g.name) FILTER (WHERE g.name IS NOT NULL), '[]') AS groups
       FROM users u
       LEFT JOIN user_groups ug ON ug.user_id = u.id
       LEFT JOIN groups g ON g.id = ug.group_id
       WHERE u.role = 'ADMIN'
       GROUP BY u.id
       ORDER BY u.created_at DESC, u.id DESC`,
    );

    const accounts = result.rows.map((row) => {
      const groups = Array.isArray(row.groups) ? row.groups : [];
      return {
        id: row.id,
        username: row.username,
        email: row.email,
        first_name: row.first_name,
        last_name: row.last_name,
        role: row.role,
        is_active: row.is_active,
        segment: employeeSegmentForGroups(groups) || 'retail',
        groups,
        created_at: row.created_at,
      };
    });

    return { accounts };
  });
}

async function updateAdminAccount(adminAccountId, payload, requester) {
  if (!isAdminAccountCreator(requester)) {
    throw httpError(403, 'Only owners or verified accountants can manage admin accounts.');
  }

  const targetUserId = validateIdentifier(adminAccountId, 'admin_account_id');

  return withTransaction(async (client) => {
    const existingResult = await client.query(
      `SELECT u.id, u.username, u.role, u.email, u.first_name, u.last_name, u.is_active,
              COALESCE(json_agg(g.name) FILTER (WHERE g.name IS NOT NULL), '[]') AS groups
       FROM users u
       LEFT JOIN user_groups ug ON ug.user_id = u.id
       LEFT JOIN groups g ON g.id = ug.group_id
       WHERE u.id = $1
       GROUP BY u.id`,
      [targetUserId],
    );
    const existing = existingResult.rows[0];
    if (!existing) {
      throw httpError(404, 'Admin account not found.');
    }
    if (existing.role !== 'ADMIN') {
      throw httpError(400, 'Only ADMIN accounts can be updated here.');
    }

    const existingGroups = Array.isArray(existing.groups) ? existing.groups : [];
    const beforeValues = {
      id: existing.id,
      username: existing.username,
      email: existing.email,
      first_name: existing.first_name,
      last_name: existing.last_name,
      role: existing.role,
      is_active: existing.is_active,
      segment: employeeSegmentForGroups(existingGroups) || 'retail',
      groups: existingGroups,
    };

    let nextUsername = existing.username;
    let nextEmail = existing.email;
    let nextFirstName = existing.first_name;
    let nextLastName = existing.last_name;
    let nextSegment = employeeSegmentForGroups(existingGroups) || 'retail';
    let nextPasswordHash = null;

    if (Object.prototype.hasOwnProperty.call(payload, 'username')) {
      nextUsername = validateUsername(payload.username);
    }
    if (Object.prototype.hasOwnProperty.call(payload, 'email')) {
      if (payload.email === null || normalizeText(payload.email) === '') {
        nextEmail = null;
      } else {
        nextEmail = validateEmail(payload.email);
      }
    }
    if (Object.prototype.hasOwnProperty.call(payload, 'first_name')) {
      nextFirstName = validateName(payload.first_name, 'first_name');
    }
    if (Object.prototype.hasOwnProperty.call(payload, 'last_name')) {
      nextLastName = validateName(payload.last_name, 'last_name');
    }
    if (Object.prototype.hasOwnProperty.call(payload, 'segment')) {
      nextSegment = validateSegment(payload.segment);
    }
    if (Object.prototype.hasOwnProperty.call(payload, 'password')) {
      const normalizedPassword = validatePasswordStrength(payload.password);
      nextPasswordHash = await hashPassword(normalizedPassword);
    }

    if (nextUsername !== existing.username) {
      const usernameExists = await client.query('SELECT 1 FROM users WHERE username = $1 AND id <> $2 LIMIT 1', [nextUsername, targetUserId]);
      if (usernameExists.rows.length > 0) {
        throw httpError(400, 'username already exists.');
      }
    }

    if (nextEmail && String(nextEmail).toLowerCase() !== String(existing.email || '').toLowerCase()) {
      const emailExists = await client.query('SELECT 1 FROM users WHERE lower(email) = lower($1) AND id <> $2 LIMIT 1', [nextEmail, targetUserId]);
      if (emailExists.rows.length > 0) {
        throw httpError(400, 'email already exists.');
      }
    }

    await client.query(
      `UPDATE users
       SET username = $1,
           email = $2,
           first_name = $3,
           last_name = $4,
           password_hash = COALESCE($5, password_hash)
       WHERE id = $6`,
      [nextUsername, nextEmail, nextFirstName, nextLastName, nextPasswordHash, targetUserId],
    );

    const groupName = nextSegment === 'wholesale' ? 'wholesale_admin' : 'retail_admin';
    const groupResult = await client.query(
      `INSERT INTO groups (name)
       VALUES ($1)
       ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name
       RETURNING id`,
      [groupName],
    );
    await client.query(
      `DELETE FROM user_groups
       WHERE user_id = $1
         AND group_id IN (SELECT id FROM groups WHERE name IN ('retail_admin', 'wholesale_admin'))`,
      [targetUserId],
    );
    await client.query('INSERT INTO user_groups (user_id, group_id) VALUES ($1, $2) ON CONFLICT (user_id, group_id) DO NOTHING', [targetUserId, groupResult.rows[0].id]);

    const updatedGroups = await getUserGroupsByUserId(client, targetUserId);
    const account = {
      id: targetUserId,
      username: nextUsername,
      email: nextEmail,
      first_name: nextFirstName,
      last_name: nextLastName,
      role: 'ADMIN',
      is_active: Boolean(existing.is_active),
      segment: employeeSegmentForGroups(updatedGroups) || 'retail',
      groups: updatedGroups,
    };

    await writeAuditLog(client, {
      userId: requester?.id ?? null,
      action: 'UPDATE',
      modelChanged: 'User',
      description: 'UPDATE admin account credentials.',
      beforeValues,
      afterValues: account,
    });

    return {
      detail: 'Admin account updated.',
      account,
    };
  });
}

async function deleteAdminAccount(adminAccountId, requester) {
  if (!isAdminAccountCreator(requester)) {
    throw httpError(403, 'Only owners or verified accountants can manage admin accounts.');
  }

  const targetUserId = validateIdentifier(adminAccountId, 'admin_account_id');
  if (requester?.id === targetUserId) {
    throw httpError(400, 'You cannot delete your own account from this screen.');
  }

  return withTransaction(async (client) => {
    const existingResult = await client.query(
      `SELECT u.id, u.username, u.role, u.email, u.first_name, u.last_name,
              COALESCE(json_agg(g.name) FILTER (WHERE g.name IS NOT NULL), '[]') AS groups
       FROM users u
       LEFT JOIN user_groups ug ON ug.user_id = u.id
       LEFT JOIN groups g ON g.id = ug.group_id
       WHERE u.id = $1
       GROUP BY u.id`,
      [targetUserId],
    );
    const existing = existingResult.rows[0];
    if (!existing) {
      throw httpError(404, 'Admin account not found.');
    }
    if (existing.role !== 'ADMIN') {
      throw httpError(400, 'Only ADMIN accounts can be deleted here.');
    }

    const existingGroups = Array.isArray(existing.groups) ? existing.groups : [];
    const beforeValues = {
      id: existing.id,
      username: existing.username,
      email: existing.email,
      first_name: existing.first_name,
      last_name: existing.last_name,
      role: existing.role,
      segment: employeeSegmentForGroups(existingGroups) || 'retail',
      groups: existingGroups,
    };

    await client.query('DELETE FROM users WHERE id = $1', [targetUserId]);

    await writeAuditLog(client, {
      userId: requester?.id ?? null,
      action: 'DELETE',
      modelChanged: 'User',
      description: 'DELETE admin account.',
      beforeValues,
      afterValues: null,
    });

    return {
      detail: 'Admin account deleted.',
    };
  });
}

async function authenticate(username, password) {
  return withTransaction(async (client) => {
    const user = await getUserWithGroupsByUsername(client, normalizeText(username));
    if (!user || !user.is_active) {
      throw httpError(400, 'Invalid username or password.');
    }
    const ok = await comparePassword(String(password), user.password_hash);
    if (!ok) {
      throw httpError(400, 'Invalid username or password.');
    }

    const groups = Array.isArray(user.groups) ? user.groups : [];
    const token = await getOrCreateToken(client, user.id);
    const branding = accountBrandingForGroups(groups);
    return {
      token,
      user: {
        id: user.id,
        username: user.username,
        role: user.role,
        groups,
        ...branding,
      },
    };
  });
}

async function currentUserFromToken(token) {
  return withTransaction(async (client) => {
    const user = await getUserWithGroupsByToken(client, token);
    if (!user || !user.is_active) {
      throw httpError(401, 'Unauthorized.');
    }
    const groups = Array.isArray(user.groups) ? user.groups : [];
    const branding = accountBrandingForGroups(groups);
    return {
      id: user.id,
      username: user.username,
      role: user.role,
      groups,
      ...branding,
    };
  });
}

async function createEmployee(data, actorUserId = null) {
  return withTransaction((client) => createEmployeeInternal(client, data, actorUserId));
}

async function updateEmployeeDetails(employeeId, data, actorUserId = null) {
  return withTransaction((client) => updateEmployeeDetailsInternal(client, employeeId, data, actorUserId));
}

async function deleteEmployee(employeeId, actorUserId = null) {
  return withTransaction((client) => deleteEmployeeInternal(client, employeeId, actorUserId));
}

async function listEmployees(user, options) {
  return withTransaction((client) => listEmployeesForUser(client, user, options));
}

async function employeeDetail(employeeId, fromDate = null) {
  return withTransaction((client) => buildEmployeeDetail(client, employeeId, fromDate));
}

async function createPKRPayment(data, actorUserId = null) {
  return withTransaction((client) => createPKRPaymentInternal(client, data, actorUserId));
}

async function updatePKRPayment(paymentId, data, actorUserId = null) {
  return withTransaction((client) => updatePKRPaymentInternal(client, paymentId, data, actorUserId));
}

async function deletePKRPayment(paymentId, actorUserId = null) {
  return withTransaction((client) => deletePKRPaymentInternal(client, paymentId, actorUserId));
}

async function createRandPayment(data, actorUserId = null) {
  return withTransaction((client) => createRandPaymentInternal(client, data, actorUserId));
}

async function updateRandPayment(paymentId, data, actorUserId = null) {
  return withTransaction((client) => updateRandPaymentInternal(client, paymentId, data, actorUserId));
}

async function deleteRandPayment(paymentId, actorUserId = null) {
  return withTransaction((client) => deleteRandPaymentInternal(client, paymentId, actorUserId));
}

async function createSalaryHistory(data, actorUserId = null) {
  return withTransaction((client) => createSalaryHistoryInternal(client, data, actorUserId));
}

async function updateSalaryHistory(historyId, data, actorUserId = null) {
  return withTransaction((client) => updateSalaryHistoryInternal(client, historyId, data, actorUserId));
}

async function deleteSalaryHistory(historyId, actorUserId = null) {
  return withTransaction((client) => deleteSalaryHistoryInternal(client, historyId, actorUserId));
}

async function updateSalaryDeduction(deductionId, data, actorUserId = null) {
  return withTransaction((client) => updateSalaryDeductionInternal(client, deductionId, data, actorUserId));
}

async function createSalaryDeduction(data, actorUserId = null) {
  return withTransaction((client) => createSalaryDeductionInternal(client, data, actorUserId));
}

async function runMonthlySalaryDeductions(data, actorUserId = null) {
  return withTransaction((client) => runMonthlySalaryDeductionsInternal(client, data, actorUserId));
}

async function employeePdfData(employeeId, fromDate = null) {
  return withTransaction((client) => buildEmployeeDetail(client, employeeId, fromDate));
}

async function employeeSummaryData(user, options) {
  return listEmployees(user, options);
}

export {
  accountBrandingForGroups,
  authenticate,
  calculateBalance,
  createEmployee,
  createPKRPayment,
  createRandPayment,
  createSalaryDeduction,
  createSalaryHistory,
  currentUserFromToken,
  deleteEmployee,
  deletePKRPayment,
  deleteRandPayment,
  deleteSalaryHistory,
  employeeDetail,
  employeePdfData,
  employeeSegmentForGroups,
  employeeSummaryData,
  listEmployees,
  monthsBetween,
  money,
  previousMonthYear,
  requestAdminAccountOtp,
  listAdminAccounts,
  updateAdminAccount,
  deleteAdminAccount,
  requestPublicSignupOtp,
  verifyAdminAccountOtp,
  verifyPublicSignupOtp,
  runMonthlySalaryDeductions,
  setupCreate,
  setupNeed,
  totalMonthsSinceJoining,
  updateEmployeeDetails,
  updatePKRPayment,
  updateRandPayment,
  updateSalaryDeduction,
  updateSalaryHistory,
};

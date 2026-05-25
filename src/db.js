import dotenv from 'dotenv';
import { Pool } from 'pg';
import { types } from 'pg';

dotenv.config();

types.setTypeParser(1082, (value) => value);

export const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

export async function query(text, params = []) {
  return pool.query(text, params);
}

export async function withTransaction(fn) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const result = await fn(client);
    await client.query('COMMIT');
    return result;
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
}

const schemaStatements = [
  `CREATE TABLE IF NOT EXISTS users (
    id BIGSERIAL PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'OWNER',
    email TEXT,
    first_name TEXT NOT NULL DEFAULT '',
    last_name TEXT NOT NULL DEFAULT '',
    is_staff BOOLEAN NOT NULL DEFAULT FALSE,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`,
  `CREATE TABLE IF NOT EXISTS groups (
    id BIGSERIAL PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`,
  `CREATE TABLE IF NOT EXISTS user_groups (
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    group_id BIGINT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, group_id)
  )`,
  `CREATE TABLE IF NOT EXISTS tokens (
    key TEXT PRIMARY KEY,
    user_id BIGINT UNIQUE NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`,
  `CREATE TABLE IF NOT EXISTS signup_otps (
    id BIGSERIAL PRIMARY KEY,
    email TEXT NOT NULL,
    username TEXT NOT NULL,
    segment TEXT NOT NULL,
    otp_hash TEXT NOT NULL,
    payload_json JSONB NOT NULL,
    created_by_user_id BIGINT NULL REFERENCES users(id) ON DELETE SET NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`,
  `CREATE TABLE IF NOT EXISTS employees (
    id BIGSERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    segment TEXT NOT NULL DEFAULT 'retail',
    joining_date DATE NOT NULL,
    current_salary NUMERIC(12,2) NOT NULL DEFAULT 0,
    visa_processing_fee NUMERIC(12,2) NOT NULL DEFAULT 0,
    balance NUMERIC(12,2) NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`,
  `CREATE TABLE IF NOT EXISTS salary_history (
    id BIGSERIAL PRIMARY KEY,
    employee_id BIGINT NOT NULL REFERENCES employees(id) ON DELETE CASCADE,
    salary NUMERIC(12,2) NOT NULL,
    effective_date DATE NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (employee_id, effective_date)
  )`,
  `CREATE TABLE IF NOT EXISTS pkr_payments (
    id BIGSERIAL PRIMARY KEY,
    employee_id BIGINT NOT NULL REFERENCES employees(id) ON DELETE CASCADE,
    date DATE NOT NULL,
    amount NUMERIC(12,2) NOT NULL,
    reference TEXT NOT NULL
  )`,
  `CREATE TABLE IF NOT EXISTS rand_payments (
    id BIGSERIAL PRIMARY KEY,
    employee_id BIGINT NOT NULL REFERENCES employees(id) ON DELETE CASCADE,
    date DATE NOT NULL,
    amount_rand NUMERIC(12,2) NOT NULL,
    conversion_rate NUMERIC(12,6) NOT NULL,
    amount_pkr NUMERIC(12,2) NOT NULL,
    reference TEXT NOT NULL
  )`,
  `CREATE TABLE IF NOT EXISTS salary_deductions (
    id BIGSERIAL PRIMARY KEY,
    employee_id BIGINT NOT NULL REFERENCES employees(id) ON DELETE CASCADE,
    date DATE NOT NULL,
    amount NUMERIC(12,2) NOT NULL,
    reference TEXT NOT NULL,
    month_year TEXT NULL
  )`,
  `CREATE TABLE IF NOT EXISTS audit_logs (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NULL REFERENCES users(id) ON DELETE SET NULL,
    action TEXT NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    model_changed TEXT NOT NULL,
    description TEXT NOT NULL,
    before_values JSONB NULL,
    after_values JSONB NULL
  )`,
  `CREATE INDEX IF NOT EXISTS idx_employees_name ON employees(name)`,
  `CREATE INDEX IF NOT EXISTS idx_employees_joining_date ON employees(joining_date)`,
  `CREATE INDEX IF NOT EXISTS idx_employees_segment ON employees(segment)`,
  `CREATE INDEX IF NOT EXISTS idx_salary_history_employee_effective_date ON salary_history(employee_id, effective_date)`,
  `CREATE INDEX IF NOT EXISTS idx_pkr_payments_employee_date ON pkr_payments(employee_id, date)`,
  `CREATE INDEX IF NOT EXISTS idx_rand_payments_employee_date ON rand_payments(employee_id, date)`,
  `CREATE INDEX IF NOT EXISTS idx_salary_deductions_employee_date ON salary_deductions(employee_id, date)`,
  `CREATE INDEX IF NOT EXISTS idx_salary_deductions_employee_month_year ON salary_deductions(employee_id, month_year)`,
  `CREATE INDEX IF NOT EXISTS idx_audit_logs_model_changed_timestamp ON audit_logs(model_changed, timestamp)`,
  `CREATE INDEX IF NOT EXISTS idx_audit_logs_user_timestamp ON audit_logs(user_id, timestamp)`,
  `CREATE INDEX IF NOT EXISTS idx_signup_otps_email_created_at ON signup_otps(email, created_at DESC)`,
  `CREATE INDEX IF NOT EXISTS idx_signup_otps_expires_at ON signup_otps(expires_at)`,
  `CREATE UNIQUE INDEX IF NOT EXISTS uniq_salary_deduction_employee_month_year ON salary_deductions(employee_id, month_year) WHERE month_year IS NOT NULL`,
];

export async function ensureSchema() {
  for (const statement of schemaStatements) {
    await pool.query(statement);
  }
}

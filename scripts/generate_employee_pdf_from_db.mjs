import fs from 'fs';
import path from 'path';
import { query } from '../src/db.js';
import { employeePdfData } from '../src/services.js';
import { buildEmployeeDetailPdf } from '../src/pdf.js';

(async () => {
  try {
    const outDir = path.join(process.cwd(), 'tmp');
    if (!fs.existsSync(outDir)) fs.mkdirSync(outDir);

    const res = await query('SELECT id FROM employees ORDER BY id LIMIT 1');
    if (!res.rows.length) {
      console.error('No employees found in DB.');
      process.exit(1);
    }

    const id = Number(res.rows[0].id);
    console.log('Found employee id', id);
    const employee = await employeePdfData(id, null);
    const buffer = await buildEmployeeDetailPdf(employee, {
      company_name: employee.segment === 'wholesale' ? 'Digital Tech WholeSale Employee Accounts' : 'Digital Tech Retail Accounts',
      generated_at: new Date().toISOString(),
      months_since_joining: employee.months_since_joining,
      total_received: employee.total_received,
      total_deducted: employee.total_deducted,
      balance: employee.balance,
      pkr_payments: employee.pkr_payments,
      rand_payments: employee.rand_payments,
      salary_deductions: employee.salary_deductions,
    });

    const outPath = path.join(outDir, `employee-${id}-detail.pdf`);
    fs.writeFileSync(outPath, buffer);
    console.log('Wrote', outPath);
  } catch (e) {
    console.error(e);
    process.exit(1);
  }
})();

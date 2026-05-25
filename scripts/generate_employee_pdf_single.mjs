import fs from 'fs';
import path from 'path';
import { query } from '../src/db.js';
import { employeePdfData } from '../src/services.js';
import { buildEmployeeDetailPdf } from '../src/pdf.js';

const idArg = process.argv[2];
if (!idArg) {
  console.error('Usage: node generate_employee_pdf_single.mjs <employeeId>');
  process.exit(1);
}
const id = Number(idArg);

(async () => {
  try {
    const outDir = path.join(process.cwd(), 'tmp');
    if (!fs.existsSync(outDir)) fs.mkdirSync(outDir);

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

    const outPath = path.join(outDir, `employee-${id}-exported.pdf`);
    fs.writeFileSync(outPath, buffer);
    console.log(outPath);
  } catch (e) {
    console.error(e);
    process.exit(1);
  }
})();

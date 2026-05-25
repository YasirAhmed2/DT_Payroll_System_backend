import fs from 'fs';
import path from 'path';
import { buildEmployeeSummaryPdf, buildEmployeeDetailPdf } from '../src/pdf.js';

(async () => {
  try {
    const outDir = path.join(process.cwd(), 'tmp');
    if (!fs.existsSync(outDir)) fs.mkdirSync(outDir);

    const sampleEmployee = {
      name: 'Yasir',
      joining_date: '2025-01-01',
      current_salary: '50000.00',
      balance: '1262000.00',
      visa_processing_fee: '1695000.00',
      segment: 'wholesale',
    };

    const summary = await buildEmployeeSummaryPdf(
      [
        {
          name: 'Yasir',
          joining_date: '2025-01-01',
          current_salary: '50000.00',
          balance: '1262000.00',
        },
      ],
      'Digital Tech Wholesale Employee Accounts',
      new Date().toISOString()
    );
    fs.writeFileSync(path.join(outDir, 'sample-summary.pdf'), summary);

    const salary_deductions = Array.from({ length: 12 }).map((_, i) => {
      const dt = new Date(2025, 11 - i, 1);
      const month = dt.toISOString().slice(0, 7);
      const date = new Date(2025, 11 - i, 31).toISOString().slice(0, 10);
      return { date, amount: '50000.00', month_year: month, reference: `AUTO-SAL-${month}` };
    });

    const detail = await buildEmployeeDetailPdf(sampleEmployee, {
      company_name: 'Digital Tech Wholesale Employee Accounts',
      generated_at: new Date().toISOString(),
      months_since_joining: 16,
      total_received: '1762000.00',
      total_deducted: '500000.00',
      balance: '1262000.00',
      pkr_payments: [
        { date: '2025-03-01', amount: '50000.00', reference: 'cash paid to his father' },
        { date: '2025-01-01', amount: '1695000.00', reference: 'VISA PROCESSING FEE' },
      ],
      rand_payments: [
        { date: '2026-01-27', amount_rand: '1000.00', conversion_rate: '17.000000', amount_pkr: '17000.00', reference: 'cash taken' },
      ],
      salary_deductions,
    });
    fs.writeFileSync(path.join(outDir, 'sample-detail.pdf'), detail);

    console.log('Wrote sample-summary.pdf and sample-detail.pdf to', outDir);
  } catch (e) {
    console.error(e);
    process.exit(1);
  }
})();

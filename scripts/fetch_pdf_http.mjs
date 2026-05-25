import fs from 'fs';
import path from 'path';
import dotenv from 'dotenv';

dotenv.config();

const token = process.env.PDF_EXPORT_TOKEN;
if (!token) {
  console.error('Set PDF_EXPORT_TOKEN before running fetch_pdf_http.mjs.');
  process.exit(1);
}

const employeeId = Number(process.argv[2] ?? process.env.EMPLOYEE_ID ?? 2);
const baseUrl = process.env.PDF_EXPORT_BASE_URL ?? 'http://127.0.0.1:8000';
const url = `${baseUrl}/api/employees/${employeeId}/export-pdf/`;

(async () => {
  try {
    const res = await fetch(url, { headers: { Authorization: `Token ${token}` } });
    if (!res.ok) {
      console.error('HTTP error', res.status, await res.text());
      process.exit(1);
    }
    const arrayBuffer = await res.arrayBuffer();
    const buffer = Buffer.from(arrayBuffer);
    const outDir = path.join(process.cwd(), 'tmp');
    if (!fs.existsSync(outDir)) fs.mkdirSync(outDir);
    const outPath = path.join(outDir, `employee-${employeeId}-http.pdf`);
    fs.writeFileSync(outPath, buffer);
    console.log('Saved', outPath);
  } catch (e) {
    console.error(e);
    process.exit(1);
  }
})();

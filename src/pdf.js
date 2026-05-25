import PDFDocument from 'pdfkit';

function money(value) {
  const numberValue = typeof value === 'number' ? value : Number(value ?? 0);
  return `PKR ${numberValue.toFixed(2)}`;
}

function formatGeneratedAt(value) {
  if (!value) {
    return '';
  }

  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return String(value);
  }

  return new Intl.DateTimeFormat('en-GB', {
    dateStyle: 'medium',
    timeStyle: 'short',
  }).format(date);
}

function writeFittedText(doc, text, x, y, maxWidth, maxFontSize, minFontSize, options = {}) {
  for (let size = maxFontSize; size >= minFontSize; size -= 0.5) {
    doc.fontSize(size);
    if (doc.widthOfString(text, options) <= maxWidth) {
      doc.text(text, x, y, {
        width: maxWidth,
        align: 'left',
        lineBreak: false,
        ellipsis: true,
        ...options,
      });
      return size;
    }
  }

  doc.fontSize(minFontSize).text(text, x, y, {
    width: maxWidth,
    align: 'left',
    lineBreak: false,
    ellipsis: true,
    ...options,
  });
  return minFontSize;
}

function addHeaderBlock(doc, title, subtitle, generatedAt) {
  const pageWidth = doc.page.width - doc.page.margins.left - doc.page.margins.right;
  const headerX = doc.page.margins.left + 18;
  const headerY = doc.y + 14;
  const rightBlockWidth = 152;
  const leftBlockWidth = pageWidth - 36 - rightBlockWidth - 12;

  doc.save();
  doc.roundedRect(doc.page.margins.left, doc.y, pageWidth, 92, 12).fill('#0f172a');
  doc.restore();

  // Use fixed font sizes and positions to avoid variation between runs
  doc.fillColor('#e2e8f0').font('Helvetica-Bold').fontSize(10).text('DIGITAL TECH', headerX, headerY, {
    width: leftBlockWidth,
    align: 'left',
    lineBreak: false,
  });

  doc.fillColor('#ffffff').font('Helvetica-Bold').fontSize(13).text(title, headerX, headerY + 16, {
    width: leftBlockWidth,
    align: 'left',
    lineBreak: false,
  });

  if (subtitle) {
    doc.fillColor('#cbd5e1').font('Helvetica').fontSize(9).text(subtitle, headerX, headerY + 40, {
      width: leftBlockWidth,
      align: 'left',
    });
  }

  doc.y += 108;
}

function addSectionTitle(doc, title, note = '') {
  const sectionWidth = doc.page.width - doc.page.margins.left - doc.page.margins.right;
  const sectionX = doc.page.margins.left;
  const titleY = doc.y + 2;

  doc.save();
  doc.roundedRect(sectionX, titleY + 2, 4, 24, 2).fill('#0f766e');
  doc.restore();

  doc.fillColor('#0f172a').font('Helvetica-Bold').fontSize(12.5).text(title, sectionX + 14, titleY, {
    width: sectionWidth - 14,
    align: 'left',
  });

  const titleHeight = doc.heightOfString(title, {
    width: sectionWidth - 14,
    align: 'left',
  });

  let nextY = titleY + titleHeight + 3;
  if (note) {
    const noteHeight = doc.heightOfString(note, {
      width: sectionWidth - 14,
      align: 'left',
    });
    doc.fillColor('#64748b').font('Helvetica').fontSize(8.5).text(note, sectionX + 14, nextY, {
      width: sectionWidth - 14,
      align: 'left',
    });
    nextY += noteHeight + 2;
  }

  doc.save();
  doc.moveTo(sectionX + 14, nextY + 2).lineTo(sectionX + sectionWidth, nextY + 2).lineWidth(0.6).strokeColor('#dbe4ea').stroke();
  doc.restore();

  doc.y = nextY + 8;
}

function measureRowHeight(doc, row, columnWidths, padding = 7) {
  let maxHeight = 0;
  for (let index = 0; index < row.length; index += 1) {
    const text = String(row[index] ?? '');
    const height = doc.heightOfString(text, {
      width: Math.max(columnWidths[index] - padding * 2, 24),
      align: 'left',
    });
    maxHeight = Math.max(maxHeight, height);
  }
  return maxHeight + padding * 2;
}

function ensureSpace(doc, requiredHeight) {
  if (doc.y + requiredHeight > doc.page.height - doc.page.margins.bottom) {
    doc.addPage();
  }
}

function addTable(doc, columns, rows) {
  const columnWidths = columns.map((column) => column.width);
  const tableWidth = columnWidths.reduce((sum, width) => sum + width, 0);
  const headerHeight = 22;
  const rowPadding = 7;

  ensureSpace(doc, headerHeight + 6);
  const headerY = doc.y;
  let currentX = doc.page.margins.left;

  doc.save();
  doc.fillColor('#0f172a');
  doc.roundedRect(currentX, headerY, tableWidth, headerHeight, 8).fill('#dbeafe');
  doc.restore();

  for (let index = 0; index < columns.length; index += 1) {
    const column = columns[index];
    doc.fillColor('#0f172a').font('Helvetica-Bold').fontSize(8.5).text(column.label, currentX + rowPadding, headerY + 7, {
      width: column.width - rowPadding * 2,
      align: column.align || 'left',
    });
    currentX += column.width;
  }

  doc.y = headerY + headerHeight;

  if (!rows.length) {
    ensureSpace(doc, 30);
    doc.fillColor('#475569').font('Helvetica').fontSize(9).text('No records found.', doc.page.margins.left + 8, doc.y + 8);
    doc.y += 26;
    // add extra spacing after empty table to separate from next section
    doc.y += 12;
    return;
  }

  rows.forEach((row, rowIndex) => {
    const rowHeight = measureRowHeight(doc, row, columnWidths, rowPadding);
    ensureSpace(doc, rowHeight + 2);

    const rowY = doc.y;
    if (rowIndex % 2 === 0) {
      doc.save();
      doc.roundedRect(doc.page.margins.left, rowY, tableWidth, rowHeight, 6).fill('#f8fafc');
      doc.restore();
    }

    let x = doc.page.margins.left;
    for (let index = 0; index < columns.length; index += 1) {
      const column = columns[index];
      doc.fillColor('#111827').font('Helvetica').fontSize(9).text(String(row[index] ?? '-'), x + rowPadding, rowY + rowPadding, {
        width: column.width - rowPadding * 2,
        align: column.align || 'left',
      });

      doc.save();
      doc.moveTo(x, rowY).lineTo(x, rowY + rowHeight).lineWidth(0.5).strokeColor('#cbd5e1').stroke();
      doc.restore();

      x += column.width;
    }

    doc.save();
    doc.moveTo(doc.page.margins.left + tableWidth, rowY).lineTo(doc.page.margins.left + tableWidth, rowY + rowHeight).lineWidth(0.5).strokeColor('#cbd5e1').stroke();
    doc.moveTo(doc.page.margins.left, rowY + rowHeight).lineTo(doc.page.margins.left + tableWidth, rowY + rowHeight).lineWidth(0.5).strokeColor('#cbd5e1').stroke();
    doc.restore();

    doc.y = rowY + rowHeight;
  });

  // add extra spacing after table to visually separate next section heading
  doc.y += 12;
}

export function buildEmployeeDetailPdf(employee, context) {
  const doc = new PDFDocument({ margin: 40, size: 'A4', compress: false });
  const chunks = [];

  doc.on('data', (chunk) => chunks.push(chunk));

  // Do not show admin name or generation timestamp in the header per UX request
  addHeaderBlock(doc, context.company_name || 'Payroll Accounts', null, context.generated_at);

  addSectionTitle(doc, 'Summary', 'Key employee details and current payroll position.');
  addTable(doc, [
    { label: 'Metric', width: 160 },
    { label: 'Value', width: 345 },
  ], [
    ['Joining date', employee.joining_date],
    ['Current salary', money(employee.current_salary)],
    ['Visa processing fee', money(employee.visa_processing_fee)],
    ['Months worked', String(context.months_since_joining)],
    ['Total received', money(context.total_received)],
    ['Total deductions', money(context.total_deducted)],
    ['Balance', money(context.balance)],
  ]);

  addSectionTitle(doc, 'PKR Payments', 'Local-currency payments recorded for this employee.');
  addTable(doc, [
    { label: 'Date', width: 90 },
    { label: 'Amount', width: 110, align: 'right' },
    { label: 'Reference', width: 305 },
  ], context.pkr_payments.map((payment) => [payment.date, money(payment.amount), payment.reference]));

  addSectionTitle(doc, 'Rand Payments', 'Foreign-currency payments converted to PKR.');
  addTable(doc, [
    { label: 'Date', width: 78 },
    { label: 'Rand', width: 82, align: 'right' },
    { label: 'Rate', width: 82, align: 'right' },
    { label: 'PKR', width: 100, align: 'right' },
    { label: 'Reference', width: 163 },
  ], context.rand_payments.map((payment) => [payment.date, String(payment.amount_rand), String(payment.conversion_rate), money(payment.amount_pkr), payment.reference]));

  addSectionTitle(doc, 'Salary Deductions', 'Monthly deductions and reference notes.');
  addTable(doc, [
    { label: 'Date', width: 88 },
    { label: 'Amount', width: 100, align: 'right' },
    { label: 'Month', width: 92 },
    { label: 'Reference', width: 225 },
  ], context.salary_deductions.map((deduction) => [deduction.date, money(deduction.amount), deduction.month_year || '-', deduction.reference]));

  const footerTimestamp = formatGeneratedAt(context.generated_at);
  if (footerTimestamp) {
    doc.moveDown(1);
    doc.fillColor('#64748b').font('Helvetica').fontSize(8.5).text(`Created on ${footerTimestamp}`, {
      align: 'right',
    });
  }

  doc.end();

  return new Promise((resolve, reject) => {
    doc.on('end', () => resolve(Buffer.concat(chunks)));
    doc.on('error', reject);
  });
}

export function buildEmployeeSummaryPdf(employees, companyName, generatedAt) {
  const doc = new PDFDocument({ margin: 40, size: 'A4', compress: false });
  const chunks = [];

  doc.on('data', (chunk) => chunks.push(chunk));

  addHeaderBlock(doc, companyName || 'Payroll Accounts', 'Employee Summary Report', generatedAt);

  addSectionTitle(doc, 'Employees', 'Overview of current employee balances and salaries.');
  addTable(doc, [
    { label: 'Name', width: 205 },
    { label: 'Joining date', width: 95 },
    { label: 'Salary', width: 105, align: 'right' },
    { label: 'Balance', width: 105, align: 'right' },
  ], employees.map((employee) => [employee.name, employee.joining_date, money(employee.current_salary), money(employee.balance)]));

  const footerTimestamp = formatGeneratedAt(generatedAt);
  if (footerTimestamp) {
    doc.moveDown(1);
    doc.fillColor('#64748b').font('Helvetica').fontSize(8.5).text(`Created on ${footerTimestamp}`, {
      align: 'right',
    });
  }

  doc.end();

  return new Promise((resolve, reject) => {
    doc.on('end', () => resolve(Buffer.concat(chunks)));
    doc.on('error', reject);
  });
}

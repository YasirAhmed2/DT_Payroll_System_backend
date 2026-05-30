import dotenv from 'dotenv';

import { ensureSchema } from './db.js';
import { createApp } from './app.js';

dotenv.config();

const port = Number(process.env.PORT || 8000);
const app = createApp();

app.get("/", (req, res) => {
  res.json({
    success: true,
    message: "DT Payroll Backend Running"
  });
});

async function main() {
  await ensureSchema();
  app.listen(port, '0.0.0.0', () => {
    // eslint-disable-next-line no-console
    console.log(`Express backend listening on http://127.0.0.1:${port}/api`);
  });
}

main().catch((error) => {
  // eslint-disable-next-line no-console
  console.error(error);
  process.exit(1);
});

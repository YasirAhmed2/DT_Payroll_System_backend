import { query } from '../src/db.js';

(async () => {
  try {
    const r = await query('SELECT key FROM tokens WHERE user_id = $1', [1]);
    console.log(r.rows);
  } catch (e) {
    console.error(e);
    process.exit(1);
  }
})();

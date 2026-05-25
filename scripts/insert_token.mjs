import { query } from '../src/db.js';

(async () => {
  try {
    const token = 'test-token-inspect-1234';
    const userId = 1;
    await query('INSERT INTO tokens("key", user_id) VALUES($1,$2) ON CONFLICT ("key") DO NOTHING', [token, userId]);
    console.log('Inserted token', token, 'for user', userId);
  } catch (e) {
    console.error(e);
    process.exit(1);
  }
})();

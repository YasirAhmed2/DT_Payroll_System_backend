import dotenv from 'dotenv';
import bcrypt from 'bcryptjs';

import { query, withTransaction } from '../src/db.js';

dotenv.config();

async function ensureGroup(client, name) {
  const result = await client.query(
    `INSERT INTO groups (name)
     VALUES ($1)
     ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name
     RETURNING id`,
    [name],
  );
  return result.rows[0].id;
}

async function ensureUser(client, { username, password, email, firstName, lastName, role }) {
  const passwordHash = await bcrypt.hash(password, 12);
  const existing = await client.query('SELECT id FROM users WHERE username = $1', [username]);
  if (existing.rows[0]) {
    await client.query(
      `UPDATE users
       SET password_hash = $1, role = $2, email = $3, first_name = $4, last_name = $5, is_staff = TRUE, is_active = TRUE
       WHERE username = $6`,
      [passwordHash, role, email, firstName, lastName, username],
    );
    return existing.rows[0].id;
  }

  const created = await client.query(
    `INSERT INTO users (username, password_hash, role, email, first_name, last_name, is_staff, is_active)
     VALUES ($1, $2, $3, $4, $5, $6, TRUE, TRUE)
     RETURNING id`,
    [username, passwordHash, role, email, firstName, lastName],
  );
  return created.rows[0].id;
}

async function main() {
  const wholesalePassword = process.env.WHOLESALE_ADMIN_PASSWORD ?? 'Wholesale@123';
  const retailPassword = process.env.RETAIL_ADMIN_PASSWORD ?? 'Retail@123';

  await withTransaction(async (client) => {
    const wholesaleGroupId = await ensureGroup(client, 'wholesale_admin');
    const retailGroupId = await ensureGroup(client, 'retail_admin');

    const wholesaleUserId = await ensureUser(client, {
      username: 'wholesale_admin',
      password: wholesalePassword,
      email: 'wholesale@digitech.local',
      firstName: 'Wholesale',
      lastName: 'Admin',
      role: 'ADMIN',
    });
    const retailUserId = await ensureUser(client, {
      username: 'retail_admin',
      password: retailPassword,
      email: 'retail@digitech.local',
      firstName: 'Retail',
      lastName: 'Admin',
      role: 'ADMIN',
    });

    await client.query(
      `INSERT INTO user_groups (user_id, group_id)
       VALUES ($1, $2)
       ON CONFLICT (user_id, group_id) DO NOTHING`,
      [wholesaleUserId, wholesaleGroupId],
    );
    await client.query(
      `INSERT INTO user_groups (user_id, group_id)
       VALUES ($1, $2)
       ON CONFLICT (user_id, group_id) DO NOTHING`,
      [retailUserId, retailGroupId],
    );
  });

  // eslint-disable-next-line no-console
  console.log('Admin accounts ready: wholesale_admin and retail_admin');
}

main().catch((error) => {
  // eslint-disable-next-line no-console
  console.error(error);
  process.exit(1);
});

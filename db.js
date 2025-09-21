import dns from 'dns';
dns.setDefaultResultOrder('ipv4first');   // <— add this line

import pkg from 'pg';
const { Pool } = pkg;

export const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

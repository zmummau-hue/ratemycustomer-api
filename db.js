// db.js — force IPv4 connection to Supabase

import dns from 'dns';
import { URL } from 'url';
import pkg from 'pg';
const { Pool } = pkg;

// 1) Read and clean the connection string from env
const RAW = (process.env.DATABASE_URL || '').trim();
if (!RAW) {
  throw new Error('DATABASE_URL missing');
}

// 2) Parse it to parts
const u = new URL(RAW);
// Expected form: postgres://USER:PASSWORD@HOST:PORT/DBNAME
const user = decodeURIComponent(u.username);
const password = decodeURIComponent(u.password);
const host = u.hostname;            // e.g. db.szurc...supabase.co
const port = Number(u.port || 5432);
const database = u.pathname.replace(/^\//, '') || 'postgres';

// 3) Resolve the host to IPv4 **once** (avoid IPv6 + avoid per-connection DNS)
const { resolve4 } = dns.promises;
const ipv4List = await resolve4(host);          // top-level await works in ESM
const ipv4 = ipv4List[0];                       // first A record

// 4) Build the Pool using the IPv4 address directly
export const pool = new Pool({
  host: ipv4,                   // use IPv4 literal
  port,
  user,
  password,
  database,
  ssl: { require: true, rejectUnauthorized: false },
  // Optional: pg will still do DNS for hostnames it sees; we gave an IP so it's fine.
});

// db.js — IPv4-first + newline-safe

import dns from 'dns';
import pkg from 'pg';
const { Pool } = pkg;

// Force IPv4 for any DNS lookups the pg client performs
function forceIPv4Lookup(hostname, _opts, cb) {
  dns.lookup(hostname, { family: 4, all: false }, cb);
}

// Trim accidental spaces/newlines in env var
const connStr = (process.env.DATABASE_URL || '').trim();

export const pool = new Pool({
  connectionString: connStr,
  ssl: { require: true, rejectUnauthorized: false }, // Supabase needs SSL
  lookup: forceIPv4Lookup, // prefer IPv4
});

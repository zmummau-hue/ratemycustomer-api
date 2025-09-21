// db.js — IPv4-first, newline-safe, no top-level await

import dns from 'dns';
import pkg from 'pg';
const { Pool } = pkg;

// Force IPv4 for hostname lookups that the pg client performs
function forceIPv4Lookup(hostname, _opts, cb) {
  dns.lookup(hostname, { family: 4, all: false }, cb);
}

// Trim any accidental spaces/newlines in env var
const connStr = (process.env.DATABASE_URL || '').trim();

export const pool = new Pool({
  connectionString: connStr,
  ssl: { require: true, rejectUnauthorized: false }, // Supabase requires SSL
  lookup: forceIPv4Lookup, // <-- crucial: prefer IPv4 even if IPv6 is present
});

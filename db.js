import dns from 'dns';
import pkg from 'pg';
const { Pool } = pkg;

function forceIPv4Lookup(hostname, _opts, cb) {
  dns.lookup(hostname, { family: 4, all: false }, cb);
}

const connStr = (process.env.DATABASE_URL || '').trim();

export const pool = new Pool({
  connectionString: connStr,
  ssl: { require: true, rejectUnauthorized: false },
  lookup: forceIPv4Lookup,
});

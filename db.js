import dns from 'dns';
import pkg from 'pg';
const { Pool } = pkg;

// Force IPv4 when resolving the DB host (avoids ENETUNREACH on IPv6)
const forceIPv4Lookup = (hostname, _opts, callback) => {
  dns.lookup(hostname, { family: 4, all: false }, callback);
};

// Trim any accidental whitespace/newlines from the env var
const connStr = (process.env.DATABASE_URL || '').trim();

export const pool = new Pool({
  connectionString: connStr,
  ssl: { require: true, rejectUnauthorized: false },
  lookup: forceIPv4Lookup
});

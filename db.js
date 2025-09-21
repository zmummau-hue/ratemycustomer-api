import dns from 'dns';
import pkg from 'pg';
const { Pool } = pkg;

// Force IPv4 when resolving the DB host (works even if IPv6 is preferred elsewhere)
const forceIPv4Lookup = (hostname, _opts, callback) => {
  dns.lookup(hostname, { family: 4, all: false }, callback);
};

export const pool = new Pool({
  connectionString: process.env.DATABASE_URL,          // keep using your Render env var
  ssl: { require: true, rejectUnauthorized: false },   // Supabase requires SSL
  lookup: forceIPv4Lookup                               // <-- the key line
});

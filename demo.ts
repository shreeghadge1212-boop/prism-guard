import { guardToolCall } from './index.js';

// Pre-warm AST parser & JIT for DDL + DML branches
guardToolCall('DROP TABLE warmup;');
guardToolCall('SELECT 1;');

console.log('\n=== PRISM-GUARD VERIFICATION SUITE ===\n');

const testCases = [
  { name: 'Malicious Drop Table Attack', sql: 'DROP TABLE users;' },
  { name: 'Unbounded Delete Attack', sql: 'DELETE FROM accounts;' },
  { name: 'Safe Parameterized Read', sql: 'SELECT id, email FROM users WHERE id = 42;' },
  { name: 'Safe Bounded Mutation', sql: 'UPDATE accounts SET balance = 100 WHERE id = 10;' }
];

for (const test of testCases) {
  const result = guardToolCall(test.sql);

  if (result.allowed) {
    console.log(`\x1b[32m[ALLOWED]\x1b[0m ${test.name}`);
    console.log(`  Query:       "${result.query}"`);
    console.log(`  Audit Hash:  ${result.auditHash}`);
    console.log(`  Latency:     ${result.latencyMs} ms\n`);
  } else {
    console.log(`\x1b[31m[BLOCKED]\x1b[0m ${test.name}`);
    console.log(`  Query:       "${test.sql}"`);
    console.log(`  Reason:      ${result.reason}`);
    console.log(`  Latency:     ${result.latencyMs} ms\n`);
  }
}
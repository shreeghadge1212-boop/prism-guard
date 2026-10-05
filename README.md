# prism-guard

Deterministic, sub-2ms in-process AST firewall & cryptographic audit ledger for AI agent SQL tool calls (Node.js / TypeScript / Postgres).

## Why not just use restricted Postgres roles?
Restricted DB roles (`REVOKE DROP, ALTER`) stop DDL, but they **cannot prevent**:
1. **Unbounded Mutations:** An agent authorized to write running `DELETE FROM accounts;` or `UPDATE users SET balance = 0;` missing a `WHERE` clause.
2. **Missing Multi-Tenant Isolation:** Enforcing deterministically that every write contains a `tenant_id` filter.
3. **Cryptographic Proof:** Real-time tamper-evident SHA-256 audit hashes for enterprise compliance reviews.

## Performance Benchmark
- Execution latency: **<2ms** (in-process, zero network proxy hops).
- Engine: Deterministic AST inspection via `pgsql-ast-parser`.
- Safety: Strict **Fail-Closed** execution on parse errors.

## Quickstart

```bash
npm install
npm test
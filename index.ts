import { parse } from 'pgsql-ast-parser';
import { createHash } from 'crypto';

export interface PrismGuardConfig {
  mode?: 'observe' | 'block'; // NEW: Observe mode flag
}

export interface GuardResult {
  allowed: boolean;
  flagged?: boolean; // NEW: Tells the client if a query was caught in observe mode
  reason?: string;
  latencyMs: number;
  auditHash?: string;
  query?: string;
}

const MAX_PAYLOAD_BYTES = 50 * 1024; // 50KB Pre-check limit

export function guardToolCall(rawQuery: string, config: PrismGuardConfig = { mode: 'block' }): GuardResult {
  const start = performance.now();
  const isObserve = config.mode === 'observe';

  // Helper to handle logic for both Observe and Block modes
  const handleBlock = (reason: string) => {
    if (isObserve) {
      console.warn(`[PRISM-GUARD: OBSERVE MODE] Threat logged: ${reason}`);
      return {
        allowed: true, // In observe mode, we DO NOT block the execution
        flagged: true,
        reason: `OBSERVED: ${reason}`,
        latencyMs: Number((performance.now() - start).toFixed(3)),
        query: rawQuery
      };
    }
    return {
      allowed: false,
      flagged: true,
      reason,
      latencyMs: Number((performance.now() - start).toFixed(3)),
    };
  };

  if (!rawQuery || Buffer.byteLength(rawQuery, 'utf8') > MAX_PAYLOAD_BYTES) {
    return handleBlock('PAYLOAD_EXCEEDS_50KB_LIMIT');
  }

  try {
    // CRITICAL FIX: Use 'parse' instead of 'parseFirst' to catch multi-statement injections
    const parsedList = parse(rawQuery);

    if (parsedList.length === 0) {
        return handleBlock('EMPTY_QUERY');
    }

    // Block injections like: SELECT 1; DROP TABLE users;
    if (parsedList.length > 1) {
        return handleBlock('MULTI_STATEMENT_BLOCKED: Multiple statements not allowed');
    }

    const parsed = parsedList[0];

    // Block CTEs (WITH clauses) where mutations can be hidden
    if (parsed.type === 'with') {
         return handleBlock('CTE_MUTATION_BLOCKED: Mutations inside WITH clauses are not permitted');
    }

    switch (parsed.type) {
      case 'drop table':
      case 'drop sequence':
      case 'drop type':
      case 'alter table':
        return handleBlock(`DESTRUCTIVE_DDL_BLOCKED: ${parsed.type.toUpperCase()}`);

      case 'delete':
      case 'update':
        if (!parsed.where) {
          return handleBlock(`UNBOUNDED_${parsed.type.toUpperCase()}_BLOCKED: Missing WHERE clause`);
        }

        // Tautology check (Blocks: WHERE 1=1 or WHERE true)
        let isTautology = false;
        if (parsed.where.type === 'boolean' && parsed.where.value === true) {
          isTautology = true;
        }
        if (parsed.where.type === 'binary' && parsed.where.op === '=' &&
            parsed.where.left.type === 'numeric' && parsed.where.right.type === 'numeric' &&
            parsed.where.left.value === parsed.where.right.value) {
          isTautology = true;
        }

        if (isTautology) {
          return handleBlock(`UNBOUNDED_${parsed.type.toUpperCase()}_BLOCKED: Tautology detected (e.g. 1=1)`);
        }
        break;

      case 'select':
      case 'insert':
        break;

      default:
        return handleBlock(`DISALLOWED_OR_UNKNOWN_OPERATION: ${(parsed as any).type || 'UNKNOWN'}`);
    }

    const auditHash = createHash('sha256').update(rawQuery).digest('hex');

    return {
      allowed: true,
      flagged: false,
      query: rawQuery,
      auditHash,
      latencyMs: Number((performance.now() - start).toFixed(3)),
    };
  } catch (err: any) {
    return handleBlock(`PARSE_EXCEPTION_FAIL_CLOSED: ${err.message || 'Syntax Error'}`);
  }
}
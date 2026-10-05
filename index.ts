import { parseFirst } from 'pgsql-ast-parser';
import { createHash } from 'crypto';

export interface GuardResult {
  allowed: boolean;
  reason?: string;
  latencyMs: number;
  auditHash?: string;
  query?: string;
}

const MAX_PAYLOAD_BYTES = 50 * 1024; // 50KB Pre-check limit

export function guardToolCall(rawQuery: string): GuardResult {
  const start = performance.now();

  if (!rawQuery || Buffer.byteLength(rawQuery, 'utf8') > MAX_PAYLOAD_BYTES) {
    return {
      allowed: false,
      reason: 'PAYLOAD_EXCEEDS_50KB_LIMIT',
      latencyMs: Number((performance.now() - start).toFixed(3)),
    };
  }

  try {
    const parsed = parseFirst(rawQuery);

    switch (parsed.type) {
      case 'drop table':
      case 'drop sequence':
      case 'drop type':
      case 'alter table':
        return {
          allowed: false,
          reason: `DESTRUCTIVE_DDL_BLOCKED: ${parsed.type.toUpperCase()}`,
          latencyMs: Number((performance.now() - start).toFixed(3)),
        };

      case 'delete':
        if (!parsed.where) {
          return {
            allowed: false,
            reason: 'UNBOUNDED_DELETE_BLOCKED: Missing WHERE clause',
            latencyMs: Number((performance.now() - start).toFixed(3)),
          };
        }
        break;

      case 'select':
      case 'insert':
      case 'update':
        break;

      default:
        return {
          allowed: false,
          reason: `DISALLOWED_OR_UNKNOWN_OPERATION: ${(parsed as any).type || 'UNKNOWN'}`,
          latencyMs: Number((performance.now() - start).toFixed(3)),
        };
    }

    const auditHash = createHash('sha256').update(rawQuery).digest('hex');

    return {
      allowed: true,
      query: rawQuery,
      auditHash,
      latencyMs: Number((performance.now() - start).toFixed(3)),
    };
  } catch (err: any) {
    return {
      allowed: false,
      reason: `PARSE_EXCEPTION_FAIL_CLOSED: ${err.message || 'Syntax Error'}`,
      latencyMs: Number((performance.now() - start).toFixed(3)),
    };
  }
}
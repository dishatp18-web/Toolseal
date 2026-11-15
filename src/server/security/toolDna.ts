import crypto from 'crypto';
import type { CanonicalToolSchema, SchemaParameterDiff, ToolSchemaProperty } from '../../types/toolseal.ts';

/**
 * Recursively sorts all object keys to create a deterministic canonical representation.
 */
function sortObjectDeep(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(sortObjectDeep);
  }
  if (value !== null && typeof value === 'object') {
    const record = value as Record<string, unknown>;
    const sorted: Record<string, unknown> = {};
    for (const key of Object.keys(record).sort()) {
      const propVal = record[key];
      if (propVal !== undefined) {
        sorted[key] = sortObjectDeep(propVal);
      }
    }
    return sorted;
  }
  return value;
}

/**
 * Normalizes a tool schema object into canonical JSON and computes its SHA-256 Tool DNA fingerprint.
 */
export function computeToolDna(schema: CanonicalToolSchema): {
  canonicalJson: string;
  sha256: string;
} {
  const normalized: CanonicalToolSchema = {
    name: schema.name,
    description: schema.description ?? '',
    parameters: {
      type: 'object',
      properties: (schema.parameters?.properties ?? {}) as Record<string, ToolSchemaProperty>,
      required: [...(schema.parameters?.required ?? [])].sort(),
      additionalProperties: schema.parameters?.additionalProperties ?? false,
    },
  };

  const canonicalObj = sortObjectDeep(normalized);
  const canonicalJson = JSON.stringify(canonicalObj);
  const sha256 = crypto.createHash('sha256').update(canonicalJson, 'utf8').digest('hex');

  return { canonicalJson, sha256 };
}

/**
 * Assesses security risk of a changed parameter name or schema definition.
 */
function evaluateParamRiskNote(paramName: string, prop?: ToolSchemaProperty | null): string {
  const lower = paramName.toLowerCase();
  const desc = (prop?.description ?? '').toLowerCase();

  if (/(exec|shell|cmd|command|eval|script|token|secret|key|password|credential)/.test(lower + ' ' + desc)) {
    return 'High-risk capability expansion: exposes execution or credential control parameter.';
  }
  if (/(url|webhook|endpoint|callback|upload|exfil|destination|host)/.test(lower + ' ' + desc)) {
    return 'Potential exfiltration vector: introduces external network target parameter.';
  }
  if (/(bypass|override|force|sudo|admin|root|skip_auth|unrestricted)/.test(lower + ' ' + desc)) {
    return 'Privilege escalation indicator: introduces authorization or safety bypass flag.';
  }
  if (/(path|file|dir|scope|all|limit|query|sql)/.test(lower + ' ' + desc)) {
    return 'Scope/access expansion: alters data boundary or filesystem access control.';
  }
  return 'Schema surface altered from approved baseline; requires administrator verification.';
}

/**
 * Compares two CanonicalToolSchemas parameter-by-parameter and returns human-readable diffs.
 */
export function diffToolSchemas(
  originalSchema: CanonicalToolSchema,
  modifiedSchema: CanonicalToolSchema
): SchemaParameterDiff[] {
  const diffs: SchemaParameterDiff[] = [];
  const origProps = originalSchema.parameters?.properties ?? {};
  const modProps = modifiedSchema.parameters?.properties ?? {};

  const allKeys = new Set([...Object.keys(origProps), ...Object.keys(modProps)]);

  for (const key of Array.from(allKeys).sort()) {
    const before = origProps[key] ?? null;
    const after = modProps[key] ?? null;

    if (!before && after) {
      diffs.push({
        parameter: key,
        changeType: 'added',
        before: null,
        after,
        riskNote: evaluateParamRiskNote(key, after),
      });
    } else if (before && !after) {
      diffs.push({
        parameter: key,
        changeType: 'removed',
        before,
        after: null,
        riskNote: 'Previously required or expected parameter removed from schema.',
      });
    } else if (before && after) {
      const beforeStr = JSON.stringify(sortObjectDeep(before));
      const afterStr = JSON.stringify(sortObjectDeep(after));
      if (beforeStr !== afterStr) {
        diffs.push({
          parameter: key,
          changeType: 'modified',
          before,
          after,
          riskNote: evaluateParamRiskNote(key, after),
        });
      }
    }
  }

  return diffs;
}

/**
 * Version-to-version diff, read as a security question.
 *
 * This is the part that does something existing open-source tooling does not.
 * The honest framing matters, because the obvious stronger claim is false:
 *
 *   Wrong:  "no tool frames spec-diff as security analysis"
 *   Right:  "no tool does it without live traffic as an input"
 *
 * Wallarm, Cerberus and 42Crunch all sell shadow and zombie API detection, and
 * they are good at it. Every one of them compares a spec against observed
 * traffic from a gateway or agent. That is a heavier deployment and a different
 * question. Spectral, at the other end, lints one document and has no concept of
 * a second, which a maintainer feature request confirms is still true.
 *
 * The gap is the middle: two documents, no runtime data, answering "what
 * disappeared from the contract, and is anyone still serving it?"
 *
 * The limit that governs the whole file: a spec is documentation. Removing a
 * path from documentation does not remove the route from the server. That is
 * exactly why a removed path is worth flagging, and exactly why this tool can
 * never confirm the finding on its own. Every diff finding is a question for a
 * human, not a verdict.
 */

import { operations, requiresAuth } from './rules.js';
import type { Finding, OperationLike, SpecLike } from './types.js';

interface OperationKey {
  path: string;
  method: string;
  operationId?: string;
  hadSecurity: boolean;
  deprecated: boolean;
}

function index(spec: SpecLike): Map<string, OperationKey> {
  const map = new Map<string, OperationKey>();
  for (const { path, method, op } of operations(spec)) {
    map.set(`${method} ${path}`, {
      path,
      method,
      operationId: op.operationId,
      hadSecurity: requiresAuth(spec, op),
      deprecated: op.deprecated === true,
    });
  }
  return map;
}

/**
 * Compare an older spec against a newer one.
 *
 * `previous` must be the earlier version. Passing them the wrong way round
 * inverts every finding, so the CLI labels the arguments rather than relying on
 * the caller to remember the order.
 */
export function diffSpecs(previous: SpecLike, current: SpecLike): Finding[] {
  const before = index(previous);
  const after = index(current);
  const out: Finding[] = [];

  for (const [key, op] of before) {
    if (after.has(key)) continue;

    // A removed operation that never required authentication is the worse case:
    // if the route is still live, it is still reachable by anyone.
    const severity = op.hadSecurity ? 'medium' : 'high';
    const wasDeprecated = op.deprecated
      ? ' It was marked deprecated before removal, which suggests a managed retirement.'
      : ' It was not marked deprecated first, so this may be an undocumented removal rather than a planned one.';

    out.push({
      rule: 'DIFF-001',
      title: 'Operation removed from the documented contract',
      evidence: 'PROVES',
      severity,
      location: `paths.${op.path}.${op.method}`,
      detail:
        `${op.method.toUpperCase()} ${op.path} exists in the previous version and is absent from the current one.` +
        wasDeprecated +
        (op.hadSecurity
          ? ''
          : ' It declared no security requirement, so if the route is still deployed it is reachable without credentials.'),
      cannotEstablish:
        'Whether the endpoint is still deployed. This proves it left the documentation. Confirming whether it left the server requires a request to it, which this tool does not make.',
    });
  }

  // Losing an auth requirement between versions is worth surfacing even when
  // the operation survives, because it is easy to do by accident during a
  // refactor and nothing else in a normal review catches it.
  for (const [key, now] of after) {
    const then = before.get(key);
    if (!then) continue;
    if (then.hadSecurity && !now.hadSecurity) {
      out.push({
        rule: 'DIFF-002',
        title: 'Operation lost its declared security requirement',
        evidence: 'PROVES',
        severity: 'high',
        location: `paths.${now.path}.${now.method}`,
        detail: `${now.method.toUpperCase()} ${now.path} declared a security requirement in the previous version and declares none now.`,
        cannotEstablish:
          'Whether authentication is still enforced at runtime. The documented requirement was dropped; the server may or may not have followed.',
      });
    }
  }

  // Newly deprecated operations are not a finding on their own. They become one
  // when nothing records an intended removal date, because that is how a
  // deprecated endpoint stays live for years.
  for (const [key, now] of after) {
    const then = before.get(key);
    if (!then) continue;
    if (!then.deprecated && now.deprecated) {
      out.push({
        rule: 'DIFF-003',
        title: 'Operation newly marked deprecated',
        evidence: 'PROVES',
        severity: 'info',
        location: `paths.${now.path}.${now.method}`,
        detail: `${now.method.toUpperCase()} ${now.path} became deprecated in this version. OpenAPI has no field for a removal date, so a deprecation with no external retirement record tends to persist.`,
        cannotEstablish:
          'Whether a retirement date exists elsewhere. This is an inventory prompt, not a defect.',
      });
    }
  }

  return out;
}

export interface DiffSummary {
  removed: number;
  lostAuth: number;
  newlyDeprecated: number;
  addedOperations: number;
  totalBefore: number;
  totalAfter: number;
}

export function summarize(previous: SpecLike, current: SpecLike): DiffSummary {
  const before = index(previous);
  const after = index(current);
  let removed = 0;
  let added = 0;
  for (const key of before.keys()) if (!after.has(key)) removed++;
  for (const key of after.keys()) if (!before.has(key)) added++;
  const findings = diffSpecs(previous, current);
  return {
    removed,
    lostAuth: findings.filter((f) => f.rule === 'DIFF-002').length,
    newlyDeprecated: findings.filter((f) => f.rule === 'DIFF-003').length,
    addedOperations: added,
    totalBefore: before.size,
    totalAfter: after.size,
  };
}

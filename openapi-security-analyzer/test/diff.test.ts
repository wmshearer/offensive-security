/**
 * Tests for the diff engine and the security-inheritance rule.
 *
 * The inheritance tests exist because of a real bug. The first run of this tool
 * against Stripe's published spec produced four HIGH findings, each asserting
 * the removed endpoint was "reachable without credentials". Stripe declares
 * `[{basicAuth}, {bearerAuth}]` at the document level and those operations
 * inherit it. The claim was false, on the highest-severity line of the output,
 * which is the line a reader acts on first.
 */

import { describe, expect, it } from 'vitest';
import { diffSpecs, summarize } from '../src/diff.js';
import { analyze, requiresAuth } from '../src/rules.js';
import type { SpecLike } from '../src/types.js';

const globalAuth: SpecLike = {
  openapi: '3.0.0',
  security: [{ bearerAuth: [] }],
  paths: {
    '/kept': { get: {} },
    '/removed': { get: {} },
  },
};

const afterRemoval: SpecLike = {
  openapi: '3.0.0',
  security: [{ bearerAuth: [] }],
  paths: { '/kept': { get: {} } },
};

describe('security requirement inheritance', () => {
  it('treats an operation with no security key as inheriting the global default', () => {
    expect(requiresAuth(globalAuth, {})).toBe(true);
  });

  it('treats an explicit empty array as opting out of the global default', () => {
    expect(requiresAuth(globalAuth, { security: [] })).toBe(false);
  });

  it('requires nothing when neither level declares a requirement', () => {
    expect(requiresAuth({ paths: {} }, {})).toBe(false);
  });

  it('honours an operation-level requirement when there is no global one', () => {
    expect(requiresAuth({ paths: {} }, { security: [{ apiKey: [] }] })).toBe(true);
  });

  it('does not claim an inheriting removed operation was unauthenticated', () => {
    // The exact regression. Before the fix this finding read HIGH and asserted
    // the endpoint was reachable without credentials.
    const findings = diffSpecs(globalAuth, afterRemoval);
    const removed = findings.find((f) => f.rule === 'DIFF-001');
    expect(removed).toBeDefined();
    expect(removed?.severity).toBe('medium');
    expect(removed?.detail).not.toContain('reachable without credentials');
  });

  it('does still flag a removed operation that genuinely had no auth', () => {
    const open: SpecLike = { openapi: '3.0.0', paths: { '/open': { get: {} } } };
    const gone: SpecLike = { openapi: '3.0.0', paths: {} };
    const findings = diffSpecs(open, gone);
    expect(findings[0]?.severity).toBe('high');
    expect(findings[0]?.detail).toContain('reachable without credentials');
  });
});

describe('diff', () => {
  it('reports an operation that left the contract', () => {
    const findings = diffSpecs(globalAuth, afterRemoval);
    expect(findings.filter((f) => f.rule === 'DIFF-001')).toHaveLength(1);
    expect(findings[0]?.location).toBe('paths./removed.get');
  });

  it('reports nothing when the specs match', () => {
    expect(diffSpecs(globalAuth, globalAuth)).toHaveLength(0);
  });

  it('flags an operation that lost its security requirement', () => {
    const before: SpecLike = {
      paths: { '/a': { post: { security: [{ bearerAuth: [] }] } } },
    };
    const after: SpecLike = { paths: { '/a': { post: { security: [] } } } };
    const findings = diffSpecs(before, after);
    expect(findings.some((f) => f.rule === 'DIFF-002')).toBe(true);
  });

  it('flags a newly deprecated operation as informational only', () => {
    const before: SpecLike = { paths: { '/a': { get: {} } } };
    const after: SpecLike = { paths: { '/a': { get: { deprecated: true } } } };
    const findings = diffSpecs(before, after);
    const dep = findings.find((f) => f.rule === 'DIFF-003');
    expect(dep?.severity).toBe('info');
  });

  it('notes when a removal followed a deprecation', () => {
    const before: SpecLike = { paths: { '/a': { get: { deprecated: true } } } };
    const after: SpecLike = { paths: {} };
    const findings = diffSpecs(before, after);
    expect(findings[0]?.detail).toContain('managed retirement');
  });

  it('counts additions and removals independently', () => {
    const s = summarize(globalAuth, afterRemoval);
    expect(s.removed).toBe(1);
    expect(s.addedOperations).toBe(0);
    expect(s.totalBefore).toBe(2);
    expect(s.totalAfter).toBe(1);
  });

  it('is direction sensitive, so a removal reads as an addition when reversed', () => {
    // Worth pinning: passing the arguments backwards produces a clean-looking
    // report rather than an error, which is why the CLI names them.
    const forward = summarize(globalAuth, afterRemoval);
    const backward = summarize(afterRemoval, globalAuth);
    expect(forward.removed).toBe(1);
    expect(backward.removed).toBe(0);
    expect(backward.addedOperations).toBe(1);
  });
});

describe('single document rules', () => {
  it('proves a plaintext server URL', () => {
    const spec: SpecLike = { servers: [{ url: 'http://api.example.com' }], paths: {} };
    const findings = analyze(spec);
    const http = findings.find((f) => f.rule === 'MISCONFIG-001');
    expect(http?.evidence).toBe('PROVES');
    expect(http?.severity).toBe('high');
  });

  it('does not flag an https server', () => {
    const spec: SpecLike = { servers: [{ url: 'https://api.example.com' }], paths: {} };
    expect(analyze(spec).some((f) => f.rule === 'MISCONFIG-001')).toBe(false);
  });

  it('proves a credential carried in the query string', () => {
    const spec: SpecLike = {
      paths: {
        '/a': { get: { parameters: [{ name: 'api_key', in: 'query' }] } },
      },
    };
    const found = analyze(spec).find((f) => f.rule === 'AUTHN-004');
    expect(found?.evidence).toBe('PROVES');
  });

  it('does not treat an ordinary query parameter as a credential', () => {
    const spec: SpecLike = {
      paths: { '/a': { get: { parameters: [{ name: 'limit', in: 'query' }] } } },
    };
    expect(analyze(spec).some((f) => f.rule === 'AUTHN-004')).toBe(false);
  });

  it('does not flag a write operation that inherits global security', () => {
    const spec: SpecLike = {
      security: [{ bearerAuth: [] }],
      paths: { '/a': { post: {} } },
    };
    expect(analyze(spec).some((f) => f.rule === 'AUTHN-001')).toBe(false);
  });

  it('flags a write operation that opts out of global security', () => {
    const spec: SpecLike = {
      security: [{ bearerAuth: [] }],
      paths: { '/a': { post: { security: [] } } },
    };
    expect(analyze(spec).some((f) => f.rule === 'AUTHN-001')).toBe(true);
  });

  it('marks every finding with what it cannot establish', () => {
    // A static spec never proves runtime behaviour. If a rule ever ships without
    // saying so, this fails.
    const spec: SpecLike = {
      servers: [{ url: 'http://x.example' }],
      paths: { '/a': { post: { parameters: [{ name: 'token', in: 'query' }] } } },
    };
    for (const finding of analyze(spec)) {
      expect(finding.cannotEstablish.length).toBeGreaterThan(20);
    }
  });
});

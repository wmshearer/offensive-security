/**
 * Single-document rules.
 *
 * These are NOT novel. Spectral's OWASP ruleset already covers this ground, and
 * pretending otherwise would be the first thing a reviewer checks and the first
 * thing they would find wrong. I counted 29 rules in that ruleset by grepping
 * the live source, spread very unevenly: API4 has 9 and API2 has 8, while API5
 * and API7 have exactly one weak heuristic each and API6 and API10 have none at
 * all.
 *
 * So these exist to make the diff engine's output legible in context, not to
 * compete. The part of this tool that does something Spectral cannot is in
 * diff.ts, because Spectral lints one document and has no concept of a second.
 *
 * The design rule here: a finding says what the spec PROVES versus what it only
 * SUGGESTS, and carries what it cannot establish. A static document describes
 * what an API claims. It cannot describe what the server does.
 */

import {
  HTTP_METHODS,
  type Finding,
  type OperationLike,
  type ParameterLike,
  type SpecLike,
} from './types.js';

/** Walk every operation in a spec, skipping non-method keys like `parameters`. */
export function* operations(
  spec: SpecLike,
): Generator<{ path: string; method: string; op: OperationLike }> {
  const paths = spec.paths ?? {};
  for (const [path, item] of Object.entries(paths)) {
    if (item === null || typeof item !== 'object') continue;
    for (const method of HTTP_METHODS) {
      const op = (item as Record<string, unknown>)[method];
      if (op && typeof op === 'object') {
        yield { path, method, op: op as OperationLike };
      }
    }
  }
}

/**
 * Whether an operation requires authentication, accounting for inheritance.
 *
 * An operation with no `security` key inherits the document-level default. Only
 * an explicit empty array opts out of it. Checking the operation level alone
 * reports every inheriting operation as unauthenticated, which is what the
 * first run of this tool against Stripe did: four high-severity findings each
 * claiming an endpoint was reachable without credentials, when Stripe declares
 * `[{basicAuth}, {bearerAuth}]` globally and those operations inherit it.
 *
 * A false claim on a high-severity finding is the worst kind to ship, because
 * it is the sentence a reader acts on first. Both the rules and the diff engine
 * call this one implementation rather than keeping a copy each.
 */
export function requiresAuth(spec: SpecLike, op: OperationLike): boolean {
  if (Array.isArray(op.security)) {
    return op.security.length > 0;
  }
  return Array.isArray(spec.security) && spec.security.length > 0;
}

/**
 * A plaintext server URL. This is one of very few things a spec genuinely
 * PROVES, and even then it proves a fact about the document rather than about
 * the deployment: a proxy in front could still force TLS.
 */
export function ruleHttpServer(spec: SpecLike): Finding[] {
  const out: Finding[] = [];
  for (const [i, server] of (spec.servers ?? []).entries()) {
    const url = server.url ?? '';
    if (url.startsWith('http://')) {
      out.push({
        rule: 'MISCONFIG-001',
        title: 'Server URL uses plaintext HTTP',
        evidence: 'PROVES',
        severity: 'high',
        location: `servers[${i}].url`,
        detail: `The documented server URL is ${url}. Credentials and payloads sent to it are not encrypted in transit.`,
        cannotEstablish:
          'Whether the deployed service actually serves plaintext. A load balancer may redirect to HTTPS regardless of what the document says.',
      });
    }
  }
  return out;
}

/** Credentials carried in a URL, which lands them in logs and referrers. */
export function ruleCredentialsInUrl(spec: SpecLike): Finding[] {
  const out: Finding[] = [];
  const credential = /^(api[-_]?key|token|secret|password|passwd|auth)$/i;
  for (const { path, method, op } of operations(spec)) {
    for (const param of op.parameters ?? []) {
      const p: ParameterLike = param;
      const where = p.in ?? '';
      const name = p.name ?? '';
      if ((where === 'query' || where === 'path') && credential.test(name)) {
        out.push({
          rule: 'AUTHN-004',
          title: 'Credential passed in the URL',
          evidence: 'PROVES',
          severity: 'high',
          location: `paths.${path}.${method}.parameters.${name}`,
          detail: `Parameter "${name}" is declared in ${where}. URLs are written to server logs, proxy logs, and browser history.`,
          cannotEstablish:
            'Whether those logs are actually retained or exposed. The transport weakness is documented; the consequence depends on the deployment.',
        });
      }
    }
  }
  return out;
}

/**
 * An operation that mutates state with no security requirement declared.
 *
 * A global `security` block covers operations that do not override it, so this
 * only fires when neither level declares one. Genuinely public write endpoints
 * exist (inbound webhooks), which is why this SUGGESTS rather than PROVES.
 */
export function ruleUnauthenticatedWrite(spec: SpecLike): Finding[] {
  const out: Finding[] = [];
  const writes = new Set(['post', 'put', 'patch', 'delete']);
  for (const { path, method, op } of operations(spec)) {
    if (!writes.has(method)) continue;
    const emptyOverride = Array.isArray(op.security) && op.security.length === 0;
    if (!requiresAuth(spec, op)) {
      out.push({
        rule: 'AUTHN-001',
        title: 'State-changing operation declares no authentication',
        evidence: 'SUGGESTS',
        severity: 'medium',
        location: `paths.${path}.${method}`,
        detail: emptyOverride
          ? `${method.toUpperCase()} ${path} explicitly overrides global security with an empty requirement, making it public.`
          : `${method.toUpperCase()} ${path} declares no security requirement and the document sets no global default.`,
        cannotEstablish:
          'Whether the server enforces authentication anyway. Specs are frequently incomplete, and an undocumented requirement is still a requirement at runtime.',
      });
    }
  }
  return out;
}

/**
 * Unbounded string inputs.
 *
 * High false-positive rate by nature: free-text fields legitimately have no
 * length bound. Reported as `info` for that reason. Volume is the signal here,
 * not any individual hit.
 */
export function ruleUnboundedString(spec: SpecLike): Finding[] {
  const out: Finding[] = [];
  for (const { path, method, op } of operations(spec)) {
    for (const param of op.parameters ?? []) {
      const schema = param.schema;
      if (!schema || schema.type !== 'string') continue;
      const bounded =
        schema.maxLength !== undefined ||
        (Array.isArray(schema.enum) && schema.enum.length > 0) ||
        schema.format !== undefined;
      if (!bounded) {
        out.push({
          rule: 'RESOURCE-001',
          title: 'String parameter has no length or value bound',
          evidence: 'SUGGESTS',
          severity: 'info',
          location: `paths.${path}.${method}.parameters.${param.name ?? '?'}`,
          detail: `Parameter "${param.name ?? '?'}" accepts a string with no maxLength, enum, or format constraint.`,
          cannotEstablish:
            'Whether the server bounds it anyway, or whether a gateway caps request size before it arrives. Free-text fields are also legitimately unbounded.',
        });
      }
    }
  }
  return out;
}

export const SINGLE_DOC_RULES = [
  ruleHttpServer,
  ruleCredentialsInUrl,
  ruleUnauthenticatedWrite,
  ruleUnboundedString,
] as const;

export function analyze(spec: SpecLike): Finding[] {
  return SINGLE_DOC_RULES.flatMap((rule) => rule(spec));
}

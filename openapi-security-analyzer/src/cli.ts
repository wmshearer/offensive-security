/**
 * Command line entry point.
 *
 * Two modes:
 *   analyze <spec>                  single-document rules
 *   diff <previous> <current>       version comparison
 *
 * The diff arguments are order-sensitive and getting them backwards inverts
 * every finding, so they are named in the usage text rather than described as
 * "two files".
 *
 * No network access anywhere in this tool. It reads files and exits.
 */

import { readFileSync } from 'node:fs';
import { analyze } from './rules.js';
import { diffSpecs, summarize } from './diff.js';
import type { Finding, SpecLike } from './types.js';

function load(path: string): SpecLike {
  const raw = readFileSync(path, 'utf8');
  try {
    return JSON.parse(raw) as SpecLike;
  } catch (err) {
    const reason = err instanceof Error ? err.message : String(err);
    throw new Error(`${path} is not valid JSON: ${reason}`);
  }
}

const SEVERITY_ORDER = { high: 0, medium: 1, low: 2, info: 3 } as const;

function render(findings: Finding[]): string {
  if (findings.length === 0) return 'No findings.\n';
  const sorted = [...findings].sort(
    (a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity],
  );
  const lines: string[] = [];
  for (const f of sorted) {
    lines.push(`[${f.severity.toUpperCase()}] ${f.rule}  ${f.title}`);
    lines.push(`  where:   ${f.location}`);
    lines.push(`  what:    ${f.detail}`);
    lines.push(`  evidence: ${f.evidence}`);
    lines.push(`  cannot establish: ${f.cannotEstablish}`);
    lines.push('');
  }
  return lines.join('\n');
}

function counts(findings: Finding[]): string {
  const by = new Map<string, number>();
  for (const f of findings) by.set(f.rule, (by.get(f.rule) ?? 0) + 1);
  const rows = [...by.entries()].sort((a, b) => b[1] - a[1]);
  return rows.map(([rule, n]) => `  ${String(n).padStart(5)}  ${rule}`).join('\n');
}

function main(argv: string[]): number {
  const [mode, ...rest] = argv;

  if (mode === 'analyze') {
    const path = rest[0];
    if (!path) {
      console.error('usage: analyze <spec.json>');
      return 2;
    }
    const findings = analyze(load(path));
    console.log(`Analyzed ${path}`);
    console.log(`${findings.length} findings\n`);
    console.log(counts(findings));
    console.log();
    console.log(render(findings.filter((f) => f.severity !== 'info')));
    const infos = findings.filter((f) => f.severity === 'info').length;
    if (infos > 0) {
      console.log(`(${infos} informational findings suppressed above. These have a`);
      console.log(' high false-positive rate by design and are counted, not listed.)');
    }
    return 0;
  }

  if (mode === 'diff') {
    const [prevPath, curPath] = rest;
    if (!prevPath || !curPath) {
      console.error('usage: diff <previous-spec.json> <current-spec.json>');
      console.error('  argument order matters: previous first, current second');
      return 2;
    }
    const previous = load(prevPath);
    const current = load(curPath);
    const s = summarize(previous, current);
    const findings = diffSpecs(previous, current);

    console.log(`previous: ${prevPath}  (${s.totalBefore} operations)`);
    console.log(`current:  ${curPath}  (${s.totalAfter} operations)`);
    console.log();
    console.log(`  ${s.addedOperations} operations added`);
    console.log(`  ${s.removed} operations removed`);
    console.log(`  ${s.lostAuth} operations lost a declared security requirement`);
    console.log(`  ${s.newlyDeprecated} operations newly deprecated`);
    console.log();
    console.log(render(findings.filter((f) => f.severity !== 'info')));
    const infos = findings.filter((f) => f.severity === 'info').length;
    if (infos > 0) {
      console.log(`(${infos} informational findings not listed.)`);
    }
    console.log();
    console.log('A removed path proves the documentation changed. It does not prove');
    console.log('the route stopped answering. Confirming that needs a request, which');
    console.log('this tool does not make.');
    return 0;
  }

  console.error('usage:');
  console.error('  analyze <spec.json>');
  console.error('  diff <previous-spec.json> <current-spec.json>');
  return 2;
}

process.exit(main(process.argv.slice(2)));

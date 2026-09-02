/**
 * Types for the analyzer.
 *
 * The OpenAPI shapes here are deliberately partial. A full typing of the
 * specification is a large dependency and this tool only reads a handful of
 * fields, so it models what it touches and treats everything else as unknown.
 * `noUncheckedIndexedAccess` is on in tsconfig, so every index access below has
 * to be narrowed before use. That is the point: this walks documents nobody in
 * this project wrote.
 */

/** How much a finding's evidence actually supports. */
export type EvidenceClass =
  /** The spec document literally states this. No inference. */
  | 'PROVES'
  /**
   * The spec is consistent with a weakness but does not establish it. Almost
   * every security finding from a static spec is this, because a contract
   * describes what an API says it does, not what the running service does.
   */
  | 'SUGGESTS';

export type Severity = 'high' | 'medium' | 'low' | 'info';

export interface Finding {
  rule: string;
  title: string;
  evidence: EvidenceClass;
  severity: Severity;
  /** JSON-pointer-ish location, e.g. `paths./v1/charges.get`. */
  location: string;
  detail: string;
  /** What this finding cannot establish. Rendered with the finding, never hidden. */
  cannotEstablish: string;
}

export interface OperationLike {
  operationId?: string;
  security?: unknown[];
  parameters?: ParameterLike[];
  deprecated?: boolean;
  responses?: Record<string, unknown>;
  requestBody?: unknown;
}

export interface ParameterLike {
  name?: string;
  in?: string;
  required?: boolean;
  schema?: SchemaLike;
}

export interface SchemaLike {
  type?: string;
  format?: string;
  maxLength?: number;
  enum?: unknown[];
  additionalProperties?: unknown;
  properties?: Record<string, SchemaLike>;
}

export interface ServerLike {
  url?: string;
  description?: string;
}

export interface SpecLike {
  openapi?: string;
  info?: { title?: string; version?: string };
  servers?: ServerLike[];
  security?: unknown[];
  paths?: Record<string, Record<string, unknown>>;
}

/** HTTP methods an operation object can appear under. */
export const HTTP_METHODS = [
  'get',
  'put',
  'post',
  'delete',
  'options',
  'head',
  'patch',
  'trace',
] as const;

export type HttpMethod = (typeof HTTP_METHODS)[number];

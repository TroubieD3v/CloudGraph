export type Confidence = "confirmed" | "inferred" | "conditional" | "unknown";
export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface Source {
  file: string;
  line?: number;
  endLine?: number;
  path?: string;
}

export interface Resource {
  id: string;
  domain: string;
  kind: string;
  type: string;
  name: string;
  namespace?: string;
  source: Source;
  labels?: Record<string, string>;
  attrs?: Record<string, unknown>;
  sensitive?: boolean;
  sensitiveReason?: string;
  generated?: boolean;
}

export interface Edge {
  id: string;
  from: string;
  to: string;
  type: string;
  label: string;
  confidence: Confidence;
  conditions?: string[];
  evidence?: string;
  source: Source;
  attack?: boolean;
}

export interface Fix {
  id: string;
  action: string;
  target: string;
  description: string;
  findingIds?: string[];
  edits?: { file: string; startLine: number; endLine: number }[];
}

export interface Finding {
  id: string;
  ruleId: string;
  title: string;
  severity: Severity;
  message: string;
  remediation: string;
  resourceId: string;
  source: Source;
  fix?: Fix;
}

export interface Step {
  from: string;
  to: string;
  edgeId: string;
  label: string;
  confidence: Confidence;
  conditions?: string[];
  evidence?: string;
  source: Source;
}

export interface Path {
  id: string;
  title: string;
  entry: string;
  target: string;
  nodes: string[];
  steps: Step[];
  confidence: Confidence;
  score: number;
  severity: Severity;
  prerequisites: string[];
  explanation: string;
  signature: string;
  findingIds?: string[];
}

export interface UnknownNote {
  id: string;
  resourceId: string;
  message: string;
  source: Source;
}

export interface Summary {
  resources: number;
  edges: number;
  findings: number;
  paths: number;
  unknowns: number;
  bySeverity: Record<string, number>;
}

export interface Analysis {
  id: string;
  name: string;
  createdAt: string;
  inputs: string[];
  resources: Resource[];
  edges: Edge[];
  findings: Finding[];
  paths: Path[];
  unknowns: UnknownNote[];
  fixes: Fix[];
  hotspots: { resourceId: string; paths: number }[];
  warnings?: string[];
  sources?: Record<string, string[]>;
  pathSearch?: PathSearch;
  summary: Summary;
}

export interface PathSearch {
  limits: { maxDepth: number; maxCandidates: number; maxPivots: number };
  candidates: number;
  depthLimitHits: number;
  candidateLimitHit: boolean;
  pivotLimitHits: number;
  complete: boolean;
  notices?: string[];
}

export interface HistoryItem {
  id: string;
  name: string;
  createdAt: string;
  summary: Summary;
}

export interface Demo {
  name: string;
  title: string;
  description: string;
}

export interface Simulation {
  applied: Fix[];
  skipped?: string[];
  pathsBefore: number;
  pathsAfter: number;
  pathsResolved: Path[];
  pathsRemaining: Path[];
  pathsNew: Path[];
  findingsBefore: number;
  findingsAfter: number;
  findingsResolved: Finding[];
}

export interface DiffResult {
  aName: string;
  bName: string;
  resourcesAdded: string[];
  resourcesRemoved: string[];
  edgesAdded: Edge[];
  edgesRemoved: Edge[];
  findingsAdded: Finding[];
  findingsRemoved: Finding[];
  pathsAppeared: Path[];
  pathsDisappeared: Path[];
  counts: Record<string, [number, number]>;
}

// API client for PatchPilot backend

const BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000';

class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
    this.name = 'ApiError';
  }
}

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE_URL}${path}`, {
    headers: { 'Content-Type': 'application/json', ...options?.headers },
    ...options,
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({ detail: res.statusText }));
    throw new ApiError(res.status, body.detail || body.error || res.statusText);
  }
  return res.json();
}

// ---- Types ----
export interface HealthResponse {
  status: string;
  backend: string;
  falkordb: string;
  llm_mode: string;
}

export interface VulnerabilityBrief {
  id: string;
  title: string;
  severity: string;
  cvss_score: number | null;
  cve: string | null;
  published: string | null;
  description: string | null;
  finding_count: number;
  is_synthetic?: boolean;
  synthetic_label?: string | null;
}

export interface VulnerabilityDetail extends VulnerabilityBrief {
  affected_packages: string[];
  finding_ids: string[];
  incomplete_evidence: boolean;
}

export interface PackageInfo {
  name: string;
  version: string;
  ecosystem: string;
  is_direct_vulnerable: boolean;
}

export interface ApplicationInfo {
  id: string;
  name: string;
  environment: string;
  language: string;
  teams: string[];
  asset_ids: string[];
  asset_criticalities: string[];
  asset_names: string[];
}

export interface AssetInfo {
  id: string;
  name: string;
  criticality: string;
  environment: string;
  region: string | null;
  exposed: boolean;
  applications: string[];
  teams: string[];
}

export interface TeamInfo {
  id: string;
  name: string;
  email: string | null;
  applications: string[];
}

export interface EvidencePath {
  app_id: string;
  app_name: string;
  path_nodes: Array<{ label: string; name: string; version?: string }>;
  hops: number;
}

export interface PriorityInfo {
  score: number;
  label: string;
  severity_contribution: number;
  asset_criticality_contribution: number;
  reach_contribution: number;
  exposure_contribution: number;
  confidence_penalty: number;
  top_asset_criticality: string;
  affected_application_count: number;
  affected_asset_count: number;
}

export interface GraphNode {
  id: string;
  label: string;
  type: string;
  data: Record<string, unknown>;
}

export interface GraphEdge {
  source: string;
  target: string;
  label: string;
}

export interface GraphData {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export interface InvestigationResult {
  investigation_id: string;
  investigation_created_at: string;
  vuln_id: string;
  vulnerability: VulnerabilityDetail;
  affected_packages: PackageInfo[];
  affected_applications: ApplicationInfo[];
  affected_assets: AssetInfo[];
  responsible_teams: TeamInfo[];
  evidence_paths: EvidencePath[];
  graph_data: GraphData;
  priority: PriorityInfo;
  evidence_complete: boolean;
  missing_evidence: string[];
  explanation: string;
  recommended_action: string;
  factors_detail: Record<string, unknown>;
  llm_summary: string | null;
  llm_used: boolean;
  mode: string;
}

export interface InvestigationBrief {
  id: string;
  created_at: string;
  status: string;
  vuln_id: string;
  vuln_title: string;
  vuln_severity: string;
}

export interface RemediationRequest {
  finding_id: string;
  investigation_id: string;
  action_type: string;
  description: string;
  team_id?: string;
}

export interface RemediationResponse {
  id: string;
  finding_id: string;
  investigation_id: string;
  action_type: string;
  description: string;
  status: string;
  created_at: string;
  team_id: string | null;
}

export interface RemediationBrief {
  id: string;
  action_type: string;
  description: string;
  status: string;
  created_at: string;
  finding_id: string | null;
  vuln_id: string | null;
  vuln_title: string | null;
  vuln_severity: string | null;
  team_name: string | null;
}

export interface OverviewStats {
  vulnerability_count: number;
  finding_count: number;
  open_findings: number;
  asset_count: number;
  critical_assets: number;
  remediation_count: number;
  investigation_count: number;
}

// ---- API functions ----
export const api = {
  health: () => request<HealthResponse>('/api/health'),
  overview: () => request<OverviewStats>('/api/overview'),

  listVulnerabilities: () => request<VulnerabilityBrief[]>('/api/vulnerabilities'),
  getVulnerability: (id: string) => request<VulnerabilityDetail>(`/api/vulnerabilities/${encodeURIComponent(id)}`),

  investigate: (vuln_id: string) =>
    request<InvestigationResult>('/api/investigate', {
      method: 'POST',
      body: JSON.stringify({ vuln_id }),
    }),

  listInvestigations: () => request<InvestigationBrief[]>('/api/investigations'),
  getInvestigation: (id: string) => request<InvestigationBrief>(`/api/investigations/${encodeURIComponent(id)}`),

  getVulnGraph: (id: string) => request<GraphData>(`/api/graph/vulnerability/${encodeURIComponent(id)}`),

  createRemediation: (data: RemediationRequest) =>
    request<RemediationResponse>('/api/remediations', {
      method: 'POST',
      body: JSON.stringify(data),
    }),
  listRemediations: () => request<RemediationBrief[]>('/api/remediations'),
  getRemediation: (id: string) => request<RemediationBrief>(`/api/remediations/${encodeURIComponent(id)}`),

  seed: (clearFirst = false) =>
    request<{ status: string; counts: Record<string, number> }>(
      `/api/seed?clear_first=${clearFirst}`,
      { method: 'POST' }
    ),
};

export { ApiError };

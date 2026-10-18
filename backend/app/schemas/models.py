"""
Pydantic request / response schemas for the PatchPilot API.
"""
from __future__ import annotations

from typing import Any, Optional
from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Shared
# ---------------------------------------------------------------------------

class ErrorResponse(BaseModel):
    error: str
    detail: Optional[str] = None


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

class HealthResponse(BaseModel):
    status: str                  # "ok" | "degraded"
    backend: str = "ok"
    falkordb: str                # "ok" | "unavailable"
    llm_mode: str


# ---------------------------------------------------------------------------
# Vulnerabilities
# ---------------------------------------------------------------------------

class VulnerabilityBrief(BaseModel):
    id: str
    title: str
    severity: str
    cvss_score: Optional[float]
    cve: Optional[str]
    published: Optional[str]
    description: Optional[str]
    finding_count: int = 0
    is_synthetic: bool = True
    synthetic_label: Optional[str] = None


class VulnerabilityDetail(VulnerabilityBrief):
    affected_packages: list[str] = []
    finding_ids: list[str] = []
    incomplete_evidence: bool = False


# ---------------------------------------------------------------------------
# Investigation
# ---------------------------------------------------------------------------

class InvestigateRequest(BaseModel):
    vuln_id: str = Field(..., min_length=1, max_length=100)


class PackageInfo(BaseModel):
    name: str
    version: str
    ecosystem: str
    is_direct_vulnerable: bool = False


class ApplicationInfo(BaseModel):
    id: str
    name: str
    environment: str
    language: str
    teams: list[str] = []
    asset_ids: list[str] = []
    asset_criticalities: list[str] = []
    asset_names: list[str] = []


class AssetInfo(BaseModel):
    id: str
    name: str
    criticality: str
    environment: str
    region: Optional[str] = None
    exposed: bool = False
    applications: list[str] = []
    teams: list[str] = []


class TeamInfo(BaseModel):
    id: str
    name: str
    email: Optional[str] = None
    applications: list[str] = []


class PathNode(BaseModel):
    label: str
    name: str
    version: Optional[str] = None


class EvidencePath(BaseModel):
    app_id: str
    app_name: str
    path_nodes: list[dict[str, Any]] = []
    hops: int


class PriorityInfo(BaseModel):
    score: float
    label: str
    severity_contribution: float
    asset_criticality_contribution: float
    reach_contribution: float
    exposure_contribution: float
    confidence_penalty: float
    top_asset_criticality: str
    affected_application_count: int
    affected_asset_count: int


class GraphNode(BaseModel):
    id: str
    label: str
    type: str
    data: dict[str, Any] = {}


class GraphEdge(BaseModel):
    source: str
    target: str
    label: str


class GraphData(BaseModel):
    nodes: list[GraphNode] = []
    edges: list[GraphEdge] = []


class InvestigationResult(BaseModel):
    investigation_id: str
    investigation_created_at: str
    vuln_id: str
    vulnerability: VulnerabilityDetail
    affected_packages: list[PackageInfo] = []
    affected_applications: list[ApplicationInfo] = []
    affected_assets: list[AssetInfo] = []
    responsible_teams: list[TeamInfo] = []
    evidence_paths: list[EvidencePath] = []
    graph_data: GraphData
    priority: PriorityInfo
    evidence_complete: bool
    missing_evidence: list[str] = []
    explanation: str
    recommended_action: str
    factors_detail: dict[str, Any] = {}
    llm_summary: Optional[str] = None
    llm_used: bool = False
    mode: str


class InvestigationBrief(BaseModel):
    id: str
    created_at: str
    status: str
    vuln_id: str
    vuln_title: str
    vuln_severity: str


# ---------------------------------------------------------------------------
# Remediation
# ---------------------------------------------------------------------------

class RemediationRequest(BaseModel):
    finding_id: str = Field(..., min_length=1)
    investigation_id: str = Field(..., min_length=1)
    action_type: str = Field(..., min_length=1, max_length=100)
    description: str = Field(..., min_length=1, max_length=2000)
    team_id: Optional[str] = None


class RemediationResponse(BaseModel):
    id: str
    finding_id: str
    investigation_id: str
    action_type: str
    description: str
    status: str
    created_at: str
    team_id: Optional[str] = None


class RemediationBrief(BaseModel):
    id: str
    action_type: str
    description: str
    status: str
    created_at: str
    finding_id: Optional[str]
    vuln_id: Optional[str]
    vuln_title: Optional[str]
    vuln_severity: Optional[str]
    team_name: Optional[str]


# ---------------------------------------------------------------------------
# Overview
# ---------------------------------------------------------------------------

class OverviewStats(BaseModel):
    vulnerability_count: int
    finding_count: int
    open_findings: int
    asset_count: int
    critical_assets: int
    remediation_count: int
    investigation_count: int

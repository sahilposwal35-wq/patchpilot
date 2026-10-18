# 🔌 PatchPilot REST API Reference

> Base URL: `http://localhost:8000`  
> Interactive OpenAPI / Swagger Documentation: `http://localhost:8000/docs`  
> ReDoc Specification: `http://localhost:8000/redoc`

All endpoints return JSON responses with standard HTTP status codes.

---

## 1. System & Health

### 1.1 Root Info
- **Endpoint**: `GET /`
- **Description**: Returns product identity, version, and documentation links.
- **Response** `200 OK`:
```json
{
  "product": "PatchPilot",
  "version": "1.0.0",
  "docs": "/docs",
  "health": "/api/health"
}
```

### 1.2 System Health
- **Endpoint**: `GET /api/health`
- **Description**: Checks backend and FalkorDB connectivity. If FalkorDB is offline, returns status `"degraded"`.
- **Response** `200 OK`:
```json
{
  "status": "ok",
  "backend": "ok",
  "falkordb": "ok",
  "llm_mode": "deterministic"
}
```
*When FalkorDB is unavailable:*
```json
{
  "status": "degraded",
  "backend": "ok",
  "falkordb": "unavailable",
  "llm_mode": "deterministic"
}
```

### 1.3 Seed Graph Dataset
- **Endpoint**: `POST /api/seed?clear_first=false`
- **Query Parameters**:
  - `clear_first` (boolean, optional, default `false`): When `true`, wipes existing graph nodes and edges before loading the dataset.
- **Description**: Loads the synthetic benchmark dataset into FalkorDB using idempotent `MERGE` statements.
- **Response** `200 OK`:
```json
{
  "status": "seeded",
  "counts": {
    "vulnerabilities": 5,
    "packages": 8,
    "applications": 4,
    "assets": 5,
    "teams": 3,
    "findings": 5
  }
}
```
- **cURL Example**:
```bash
curl -X POST "http://localhost:8000/api/seed?clear_first=true"
```

---

## 2. Overview

### 2.1 Get Overview Statistics
- **Endpoint**: `GET /api/overview`
- **Description**: Returns aggregated metrics across vulnerabilities, assets, investigations, and remediations.
- **Response** `200 OK`:
```json
{
  "vulnerability_count": 5,
  "finding_count": 5,
  "open_findings": 5,
  "asset_count": 5,
  "critical_assets": 2,
  "remediation_count": 3,
  "investigation_count": 4
}
```
- **cURL Example**:
```bash
curl -X GET "http://localhost:8000/api/overview"
```

---

## 3. Vulnerabilities

### 3.1 List All Vulnerabilities
- **Endpoint**: `GET /api/vulnerabilities`
- **Description**: Returns all vulnerabilities stored in FalkorDB with severity, CVSS, and synthetic benchmark indicators.
- **Response** `200 OK`:
```json
[
  {
    "id": "CVE-2021-44228",
    "title": "Log4Shell Remote Code Execution",
    "severity": "CRITICAL",
    "cvss_score": 10.0,
    "cve": "CVE-2021-44228",
    "published": "2021-12-10",
    "description": "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP.",
    "finding_count": 1,
    "is_synthetic": true,
    "synthetic_label": "[SYNTHETIC BENCHMARK] Ground truth fixture"
  }
]
```
- **cURL Example**:
```bash
curl -X GET "http://localhost:8000/api/vulnerabilities"
```

### 3.2 Get Vulnerability Detail
- **Endpoint**: `GET /api/vulnerabilities/{vuln_id}`
- **Parameters**: `vuln_id` (string, path parameter, e.g. `CVE-2021-44228`)
- **Response** `200 OK`:
```json
{
  "id": "CVE-2021-44228",
  "title": "Log4Shell Remote Code Execution",
  "severity": "CRITICAL",
  "cvss_score": 10.0,
  "cve": "CVE-2021-44228",
  "published": "2021-12-10",
  "description": "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP.",
  "finding_count": 1,
  "affected_packages": ["log4j-core:2.14.1"],
  "finding_ids": ["FIND-001"],
  "incomplete_evidence": false,
  "is_synthetic": true,
  "synthetic_label": "[SYNTHETIC BENCHMARK] Ground truth fixture"
}
```
- **Error Response** `404 Not Found`:
```json
{
  "detail": "Vulnerability 'CVE-UNKNOWN' not found."
}
```

---

## 4. Investigations (Triage Agent)

### 4.1 Run Investigation
- **Endpoint**: `POST /api/investigate`
- **Description**: Triggers the autonomous investigation agent on the given vulnerability. Executes multi-hop FalkorDB traversals, computes the deterministic priority score, generates explainable reasoning, and persists the investigation record.
- **Request Body**:
```json
{
  "vuln_id": "CVE-2021-44228"
}
```
- **Response** `200 OK`:
```json
{
  "investigation_id": "INV-CVE-2021-44228-1718000000",
  "vuln_id": "CVE-2021-44228",
  "vuln_title": "Log4Shell Remote Code Execution",
  "vuln_severity": "CRITICAL",
  "cvss_score": 10.0,
  "priority_score": 88.0,
  "priority_label": "CRITICAL",
  "status": "COMPLETED",
  "affected_packages": [
    {
      "name": "log4j-core",
      "version": "2.14.1",
      "ecosystem": "maven",
      "is_direct_vulnerable": true
    },
    {
      "name": "spring-boot-starter-log4j2",
      "version": "2.5.0",
      "ecosystem": "maven",
      "is_direct_vulnerable": false
    }
  ],
  "affected_applications": [
    {
      "name": "payment-service",
      "language": "java",
      "tier": "tier-1",
      "repo_url": "https://github.com/org/payment-service"
    }
  ],
  "affected_assets": [
    {
      "name": "prod-k8s-payment-cluster",
      "type": "k8s-cluster",
      "environment": "production",
      "exposure": "public",
      "criticality": "CRITICAL"
    }
  ],
  "responsible_teams": [
    {
      "name": "Payments Core Team",
      "email": "payments-team@company.internal",
      "slack_channel": "#team-payments",
      "on_call": "alice@company.internal"
    }
  ],
  "timeline": [
    {
      "step": 1,
      "title": "Vulnerability Ingestion",
      "detail": "Extracted CVSS 10.0 for CVE-2021-44228",
      "timestamp": "2026-10-18T12:00:00Z"
    },
    {
      "step": 2,
      "title": "Transitive Dependency Traversal",
      "detail": "Identified 2 affected packages via FalkorDB graph path.",
      "timestamp": "2026-10-18T12:00:01Z"
    }
  ],
  "reasoning": "Vulnerability CVE-2021-44228 affects log4j-core. It propagates transitively to payment-service deployed on public production cluster prod-k8s-payment-cluster. Immediate patch recommended.",
  "recommended_action": "Immediate patch or mitigation required. Escalate to responsible team within 24 hours.",
  "factors_detail": {
    "severity_score": 40.0,
    "criticality_score": 30.0,
    "reach_score": 8.0,
    "exposure_score": 10.0,
    "confidence_penalty": 0.0
  }
}
```
- **cURL Example**:
```bash
curl -X POST "http://localhost:8000/api/investigate" \
     -H "Content-Type: application/json" \
     -d '{"vuln_id": "CVE-2021-44228"}'
```

### 4.2 List Investigations
- **Endpoint**: `GET /api/investigations`
- **Description**: Returns all historical triage investigations stored in FalkorDB.
- **Response** `200 OK`:
```json
[
  {
    "id": "INV-CVE-2021-44228-1718000000",
    "vuln_id": "CVE-2021-44228",
    "vuln_title": "Log4Shell Remote Code Execution",
    "vuln_severity": "CRITICAL",
    "priority_score": 88.0,
    "priority_label": "CRITICAL",
    "status": "COMPLETED",
    "completed_at": "2026-10-18T12:00:05Z",
    "affected_app_count": 1,
    "affected_asset_count": 1
  }
]
```

### 4.3 Get Investigation Details
- **Endpoint**: `GET /api/investigations/{inv_id}`
- **Response** `200 OK`: Full investigation details (equivalent to `InvestigationResult`).
- **Error Response** `404 Not Found`:
```json
{
  "detail": "Investigation 'INV-NONEXISTENT' not found."
}
```

---

## 5. Graph Visualization

### 5.1 Get Vulnerability Subgraph
- **Endpoint**: `GET /api/graph/vulnerability/{vuln_id}`
- **Description**: Returns the nodes and edges for rendering an interactive dependency and infrastructure graph in `@xyflow/react`.
- **Response** `200 OK`:
```json
{
  "nodes": [
    {
      "id": "vuln-CVE-2021-44228",
      "label": "CVE-2021-44228",
      "type": "vulnerability",
      "data": {
        "title": "Log4Shell Remote Code Execution",
        "severity": "CRITICAL",
        "cvss": 10.0
      }
    },
    {
      "id": "pkg-log4j-core",
      "label": "log4j-core (2.14.1)",
      "type": "package",
      "data": { "ecosystem": "maven" }
    },
    {
      "id": "app-payment-service",
      "label": "payment-service",
      "type": "application",
      "data": { "tier": "tier-1" }
    },
    {
      "id": "asset-prod-k8s",
      "label": "prod-k8s-payment-cluster",
      "type": "asset",
      "data": { "criticality": "CRITICAL", "exposure": "public" }
    },
    {
      "id": "team-payments",
      "label": "Payments Core Team",
      "type": "team",
      "data": { "email": "payments-team@company.internal" }
    }
  ],
  "edges": [
    { "id": "e1", "source": "vuln-CVE-2021-44228", "target": "pkg-log4j-core", "label": "AFFECTS" },
    { "id": "e2", "source": "app-payment-service", "target": "pkg-log4j-core", "label": "USES" },
    { "id": "e3", "source": "app-payment-service", "target": "asset-prod-k8s", "label": "DEPLOYS_TO" },
    { "id": "e4", "source": "team-payments", "target": "app-payment-service", "label": "OWNS" }
  ]
}
```
- **cURL Example**:
```bash
curl -X GET "http://localhost:8000/api/graph/vulnerability/CVE-2021-44228"
```

---

## 6. Remediations

### 6.1 Create Simulated Remediation
- **Endpoint**: `POST /api/remediations`
- **Status Code**: `201 Created`
- **Description**: Proposes or approves a simulated remediation action in the graph.
- **Request Body**:
```json
{
  "finding_id": "FIND-001",
  "investigation_id": "INV-CVE-2021-44228-1718000000",
  "action_type": "UPGRADE_PACKAGE",
  "description": "Upgrade log4j-core from 2.14.1 to 2.17.1 across payment-service.",
  "team_id": "team-payments"
}
```
- **Response** `201 Created`:
```json
{
  "id": "REM-1718000100",
  "finding_id": "FIND-001",
  "investigation_id": "INV-CVE-2021-44228-1718000000",
  "action_type": "UPGRADE_PACKAGE",
  "description": "Upgrade log4j-core from 2.14.1 to 2.17.1 across payment-service.",
  "status": "APPROVED",
  "team_id": "team-payments",
  "created_at": "2026-10-18T12:05:00Z"
}
```

### 6.2 List Remediations
- **Endpoint**: `GET /api/remediations`
- **Response** `200 OK`: Returns array of `RemediationBrief` objects.

### 6.3 Get Remediation Details
- **Endpoint**: `GET /api/remediations/{rem_id}`
- **Response** `200 OK`: Details of a specific remediation item.

---

## 7. Error Handling & Status Codes

| HTTP Status | Meaning | Typical Trigger |
| :--- | :--- | :--- |
| `200 OK` | Request succeeded | Standard GET or POST response. |
| `201 Created` | Resource created | Successful `POST /api/remediations`. |
| `400 Bad Request` | Invalid payload | Malformed JSON or invalid parameter types. |
| `404 Not Found` | Entity not found | Unknown vulnerability, investigation, or remediation ID. |
| `500 Server Error` | Backend exception | Unhandled graph query error or database connection timeout. |

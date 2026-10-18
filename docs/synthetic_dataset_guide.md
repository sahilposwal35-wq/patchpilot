# PatchPilot Synthetic Dataset & Benchmark Guide

> **DISCLAIMER:** All findings, CVE codes, package versions, software services, and infrastructure records in this dataset are **100% synthetic**. They were engineered specifically for hackathon demonstrations to test how AI agents reason over connected graph topologies. They do not represent real-world vulnerabilities.

---

## 1. Why a Graph-First Synthetic Dataset?

Track 01 (*Agents That Act on Connected Data*) requires AI agents to solve problems by traversing real graph relationships rather than relying on static isolated tables.

In vulnerability management, flat CVSS scores fail because:
1. They ignore **transitive blast radius** (how many microservices inherit the vulnerability 2, 3, or 4 hops away).
2. They ignore **runtime deployment context** (whether the application is running in an internet-exposed production Kubernetes cluster or an isolated internal staging VM).
3. They ignore **ownership** (which team owns the code repository and should be assigned the remediation).

This synthetic dataset models this exact connected topology in **FalkorDB**:

$$\text{Vulnerability} \longrightarrow \text{Package} \stackrel{\text{transitive}}{\longleftarrow} \text{Application} \longrightarrow \text{Asset} \longrightarrow \text{Team}$$

---

## 2. Dataset Entities & Ground Truth Scenarios

The dataset is version-controlled in [`data/synthetic_data/graph_dataset.json`](../data/synthetic_data/graph_dataset.json). It provides 4 specific test cases with verified mathematical ground-truth answers:

### Test Case 1: Direct Package Reachability
* **Entity**: `VULN-2024-001` (Heap buffer overflow in `xml-parser@2.4.1`, CRITICAL 9.8).
* **Direct Consumers**:
  * `auth-middleware@1.3.0` directly imports `xml-parser`.
  * `http-client@5.0.0` directly imports `xml-parser`.
* **Applications**:
  * `Payment Gateway` (uses `auth-middleware@1.3.0`).
  * `User Portal` (uses `http-client@5.0.0`).
* **Expected Result**: 1 package hop from vulnerable library to consumer application.

### Test Case 2: Deep Transitive Multi-Hop Dependency
* **Entity**: `VULN-2024-001` affecting `xml-parser@2.4.1`.
* **Traversed Chain** (3 hops):
  ```
  xml-parser@2.4.1 (vulnerable)
     ^
     | [:DEPENDS_ON]
  http-client@5.0.0 (hop 1)
     ^
     | [:DEPENDS_ON]
  data-processor@2.1.0 (hop 2)
     ^
     | [:DEPENDS_ON]
  report-engine@4.0.0 (hop 3)
     ^
     | [:USES]
  Report Generator (Application)
  ```
* **Expected Result**: `Report Generator` is discovered as vulnerable despite having no direct dependency on `xml-parser`. The Cypher path returned has length 4 edges.

### Test Case 3: Multi-Asset Impact & Public Internet Exposure
* **Entity**: `VULN-2024-001`.
* **Discovered Workloads & Deployments**:
  * `Payment Gateway` $\to$ deployed to `asset-prod-k8s` (CRITICAL, internet-facing) and `asset-payments-db` (CRITICAL, internal).
  * `User Portal` $\to$ deployed to `asset-prod-k8s`.
  * `Report Generator` $\to$ deployed to `asset-batch-server` (MEDIUM, internal).
* **Deterministic Priority Score Breakdown**:
  * Severity Weight: `40.0` (CRITICAL)
  * Highest Asset Criticality: `30.0` (`asset-prod-k8s` is CRITICAL)
  * Public Exposure Bonus: `10.0` (`exposed: true` on `asset-prod-k8s`)
  * Reach Score: `9.2` (3 applications affected: $\min(20, 20 \times \frac{\ln(3+1)}{\ln(11)})$)
  * Confidence Penalty: `0.0` (all evidence complete)
  * **Total Score: 89.2 / 100 $\implies$ Priority: CRITICAL**

### Test Case 4: Insufficient Evidence & Missing Ownership Handling
* **Entity**: `VULN-2024-004` (Path traversal in `file-utils@3.1.2`, HIGH 7.5).
* **Missing Facts In Graph**:
  * Vulnerability has property `incomplete_evidence: true`.
  * Affected application `Report Generator` has `team_id: null` (unassigned code owner).
* **Deterministic Agent Behavior**:
  * Applies **-15.0 confidence penalty**.
  * Emits missing evidence flags in structured output:
    * *"Vulnerability evidence is marked as incomplete by the detection source."*
    * *"One or more affected applications have no assigned responsible team."*
  * Flags priority as **UNCERTAIN** or degraded score.
  * Triage Agent outputs: *"Gather missing evidence before determining priority. Do not assume low risk."*

---

## 3. Cypher Traversal Queries

The backend executes these parameterized Cypher queries against FalkorDB to prove each path:

### Query 1: Reverse Dependency Expansion
```cypher
MATCH (v:Vulnerability {id: $vid})-[:AFFECTS]->(vp:Package)
OPTIONAL MATCH path = (dependent:Package)-[:DEPENDS_ON*1..4]->(vp)
RETURN vp.name AS vuln_pkg,
       vp.version AS vuln_ver,
       dependent.name AS dep_pkg,
       dependent.version AS dep_ver,
       length(path) AS depth
```

### Query 2: Asset Exposure & Criticality Resolution
```cypher
MATCH (v:Vulnerability {id: $vid})-[:AFFECTS]->(vp:Package)
MATCH (appPkg:Package)-[:DEPENDS_ON*0..4]->(vp)
MATCH (a:Application)-[:USES]->(appPkg)
MATCH (a)-[:DEPLOYED_AS]->(s:Asset)
RETURN DISTINCT s.id, s.name, s.criticality, s.environment, s.exposed
ORDER BY CASE s.criticality
  WHEN 'CRITICAL' THEN 1
  WHEN 'HIGH' THEN 2
  WHEN 'MEDIUM' THEN 3
  ELSE 4 END ASC
```

### Query 3: Evidence Path Trace (UI Visualizer)
```cypher
MATCH (v:Vulnerability {id: $vid})-[:AFFECTS]->(vp:Package)
MATCH (appPkg:Package)-[:DEPENDS_ON*0..4]->(vp)
MATCH (a:Application)-[:USES]->(appPkg)
MATCH path = (a)-[:USES]->(appPkg)-[:DEPENDS_ON*0..4]->(vp)
RETURN a.id, a.name, [n IN nodes(path) | {label: labels(n)[0], name: coalesce(n.name, n.id), version: n.version}] AS steps,
       length(path) AS hops
```

---

## 4. How to Reset and Reseed

The graph seeding is **100% idempotent** through Cypher `MERGE`.

### Quick Reseed Commands

```bash
# 1. Reset and clean reseed via CLI
cd patchpilot/backend
./venv/bin/python ../scripts/seed_graph.py --clear

# 2. Reseed via API
curl -X POST "http://localhost:8000/api/seed?clear_first=true"

# 3. Verify node counts
python3 -c "
from app.db.connection import get_graph
g = get_graph()
for label in ['Vulnerability', 'Package', 'Application', 'Asset', 'Team', 'Finding']:
    res = g.query(f'MATCH (n:{label}) RETURN count(n)').result_set[0][0]
    print(f'{label}: {res}')
"
```

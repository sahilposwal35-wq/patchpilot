"""
Graph query operations — all FalkorDB Cypher queries live here.

Edge direction convention:
  (:Package)-[:DEPENDS_ON]->(:Package)   A depends on B means A→B
  Impact traversal goes *against* DEPENDS_ON direction:
  start from vulnerable package, find packages that DEPEND ON it.
"""
from __future__ import annotations

import json
import logging
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.db.connection import get_graph

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _row_to_dict(row: list[Any], keys: list[str]) -> dict[str, Any]:
    return {k: v for k, v in zip(keys, row)}


def _node_props(node: Any) -> dict[str, Any]:
    """Extract properties from a FalkorDB Node object."""
    if node is None:
        return {}
    try:
        props = dict(node.properties) if hasattr(node, "properties") else {}
        if hasattr(node, "labels"):
            props["_labels"] = list(node.labels)
        return props
    except Exception:
        return {}


# ---------------------------------------------------------------------------
# Schema / Constraints
# ---------------------------------------------------------------------------

def ensure_indexes() -> None:
    """Create indexes if they don't exist (idempotent)."""
    g = get_graph()
    index_commands = [
        "CREATE INDEX FOR (v:Vulnerability) ON (v.id)",
        "CREATE INDEX FOR (p:Package) ON (p.name, p.version)",
        "CREATE INDEX FOR (a:Application) ON (a.id)",
        "CREATE INDEX FOR (s:Asset) ON (s.id)",
        "CREATE INDEX FOR (t:Team) ON (t.id)",
        "CREATE INDEX FOR (f:Finding) ON (f.id)",
        "CREATE INDEX FOR (i:Investigation) ON (i.id)",
        "CREATE INDEX FOR (r:Remediation) ON (r.id)",
    ]
    for cmd in index_commands:
        try:
            g.query(cmd)
        except Exception:
            pass  # Index may already exist


# ---------------------------------------------------------------------------
# Seed / Load synthetic data
# ---------------------------------------------------------------------------

SYNTHETIC_DATA = {
    "vulnerabilities": [
        {
            "id": "VULN-2024-001",
            "title": "Remote Code Execution in xml-parser",
            "description": "A heap buffer overflow in xml-parser ≤2.4.1 allows an attacker to execute arbitrary code via a crafted XML document.",
            "severity": "CRITICAL",
            "cvss_score": 9.8,
            "cve": "CVE-2024-12345",
            "published": "2024-03-15",
        },
        {
            "id": "VULN-2024-002",
            "title": "SQL Injection in query-builder",
            "description": "Improper input sanitization in query-builder ≤1.2.0 allows SQL injection via user-supplied filter parameters.",
            "severity": "HIGH",
            "cvss_score": 8.1,
            "cve": "CVE-2024-67890",
            "published": "2024-04-02",
        },
        {
            "id": "VULN-2024-003",
            "title": "Denial of Service in log-rotator",
            "description": "An uncontrolled resource consumption bug in log-rotator ≤0.9.5 allows an attacker to exhaust disk space.",
            "severity": "MEDIUM",
            "cvss_score": 5.3,
            "cve": "CVE-2024-11111",
            "published": "2024-05-10",
        },
        {
            "id": "VULN-2024-004",
            "title": "Path Traversal in file-utils",
            "description": "Insufficient path validation in file-utils ≤3.1.2 allows directory traversal attacks.",
            "severity": "HIGH",
            "cvss_score": 7.5,
            "cve": "CVE-2024-22222",
            "published": "2024-06-01",
            "incomplete_evidence": True,  # Demo: uncertain scenario
        },
    ],
    "packages": [
        # Vulnerable packages
        {"name": "xml-parser", "version": "2.4.1", "ecosystem": "npm"},
        {"name": "query-builder", "version": "1.2.0", "ecosystem": "pip"},
        {"name": "log-rotator", "version": "0.9.5", "ecosystem": "npm"},
        {"name": "file-utils", "version": "3.1.2", "ecosystem": "npm"},
        # Dependency chain packages
        {"name": "http-client", "version": "5.0.0", "ecosystem": "npm"},
        {"name": "data-processor", "version": "2.1.0", "ecosystem": "npm"},
        {"name": "auth-middleware", "version": "1.3.0", "ecosystem": "npm"},
        {"name": "report-engine", "version": "4.0.0", "ecosystem": "npm"},
        {"name": "orm-core", "version": "3.2.0", "ecosystem": "pip"},
        {"name": "cache-layer", "version": "1.1.0", "ecosystem": "npm"},
    ],
    "dependency_edges": [
        # http-client depends on xml-parser (direct)
        ("http-client", "5.0.0", "xml-parser", "2.4.1"),
        # data-processor depends on http-client (transitive chain)
        ("data-processor", "2.1.0", "http-client", "5.0.0"),
        # report-engine depends on data-processor (3-hop chain)
        ("report-engine", "4.0.0", "data-processor", "2.1.0"),
        # auth-middleware also depends on xml-parser directly
        ("auth-middleware", "1.3.0", "xml-parser", "2.4.1"),
        # orm-core depends on query-builder
        ("orm-core", "3.2.0", "query-builder", "1.2.0"),
        # cache-layer depends on log-rotator
        ("cache-layer", "1.1.0", "log-rotator", "0.9.5"),
        # report-engine also uses file-utils directly
        ("report-engine", "4.0.0", "file-utils", "3.1.2"),
    ],
    "teams": [
        {"id": "team-platform", "name": "Platform Engineering", "email": "platform@example.com"},
        {"id": "team-payments", "name": "Payments Team", "email": "payments@example.com"},
        {"id": "team-analytics", "name": "Analytics Team", "email": "analytics@example.com"},
        {"id": "team-infra", "name": "Infrastructure Team", "email": "infra@example.com"},
        # Deliberately no team for one app to test missing-ownership scenario
    ],
    "applications": [
        {
            "id": "app-payment-gateway",
            "name": "Payment Gateway",
            "environment": "production",
            "language": "JavaScript",
            "team_id": "team-payments",
        },
        {
            "id": "app-user-portal",
            "name": "User Portal",
            "environment": "production",
            "language": "JavaScript",
            "team_id": "team-platform",
        },
        {
            "id": "app-analytics-service",
            "name": "Analytics Service",
            "environment": "production",
            "language": "Python",
            "team_id": "team-analytics",
        },
        {
            "id": "app-internal-tools",
            "name": "Internal Tools",
            "environment": "staging",
            "language": "JavaScript",
            "team_id": "team-infra",
        },
        {
            "id": "app-report-generator",
            "name": "Report Generator",
            "environment": "production",
            "language": "JavaScript",
            "team_id": None,  # No owner — tests missing-ownership path
        },
    ],
    "app_package_edges": [
        # Payment Gateway uses auth-middleware (which depends on xml-parser)
        ("app-payment-gateway", "auth-middleware", "1.3.0"),
        # User Portal uses http-client (which depends on xml-parser)
        ("app-user-portal", "http-client", "5.0.0"),
        # Analytics Service uses orm-core (which depends on query-builder)
        ("app-analytics-service", "orm-core", "3.2.0"),
        # Internal Tools uses cache-layer (which depends on log-rotator)
        ("app-internal-tools", "cache-layer", "1.1.0"),
        # Report Generator uses report-engine (which depends on xml-parser via 3-hop chain)
        ("app-report-generator", "report-engine", "4.0.0"),
        # User Portal also uses data-processor directly
        ("app-user-portal", "data-processor", "2.1.0"),
    ],
    "assets": [
        {
            "id": "asset-prod-k8s",
            "name": "Production Kubernetes Cluster",
            "criticality": "CRITICAL",
            "environment": "production",
            "region": "us-east-1",
            "exposed": True,
        },
        {
            "id": "asset-payments-db",
            "name": "Payments Database",
            "criticality": "CRITICAL",
            "environment": "production",
            "region": "us-east-1",
            "exposed": False,
        },
        {
            "id": "asset-analytics-cluster",
            "name": "Analytics Processing Cluster",
            "criticality": "HIGH",
            "environment": "production",
            "region": "us-west-2",
            "exposed": False,
        },
        {
            "id": "asset-staging-env",
            "name": "Staging Environment",
            "criticality": "LOW",
            "environment": "staging",
            "region": "us-east-1",
            "exposed": False,
        },
        {
            "id": "asset-batch-server",
            "name": "Batch Report Server",
            "criticality": "MEDIUM",
            "environment": "production",
            "region": "eu-west-1",
            "exposed": False,
        },
    ],
    "app_asset_edges": [
        ("app-payment-gateway", "asset-prod-k8s"),
        ("app-payment-gateway", "asset-payments-db"),
        ("app-user-portal", "asset-prod-k8s"),
        ("app-analytics-service", "asset-analytics-cluster"),
        ("app-internal-tools", "asset-staging-env"),
        ("app-report-generator", "asset-batch-server"),
    ],
    "findings": [
        {
            "id": "finding-001",
            "vuln_id": "VULN-2024-001",
            "status": "open",
            "source": "SAST",
            "detected_at": "2024-03-16",
            "severity_override": None,
        },
        {
            "id": "finding-002",
            "vuln_id": "VULN-2024-002",
            "status": "open",
            "source": "Dependency Scanner",
            "detected_at": "2024-04-03",
            "severity_override": None,
        },
        {
            "id": "finding-003",
            "vuln_id": "VULN-2024-003",
            "status": "open",
            "source": "DAST",
            "detected_at": "2024-05-11",
            "severity_override": None,
        },
        {
            "id": "finding-004",
            "vuln_id": "VULN-2024-004",
            "status": "open",
            "source": "Manual Review",
            "detected_at": "2024-06-05",
            "severity_override": None,
            "incomplete_evidence": True,
        },
    ],
}

# Map vuln_id → affected package
VULN_PACKAGE_MAP = {
    "VULN-2024-001": ("xml-parser", "2.4.1"),
    "VULN-2024-002": ("query-builder", "1.2.0"),
    "VULN-2024-003": ("log-rotator", "0.9.5"),
    "VULN-2024-004": ("file-utils", "3.1.2"),
}


def load_seed_dataset(file_path: str | Path | None = None) -> dict[str, Any]:
    """
    Load synthetic benchmark dataset from a JSON file.
    Falls back gracefully to the embedded SYNTHETIC_DATA dictionary.
    """
    candidates: list[Path] = []
    if file_path:
        candidates.append(Path(file_path))

    env_path = os.environ.get("PATCHPILOT_SEED_FILE")
    if env_path:
        candidates.append(Path(env_path))

    # Standard locations relative to project repository
    repo_root = Path(__file__).resolve().parents[3]
    candidates.append(repo_root / "data" / "synthetic_data" / "graph_dataset.json")
    candidates.append(Path(__file__).resolve().parents[2] / "data" / "synthetic_data" / "graph_dataset.json")
    candidates.append(Path("/app/data/synthetic_data/graph_dataset.json"))
    candidates.append(Path.cwd() / "data" / "synthetic_data" / "graph_dataset.json")
    candidates.append(Path.cwd().parent / "data" / "synthetic_data" / "graph_dataset.json")

    for p in candidates:
        if p.is_file():
            try:
                with open(p, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    logger.info("Loaded seed dataset from file: %s", p)
                    return data
            except Exception as exc:
                logger.warning("Could not parse seed file %s: %s", p, exc)

    logger.info("Using embedded SYNTHETIC_DATA dataset")
    return SYNTHETIC_DATA


def seed_graph(clear_first: bool = False, dataset_path: str | Path | None = None) -> dict[str, int]:
    """
    Load synthetic data into FalkorDB. Idempotent via MERGE.
    Returns counts of nodes created.
    """
    g = get_graph()

    if clear_first:
        g.query("MATCH (n) DETACH DELETE n")
        logger.info("Graph cleared before seed.")

    dataset = load_seed_dataset(dataset_path)
    vulns = dataset.get("vulnerabilities", SYNTHETIC_DATA["vulnerabilities"])
    packages = dataset.get("packages", SYNTHETIC_DATA["packages"])
    dep_edges = dataset.get("dependency_edges", SYNTHETIC_DATA["dependency_edges"])
    vuln_pkg_map = dataset.get("vuln_package_map", VULN_PACKAGE_MAP)
    teams = dataset.get("teams", SYNTHETIC_DATA["teams"])
    apps = dataset.get("applications", SYNTHETIC_DATA["applications"])
    app_pkg_edges = dataset.get("app_package_edges", SYNTHETIC_DATA["app_package_edges"])
    assets = dataset.get("assets", SYNTHETIC_DATA["assets"])
    app_asset_edges = dataset.get("app_asset_edges", SYNTHETIC_DATA["app_asset_edges"])
    findings = dataset.get("findings", SYNTHETIC_DATA["findings"])

    counts: dict[str, int] = {}

    # Vulnerabilities
    for v in vulns:
        g.query(
            """
            MERGE (v:Vulnerability {id: $id})
            SET v.title = $title,
                v.description = $description,
                v.severity = $severity,
                v.cvss_score = $cvss_score,
                v.cve = $cve,
                v.published = $published,
                v.incomplete_evidence = $inc,
                v.is_synthetic = true,
                v.synthetic_label = $syn_label
            """,
            {
                "id": v["id"],
                "title": v["title"],
                "description": v["description"],
                "severity": v["severity"],
                "cvss_score": float(v["cvss_score"]),
                "cve": v["cve"],
                "published": v["published"],
                "inc": v.get("incomplete_evidence", False),
                "syn_label": v.get("synthetic_label", "SYNTHETIC TEST BENCHMARK"),
            },
        )
    counts["vulnerabilities"] = len(vulns)

    # Packages
    for p in packages:
        g.query(
            """
            MERGE (p:Package {name: $name, version: $version})
            SET p.ecosystem = $ecosystem,
                p.is_synthetic = true
            """,
            {"name": p["name"], "version": p["version"], "ecosystem": p["ecosystem"]},
        )
    counts["packages"] = len(packages)

    # DEPENDS_ON edges: A-[:DEPENDS_ON]->B means A depends on B
    for (a_name, a_ver, b_name, b_ver) in dep_edges:
        g.query(
            """
            MATCH (a:Package {name: $a_name, version: $a_ver})
            MATCH (b:Package {name: $b_name, version: $b_ver})
            MERGE (a)-[:DEPENDS_ON]->(b)
            """,
            {"a_name": a_name, "a_ver": a_ver, "b_name": b_name, "b_ver": b_ver},
        )

    # Vulnerability AFFECTS Package
    for vuln_id, pkg_info in vuln_pkg_map.items():
        pkg_name, pkg_ver = pkg_info[0], pkg_info[1]
        g.query(
            """
            MATCH (v:Vulnerability {id: $vid})
            MATCH (p:Package {name: $pname, version: $pver})
            MERGE (v)-[:AFFECTS]->(p)
            """,
            {"vid": vuln_id, "pname": pkg_name, "pver": pkg_ver},
        )

    # Teams
    for t in teams:
        g.query(
            """
            MERGE (t:Team {id: $id})
            SET t.name = $name, t.email = $email,
                t.is_synthetic = true
            """,
            {"id": t["id"], "name": t["name"], "email": t["email"]},
        )
    counts["teams"] = len(teams)

    # Applications
    for a in apps:
        g.query(
            """
            MERGE (a:Application {id: $id})
            SET a.name = $name, a.environment = $env, a.language = $lang,
                a.is_synthetic = true
            """,
            {
                "id": a["id"],
                "name": a["name"],
                "env": a["environment"],
                "lang": a["language"],
            },
        )
    counts["applications"] = len(apps)

    # App OWNED_BY Team
    for a in apps:
        if a.get("team_id"):
            g.query(
                """
                MATCH (a:Application {id: $aid})
                MATCH (t:Team {id: $tid})
                MERGE (a)-[:OWNED_BY]->(t)
                """,
                {"aid": a["id"], "tid": a["team_id"]},
            )

    # App USES Package
    for (app_id, pkg_name, pkg_ver) in app_pkg_edges:
        g.query(
            """
            MATCH (a:Application {id: $aid})
            MATCH (p:Package {name: $pname, version: $pver})
            MERGE (a)-[:USES]->(p)
            """,
            {"aid": app_id, "pname": pkg_name, "pver": pkg_ver},
        )

    # Assets
    for s in assets:
        g.query(
            """
            MERGE (s:Asset {id: $id})
            SET s.name = $name, s.criticality = $crit,
                s.environment = $env, s.region = $region,
                s.exposed = $exposed,
                s.is_synthetic = true
            """,
            {
                "id": s["id"],
                "name": s["name"],
                "crit": s["criticality"],
                "env": s["environment"],
                "region": s["region"],
                "exposed": s["exposed"],
            },
        )
    counts["assets"] = len(assets)

    # App DEPLOYED_AS Asset
    for (app_id, asset_id) in app_asset_edges:
        g.query(
            """
            MATCH (a:Application {id: $aid})
            MATCH (s:Asset {id: $sid})
            MERGE (a)-[:DEPLOYED_AS]->(s)
            """,
            {"aid": app_id, "sid": asset_id},
        )

    # Findings
    for f in findings:
        g.query(
            """
            MERGE (f:Finding {id: $id})
            SET f.status = $status, f.source = $source,
                f.detected_at = $det, f.incomplete_evidence = $inc,
                f.is_synthetic = true
            """,
            {
                "id": f["id"],
                "status": f["status"],
                "source": f["source"],
                "det": f["detected_at"],
                "inc": f.get("incomplete_evidence", False),
            },
        )
        # Finding IDENTIFIES Vulnerability
        g.query(
            """
            MATCH (f:Finding {id: $fid})
            MATCH (v:Vulnerability {id: $vid})
            MERGE (f)-[:IDENTIFIES]->(v)
            """,
            {"fid": f["id"], "vid": f["vuln_id"]},
        )
    counts["findings"] = len(findings)

    logger.info("Seed complete: %s", counts)
    ensure_indexes()
    return counts


# ---------------------------------------------------------------------------
# Query: Get all vulnerabilities (for list view)
# ---------------------------------------------------------------------------

def get_all_vulnerabilities() -> list[dict]:
    g = get_graph()
    result = g.query(
        """
        MATCH (v:Vulnerability)
        OPTIONAL MATCH (f:Finding)-[:IDENTIFIES]->(v)
        RETURN v.id, v.title, v.severity, v.cvss_score, v.cve,
               v.published, v.description, count(f) AS finding_count,
               coalesce(v.is_synthetic, true) AS is_synthetic,
               v.synthetic_label
        ORDER BY v.cvss_score DESC
        """
    )
    rows = []
    for row in result.result_set:
        rows.append({
            "id": row[0],
            "title": row[1],
            "severity": row[2],
            "cvss_score": row[3],
            "cve": row[4],
            "published": row[5],
            "description": row[6],
            "finding_count": row[7],
            "is_synthetic": bool(row[8]) if len(row) > 8 else True,
            "synthetic_label": row[9] if len(row) > 9 else None,
        })
    return rows


def get_vulnerability_by_id(vuln_id: str) -> dict | None:
    g = get_graph()
    result = g.query(
        """
        MATCH (v:Vulnerability {id: $id})
        OPTIONAL MATCH (v)-[:AFFECTS]->(p:Package)
        OPTIONAL MATCH (f:Finding)-[:IDENTIFIES]->(v)
        RETURN v.id, v.title, v.severity, v.cvss_score, v.cve,
               v.published, v.description, v.incomplete_evidence,
               collect(DISTINCT p.name + '@' + p.version) AS packages,
               collect(DISTINCT f.id) AS findings,
               coalesce(v.is_synthetic, true) AS is_synthetic,
               v.synthetic_label
        """,
        {"id": vuln_id},
    )
    if not result.result_set:
        return None
    row = result.result_set[0]
    return {
        "id": row[0],
        "title": row[1],
        "severity": row[2],
        "cvss_score": row[3],
        "cve": row[4],
        "published": row[5],
        "description": row[6],
        "incomplete_evidence": row[7],
        "affected_packages": row[8],
        "finding_ids": row[9],
        "is_synthetic": bool(row[10]) if len(row) > 10 else True,
        "synthetic_label": row[11] if len(row) > 11 else None,
    }


# ---------------------------------------------------------------------------
# Query: Trace affected packages (direct + transitive, depth-bounded)
# ---------------------------------------------------------------------------

def trace_affected_packages(vuln_id: str, max_depth: int = 4) -> list[dict]:
    """
    Find all packages that directly or transitively depend on the
    vulnerable package.

    Direction: vulnerable_pkg <-[:DEPENDS_ON*1..max_depth]- dependent_pkg
    """
    g = get_graph()
    result = g.query(
        f"""
        MATCH (v:Vulnerability {{id: $vuln_id}})-[:AFFECTS]->(vp:Package)
        OPTIONAL MATCH (dp:Package)-[:DEPENDS_ON*1..{max_depth}]->(vp)
        WITH vp, collect(DISTINCT dp) AS dependents
        UNWIND ([vp] + dependents) AS pkg
        RETURN DISTINCT pkg.name, pkg.version, pkg.ecosystem,
               CASE WHEN pkg.name = vp.name AND pkg.version = vp.version
                    THEN 0 ELSE 1 END AS is_transitive
        """,
        {"vuln_id": vuln_id},
    )
    pkgs = []
    for row in result.result_set:
        pkgs.append({
            "name": row[0],
            "version": row[1],
            "ecosystem": row[2],
            "is_direct_vulnerable": row[3] == 0,
        })
    return pkgs


# ---------------------------------------------------------------------------
# Query: Trace affected applications
# ---------------------------------------------------------------------------

def trace_affected_applications(vuln_id: str, max_depth: int = 4) -> list[dict]:
    """
    Return all applications that use a package affected by the vulnerability,
    directly or transitively.
    """
    g = get_graph()
    result = g.query(
        f"""
        MATCH (v:Vulnerability {{id: $vuln_id}})-[:AFFECTS]->(vp:Package)
        MATCH (app:Application)-[:USES]->(entry:Package)
        WHERE (entry)-[:DEPENDS_ON*0..{max_depth}]->(vp) OR entry = vp
        OPTIONAL MATCH (app)-[:OWNED_BY]->(t:Team)
        OPTIONAL MATCH (app)-[:DEPLOYED_AS]->(s:Asset)
        RETURN DISTINCT app.id, app.name, app.environment, app.language,
               collect(DISTINCT t.name) AS teams,
               collect(DISTINCT s.id) AS asset_ids,
               collect(DISTINCT s.criticality) AS asset_criticalities,
               collect(DISTINCT s.name) AS asset_names
        """,
        {"vuln_id": vuln_id},
    )
    apps = []
    for row in result.result_set:
        apps.append({
            "id": row[0],
            "name": row[1],
            "environment": row[2],
            "language": row[3],
            "teams": [t for t in row[4] if t],
            "asset_ids": row[5],
            "asset_criticalities": row[6],
            "asset_names": row[7],
        })
    return apps


# ---------------------------------------------------------------------------
# Query: Analyze asset impact
# ---------------------------------------------------------------------------

def analyze_asset_impact(vuln_id: str, max_depth: int = 4) -> list[dict]:
    """
    Return assets affected by the vulnerability with their criticality
    and the application responsible.
    """
    g = get_graph()
    result = g.query(
        f"""
        MATCH (v:Vulnerability {{id: $vuln_id}})-[:AFFECTS]->(vp:Package)
        MATCH (app:Application)-[:USES]->(entry:Package)
        WHERE (entry)-[:DEPENDS_ON*0..{max_depth}]->(vp) OR entry = vp
        MATCH (app)-[:DEPLOYED_AS]->(s:Asset)
        OPTIONAL MATCH (app)-[:OWNED_BY]->(t:Team)
        RETURN DISTINCT s.id, s.name, s.criticality, s.environment,
               s.region, s.exposed,
               collect(DISTINCT app.name) AS applications,
               collect(DISTINCT t.name) AS teams
        ORDER BY
          CASE s.criticality
            WHEN 'CRITICAL' THEN 0
            WHEN 'HIGH' THEN 1
            WHEN 'MEDIUM' THEN 2
            WHEN 'LOW' THEN 3
            ELSE 4
          END
        """,
        {"vuln_id": vuln_id},
    )
    assets = []
    for row in result.result_set:
        assets.append({
            "id": row[0],
            "name": row[1],
            "criticality": row[2],
            "environment": row[3],
            "region": row[4],
            "exposed": row[5],
            "applications": row[6],
            "teams": [t for t in row[7] if t],
        })
    return assets


# ---------------------------------------------------------------------------
# Query: Get responsible teams
# ---------------------------------------------------------------------------

def get_responsible_teams(vuln_id: str, max_depth: int = 4) -> list[dict]:
    g = get_graph()
    result = g.query(
        f"""
        MATCH (v:Vulnerability {{id: $vuln_id}})-[:AFFECTS]->(vp:Package)
        MATCH (app:Application)-[:USES]->(entry:Package)
        WHERE (entry)-[:DEPENDS_ON*0..{max_depth}]->(vp) OR entry = vp
        OPTIONAL MATCH (app)-[:OWNED_BY]->(t:Team)
        RETURN DISTINCT t.id, t.name, t.email,
               collect(DISTINCT app.name) AS applications
        """,
        {"vuln_id": vuln_id},
    )
    teams = []
    for row in result.result_set:
        if row[0] is None:
            continue
        teams.append({
            "id": row[0],
            "name": row[1],
            "email": row[2],
            "applications": row[3],
        })
    return teams


# ---------------------------------------------------------------------------
# Query: Retrieve evidence path (dependency chain)
# ---------------------------------------------------------------------------

def retrieve_evidence_paths(vuln_id: str, max_depth: int = 4) -> list[dict]:
    """
    Return explicit dependency paths from vulnerable package to applications.
    Each path is a list of node-dicts representing the chain.
    """
    g = get_graph()
    result = g.query(
        f"""
        MATCH (v:Vulnerability {{id: $vuln_id}})-[:AFFECTS]->(vp:Package)
        MATCH path = (app:Application)-[:USES]->(entry:Package)-[:DEPENDS_ON*0..{max_depth}]->(vp)
        RETURN app.id, app.name,
               [node IN nodes(path) | {{label: labels(node)[0], name: coalesce(node.name, node.id, ''), version: coalesce(node.version, '')}}] AS path_nodes,
               length(path) AS hops
        ORDER BY hops ASC
        LIMIT 20
        """,
        {"vuln_id": vuln_id},
    )
    paths = []
    for row in result.result_set:
        paths.append({
            "app_id": row[0],
            "app_name": row[1],
            "path_nodes": row[2],
            "hops": row[3],
        })
    return paths


# ---------------------------------------------------------------------------
# Graph data for visualization
# ---------------------------------------------------------------------------

def get_graph_data_for_vuln(vuln_id: str, max_depth: int = 4) -> dict:
    """
    Return nodes and edges suitable for graph visualization,
    scoped to the affected subgraph of a vulnerability.
    """
    g = get_graph()

    nodes: dict[str, dict] = {}
    edges: list[dict] = []

    # Vulnerability node
    vuln = get_vulnerability_by_id(vuln_id)
    if vuln:
        nodes[vuln_id] = {
            "id": vuln_id,
            "label": vuln["title"],
            "type": "Vulnerability",
            "data": vuln,
        }

    # Affected package + dependency chain
    pkg_result = g.query(
        f"""
        MATCH (v:Vulnerability {{id: $vuln_id}})-[:AFFECTS]->(vp:Package)
        OPTIONAL MATCH (dp:Package)-[:DEPENDS_ON*1..{max_depth}]->(vp)
        RETURN DISTINCT vp.name, vp.version, vp.ecosystem,
               dp.name AS dep_name, dp.version AS dep_version, dp.ecosystem AS dep_eco
        """,
        {"vuln_id": vuln_id},
    )
    vuln_pkg_id = None
    for row in pkg_result.result_set:
        vp_id = f"{row[0]}@{row[1]}"
        if vp_id not in nodes:
            nodes[vp_id] = {
                "id": vp_id,
                "label": f"{row[0]}@{row[1]}",
                "type": "Package",
                "data": {"name": row[0], "version": row[1], "ecosystem": row[2], "vulnerable": True},
            }
            vuln_pkg_id = vp_id
            edges.append({"source": vuln_id, "target": vp_id, "label": "AFFECTS"})
        if row[3]:
            dp_id = f"{row[3]}@{row[4]}"
            if dp_id not in nodes:
                nodes[dp_id] = {
                    "id": dp_id,
                    "label": f"{row[3]}@{row[4]}",
                    "type": "Package",
                    "data": {"name": row[3], "version": row[4], "ecosystem": row[5]},
                }
            edge_key = f"{dp_id}→{vp_id}"
            if not any(e["source"] == dp_id and e["target"] == vp_id for e in edges):
                edges.append({"source": dp_id, "target": vp_id, "label": "DEPENDS_ON"})

    # Applications, assets, teams
    app_result = g.query(
        f"""
        MATCH (v:Vulnerability {{id: $vuln_id}})-[:AFFECTS]->(vp:Package)
        MATCH (app:Application)-[:USES]->(entry:Package)
        WHERE (entry)-[:DEPENDS_ON*0..{max_depth}]->(vp) OR entry = vp
        OPTIONAL MATCH (app)-[:OWNED_BY]->(t:Team)
        OPTIONAL MATCH (app)-[:DEPLOYED_AS]->(s:Asset)
        RETURN DISTINCT app.id, app.name, app.environment,
               entry.name, entry.version,
               t.id, t.name,
               s.id, s.name, s.criticality
        """,
        {"vuln_id": vuln_id},
    )
    for row in app_result.result_set:
        app_id = row[0]
        if app_id and app_id not in nodes:
            nodes[app_id] = {
                "id": app_id,
                "label": row[1],
                "type": "Application",
                "data": {"name": row[1], "environment": row[2]},
            }
        entry_id = f"{row[3]}@{row[4]}" if row[3] else None
        if entry_id and entry_id in nodes and app_id:
            if not any(e["source"] == app_id and e["target"] == entry_id for e in edges):
                edges.append({"source": app_id, "target": entry_id, "label": "USES"})

        team_id = row[5]
        if team_id and team_id not in nodes:
            nodes[team_id] = {
                "id": team_id,
                "label": row[6],
                "type": "Team",
                "data": {"name": row[6]},
            }
        if team_id and app_id:
            if not any(e["source"] == app_id and e["target"] == team_id for e in edges):
                edges.append({"source": app_id, "target": team_id, "label": "OWNED_BY"})

        asset_id = row[7]
        if asset_id and asset_id not in nodes:
            nodes[asset_id] = {
                "id": asset_id,
                "label": row[8],
                "type": "Asset",
                "data": {"name": row[8], "criticality": row[9]},
            }
        if asset_id and app_id:
            if not any(e["source"] == app_id and e["target"] == asset_id for e in edges):
                edges.append({"source": app_id, "target": asset_id, "label": "DEPLOYED_AS"})

    return {"nodes": list(nodes.values()), "edges": edges}


# ---------------------------------------------------------------------------
# Investigations
# ---------------------------------------------------------------------------

def create_investigation(vuln_id: str, result_json: str) -> dict:
    inv_id = f"inv-{uuid.uuid4().hex[:8]}"
    now = datetime.now(timezone.utc).isoformat()
    g = get_graph()
    g.query(
        """
        MATCH (v:Vulnerability {id: $vid})
        CREATE (i:Investigation {id: $iid, created_at: $now, status: 'completed', result: $result})
        CREATE (i)-[:INVESTIGATES]->(v)
        """,
        {"vid": vuln_id, "iid": inv_id, "now": now, "result": result_json},
    )
    return {"id": inv_id, "vuln_id": vuln_id, "created_at": now, "status": "completed"}


def get_all_investigations() -> list[dict]:
    g = get_graph()
    result = g.query(
        """
        MATCH (i:Investigation)-[:INVESTIGATES]->(v:Vulnerability)
        RETURN i.id, i.created_at, i.status, v.id, v.title, v.severity
        ORDER BY i.created_at DESC
        LIMIT 50
        """
    )
    rows = []
    for row in result.result_set:
        rows.append({
            "id": row[0],
            "created_at": row[1],
            "status": row[2],
            "vuln_id": row[3],
            "vuln_title": row[4],
            "vuln_severity": row[5],
        })
    return rows


def get_investigation_by_id(inv_id: str) -> dict | None:
    g = get_graph()
    result = g.query(
        """
        MATCH (i:Investigation {id: $id})-[:INVESTIGATES]->(v:Vulnerability)
        RETURN i.id, i.created_at, i.status, i.result, v.id, v.title
        """,
        {"id": inv_id},
    )
    if not result.result_set:
        return None
    row = result.result_set[0]
    return {
        "id": row[0],
        "created_at": row[1],
        "status": row[2],
        "result": row[3],
        "vuln_id": row[4],
        "vuln_title": row[5],
    }


# ---------------------------------------------------------------------------
# Remediations
# ---------------------------------------------------------------------------

def create_remediation(
    finding_id: str,
    investigation_id: str,
    action_type: str,
    description: str,
    team_id: str | None,
) -> dict:
    rem_id = f"rem-{uuid.uuid4().hex[:8]}"
    now = datetime.now(timezone.utc).isoformat()
    g = get_graph()
    g.query(
        """
        MATCH (f:Finding {id: $fid})
        MATCH (i:Investigation {id: $iid})
        CREATE (r:Remediation {id: $rid, action_type: $atype,
               description: $desc, status: 'approved',
               created_at: $now})
        CREATE (r)-[:ADDRESSES]->(f)
        CREATE (r)-[:SUPPORTED_BY]->(i)
        """,
        {
            "fid": finding_id,
            "iid": investigation_id,
            "rid": rem_id,
            "atype": action_type,
            "desc": description,
            "now": now,
        },
    )
    if team_id:
        g.query(
            """
            MATCH (r:Remediation {id: $rid})
            MATCH (t:Team {id: $tid})
            MERGE (r)-[:PROPOSED_FOR]->(t)
            """,
            {"rid": rem_id, "tid": team_id},
        )
    return {
        "id": rem_id,
        "finding_id": finding_id,
        "investigation_id": investigation_id,
        "action_type": action_type,
        "description": description,
        "status": "approved",
        "created_at": now,
        "team_id": team_id,
    }


def get_all_remediations() -> list[dict]:
    g = get_graph()
    result = g.query(
        """
        MATCH (r:Remediation)-[:ADDRESSES]->(f:Finding)-[:IDENTIFIES]->(v:Vulnerability)
        OPTIONAL MATCH (r)-[:PROPOSED_FOR]->(t:Team)
        RETURN r.id, r.action_type, r.description, r.status, r.created_at,
               f.id, v.id, v.title, v.severity, t.name
        ORDER BY r.created_at DESC
        LIMIT 50
        """
    )
    rows = []
    for row in result.result_set:
        rows.append({
            "id": row[0],
            "action_type": row[1],
            "description": row[2],
            "status": row[3],
            "created_at": row[4],
            "finding_id": row[5],
            "vuln_id": row[6],
            "vuln_title": row[7],
            "vuln_severity": row[8],
            "team_name": row[9],
        })
    return rows


def get_remediation_by_id(rem_id: str) -> dict | None:
    g = get_graph()
    result = g.query(
        """
        MATCH (r:Remediation {id: $id})-[:ADDRESSES]->(f:Finding)-[:IDENTIFIES]->(v:Vulnerability)
        OPTIONAL MATCH (r)-[:PROPOSED_FOR]->(t:Team)
        OPTIONAL MATCH (r)-[:SUPPORTED_BY]->(i:Investigation)
        RETURN r.id, r.action_type, r.description, r.status, r.created_at,
               f.id, v.id, v.title, t.name, i.id
        """,
        {"id": rem_id},
    )
    if not result.result_set:
        return None
    row = result.result_set[0]
    return {
        "id": row[0],
        "action_type": row[1],
        "description": row[2],
        "status": row[3],
        "created_at": row[4],
        "finding_id": row[5],
        "vuln_id": row[6],
        "vuln_title": row[7],
        "team_name": row[8],
        "investigation_id": row[9],
    }


# ---------------------------------------------------------------------------
# Overview / summary stats
# ---------------------------------------------------------------------------

def get_overview_stats() -> dict:
    g = get_graph()
    vuln_count = g.query("MATCH (v:Vulnerability) RETURN count(v)").result_set[0][0]
    finding_count = g.query("MATCH (f:Finding) RETURN count(f)").result_set[0][0]
    open_findings = g.query("MATCH (f:Finding {status:'open'}) RETURN count(f)").result_set[0][0]
    asset_count = g.query("MATCH (s:Asset) RETURN count(s)").result_set[0][0]
    critical_assets = g.query(
        "MATCH (s:Asset {criticality:'CRITICAL'}) RETURN count(s)"
    ).result_set[0][0]
    rem_count = g.query("MATCH (r:Remediation) RETURN count(r)").result_set[0][0]
    inv_count = g.query("MATCH (i:Investigation) RETURN count(i)").result_set[0][0]

    return {
        "vulnerability_count": vuln_count,
        "finding_count": finding_count,
        "open_findings": open_findings,
        "asset_count": asset_count,
        "critical_assets": critical_assets,
        "remediation_count": rem_count,
        "investigation_count": inv_count,
    }

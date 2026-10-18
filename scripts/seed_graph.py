#!/usr/bin/env python3
"""
PatchPilot Synthetic Graph Data Seeder.

Loads synthetic benchmark graph data into FalkorDB using idempotent Cypher MERGE.
Supports clearing existing data and custom seed JSON files.

Usage:
  cd patchpilot/backend
  ./venv/bin/python ../scripts/seed_graph.py [--clear] [--file PATH]
"""
import sys
import os
import argparse
from pathlib import Path

# Add backend directory to sys.path
backend_dir = Path(__file__).resolve().parent.parent / "backend"
sys.path.insert(0, str(backend_dir))


def main():
    parser = argparse.ArgumentParser(
        description="Seed PatchPilot synthetic benchmark graph data into FalkorDB",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python seed_graph.py
  python seed_graph.py --clear
  python seed_graph.py --file ../data/synthetic_data/graph_dataset.json --clear
        """,
    )
    parser.add_argument(
        "--clear",
        action="store_true",
        help="Clear entire graph before seeding (clean state reset)",
    )
    parser.add_argument(
        "--file",
        type=str,
        default=None,
        help="Optional path to custom JSON seed dataset file (defaults to data/synthetic_data/graph_dataset.json)",
    )
    args = parser.parse_args()

    from app.db.connection import ping, get_client
    from app.core.config import settings
    from app.graph.queries import seed_graph

    print("==================================================")
    print(" PatchPilot Synthetic Dataset Loader")
    print("==================================================")
    print("DISCLAIMER: All dataset entities are SYNTHETIC benchmarks")
    print("for evaluation of graph AI triage agents. Not real CVEs.")
    print(f"Target: FalkorDB @ {settings.falkordb_host}:{settings.falkordb_port} [graph: {settings.falkordb_graph}]")

    if not ping():
        print(f"\n[ERROR] Cannot connect to FalkorDB on {settings.falkordb_host}:{settings.falkordb_port}.")
        print("Ensure FalkorDB is running: docker compose up -d falkordb")
        sys.exit(1)

    print("\n[OK] FalkorDB connection verified.")
    if args.clear:
        print("[ACTION] Clearing existing graph nodes and edges (--clear flag enabled)...")
    else:
        print("[ACTION] Ingesting synthetic data using idempotent MERGE queries...")

    try:
        counts = seed_graph(clear_first=args.clear, dataset_path=args.file)
        print("\n[SUCCESS] Seed operation complete. Entity node counts in FalkorDB:")
        for entity_type, count in counts.items():
            print(f"  • {entity_type.capitalize()}: {count}")

        print("\nGround-truth test scenarios ready in graph:")
        print("  1. Direct dependency: VULN-2024-001 -> auth-middleware (Payment Gateway)")
        print("  2. Transitive 3-hop chain: VULN-2024-001 -> report-engine (Report Generator)")
        print("  3. Public asset exposure: Payment Gateway -> Production Kubernetes Cluster (CRITICAL, exposed)")
        print("  4. Insufficient evidence: VULN-2024-004 (incomplete_evidence=true, unassigned team)")
        print("==================================================")
    except Exception as exc:
        print(f"\n[ERROR] Seed execution failed: {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()

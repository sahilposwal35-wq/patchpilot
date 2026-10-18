import { useEffect, useState, useCallback } from 'react';
import { useSearchParams } from 'react-router-dom';
import { api, ApiError } from '../services/api';
import type { VulnerabilityBrief, InvestigationResult, GraphNode } from '../services/api';
import { SeverityBadge, PriorityBadge, CriticalityBadge, SyntheticBadge } from '../components/Badges';
import { PriorityScoreCard } from '../components/PriorityScoreCard';
import { EvidencePathView } from '../components/EvidencePathView';
import { DependencyGraph } from '../components/DependencyGraph';
import { RemediationModal } from '../components/RemediationModal';
import {
  Search,
  Play,
  ChevronDown,
  ChevronUp,
  AlertTriangle,
  CheckCircle,
  Server,
  Package,
  Users,
  Shield,
  Zap,
  Info,
  ExternalLink,
} from 'lucide-react';

// ---- Investigation step labels ----
const STEPS = [
  { key: 'vuln', label: 'Retrieving vulnerability details' },
  { key: 'packages', label: 'Tracing affected packages' },
  { key: 'apps', label: 'Identifying affected applications' },
  { key: 'assets', label: 'Analyzing asset impact' },
  { key: 'teams', label: 'Looking up responsible teams' },
  { key: 'paths', label: 'Retrieving evidence paths' },
  { key: 'priority', label: 'Computing priority score' },
  { key: 'persist', label: 'Persisting investigation record' },
];

export function InvestigatePage() {
  const [searchParams] = useSearchParams();
  const [vulns, setVulns] = useState<VulnerabilityBrief[]>([]);
  const [selectedVulnId, setSelectedVulnId] = useState<string>(searchParams.get('vuln') || '');
  const [investigating, setInvestigating] = useState(false);
  const [stepIndex, setStepIndex] = useState(-1);
  const [result, setResult] = useState<InvestigationResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [evidenceOpen, setEvidenceOpen] = useState(false);
  const [showModal, setShowModal] = useState(false);
  const [remediationSuccess, setRemediationSuccess] = useState<string | null>(null);
  const [selectedGraphNode, setSelectedGraphNode] = useState<GraphNode | null>(null);

  // Load vulnerability list
  useEffect(() => {
    api.listVulnerabilities().then(setVulns).catch(console.error);
  }, []);

  // Auto-investigate if vuln param present
  useEffect(() => {
    const v = searchParams.get('vuln');
    if (v && vulns.find((x) => x.id === v)) {
      setSelectedVulnId(v);
    }
  }, [searchParams, vulns]);

  const runInvestigation = useCallback(async () => {
    if (!selectedVulnId) return;
    setInvestigating(true);
    setError(null);
    setResult(null);
    setRemediationSuccess(null);
    setEvidenceOpen(false);

    // Animate through steps
    for (let i = 0; i < STEPS.length - 1; i++) {
      setStepIndex(i);
      await new Promise((r) => setTimeout(r, 350));
    }

    try {
      const res = await api.investigate(selectedVulnId);
      setStepIndex(STEPS.length - 1);
      await new Promise((r) => setTimeout(r, 250));
      setResult(res);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Investigation failed. Check backend connection.');
    } finally {
      setInvestigating(false);
      setStepIndex(-1);
    }
  }, [selectedVulnId]);

  const selectedVuln = vulns.find((v) => v.id === selectedVulnId);

  const highlightNodes = result
    ? result.evidence_paths.flatMap((p) => p.path_nodes.map((n) => n.name))
    : [];

  return (
    <div>
      <div className="page-header">
        <div className="page-header-left">
          <span className="page-header-title">Investigate</span>
        </div>
        {result && !investigating && (
          <button
            className="btn btn-secondary btn-sm"
            onClick={runInvestigation}
            id="btn-reinvestigate"
          >
            <Search size={14} />
            Re-investigate
          </button>
        )}
      </div>

      <div className="page-content" style={{ maxWidth: 1100 }}>

        {/* Step 1: Select vulnerability */}
        <div className="card" style={{ marginBottom: 'var(--space-5)' }}>
          <div className="card-header">
            <div className="flex items-center gap-2">
              <div
                style={{
                  width: 24, height: 24,
                  background: 'var(--accent-primary)',
                  borderRadius: '50%',
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  color: 'white', fontSize: 12, fontWeight: 700, flexShrink: 0,
                }}
              >1</div>
              <span className="section-title">Select a Vulnerability</span>
            </div>
          </div>
          <div className="card-body">
            <div style={{ display: 'grid', gridTemplateColumns: '1fr auto', gap: 'var(--space-3)', alignItems: 'end' }}>
              <div className="form-group">
                <label htmlFor="vuln-select" className="form-label">Vulnerability</label>
                <select
                  id="vuln-select"
                  className="form-select"
                  value={selectedVulnId}
                  onChange={(e) => {
                    setSelectedVulnId(e.target.value);
                    setResult(null);
                    setError(null);
                  }}
                >
                  <option value="">— Choose a vulnerability —</option>
                  {vulns.map((v) => (
                    <option key={v.id} value={v.id}>
                      [{v.severity}] {v.title} ({v.id})
                    </option>
                  ))}
                </select>
              </div>
              <button
                className="btn btn-primary btn-lg"
                onClick={runInvestigation}
                disabled={!selectedVulnId || investigating}
                id="btn-start-investigation"
                aria-label="Start graph investigation"
              >
                {investigating ? (
                  <>
                    <span className="spinner" style={{ width: 16, height: 16 }} />
                    Investigating…
                  </>
                ) : (
                  <>
                    <Play size={16} />
                    Investigate
                  </>
                )}
              </button>
            </div>

            {/* Selected vuln info */}
            {selectedVuln && (
              <div
                style={{
                  marginTop: 'var(--space-4)',
                  background: 'var(--bg-subtle)',
                  borderRadius: 'var(--radius)',
                  padding: 'var(--space-4)',
                  border: '1px solid var(--border)',
                  display: 'flex', gap: 'var(--space-4)', alignItems: 'flex-start',
                }}
              >
                <Shield size={16} style={{ color: 'var(--sev-critical)', marginTop: 2, flexShrink: 0 }} />
                <div className="flex flex-col gap-1" style={{ flex: 1 }}>
                  <div className="flex items-center gap-2 flex-wrap">
                    <SeverityBadge severity={selectedVuln.severity} />
                    {selectedVuln.cvss_score && (
                      <span className="badge badge-uncertain">CVSS {selectedVuln.cvss_score}</span>
                    )}
                    {selectedVuln.cve && (
                      <span className="text-xs text-tertiary font-mono">{selectedVuln.cve}</span>
                    )}
                    <SyntheticBadge label="SYNTHETIC BENCHMARK" />
                  </div>
                  <div className="font-semibold">{selectedVuln.title}</div>
                  {selectedVuln.description && (
                    <p className="text-sm text-secondary">{selectedVuln.description}</p>
                  )}
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Step 2: Progress / Result */}
        {investigating && (
          <div className="card" style={{ marginBottom: 'var(--space-5)' }}>
            <div className="card-header">
              <div className="flex items-center gap-2">
                <span className="spinner" />
                <span className="section-title">Investigation in Progress</span>
              </div>
            </div>
            <div className="card-body">
              <div className="progress-steps">
                {STEPS.map((step, i) => {
                  const state = i < stepIndex ? 'done' : i === stepIndex ? 'active' : 'pending';
                  return (
                    <div key={step.key} className={`progress-step ${state}`}>
                      <div className={`step-icon ${state}`}>
                        {state === 'done' ? '✓' : state === 'active' ? '→' : i + 1}
                      </div>
                      {step.label}
                      {state === 'active' && (
                        <span className="spinner" style={{ width: 12, height: 12, marginLeft: 4 }} />
                      )}
                    </div>
                  );
                })}
              </div>
              <div className="alert alert-info mt-4">
                <Zap size={14} style={{ flexShrink: 0 }} />
                Executing Cypher queries against FalkorDB graph database…
              </div>
            </div>
          </div>
        )}

        {/* Error */}
        {error && (
          <div className="alert alert-error" style={{ marginBottom: 'var(--space-5)' }}>
            <AlertTriangle size={16} style={{ flexShrink: 0 }} />
            <div>
              <strong>Investigation failed</strong>
              <div className="text-sm" style={{ marginTop: 4 }}>{error}</div>
            </div>
          </div>
        )}

        {/* Remediation success */}
        {remediationSuccess && (
          <div className="alert alert-success" style={{ marginBottom: 'var(--space-5)' }}>
            <CheckCircle size={16} style={{ flexShrink: 0 }} />
            <div>
              <strong>Remediation recorded in FalkorDB</strong>
              <div className="text-xs" style={{ marginTop: 2 }}>Record ID: {remediationSuccess}</div>
            </div>
          </div>
        )}

        {/* Results */}
        {result && !investigating && (
          <>
            {/* Synthetic Benchmark Disclaimer Banner */}
            <div className="alert alert-info" style={{ marginBottom: 'var(--space-4)' }}>
              <Info size={16} style={{ flexShrink: 0, color: 'var(--accent-primary)' }} />
              <div className="text-xs text-secondary">
                <strong style={{ color: 'var(--text-primary)' }}>Synthetic Benchmark Triage: </strong>
                All dependency paths, packages, and assets shown are synthetic test fixtures designed to evaluate FalkorDB multi-hop reachability and deterministic scoring. Not a real-world vulnerability.
              </div>
            </div>

            {/* Missing evidence warning */}
            {!result.evidence_complete && (
              <div className="alert alert-warning" style={{ marginBottom: 'var(--space-5)' }}>
                <AlertTriangle size={16} style={{ flexShrink: 0 }} />
                <div>
                  <strong>Incomplete Evidence</strong>
                  <ul style={{ margin: '4px 0 0', paddingLeft: 16 }}>
                    {result.missing_evidence.map((m, i) => (
                      <li key={i} className="text-sm">{m}</li>
                    ))}
                  </ul>
                </div>
              </div>
            )}

            {/* Priority + Recommendation */}
            <div className="grid-2" style={{ marginBottom: 'var(--space-5)' }}>
              <div className="card">
                <div className="card-header">
                  <span className="section-title">Priority Assessment</span>
                  <PriorityBadge label={result.priority.label} score={result.priority.score} />
                </div>
                <div className="card-body">
                  <PriorityScoreCard priority={result.priority} factorsDetail={result.factors_detail} />
                </div>
              </div>

              <div className="card">
                <div className="card-header">
                  <span className="section-title">Recommendation</span>
                </div>
                <div className="card-body flex flex-col gap-4">
                  <div
                    style={{
                      background: 'var(--accent-primary-subtle)',
                      border: '1px solid var(--accent-primary-border)',
                      borderRadius: 'var(--radius)',
                      padding: 'var(--space-4)',
                    }}
                  >
                    <p className="text-sm font-medium" style={{ color: 'var(--accent-primary)' }}>
                      {result.recommended_action}
                    </p>
                  </div>

                  <p className="text-sm text-secondary">{result.explanation}</p>

                  {result.llm_summary && (
                    <div
                      style={{
                        background: 'var(--bg-subtle)',
                        borderRadius: 'var(--radius)',
                        padding: 'var(--space-3)',
                        border: '1px solid var(--border)',
                      }}
                    >
                      <div className="label mb-2">AI Summary ({result.mode})</div>
                      <p className="text-sm text-secondary">{result.llm_summary}</p>
                    </div>
                  )}

                  <div className="flex items-center gap-2 text-xs text-tertiary">
                    <Info size={12} />
                    Investigation ID: <span className="font-mono">{result.investigation_id}</span>
                  </div>

                  {/* Approve remediation */}
                  {!remediationSuccess && (
                    <button
                      className="btn btn-primary"
                      onClick={() => setShowModal(true)}
                      id="btn-approve-remediation"
                      aria-label="Approve simulated remediation action"
                    >
                      <CheckCircle size={14} />
                      Approve Remediation
                    </button>
                  )}
                </div>
              </div>
            </div>

            {/* Affected entities */}
            <div className="grid-2" style={{ marginBottom: 'var(--space-5)' }}>
              {/* Applications */}
              <div className="card">
                <div className="card-header">
                  <div className="flex items-center gap-2">
                    <Server size={15} style={{ color: 'var(--accent-primary)' }} />
                    <span className="section-title">Affected Applications</span>
                  </div>
                  <span className="badge badge-green">{result.affected_applications.length}</span>
                </div>
                <div>
                  {result.affected_applications.length === 0 ? (
                    <div className="state-container" style={{ padding: 'var(--space-5)' }}>
                      <span className="state-sub">No affected applications identified.</span>
                    </div>
                  ) : (
                    result.affected_applications.map((app) => (
                      <div key={app.id} className="list-item" style={{ cursor: 'default' }}>
                        <div style={{ flex: 1 }}>
                          <div className="font-medium text-sm">{app.name}</div>
                          <div className="flex items-center gap-2" style={{ marginTop: 4 }}>
                            <span className="badge badge-uncertain">{app.environment}</span>
                            <span className="text-xs text-tertiary">{app.language}</span>
                          </div>
                          {app.asset_names.length > 0 && (
                            <div className="text-xs text-tertiary" style={{ marginTop: 2 }}>
                              Assets: {app.asset_names.join(', ')}
                            </div>
                          )}
                          {app.teams.length > 0 ? (
                            <div className="text-xs" style={{ color: 'var(--accent-primary)', marginTop: 2 }}>
                              Team: {app.teams.join(', ')}
                            </div>
                          ) : (
                            <div className="text-xs" style={{ color: 'var(--sev-critical)', marginTop: 2 }}>
                              ⚠ No team assigned
                            </div>
                          )}
                        </div>
                        <div className="flex flex-col gap-1 items-end">
                          {app.asset_criticalities.map((c, i) => (
                            <CriticalityBadge key={i} criticality={c} />
                          ))}
                        </div>
                      </div>
                    ))
                  )}
                </div>
              </div>

              {/* Assets */}
              <div className="card">
                <div className="card-header">
                  <div className="flex items-center gap-2">
                    <Server size={15} style={{ color: '#7B3FA0' }} />
                    <span className="section-title">Affected Assets</span>
                  </div>
                  <span className="badge badge-green">{result.affected_assets.length}</span>
                </div>
                <div>
                  {result.affected_assets.length === 0 ? (
                    <div className="state-container" style={{ padding: 'var(--space-5)' }}>
                      <span className="state-sub">No asset deployment records found.</span>
                    </div>
                  ) : (
                    result.affected_assets.map((asset) => (
                      <div key={asset.id} className="list-item" style={{ cursor: 'default' }}>
                        <div style={{ flex: 1 }}>
                          <div className="flex items-center gap-2" style={{ marginBottom: 4 }}>
                            <CriticalityBadge criticality={asset.criticality} />
                            {asset.exposed && (
                              <span className="badge badge-critical" style={{ fontSize: 10 }}>
                                Internet-exposed
                              </span>
                            )}
                          </div>
                          <div className="font-medium text-sm">{asset.name}</div>
                          <div className="text-xs text-tertiary">
                            {asset.environment} · {asset.region}
                          </div>
                          <div className="text-xs text-secondary" style={{ marginTop: 2 }}>
                            Apps: {asset.applications.join(', ')}
                          </div>
                        </div>
                      </div>
                    ))
                  )}
                </div>
              </div>
            </div>

            {/* Packages + Teams */}
            <div className="grid-2" style={{ marginBottom: 'var(--space-5)' }}>
              <div className="card">
                <div className="card-header">
                  <div className="flex items-center gap-2">
                    <Package size={15} style={{ color: '#1A5EA8' }} />
                    <span className="section-title">Affected Packages</span>
                  </div>
                  <span className="badge badge-green">{result.affected_packages.length}</span>
                </div>
                <div className="card-body">
                  <div className="tag-list">
                    {result.affected_packages.map((p, i) => (
                      <span
                        key={i}
                        className={`badge ${p.is_direct_vulnerable ? 'badge-critical' : ''}`}
                        style={
                          !p.is_direct_vulnerable
                            ? { background: '#EBF3FD', color: '#1A5EA8', borderColor: '#B0D0F5' }
                            : undefined
                        }
                        title={p.is_direct_vulnerable ? 'Directly vulnerable' : 'Transitively affected'}
                      >
                        {p.name}@{p.version}
                        {p.is_direct_vulnerable && ' ⚠'}
                      </span>
                    ))}
                  </div>
                </div>
              </div>

              <div className="card">
                <div className="card-header">
                  <div className="flex items-center gap-2">
                    <Users size={15} style={{ color: 'var(--sev-high)' }} />
                    <span className="section-title">Responsible Teams</span>
                  </div>
                </div>
                <div>
                  {result.responsible_teams.length === 0 ? (
                    <div className="state-container" style={{ padding: 'var(--space-5)' }}>
                      <div className="alert alert-warning" style={{ textAlign: 'left' }}>
                        <AlertTriangle size={14} style={{ flexShrink: 0 }} />
                        No team ownership found for affected applications.
                      </div>
                    </div>
                  ) : (
                    result.responsible_teams.map((t) => (
                      <div key={t.id} className="list-item" style={{ cursor: 'default' }}>
                        <div style={{ flex: 1 }}>
                          <div className="font-medium text-sm">{t.name}</div>
                          {t.email && (
                            <div className="text-xs text-secondary">{t.email}</div>
                          )}
                          <div className="text-xs text-tertiary">
                            Owns: {t.applications.join(', ')}
                          </div>
                        </div>
                      </div>
                    ))
                  )}
                </div>
              </div>
            </div>

            {/* Evidence paths (collapsible) */}
            <div className="card" style={{ marginBottom: 'var(--space-5)' }}>
              <div
                className="card-header collapsible-header"
                onClick={() => setEvidenceOpen(!evidenceOpen)}
                role="button"
                tabIndex={0}
                onKeyDown={(e) => e.key === 'Enter' && setEvidenceOpen(!evidenceOpen)}
                aria-expanded={evidenceOpen}
                id="btn-toggle-evidence"
              >
                <div className="flex items-center gap-2">
                  <ExternalLink size={15} style={{ color: 'var(--text-secondary)' }} />
                  <span className="section-title">Dependency Evidence Paths</span>
                  <span className="badge badge-green">{result.evidence_paths.length} paths</span>
                </div>
                {evidenceOpen ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
              </div>
              {evidenceOpen && (
                <div className="card-body">
                  <p className="text-sm text-secondary" style={{ marginBottom: 'var(--space-4)' }}>
                    These are the actual dependency chains returned from FalkorDB connecting the vulnerability to affected applications.
                    Every node and relationship shown exists in the graph.
                  </p>
                  <EvidencePathView paths={result.evidence_paths} />
                </div>
              )}
            </div>

            {/* Dependency Graph */}
            <div className="card" style={{ marginBottom: 'var(--space-5)' }}>
              <div className="card-header">
                <span className="section-title">Vulnerability Subgraph</span>
                <span className="text-xs text-tertiary">
                  {result.graph_data.nodes.length} nodes · {result.graph_data.edges.length} edges
                </span>
              </div>
              <div style={{ padding: 0, borderRadius: '0 0 var(--radius-lg) var(--radius-lg)', overflow: 'hidden' }}>
                <DependencyGraph
                  graphData={result.graph_data}
                  highlightNodeIds={highlightNodes}
                  onNodeSelect={setSelectedGraphNode}
                  height={480}
                />
              </div>
              {selectedGraphNode && (
                <div
                  className="card-footer"
                  style={{ background: 'var(--bg-subtle)' }}
                >
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="label">Selected:</span>
                    <span className={`path-node type-${selectedGraphNode.type}`}>
                      {selectedGraphNode.type}
                    </span>
                    <span className="font-medium text-sm">{selectedGraphNode.label}</span>
                    {Object.entries(selectedGraphNode.data).slice(0, 4).map(([k, v]) => (
                      <span key={k} className="text-xs text-tertiary">
                        {k}: <span className="font-mono">{String(v)}</span>
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </>
        )}
      </div>

      {/* Remediation modal */}
      {showModal && result && (
        <RemediationModal
          investigation={result}
          onClose={() => setShowModal(false)}
          onSuccess={(id) => {
            setRemediationSuccess(id);
            setShowModal(false);
          }}
        />
      )}
    </div>
  );
}

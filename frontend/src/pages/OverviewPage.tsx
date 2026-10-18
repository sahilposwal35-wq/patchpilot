import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { api, ApiError } from '../services/api';
import type { OverviewStats, VulnerabilityBrief, InvestigationBrief, RemediationBrief } from '../services/api';
import { SeverityBadge, SyntheticBadge } from '../components/Badges';
import {
  Shield,
  AlertTriangle,
  Server,
  ClipboardCheck,
  ChevronRight,
  Clock,
  Search,
  RefreshCw,
} from 'lucide-react';

export function OverviewPage() {
  const navigate = useNavigate();
  const [stats, setStats] = useState<OverviewStats | null>(null);
  const [vulns, setVulns] = useState<VulnerabilityBrief[]>([]);
  const [investigations, setInvestigations] = useState<InvestigationBrief[]>([]);
  const [remediations, setRemediations] = useState<RemediationBrief[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    setLoading(true);
    setError(null);
    try {
      const [s, v, inv, rem] = await Promise.all([
        api.overview(),
        api.listVulnerabilities(),
        api.listInvestigations(),
        api.listRemediations(),
      ]);
      setStats(s);
      setVulns(v);
      setInvestigations(inv.slice(0, 5));
      setRemediations(rem.slice(0, 5));
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to load data. Is the backend running?');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, []);

  const topVulns = [...vulns].sort((a, b) => (b.cvss_score || 0) - (a.cvss_score || 0)).slice(0, 6);

  return (
    <div>
      {/* Page header */}
      <div className="page-header">
        <div className="page-header-left">
          <span className="page-header-title">Overview</span>
        </div>
        <button className="btn btn-ghost btn-sm" onClick={load} disabled={loading} aria-label="Refresh data">
          <RefreshCw size={14} className={loading ? 'spinning' : ''} />
          Refresh
        </button>
      </div>

      <div className="page-content">
        {/* Title */}
        <div style={{ marginBottom: 'var(--space-6)' }}>
          <h1 className="page-title">Security Overview</h1>
          <p className="page-subtitle">
            Graph-powered vulnerability intelligence. FalkorDB tracks every dependency, application, and asset relationship.
          </p>
        </div>

        {/* Error state */}
        {error && (
          <div className="alert alert-error" style={{ marginBottom: 'var(--space-5)' }}>
            <AlertTriangle size={16} style={{ flexShrink: 0 }} />
            <div>
              <strong>{error}</strong>
              <div className="text-xs mt-2">
                Make sure the backend is running: <code>cd backend && uvicorn app.main:app</code>
              </div>
            </div>
          </div>
        )}

        {/* Metrics row */}
        {loading ? (
          <div className="grid-4" style={{ marginBottom: 'var(--space-6)' }}>
            {[1, 2, 3, 4].map((i) => (
              <div key={i} className="metric-card" style={{ opacity: 0.5, minHeight: 90 }} />
            ))}
          </div>
        ) : stats ? (
          <div className="grid-4" style={{ marginBottom: 'var(--space-6)' }}>
            <div className="metric-card">
              <div className="flex items-center gap-2">
                <Shield size={16} style={{ color: 'var(--sev-critical)' }} />
                <span className="metric-label">Vulnerabilities</span>
              </div>
              <div className="metric-value">{stats.vulnerability_count}</div>
              <div className="metric-sub">{stats.finding_count} findings · {stats.open_findings} open</div>
            </div>
            <div className="metric-card">
              <div className="flex items-center gap-2">
                <Server size={16} style={{ color: 'var(--accent-primary)' }} />
                <span className="metric-label">Assets</span>
              </div>
              <div className="metric-value">{stats.asset_count}</div>
              <div className="metric-sub">
                <span style={{ color: 'var(--sev-critical)' }}>{stats.critical_assets} critical</span>
              </div>
            </div>
            <div className="metric-card">
              <div className="flex items-center gap-2">
                <Search size={16} style={{ color: 'var(--accent-amber)' }} />
                <span className="metric-label">Investigations</span>
              </div>
              <div className="metric-value">{stats.investigation_count}</div>
              <div className="metric-sub">Graph-based analysis runs</div>
            </div>
            <div className="metric-card">
              <div className="flex items-center gap-2">
                <ClipboardCheck size={16} style={{ color: 'var(--sev-low)' }} />
                <span className="metric-label">Remediations</span>
              </div>
              <div className="metric-value">{stats.remediation_count}</div>
              <div className="metric-sub">Approved simulated actions</div>
            </div>
          </div>
        ) : null}

        {/* Two-column layout */}
        <div className="grid-2" style={{ alignItems: 'start' }}>
          {/* Vulnerabilities list */}
          <div className="card">
            <div className="card-header">
              <div className="flex items-center gap-2">
                <Shield size={16} style={{ color: 'var(--sev-critical)' }} />
                <span className="section-title">Priority Vulnerabilities</span>
              </div>
              <span className="badge badge-critical">{stats?.open_findings || 0} open</span>
            </div>

            {loading ? (
              <div className="state-container" style={{ padding: 'var(--space-8)' }}>
                <div className="spinner" />
              </div>
            ) : topVulns.length === 0 ? (
              <div className="state-container">
                <div className="state-icon">🔍</div>
                <span className="state-title">No vulnerabilities found</span>
                <span className="state-sub">Seed the database to load synthetic data.</span>
                <button className="btn btn-primary btn-sm" onClick={() => api.seed().then(load)}>
                  Seed Data
                </button>
              </div>
            ) : (
              <div>
                {topVulns.map((v) => (
                  <div
                    key={v.id}
                    className="list-item"
                    onClick={() => navigate(`/investigate?vuln=${v.id}`)}
                    role="button"
                    tabIndex={0}
                    onKeyDown={(e) => e.key === 'Enter' && navigate(`/investigate?vuln=${v.id}`)}
                    aria-label={`Investigate ${v.title}`}
                  >
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div className="flex items-center gap-2" style={{ marginBottom: 4 }}>
                        <SeverityBadge severity={v.severity} />
                        {v.cvss_score && (
                          <span className="text-xs text-tertiary">CVSS {v.cvss_score}</span>
                        )}
                        <SyntheticBadge label="SYNTHETIC" />
                      </div>
                      <div className="font-medium text-sm truncate">{v.title}</div>
                      <div className="text-xs text-tertiary" style={{ marginTop: 2 }}>
                        {v.cve} · {v.finding_count} finding{v.finding_count !== 1 ? 's' : ''}
                      </div>
                    </div>
                    <ChevronRight size={16} style={{ color: 'var(--text-tertiary)', flexShrink: 0 }} />
                  </div>
                ))}
                <div className="card-footer" style={{ textAlign: 'center' }}>
                  <button
                    className="btn btn-primary btn-sm"
                    onClick={() => navigate('/investigate')}
                    id="btn-investigate-all"
                  >
                    <Search size={14} />
                    Investigate
                  </button>
                </div>
              </div>
            )}
          </div>

          {/* Right column */}
          <div className="flex flex-col gap-5">
            {/* Recent investigations */}
            <div className="card">
              <div className="card-header">
                <div className="flex items-center gap-2">
                  <Clock size={16} style={{ color: 'var(--accent-amber)' }} />
                  <span className="section-title">Recent Investigations</span>
                </div>
              </div>
              {investigations.length === 0 ? (
                <div className="state-container" style={{ padding: 'var(--space-6)' }}>
                  <span className="state-sub">No investigations yet. Run one from the Investigate page.</span>
                </div>
              ) : (
                <div>
                  {investigations.map((inv) => (
                    <div key={inv.id} className="activity-item" style={{ padding: 'var(--space-3) var(--space-5)', borderBottom: '1px solid var(--border)' }}>
                      <div className="activity-dot" />
                      <div className="activity-content">
                        <div className="activity-title">{inv.vuln_title}</div>
                        <div className="flex items-center gap-2">
                          <SeverityBadge severity={inv.vuln_severity} />
                          <span className="activity-time">
                            {new Date(inv.created_at).toLocaleString()}
                          </span>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Recent remediations */}
            <div className="card">
              <div className="card-header">
                <div className="flex items-center gap-2">
                  <ClipboardCheck size={16} style={{ color: 'var(--sev-low)' }} />
                  <span className="section-title">Recent Remediations</span>
                </div>
              </div>
              {remediations.length === 0 ? (
                <div className="state-container" style={{ padding: 'var(--space-6)' }}>
                  <span className="state-sub">No remediations approved yet.</span>
                </div>
              ) : (
                <div>
                  {remediations.map((rem) => (
                    <div key={rem.id} className="activity-item" style={{ padding: 'var(--space-3) var(--space-5)', borderBottom: '1px solid var(--border)' }}>
                      <div className="activity-dot" style={{ background: 'var(--sev-low)' }} />
                      <div className="activity-content">
                        <div className="activity-title">{rem.action_type.replace(/_/g, ' ')}</div>
                        <div className="flex items-center gap-2">
                          <span className="badge badge-green" style={{ fontSize: 10 }}>
                            {rem.status}
                          </span>
                          {rem.vuln_title && (
                            <span className="text-xs text-tertiary truncate">{rem.vuln_title}</span>
                          )}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

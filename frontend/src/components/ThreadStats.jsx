import React from 'react';

const ThreadStats = ({ stats, threatData }) => {
  const topSources = Object.entries(stats.by_source || {})
    .sort(([,a], [,b]) => b - a)
    .slice(0, 5);

  return (
    <div className="thread-stats">
      <h2>Threat Intelligence Overview</h2>
      
      <div className="stats-grid">
        <div className="stat-section">
          <h3>Core Metrics</h3>
          <div className="metric-cards">
            <div className="metric-card">
              <span className="metric-value">{stats.total_threats || 0}</span>
              <span className="metric-label">Total Threats</span>
            </div>
            <div className="metric-card">
              <span className="metric-value">{Object.keys(stats.by_source || {}).length}</span>
              <span className="metric-label">Data Sources</span>
            </div>
            <div className="metric-card">
              <span className="metric-value">{Object.keys(stats.by_country || {}).length}</span>
              <span className="metric-label">Countries</span>
            </div>
          </div>
        </div>

        <div className="stat-section">
          <h3>Severity Distribution</h3>
          <div className="severity-breakdown">
            <div className="severity-list">
              <div className="severity-item critical">
                <span className="severity-dot"></span>
                <span className="severity-label">Critical</span>
                <span className="severity-count">{stats.by_severity?.critical || 0}</span>
              </div>
              <div className="severity-item high">
                <span className="severity-dot"></span>
                <span className="severity-label">High</span>
                <span className="severity-count">{stats.by_severity?.high || 0}</span>
              </div>
              <div className="severity-item medium">
                <span className="severity-dot"></span>
                <span className="severity-label">Medium</span>
                <span className="severity-count">{stats.by_severity?.medium || 0}</span>
              </div>
              <div className="severity-item low">
                <span className="severity-dot"></span>
                <span className="severity-label">Low</span>
                <span className="severity-count">{stats.by_severity?.low || 0}</span>
              </div>
            </div>
          </div>
        </div>

        <div className="stat-section">
          <h3>Top Sources</h3>
          <div className="sources-list">
            {topSources.map(([source, count]) => (
              <div key={source} className="source-item">
                <span className="source-name">{source}</span>
                <span className="source-count">{count}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};

export default ThreadStats;
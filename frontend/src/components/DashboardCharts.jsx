import React from 'react';

const DashboardCharts = ({ stats, threatData }) => {
  const severityData = [
    { name: 'Critical', value: stats.by_severity?.critical || 0, color: '#dc3545' },
    { name: 'High', value: stats.by_severity?.high || 0, color: '#fd7e14' },
    { name: 'Medium', value: stats.by_severity?.medium || 0, color: '#ffc107' },
    { name: 'Low', value: stats.by_severity?.low || 0, color: '#28a745' }
  ];

  const sourceData = Object.entries(stats.by_source || {}).map(([name, value]) => ({
    name: name.charAt(0).toUpperCase() + name.slice(1),
    value
  }));

  return (
    <div className="dashboard-charts">
      <h2>Threat Intelligence Visualization</h2>
      
      <div className="charts-grid">
        <div className="chart-container">
          <h3>Threat Severity Distribution</h3>
          <div className="severity-chart">
            {severityData.map((item, index) => (
              <div key={index} className="severity-bar">
                <div className="bar-header">
                  <span className="severity-name" style={{ color: item.color }}>
                    ● {item.name}
                  </span>
                  <span className="severity-value">{item.value}</span>
                </div>
                <div className="bar-track">
                  <div 
                    className="bar-fill"
                    style={{ 
                      width: `${(item.value / Math.max(...severityData.map(s => s.value))) * 100}%`,
                      backgroundColor: item.color
                    }}
                  ></div>
                </div>
              </div>
            ))}
          </div>
        </div>

        <div className="chart-container">
          <h3>Threats by Data Source</h3>
          <div className="source-chart">
            {sourceData.map((item, index) => (
              <div key={index} className="source-item">
                <span className="source-name">{item.name}</span>
                <span className="source-count">{item.value}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};

export default DashboardCharts;
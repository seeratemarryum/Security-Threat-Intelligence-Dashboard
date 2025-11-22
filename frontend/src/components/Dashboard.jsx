import React, { useState, useEffect } from 'react';
import { threatIntelAPI } from '../api';
import ThreadStats from './ThreadStats';
import ThreadTable from './ThreadTable';
import UploadLogs from './UploadLogs';
import DashboardCharts from './DashboardCharts';
import './Dashboard.css';

const Dashboard = () => {
  const [threatData, setThreatData] = useState([]);
  const [stats, setStats] = useState({
    total_threats: 0,
    by_severity: { critical: 0, high: 0, medium: 0, low: 0 },
    by_source: {},
    by_country: {}
  });
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState('overview');
  const [lastUpdated, setLastUpdated] = useState(null);

  const calculateStats = (data) => {
    const by_severity = { critical: 0, high: 0, medium: 0, low: 0 };
    const by_source = {};
    const by_country = {};

    data.forEach(threat => {
      if (threat.severity && by_severity[threat.severity] !== undefined) {
        by_severity[threat.severity]++;
      }

      const source = threat.source || 'unknown';
      by_source[source] = (by_source[source] || 0) + 1;

      const country = threat.country || 'Unknown';
      by_country[country] = (by_country[country] || 0) + 1;
    });

    return {
      total_threats: data.length,
      by_severity,
      by_source,
      by_country
    };
  };

  const fetchThreatData = async () => {
    try {
      const response = await threatIntelAPI.getThreatIntel();
      if (response.data.success) {
        const newData = response.data.data;
        setThreatData(newData);
        setLastUpdated(response.data.timestamp);
        
        const calculatedStats = calculateStats(newData);
        setStats(calculatedStats);
      }
    } catch (error) {
      console.error('Error fetching threat data:', error);
    }
  };

  const loadData = async () => {
    setLoading(true);
    await fetchThreatData();
    setLoading(false);
  };

  useEffect(() => {
    loadData();
    
    const interval = setInterval(loadData, 120000);
    return () => clearInterval(interval);
  }, []);

  const refreshData = () => {
    loadData();
  };

  const handleDataUpdate = (newThreats) => {
    if (Array.isArray(newThreats)) {
      const formattedThreats = newThreats.map(match => ({
        type: 'log_match',
        ip: match.ip_address,
        severity: match.severity || 'high',
        source: match.source || 'log_analysis',
        country: match.details?.country || 'Unknown',
        abuse_confidence: match.confidence_score,
        details: match.details,
        timestamp: new Date().toISOString()
      }));
      
      const updatedData = [...threatData, ...formattedThreats];
      setThreatData(updatedData);
      const calculatedStats = calculateStats(updatedData);
      setStats(calculatedStats);
    }
    setLastUpdated(new Date().toISOString());
  };

  if (loading) {
    return (
      <div className="loading-container">
        <div className="loading-spinner"></div>
        <div className="loading-text">Loading Security Dashboard...</div>
      </div>
    );
  }

  return (
    <div className="dashboard">
      <header className="dashboard-header">
        <div className="header-content">
          <h1>🛡️ Security Threat Intelligence Dashboard</h1>
          <p>Real-time threat monitoring and log analysis</p>
          {lastUpdated && (
            <div className="last-updated">
              Last updated: {new Date(lastUpdated).toLocaleString()}
            </div>
          )}
        </div>
        <div className="header-actions">
          <button onClick={refreshData} className="refresh-btn">
            🔄 Refresh Now
          </button>
        </div>
      </header>

      <nav className="dashboard-nav">
        <button 
          className={activeTab === 'overview' ? 'active' : ''}
          onClick={() => setActiveTab('overview')}
        >
          📊 Overview
        </button>
        <button 
          className={activeTab === 'threats' ? 'active' : ''}
          onClick={() => setActiveTab('threats')}
        >
          🔍 Threat Feed
        </button>
        <button 
          className={activeTab === 'upload' ? 'active' : ''}
          onClick={() => setActiveTab('upload')}
        >
          📁 Log Analysis
        </button>
      </nav>

      <div className="dashboard-content">
        {activeTab === 'overview' && (
          <div className="overview-tab">
            <div className="quick-stats-grid">
              <div className="stat-card critical">
                <div className="stat-icon">🔴</div>
                <div className="stat-content">
                  <div className="stat-number">{stats.by_severity?.critical || 0}</div>
                  <div className="stat-label">Critical Threats</div>
                </div>
              </div>
              <div className="stat-card high">
                <div className="stat-icon">🟠</div>
                <div className="stat-content">
                  <div className="stat-number">{stats.by_severity?.high || 0}</div>
                  <div className="stat-label">High Severity</div>
                </div>
              </div>
              <div className="stat-card medium">
                <div className="stat-icon">🟡</div>
                <div className="stat-content">
                  <div className="stat-number">{stats.by_severity?.medium || 0}</div>
                  <div className="stat-label">Medium Severity</div>
                </div>
              </div>
              <div className="stat-card total">
                <div className="stat-icon">📈</div>
                <div className="stat-content">
                  <div className="stat-number">{stats.total_threats || 0}</div>
                  <div className="stat-label">Total Threats</div>
                </div>
              </div>
            </div>
            
            <DashboardCharts stats={stats} threatData={threatData} />
            <ThreadStats stats={stats} threatData={threatData} />
          </div>
        )}

        {activeTab === 'threats' && (
          <ThreadTable data={threatData} onRefresh={refreshData} />
        )}

        {activeTab === 'upload' && (
          <UploadLogs onThreatsDetected={handleDataUpdate} />
        )}
      </div>
    </div>
  );
};

export default Dashboard;
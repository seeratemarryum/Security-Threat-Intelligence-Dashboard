import React, { useState } from 'react';

const ThreadTable = ({ data, onRefresh }) => {
  const [filter, setFilter] = useState('all');
  const [searchTerm, setSearchTerm] = useState('');

  const filteredData = data.filter(item => {
    if (!item) return false;
    
    const itemIp = item.ip || '';
    const itemType = item.type || '';
    const itemCountry = item.country || '';
    
    const matchesFilter = filter === 'all' || (item.severity && item.severity === filter);
    const matchesSearch = 
      itemIp.toLowerCase().includes(searchTerm.toLowerCase()) ||
      itemType.toLowerCase().includes(searchTerm.toLowerCase()) ||
      itemCountry.toLowerCase().includes(searchTerm.toLowerCase());
    
    return matchesFilter && matchesSearch;
  });

  const getSeverityClass = (severity) => {
    if (!severity) return 'severity-unknown';
    return `severity-${severity}`;
  };

  return (
    <div className="thread-table">
      <div className="table-controls">
        <div className="search-box">
          <input
            type="text"
            placeholder="Search by IP, type, or country..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
          />
        </div>
        <div className="filter-controls">
          <select value={filter} onChange={(e) => setFilter(e.target.value)}>
            <option value="all">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
        </div>
      </div>

      <div className="table-container">
        <table>
          <thead>
            <tr>
              <th>Type</th>
              <th>IP Address</th>
              <th>Severity</th>
              <th>Country</th>
              <th>Source</th>
              <th>Details</th>
              <th>Confidence</th>
            </tr>
          </thead>
          <tbody>
            {filteredData.map((threat, index) => (
              <tr key={index} className="threat-row">
                <td>
                  <span className={`threat-type ${threat.type?.replace('_', ' ') || 'unknown'}`}>
                    {threat.type?.replace('_', ' ') || 'Unknown'}
                  </span>
                </td>
                <td className="ip-address">{threat.ip || 'N/A'}</td>
                <td>
                  <span className={`severity-badge ${getSeverityClass(threat.severity)}`}>
                    {threat.severity || 'unknown'}
                  </span>
                </td>
                <td>{threat.country || 'Unknown'}</td>
                <td>
                  <span className="source-badge">{threat.source || 'unknown'}</span>
                </td>
                <td className="threat-details">
                  {threat.source === 'shodan' && (
                    <span>Port {threat.port || 'N/A'} - {threat.product || 'Unknown'}</span>
                  )}
                  {threat.source === 'abuseipdb' && (
                    <span>{threat.isp || 'Unknown'} - {threat.total_reports || 0} reports</span>
                  )}
                </td>
                <td>
                  {threat.abuse_confidence && (
                    <div className="confidence-score">
                      {threat.abuse_confidence}%
                    </div>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        
        {filteredData.length === 0 && (
          <div className="no-data">
            No threats found matching your criteria.
          </div>
        )}
      </div>
    </div>
  );
};

export default ThreadTable;
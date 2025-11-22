import React, { useState } from 'react';
import { threatIntelAPI } from '../api';

const UploadLogs = ({ onThreatsDetected }) => {
  const [selectedFile, setSelectedFile] = useState(null);
  const [uploading, setUploading] = useState(false);
  const [results, setResults] = useState(null);
  const [error, setError] = useState('');

  const handleFileSelect = (event) => {
    const file = event.target.files[0];
    if (file) {
      setSelectedFile(file);
      setError('');
      setResults(null);
    }
  };

  const handleUpload = async () => {
    if (!selectedFile) {
      setError('Please select a file first');
      return;
    }

    setUploading(true);
    setError('');

    const formData = new FormData();
    formData.append('file', selectedFile);

    try {
      const response = await threatIntelAPI.uploadLogs(formData);
      if (response.data.success) {
        setResults(response.data);
        if (response.data.threat_matches > 0) {
          onThreatsDetected && onThreatsDetected(response.data.matches);
        }
      } else {
        setError(response.data.error || 'Upload failed');
      }
    } catch (err) {
      setError('Upload failed: ' + (err.response?.data?.error || err.message));
    } finally {
      setUploading(false);
    }
  };

  const resetForm = () => {
    setSelectedFile(null);
    setResults(null);
    setError('');
  };

  return (
    <div className="upload-logs">
      <h2>Log File Analysis</h2>
      <p>Upload your server logs to cross-check against threat intelligence feeds</p>

      {!results ? (
        <div className="upload-area">
          <div className="file-input-container">
            <input
              type="file"
              id="log-file"
              onChange={handleFileSelect}
              accept=".log,.txt,.csv"
            />
            <label htmlFor="log-file" className="file-label">
              {selectedFile ? selectedFile.name : 'Choose Log File'}
            </label>
          </div>

          <button 
            onClick={handleUpload} 
            disabled={!selectedFile || uploading}
            className="upload-btn"
          >
            {uploading ? 'Analyzing...' : 'Analyze Logs'}
          </button>
        </div>
      ) : (
        <div className="results-section">
          <div className="results-header">
            <h3>Analysis Results</h3>
            <button onClick={resetForm} className="new-analysis-btn">
              New Analysis
            </button>
          </div>
          
          <div className="result-stats">
            <div className="result-stat">
              <strong>Processed Entries:</strong> {results.processed_entries}
            </div>
            <div className="result-stat">
              <strong>Threat Matches:</strong> {results.threat_matches}
            </div>
          </div>

          {results.matches && results.matches.length > 0 && (
            <div className="threat-matches">
              <h4>🚨 Threat Matches Found</h4>
              {results.matches.map((match, index) => (
                <div key={index} className="threat-match">
                  <div className="match-header">
                    <span className="ip-address">{match.ip_address}</span>
                    <span className={`severity-badge severity-${match.severity}`}>
                      {match.severity}
                    </span>
                    <span className="confidence">
                      Confidence: {match.confidence_score}%
                    </span>
                  </div>
                  <div className="match-details">
                    <div className="log-entry">
                      <strong>Log Entry:</strong> {match.log_entry.content}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}

          {results.matches && results.matches.length === 0 && (
            <div className="no-threats">
              <div className="success-icon">✅</div>
              <h4>No Threat Matches Found</h4>
              <p>No malicious IP addresses were detected in your log file.</p>
            </div>
          )}
        </div>
      )}

      {error && (
        <div className="error-message">
          {error}
        </div>
      )}
    </div>
  );
};

export default UploadLogs;
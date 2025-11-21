# 🔒 Security Threat Intelligence Dashboard

A comprehensive security dashboard that aggregates threat intelligence from **Shodan** and **AbuseIPDB**, with log analysis capabilities for security monitoring and threat detection.

![Dashboard Overview](screenshots/dashboard-overview.png)

## ✨ Features

### 🔍 **Threat Intelligence Aggregation**
- **Shodan Integration**: Discover vulnerable services and exposed systems
- **AbuseIPDB Integration**: Identify malicious IP addresses from global reports
- **Real-time Data**: Live threat intelligence feeds
- **Multi-source Correlation**: Combine data from multiple threat intelligence sources

### 📊 **Interactive Dashboards**
- **Threat Overview**: Visualize threats by severity, source, and geography
- **Statistics & Charts**: Interactive charts showing threat distribution
- **Real-time Metrics**: Live counters and severity breakdowns
- **Filtering & Search**: Advanced filtering by severity, source, and keywords

### 📁 **Log Analysis & Correlation**
- **Log Upload**: Upload server, firewall, or application logs
- **IP Cross-referencing**: Automatically match log entries with threat intelligence
- **Attack Pattern Detection**: Identify SQL injection, XSS, path traversal attempts
- **Security Reporting**: Generate comprehensive security assessment reports

### 🎯 **Threat Investigation**
- **IP Reputation Checking**: Detailed analysis of specific IP addresses
- **Threat Details**: View comprehensive threat information
- **Confidence Scoring**: Abuse confidence scores and severity ratings
- **Geolocation Data**: Threat origin mapping and country analysis

## 🛠️ Technology Stack

### Backend
- **Python 3.8+** with Flask web framework
- **Shodan API** for vulnerability intelligence
- **AbuseIPDB API** for IP reputation data
- **RESTful API** architecture

### Frontend
- **React 18** with modern hooks
- **Chart.js** for data visualization
- **Axios** for API communication
- **CSS3** with responsive design

## 🚀 Quick Start

### Prerequisites
- Python 3.8 or higher
- Node.js 14 or higher
- Shodan API account
- AbuseIPDB API account

### Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd security-dashboard

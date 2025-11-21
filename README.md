# 🔒 Security Threat Intelligence Dashboard

A comprehensive security dashboard that aggregates threat intelligence from **Shodan** and **AbuseIPDB**, with log analysis capabilities for security monitoring and threat detection.

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

2. **Backend Setup**
bash

cd backend
python -m venv venv
venv\Scripts\activate  # Windows
# source venv/bin/activate  # Linux/Mac
pip install -r requirements.txt

3. **Configure API Keys**
bash

# Create .env file in backend directory
echo "SHODAN_API_KEY=your_shodan_key_here" > .env
echo "ABUSEIPDB_API_KEY=your_abuseipdb_key_here" >> .env

4. **Frontend Setup**
bash

cd frontend
npm install

**Running the Application**
    **Start Backend** (Terminal 1)
    cd backend
    python app.py
Backend runs on: http://localhost:5000

   **Start Frontend (Terminal 2)**
   cd frontend
   npm start

Frontend runs on: http://localhost:3000

**Access Dashboard**
Open http://localhost:3000 in your browser

**🔧 API Endpoints**
**Threat Intelligence**

    GET /api/threat-intel - Get threat intelligence feed

    GET /api/stats - Get threat statistics

    GET /api/check-ip/<ip> - Check specific IP reputation

**Log Analysis**

    POST /api/upload-logs - Upload and analyze log files

    GET /api/search - Search threats

**System**

    GET /api/health - System health check

🎯 **Usage Examples**
**1. Monitoring Threat Feed**

    Navigate to "Threat Feed" tab

    Filter by severity (Critical, High, Medium, Low)

    Search specific IPs or countries

    View detailed threat information

**2. Analyzing Log Files**

    Go to "Log Analysis" tab

    Upload server logs (Apache, Nginx, etc.)

    Review automatic threat matches

    Download security report

**3. Investigating Specific IPs**

    Use IP check feature in Threat Feed

    Get combined intelligence from Shodan & AbuseIPDB

    View vulnerability and reputation data

**🔒 Security Features**

    Real-time Threat Intelligence: Live data from trusted sources

    Automated Correlation: Automatic matching of logs with threat data

    Severity Classification: Intelligent threat scoring

    Comprehensive Reporting: Detailed security assessment

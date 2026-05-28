# System Architecture - Network IDS

## Overview

The Network Intrusion Detection System (NIDS) is a modular architecture consisting of:
1. **Suricata IDS Engine** - Network packet capture and analysis
2. **Alert Monitor** - Real-time alert processing
3. **Response Handler** - Automated incident response
4. **Dashboard** - Web-based visualization

## Architecture Diagram

```
                              Network Traffic
                                    |
                                    v
                    +---------------------------+
                    |  Network Interface (eth0) |
                    +---------------------------+
                                    |
                                    v
                    +---------------------------+
                    |   Suricata IDS Engine     |
                    |  (Packet Capture & Rules)|
                    |  - Protocol Analysis     |
                    |  - Pattern Matching      |
                    |  - Alert Generation      |
                    +---------------------------+
                                    |
                                    v
                         eve.json (JSON alerts)
                                    |
                    +-------+-------+-------+
                    |       |               |
                    v       v               v
        Alert Log  Fast Log Syslog    Unified Log
                    |
                    v
                    +---------------------------+
                    |   Alert Monitor (Python) |
                    |  - Log parsing           |
                    |  - Alert aggregation     |
                    |  - Severity filtering    |
                    |  - Statistics tracking   |
                    +---------------------------+
                                    |
                                    v
                    processed_alerts.json
                                    |
                                    v
                    +---------------------------+
                    | Response Handler (Python)|
                    |  - IP blocking (iptables)|
                    |  - Rate limiting (tc)    |
                    |  - Enhanced logging      |
                    |  - Incident ticketing    |
                    +---------------------------+
                                    |
                                    v
                    response_actions.json
                    incident_tickets.json
                    blocked_ips.txt
                                    |
                    +-------+-------+-------+
                    |       |               |
                    v       v               v
            Iptables  Syslog  Notifications
            Rules    Entries   Alerts
                    |
                    v
                    +---------------------------+
                    | Dashboard (Flask/Web)    |
                    |  - Statistics display    |
                    |  - Chart visualization   |
                    |  - Real-time metrics     |
                    |  - Incident tracking     |
                    +---------------------------+
                                    |
                                    v
                    http://localhost:5000
```

## Component Details

### 1. Suricata IDS Engine

**Location:** Container `ids-suricata`
**Configuration:** `config/suricata.yaml`
**Rules:** `rules/*.rules`
**Output:** `/var/log/suricata/eve.json`

**Responsibilities:**
- Captures packets from network interface
- Applies detection rules
- Generates alerts in JSON format
- Logs protocol-specific data (DNS, HTTP, TLS)
- Performs stream reassembly

**Key Files:**
- `eve.json` - Main event log (all alerts)
- `alert.log` - Consolidated alerts
- `fast.log` - Fast alert format
- `suricata.log` - Service logs

**Performance Metrics:**
- Processes packets in real-time
- ~100K packets/sec typical throughput
- Memory: 500MB-2GB depending on rules
- CPU: Scales with packet rate

### 2. Alert Monitor Service

**Location:** Container `ids-monitor`
**Script:** `scripts/alert_monitor.py`
**Input:** `/var/log/suricata/eve.json`
**Output:** `processed_alerts.json`, `blocked_ips.txt`

**Responsibilities:**
- Reads Suricata alerts continuously
- Parses JSON alert format
- Filters duplicate alerts
- Calculates threat statistics
- Determines action severity
- Logs processed alerts
- Sends notifications

**Key Methods:**
```
process_alert()           - Main alert processing
handle_critical_alert()   - Critical severity (SID=1)
handle_high_alert()       - High severity (SID=2)
handle_medium_alert()     - Medium/Low severity (SID=3-4)
block_ip()                - IP blocking logic
log_alert()               - Structured logging
```

**Output Format:**
```json
{
  "timestamp": "2026-05-10T14:30:45.123456",
  "message": "SQL Injection attempt",
  "src_ip": "203.0.113.50",
  "dest_ip": "192.168.1.100",
  "dest_port": 80,
  "severity": 2,
  "processed_at": "2026-05-10T14:30:46"
}
```

### 3. Response Handler Service

**Location:** Container `ids-response`
**Script:** `scripts/response_handler.py`
**Input:** `processed_alerts.json`
**Output:** `response_actions.json`, `incident_tickets.json`

**Responsibilities:**
- Monitors processed alerts
- Implements response actions
- Manages IP whitelist
- Blocks malicious IPs (iptables)
- Rate limits suspicious traffic
- Creates incident tickets
- Logs all actions taken

**Response Actions:**
```
BLOCK_IP          - Add firewall rule to block IP
RATE_LIMIT        - Limit bandwidth to suspicious IP
REROUTE_TRAFFIC   - Redirect traffic away
ENHANCED_LOGGING  - Enable detailed logging
INCIDENT_TICKET   - Create incident for review
```

**Decision Tree:**
```
Alert received
  ↓
Check whitelist?
  ├─ Yes → Skip
  └─ No → Check severity
        ↓
    Severity=1 (Critical)?
      ├─ Yes → Block IP + Log + Ticket
      └─ No → Severity=2 (High)?
          ├─ Yes → Block (600s) + Ticket
          └─ No → Rate limit + Enhanced logging
```

### 4. Dashboard Service

**Location:** Container `ids-dashboard`, Port 5000
**Application:** `dashboard/app.py`
**Template:** `dashboard/templates/dashboard.html`

**Responsibilities:**
- Serves web interface on port 5000
- Provides API endpoints
- Loads data from JSON files
- Visualizes statistics
- Shows real-time metrics
- Displays threat intelligence

**API Endpoints:**
```
GET /api/statistics    - Overall stats and trends
GET /api/alerts        - Recent alerts
GET /api/blocked-ips   - Currently blocked IPs
GET /api/incidents     - Open incidents
GET /api/health        - System health status
```

**Dashboard Features:**
- Real-time metrics cards
- Severity distribution pie chart
- Hourly alert trend line graph
- Top attackers table
- Latest alerts log
- Blocked IP history
- System status indicator

## Data Flow

### Alert Processing Pipeline

```
1. Packet arrives on eth0
2. Suricata captures packet
3. Pattern matching against rules
4. Alert generated if match
5. Alert written to eve.json
6. Alert Monitor reads eve.json
7. Duplicate check
8. Severity determination
9. Alert logged to processed_alerts.json
10. Response Handler reads processed_alerts.json
11. Whitelist check
12. Response action executed
13. Action logged to response_actions.json
14. Dashboard reads data files
15. Statistics calculated
16. Web UI updated (10s refresh)
```

## File Structure

```
/app/
├── config/
│   ├── suricata.yaml           # Main Suricata config
│   └── whitelist.txt           # Trusted IPs
├── rules/
│   ├── custom-rules.rules      # Custom detection rules
│   └── default-rules.rules     # Standard patterns
├── scripts/
│   ├── alert_monitor.py        # Alert processor
│   └── response_handler.py     # Response executor
├── dashboard/
│   ├── app.py                  # Flask application
│   └── templates/
│       └── dashboard.html      # Web UI
├── logs/                       # Log directory
│   ├── suricata/              # Suricata output
│   ├── monitor/               # Alert monitor logs
│   ├── response/              # Response handler logs
│   └── dashboard/             # Dashboard logs
├── data/                       # Persistent data
│   ├── processed_alerts.json   # Alert log
│   ├── response_actions.json   # Response actions
│   ├── incident_tickets.json   # Incident log
│   └── blocked_ips.txt         # Blocked IP list
├── docker-compose.yml
├── Dockerfile.*               # Container definitions
├── requirements.txt           # Python dependencies
├── README.md                  # Main documentation
└── DEPLOYMENT.md              # Deployment guide
```

## Security Model

### Defense Layers

1. **Detection Layer (Suricata)**
   - Network-based detection
   - Pattern matching against threats
   - Protocol analysis

2. **Processing Layer (Alert Monitor)**
   - Alert filtering and aggregation
   - Duplicate elimination
   - Severity classification

3. **Response Layer (Response Handler)**
   - Automated blocking
   - Rate limiting
   - Incident documentation

4. **Presentation Layer (Dashboard)**
   - Visualization
   - Analytics
   - Incident tracking

### Trust Boundaries

```
                    Internet
                       |
                   [Firewall]
                       |
                 [Monitoring IDS]
                       |
           [Internal Network]
               |           |
           [Systems]   [Dashboard]
                           (Trusted Admin Access)
```

## Performance Considerations

### CPU Usage

- Suricata: 1 CPU per 5Gbps throughput
- Alert Monitor: ~0.1 CPU (lightweight)
- Response Handler: ~0.05 CPU (lightweight)
- Dashboard: ~0.1 CPU (on-demand)

### Memory Usage

- Suricata: 1GB base + 500MB per 1000 rules
- Alert Monitor: 100MB
- Response Handler: 100MB
- Dashboard: 200MB

### Disk Usage

- Alert logs: ~100MB per 1M alerts
- Response logs: ~10MB per 100K actions
- Historical data: ~500MB per month

### Scalability

**For 10Gbps Network:**
- 4 Suricata threads
- Distributed rule set
- Elasticsearch for aggregation
- Kafka for alert buffering

## Integration Points

### Input Sources
- Network traffic (packet capture)
- Rule feeds (GitHub, commercial)
- Threat intelligence feeds

### Output Destinations
- Syslog servers
- SIEM platforms (Splunk, ELK)
- Incident response systems
- Ticketing systems
- Email/Slack notifications
- WAF/NGFW devices

## Deployment Models

### Model 1: Standalone
- Single system monitoring one interface
- Local storage
- Single dashboard

### Model 2: Distributed
- Multiple capture points
- Centralized aggregation
- Shared dashboard

### Model 3: Cloud
- AWS EC2 / GCP Compute
- CloudWatch/Stackdriver integration
- Managed logging services

## Future Enhancements

- Machine Learning-based anomaly detection
- Threat intelligence feed integration
- Automated incident response playbooks
- HA/Failover setup
- Multi-tenancy support
- Advanced visualization (3D attack maps)

---
Version: 1.0
Updated: May 2026

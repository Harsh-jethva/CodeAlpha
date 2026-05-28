# Network Intrusion Detection System - Complete Package

## Quick Overview

This is a production-ready Network Intrusion Detection System (NIDS) using Suricata with automated response mechanisms and web-based visualization.

## What You Get

### Core Services
1. **Suricata IDS** - Real-time network packet analysis and threat detection
2. **Alert Monitor** - Processes and aggregates alerts from Suricata
3. **Response Handler** - Automatically blocks threats using iptables
4. **Web Dashboard** - Real-time visualization at http://localhost:5000

### Features
✅ Real-time network monitoring  
✅ Custom and default detection rules  
✅ Automated IP blocking and rate limiting  
✅ Incident ticketing system  
✅ Live threat dashboard  
✅ JSON-based alert storage  
✅ Docker containerization  
✅ Fully documented and tested  

## File Structure

```
t4/
├── README.md                    ← Start here!
├── DEPLOYMENT.md                ← Deployment guide
├── ARCHITECTURE.md              ← System design documentation
├── TROUBLESHOOTING.md           ← Troubleshooting guide
├── test_suite.py                ← Automated test suite
├── quickstart.sh                ← Quick start script
├── requirements.txt             ← Python dependencies
│
├── config/
│   ├── suricata.yaml           ← Main Suricata configuration
│   └── whitelist.txt           ← Trusted IPs (won't be blocked)
│
├── rules/
│   ├── custom-rules.rules      ← 101 custom detection rules
│   └── default-rules.rules     ← 39 standard detection patterns
│
├── scripts/
│   ├── alert_monitor.py        ← Alert processing engine
│   └── response_handler.py     ← Response action executor
│
├── dashboard/
│   ├── app.py                  ← Flask web application
│   └── templates/
│       └── dashboard.html      ← Interactive web dashboard
│
├── docker-compose.yml          ← Service orchestration
├── Dockerfile.monitor          ← Alert monitor container
├── Dockerfile.response         ← Response handler container
├── Dockerfile.dashboard        ← Dashboard container
│
├── logs/                       ← (created on first run)
│   ├── suricata/              ← Suricata output logs
│   ├── monitor/               ← Alert monitor logs
│   ├── response/              ← Response handler logs
│   └── dashboard/             ← Dashboard application logs
│
└── data/                       ← (created on first run)
    ├── processed_alerts.json   ← Structured alert log
    ├── response_actions.json   ← Response action history
    ├── incident_tickets.json   ← Incident log
    └── blocked_ips.txt         ← IP block log
```

## Getting Started

### Option 1: Quick Start (5 minutes)

```bash
# Make script executable
chmod +x quickstart.sh

# Run quick start
./quickstart.sh

# Dashboard will be available at http://localhost:5000
```

### Option 2: Manual Setup

```bash
# Create required directories
mkdir -p logs/suricata logs/monitor logs/response logs/dashboard data

# Install dependencies (Python only)
pip install -r requirements.txt

# Start with Docker Compose
docker-compose up -d

# Check status
docker-compose ps

# View dashboard
# Open http://localhost:5000 in browser
```

## Key Components Explained

### 1. Suricata Configuration (config/suricata.yaml)
- Network interface monitoring setup
- Home/external network definitions
- Buffer and stream reassembly settings
- Detection engine configuration
- Performance tuning options

### 2. Detection Rules (rules/)
**custom-rules.rules** contains:
- SQL Injection detection (4 rules)
- Buffer Overflow detection (3 rules)
- Port Scan detection (5 rules)
- Command Injection detection (4 rules)
- Malware Signatures (4 rules)
- DDoS Pattern detection (4 rules)
- Reconnaissance & Scanning (3 rules)
- Suspicious Protocol behavior (3 rules)
- Network Anomalies (3 rules)
- Exploit Signatures (3 rules)
- File Transfer Monitoring (2 rules)

**default-rules.rules** contains:
- Protocol Violations (3 rules)
- Policy Violations (4 rules)
- Suspicious Patterns (3 rules)
- Application Attacks (4 rules)
- Network Defense Evasion (2 rules)
- System Access Attempts (4 rules)
- Credential Attacks (2 rules)
- Network Scanning Tools (2 rules)
- VPN & Tunneling detection (2 rules)
- Proxy & Tunneling detection (1 rule)
- Botnet Signatures (2 rules)
- Ransomware Patterns (2 rules)

### 3. Alert Monitor (scripts/alert_monitor.py)
Continuously monitors Suricata alerts and:
- Reads eve.json for new alerts
- Deduplicates alerts
- Classifies severity levels
- Tracks threat statistics
- Blocks critical IPs
- Sends notifications
- Maintains processed alert log

### 4. Response Handler (scripts/response_handler.py)
Executes automated responses:
- Blocks malicious IPs (iptables)
- Rate limits suspicious traffic
- Reroutes attack traffic
- Enables enhanced logging
- Creates incident tickets
- Maintains whitelist

### 5. Dashboard (dashboard/app.py)
Web interface showing:
- Real-time alert metrics
- Threat severity distribution
- Hourly alert trends
- Top attacking IPs
- Latest alerts
- Blocked IP history
- Incident status
- System health

## Monitoring the System

### View Real-Time Alerts
```bash
# Suricata alerts
tail -f logs/suricata/eve.json | jq .

# Processed alerts
tail -f data/processed_alerts.json | jq .

# Response actions
tail -f data/response_actions.json | jq .
```

### Check Dashboard
Open browser: `http://localhost:5000`

### View Logs
```bash
# All services
docker-compose logs -f

# Specific service
docker logs -f ids-suricata
docker logs -f ids-monitor
docker logs -f ids-response
docker logs -f ids-dashboard
```

## Configuration Tips

### Monitor Different Interface
Edit `config/suricata.yaml` and change eth0 to your interface:
```yaml
inputs:
  - interface: ens0
```

### Define Your Network
Edit `config/suricata.yaml` HOME_NET:
```yaml
vars:
  address-groups:
    HOME_NET: "[192.168.0.0/16, 10.0.0.0/8]"
```

### Whitelist Trusted IPs
Edit `config/whitelist.txt` to prevent false positives:
```
192.168.1.100
203.0.113.50
10.0.0.0/8
```

### Add Custom Rules
Add to `rules/custom-rules.rules`:
```
alert tcp any any -> any 22 (msg:"SSH login attempt"; flow:to_server; sid:1010000;)
```

## Testing

Run the automated test suite:
```bash
python3 test_suite.py
```

This will verify:
- Environment setup
- Configuration validity
- Service deployment
- Connectivity
- Log generation
- Rule syntax
- Alert generation
- Response actions
- Performance metrics
- Dashboard functionality
- Security configuration

## Performance Tuning

### High Traffic Networks (>10Gbps)
- Enable multithreading in suricata.yaml
- Increase buffer sizes
- Reduce rule set
- Use SSD for logs

### Low Resource Systems
- Disable unused protocol analyzers
- Reduce rule set
- Single-threaded mode
- Smaller stream buffers

See DEPLOYMENT.md for detailed tuning guide.

## Integration Examples

### Send Alerts to Splunk
Modify `scripts/alert_monitor.py` to post to Splunk HTTP Event Collector

### Slack Notifications
Add webhook integration in response_handler.py

### SIEM Integration
Export alerts to ELK Stack or other SIEM

### Ticketing Systems
Create tickets in Jira or ServiceNow automatically

See DEPLOYMENT.md for integration examples.

## Troubleshooting

### No Alerts Generated
1. Verify network interface: `ip link show`
2. Check traffic exists: `sudo tcpdump -i eth0 -c 10`
3. Validate rules loaded: `suricata -c config/suricata.yaml -S`

### High CPU Usage
1. Disable expensive rules
2. Enable multithreading
3. Reduce buffer sizes
4. Increase system buffers

### Memory Issues
1. Reduce stream reassembly buffer
2. Decrease app-layer memcap
3. Use smaller rule set

### Dashboard Not Loading
1. Check port 5000: `sudo netstat -tlnp | grep 5000`
2. View logs: `docker logs ids-dashboard`
3. Restart: `docker-compose restart dashboard`

Full troubleshooting guide available in TROUBLESHOOTING.md

## Security Considerations

⚠️ **Important:**
- Run with minimal necessary privileges
- Secure dashboard with authentication in production
- Protect alert logs (contain network information)
- Keep rule sets updated
- Monitor system resources
- Implement regular backups

## Next Steps

1. ✅ Read README.md (you are here)
2. 📖 Review DEPLOYMENT.md for detailed setup
3. 🏗️ Study ARCHITECTURE.md to understand design
4. 🧪 Run test_suite.py to verify installation
5. 🎯 Access dashboard at http://localhost:5000
6. 📊 Analyze alerts and fine-tune rules
7. 🔧 Configure response actions
8. 📈 Monitor and tune for your network

## Support

- **Suricata Docs:** https://suricata.io/documentation/
- **Rules Reference:** https://suricata.readthedocs.io/
- **Community:** https://suricata.io/community/

## License & Attribution

This IDS package uses:
- Suricata (open source)
- Python ecosystem
- Flask web framework
- Chart.js visualization

See respective projects for licenses.

---

**Version:** 1.0  
**Created:** May 2026  
**Status:** Production Ready

**Questions?** See DEPLOYMENT.md, ARCHITECTURE.md, or TROUBLESHOOTING.md

# Network Intrusion Detection System (NIDS)

A comprehensive Network-based Intrusion Detection System using Suricata with automated alerting, response mechanisms, and real-time visualization.

## Features

- **Real-time Threat Detection**: Uses Suricata IDS engine to monitor network traffic
- **Custom Alert Rules**: Detectable threats include SQL injection, buffer overflow, port scans, malware signatures
- **Automated Response**: Blocks suspicious IPs, logs incidents, triggers notifications
- **Live Dashboard**: Web-based visualization of detected threats and network activity
- **Continuous Monitoring**: Runs as persistent services with log aggregation
- **Integration Ready**: Works with ELK Stack, Splunk, or custom logging systems

## Architecture

```
Network Interface (eth0)
    ↓
Suricata (IDS Engine)
    ├─ Rule Engine
    ├─ Protocol Analyzer
    └─ Alert Generator
    ↓
Alert Processing
    ├─ Log Aggregator
    ├─ Response Handler
    └─ Notification System
    ↓
Visualization Dashboard
    ├─ Attack Metrics
    ├─ Timeline
    └─ Threat Intelligence
```

## Quick Start

### Prerequisites
- Docker & Docker Compose (OR)
- Linux/Unix system with Suricata installed
- Python 3.8+
- Network interface to monitor

### Option 1: Docker Setup (Recommended)

```bash
# Build and start services
docker-compose up -d

# View logs
docker-compose logs -f suricata
docker-compose logs -f monitor
docker-compose logs -f dashboard
```

### Option 2: Manual Setup

```bash
# Install Suricata
sudo apt-get install suricata

# Copy configuration
sudo cp suricata.yaml /etc/suricata/

# Start Suricata
sudo systemctl start suricata

# Run Python services
python3 alert_monitor.py &
python3 response_handler.py &
python3 run_dashboard.py
```

## Files

- `suricata.yaml` - Main Suricata configuration
- `rules/custom-rules.rules` - Custom detection rules
- `rules/default-rules.rules` - Standard threat patterns
- `alert_monitor.py` - Reads and processes alerts
- `response_handler.py` - Implements response actions
- `run_dashboard.py` - Flask-based visualization dashboard
- `docker-compose.yml` - Containerized deployment
- `Dockerfile` - Container image definition

## Configuration

### Network Interface
Edit `suricata.yaml` to specify the interface to monitor:
```yaml
vars:
  address-groups:
    HOME_NET: "[192.168.0.0/16,10.0.0.0/8]"
    EXTERNAL_NET: "!$HOME_NET"
    HTTP_PORTS: "80"
    SHELLCODE_PORTS: "!80"
    SSH_PORTS: "22"
```

### Custom Rules
Add detection rules in `rules/custom-rules.rules`:
```
alert tcp any any -> any any (msg:"Detect Port Scan"; flow:stateless; flags:!A; sid:1000001;)
```

## Monitoring

### Real-time Alerts
```bash
tail -f /var/log/suricata/eve.json
```

### Dashboard Access
Open browser: `http://localhost:5000`

## Response Actions

The system automatically:
1. **Logs threats** - Stores incident details for forensics
2. **Blocks IPs** - Uses iptables to block malicious sources
3. **Sends alerts** - Notifies administrators
4. **Creates reports** - Generates daily incident summaries

## Rules Categories

- **SQL Injection**: Detects SQL injection attempts
- **Buffer Overflow**: Identifies buffer overflow exploits
- **Port Scans**: Recognizes network reconnaissance
- **Malware Signatures**: Matches known malicious patterns
- **DDoS Patterns**: Detects distributed attack indicators
- **Command Injection**: Identifies shell command injection
- **Suspicious Protocols**: Monitors unusual network behavior

## Performance Tuning

For high-traffic networks, adjust in `suricata.yaml`:
```yaml
threading:
  set-cpu-affinity: yes
  cpu-affinity:
    - management-cpu-set:
        cpu: [ "0" ]
      receive-cpu-set:
        cpu: [ "1" ]
```

## Troubleshooting

### No Alerts Generated
- Check network interface name: `ip link show`
- Verify rules loaded: `suricata -c suricata.yaml -T`
- Check alert log: `tail -f /var/log/suricata/alert-debug.log`

### High CPU Usage
- Reduce rule set
- Enable multithreading
- Check capture filter

### Dashboard Not Loading
```bash
python3 run_dashboard.py --debug
```

## Security Considerations

⚠️ **Important**: 
- Run Suricata with appropriate permissions
- Keep rule sets updated
- Monitor system resources
- Implement access controls on dashboard
- Use HTTPS in production

## Future Enhancements

- [ ] Integration with threat intelligence feeds
- [ ] Machine learning-based anomaly detection
- [ ] Automated incident response with Playbooks
- [ ] Cloud deployment templates (AWS/GCP)
- [ ] Mobile alerting notifications
- [ ] Compliance reporting (PCI-DSS, HIPAA)

## Support & Documentation

For Suricata documentation: https://suricata.io/documentation/
For rules reference: https://github.com/OISF/suricata-rules

---
**Last Updated**: May 2026

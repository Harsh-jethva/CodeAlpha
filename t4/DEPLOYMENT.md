# Deployment Guide - Network Intrusion Detection System

## Prerequisites

- Docker & Docker Compose installed
- Linux kernel with iptables support
- Network interface available for monitoring (e.g., eth0)
- 2GB+ RAM available
- 10GB+ disk space for logs

## Quick Deployment

### Option 1: Docker Compose (Recommended)

1. **Verify network interface:**
   ```bash
   ip link show
   # Note: Replace eth0 in configs if interface name differs
   ```

2. **Create logs directory:**
   ```bash
   mkdir -p logs/suricata logs/monitor data
   chmod 755 logs data
   ```

3. **Update interface in configuration:**
   ```bash
   # Edit config/suricata.yaml
   # Change eth0 to your interface name if needed
   ```

4. **Start services:**
   ```bash
   docker-compose up -d
   ```

5. **Access dashboard:**
   ```
   http://localhost:5000
   ```

6. **View logs:**
   ```bash
   # Suricata IDS
   docker logs -f ids-suricata
   
   # Alert Monitor
   docker logs -f ids-monitor
   
   # Response Handler
   docker logs -f ids-response
   
   # Dashboard
   docker logs -f ids-dashboard
   ```

### Option 2: Manual Installation (Linux)

1. **Install Suricata:**
   ```bash
   sudo apt-get update
   sudo apt-get install suricata
   ```

2. **Configure Suricata:**
   ```bash
   sudo cp config/suricata.yaml /etc/suricata/
   sudo cp rules/*.rules /etc/suricata/rules/
   sudo suricata -c /etc/suricata/suricata.yaml -T  # Test config
   ```

3. **Start Suricata:**
   ```bash
   sudo systemctl restart suricata
   sudo systemctl enable suricata
   ```

4. **Install Python dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

5. **Run services in separate terminals:**
   ```bash
   # Terminal 1 - Alert Monitor
   python3 scripts/alert_monitor.py
   
   # Terminal 2 - Response Handler
   python3 scripts/response_handler.py
   
   # Terminal 3 - Dashboard
   python3 -m dashboard.app
   ```

## Configuration

### Suricata Configuration (config/suricata.yaml)

Key settings to customize:

- **Network Interface:** Change `eth0` to your interface
- **HOME_NET:** Define your internal network ranges
- **EXTERNAL_NET:** Define external networks
- **Listening Port:** Adjust capture buffer and NIC settings for performance

### Custom Rules (rules/custom-rules.rules)

Add your custom detection rules:

```
alert tcp $EXTERNAL_NET any -> $HOME_NET 22 (
    msg:"Custom SSH scan detection";
    flow:to_server,new;
    flags:S;
    sid:1000999;
)
```

### Whitelist (config/whitelist.txt)

Add trusted IPs to prevent false positive blocks:
```
192.168.1.100
203.0.113.50
10.0.0.0/8
```

## Monitoring

### Real-time Log Viewing

```bash
# Watch Suricata alerts
tail -f /var/log/suricata/alert.log

# Watch JSON alerts
tail -f /var/log/suricata/eve.json | jq .

# Monitor processed alerts
tail -f processed_alerts.json | jq .
```

### Dashboard Metrics

Access http://localhost:5000 to view:
- Real-time alert statistics
- Attack source analysis
- Threat distribution
- Hourly trend analysis
- Blocked IP addresses
- Incident tickets
- Response action history

## Performance Tuning

### For High-Traffic Networks (>10Gbps)

1. **Enable multithreading in suricata.yaml:**
   ```yaml
   threading:
     set-cpu-affinity: yes
     cpu-affinity:
       - management-cpu-set: cpu: ["0"]
         receive-cpu-set: cpu: ["1-2"]
         worker-cpu-set: cpu: ["3-11"]
   ```

2. **Increase buffer sizes:**
   ```yaml
   inputs:
     - interface: eth0
       ring-size: 500000
       buffer-size: 64000
   ```

3. **Optimize rule set:**
   - Remove unused rules
   - Use `rule profiling` to identify slow rules
   - Use `threshold` to avoid alert spam

### For Low-Resource Systems

1. **Reduce rule set:**
   ```bash
   # Only load critical rules
   # Edit suricata.yaml to include fewer rule files
   ```

2. **Disable protocol analyzers:**
   ```yaml
   app-layer:
     protocols:
       tls: no
       http: yes
       dns: no
   ```

## Troubleshooting

### No alerts being generated

1. **Verify interface is capturing traffic:**
   ```bash
   sudo tcpdump -i eth0 -c 10  # Should show packets
   ```

2. **Check Suricata is running:**
   ```bash
   sudo systemctl status suricata
   ps aux | grep suricata
   ```

3. **Verify rules are loaded:**
   ```bash
   suricata -c /etc/suricata/suricata.yaml -T
   suricata -c /etc/suricata/suricata.yaml -S | wc -l
   ```

4. **Check logs for errors:**
   ```bash
   tail -f /var/log/suricata/suricata.log
   ```

### High CPU usage

1. **Identify slow rules:**
   ```bash
   grep "rule:" /var/log/suricata/suricata.log | grep "slow"
   ```

2. **Reduce rule set or disable problematic rules**

3. **Enable rule profiling in suricata.yaml:**
   ```yaml
   profiling:
     rules: yes
   ```

### Memory issues

1. **Check memory usage:**
   ```bash
   ps aux | grep suricata
   free -h
   ```

2. **Reduce stream reassembly:**
   ```yaml
   stream:
     memcap: 16777216  # 16MB instead of 32MB
   ```

## Security Considerations

1. **Run with minimal privileges:**
   - Suricata should NOT run as root if possible
   - Response handler needs iptables access only when blocking

2. **Secure dashboard:**
   ```bash
   # Use reverse proxy (nginx)
   # Enable SSL/TLS
   # Implement authentication
   ```

3. **Protect alert data:**
   ```bash
   # Encrypt sensitive logs
   # Restrict file permissions
   chmod 600 processed_alerts.json
   ```

4. **Regular updates:**
   ```bash
   # Update rules frequently
   suricata-update  # Update Suricata rules
   
   # Keep system patched
   sudo apt-get update && sudo apt-get upgrade
   ```

## Integration Examples

### Send Alerts to Splunk

Add to Python scripts:
```python
import requests

def send_to_splunk(alert):
    splunk_url = "https://splunk.example.com:8088/services/collector"
    headers = {"Authorization": f"Splunk {SPLUNK_TOKEN}"}
    requests.post(splunk_url, json=alert, headers=headers)
```

### Slack Notifications

```python
def send_slack_alert(message):
    webhook_url = "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
    requests.post(webhook_url, json={"text": message})
```

### Email Alerts

```python
import smtplib
from email.mime.text import MIMEText

def send_email_alert(alert):
    msg = MIMEText(str(alert))
    msg['Subject'] = f"Security Alert: {alert['message']}"
    
    with smtplib.SMTP('localhost') as server:
        server.send_message(msg)
```

## Maintenance

### Daily Tasks
- Monitor alert trends
- Review critical alerts
- Check system resources

### Weekly Tasks
- Review closed incidents
- Update whitelists
- Analyze false positives

### Monthly Tasks
- Update rule sets
- Audit blocked IPs
- Performance optimization
- Security patches

## Advanced Topics

### Custom Alert Processing
Modify `scripts/alert_monitor.py` to:
- Send to SIEM
- Create tickets in Jira
- Post to Kafka
- Write to time-series DB

### Advanced Response Actions
Extend `scripts/response_handler.py` to:
- Auto-remediate compromised systems
- Trigger incident response playbooks
- Integrate with WAF
- Update threat intelligence feeds

### Cluster Deployment
For production deployments:
- Use load balancer for traffic mirroring
- Run multiple Suricata instances
- Centralize logging with ELK
- Use Kafka for alert aggregation

## Support & Resources

- Suricata Documentation: https://suricata.io/
- Rules Format: https://suricata.readthedocs.io/
- Community: https://suricata.io/community/

---
Last Updated: May 2026

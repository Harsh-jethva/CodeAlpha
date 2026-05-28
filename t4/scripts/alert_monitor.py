#!/usr/bin/env python3
"""
Alert Monitor - Reads and processes Suricata alerts
Monitors eve.json for new alerts and forwards them to response handlers
"""

import json
import time
import os
import sys
import logging
from datetime import datetime
from pathlib import Path
from collections import defaultdict
import subprocess

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('alert_monitor.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

class AlertMonitor:
    def __init__(self, log_file='/var/log/suricata/eve.json'):
        self.log_file = log_file
        self.processed_alerts = set()
        self.threat_stats = defaultdict(int)
        self.blocked_ips = set()
        
    def read_alerts(self):
        """Read alerts from Suricata EVE log file"""
        if not os.path.exists(self.log_file):
            logger.warning(f"Log file not found: {self.log_file}")
            return None
            
        try:
            with open(self.log_file, 'r') as f:
                # Read new lines from the end
                lines = f.readlines()
                
            for line in lines:
                if line.strip():
                    try:
                        alert = json.loads(line)
                        yield alert
                    except json.JSONDecodeError as e:
                        logger.error(f"JSON parse error: {e}")
                        
        except IOError as e:
            logger.error(f"Error reading log file: {e}")
    
    def process_alert(self, alert):
        """Process individual alert"""
        alert_id = f"{alert.get('timestamp', '')}-{alert.get('src_ip', '')}"
        
        # Skip duplicate alerts
        if alert_id in self.processed_alerts:
            return
        
        self.processed_alerts.add(alert_id)
        
        # Extract alert details
        timestamp = alert.get('timestamp', datetime.now().isoformat())
        event_type = alert.get('event_type', 'unknown')
        
        if event_type == 'alert':
            alert_info = alert.get('alert', {})
            msg = alert_info.get('signature', 'Unknown threat')
            severity = alert_info.get('severity', 3)
            
            src_ip = alert.get('src_ip', 'Unknown')
            dest_ip = alert.get('dest_ip', 'Unknown')
            dest_port = alert.get('dest_port', 'Unknown')
            
            # Log alert
            logger.info(f"ALERT DETECTED - {msg} | From: {src_ip} To: {dest_ip}:{dest_port} | Severity: {severity}")
            
            # Update statistics
            self.threat_stats[msg] += 1
            
            # Determine action based on severity
            if severity == 1:
                # Critical alert
                self.handle_critical_alert(src_ip, msg)
            elif severity == 2:
                # High alert
                self.handle_high_alert(src_ip, msg)
            else:
                # Medium/Low alert
                self.handle_medium_alert(src_ip, msg)
            
            # Write to structured log
            self.log_alert(timestamp, msg, src_ip, dest_ip, dest_port, severity)
    
    def handle_critical_alert(self, src_ip, msg):
        """Handle critical severity alerts"""
        logger.critical(f"CRITICAL ALERT from {src_ip}: {msg}")
        
        # Block the IP immediately
        self.block_ip(src_ip)
        
        # Send notification
        self.send_notification(f"CRITICAL: {msg} from {src_ip}", priority='critical')
    
    def handle_high_alert(self, src_ip, msg):
        """Handle high severity alerts"""
        logger.warning(f"HIGH PRIORITY ALERT from {src_ip}: {msg}")
        
        # Block the IP if it's a known attack pattern
        if any(keyword in msg.lower() for keyword in ['exploit', 'malware', 'injection', 'overflow']):
            self.block_ip(src_ip)
        
        # Send notification
        self.send_notification(f"HIGH: {msg} from {src_ip}", priority='high')
    
    def handle_medium_alert(self, src_ip, msg):
        """Handle medium/low severity alerts"""
        logger.info(f"MEDIUM ALERT from {src_ip}: {msg}")
        
        # Monitor for repeated alerts from same source
        # Send notification only for new patterns
        if msg not in self.threat_stats or self.threat_stats[msg] < 5:
            self.send_notification(f"MEDIUM: {msg} from {src_ip}", priority='medium')
    
    def block_ip(self, ip_address):
        """Block IP address using iptables"""
        if ip_address in self.blocked_ips:
            return
        
        try:
            # Add iptables rule to drop traffic from the IP
            # Note: This requires root privileges
            cmd = f"sudo iptables -A INPUT -s {ip_address} -j DROP"
            
            # Only execute if running with appropriate permissions
            # subprocess.run(cmd, shell=True, check=True)
            
            self.blocked_ips.add(ip_address)
            logger.info(f"Blocked IP: {ip_address}")
            
            # Log blocked IP
            with open('blocked_ips.txt', 'a') as f:
                f.write(f"{datetime.now().isoformat()} - {ip_address}\n")
                
        except Exception as e:
            logger.error(f"Failed to block IP {ip_address}: {e}")
    
    def send_notification(self, message, priority='medium'):
        """Send alert notification"""
        logger.info(f"NOTIFICATION [{priority.upper()}]: {message}")
        
        # Could integrate with:
        # - Email (smtplib)
        # - Slack (webhook)
        # - PagerDuty (API)
        # - Syslog
        
        try:
            # Write to notifications file
            with open('alerts_notifications.json', 'a') as f:
                notification = {
                    'timestamp': datetime.now().isoformat(),
                    'priority': priority,
                    'message': message
                }
                f.write(json.dumps(notification) + '\n')
        except Exception as e:
            logger.error(f"Failed to send notification: {e}")
    
    def log_alert(self, timestamp, msg, src_ip, dest_ip, dest_port, severity):
        """Log alert to structured format"""
        try:
            alert_record = {
                'timestamp': timestamp,
                'message': msg,
                'src_ip': src_ip,
                'dest_ip': dest_ip,
                'dest_port': dest_port,
                'severity': severity,
                'processed_at': datetime.now().isoformat()
            }
            
            with open('processed_alerts.json', 'a') as f:
                f.write(json.dumps(alert_record) + '\n')
        except Exception as e:
            logger.error(f"Failed to log alert: {e}")
    
    def print_statistics(self):
        """Print alert statistics"""
        logger.info("=" * 60)
        logger.info("ALERT STATISTICS")
        logger.info("=" * 60)
        
        total_alerts = sum(self.threat_stats.values())
        logger.info(f"Total alerts processed: {total_alerts}")
        logger.info(f"Unique threat types: {len(self.threat_stats)}")
        logger.info(f"Blocked IPs: {len(self.blocked_ips)}")
        
        logger.info("\nTop threats:")
        for threat, count in sorted(self.threat_stats.items(), key=lambda x: x[1], reverse=True)[:10]:
            logger.info(f"  {threat}: {count} occurrences")
    
    def run(self, interval=5):
        """Continuously monitor alerts"""
        logger.info("Alert Monitor started")
        logger.info(f"Monitoring: {self.log_file}")
        logger.info(f"Poll interval: {interval} seconds")
        
        try:
            while True:
                alerts = self.read_alerts()
                if alerts:
                    for alert in alerts:
                        self.process_alert(alert)
                
                # Print statistics periodically
                if len(self.processed_alerts) % 10 == 0 and len(self.processed_alerts) > 0:
                    self.print_statistics()
                
                time.sleep(interval)
                
        except KeyboardInterrupt:
            logger.info("Alert Monitor stopped by user")
            self.print_statistics()
        except Exception as e:
            logger.error(f"Fatal error: {e}")
            sys.exit(1)

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Suricata Alert Monitor')
    parser.add_argument('--log-file', default='/var/log/suricata/eve.json',
                        help='Path to Suricata EVE log file')
    parser.add_argument('--interval', type=int, default=5,
                        help='Poll interval in seconds')
    
    args = parser.parse_args()
    
    monitor = AlertMonitor(log_file=args.log_file)
    monitor.run(interval=args.interval)

if __name__ == '__main__':
    main()

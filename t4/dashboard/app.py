#!/usr/bin/env python3
"""
IDS Dashboard - Real-time visualization of network threats
Flask-based web interface for monitoring detected intrusions and system status
"""

import json
import os
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from pathlib import Path

from flask import Flask, render_template, jsonify, request
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['JSON_SORT_KEYS'] = False

class ThreatAnalyzer:
    def __init__(self):
        # Use absolute paths relative to script location
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        data_dir = os.path.join(base_dir, 'data')
        self.alerts_file = os.path.join(data_dir, 'processed_alerts.json')
        self.blocked_ips_file = os.path.join(data_dir, 'blocked_ips.txt')
        self.response_file = os.path.join(data_dir, 'response_actions.json')
        self.incidents_file = os.path.join(data_dir, 'incident_tickets.json')
    
    def load_alerts(self, limit=1000):
        """Load recent alerts"""
        alerts = []
        if os.path.exists(self.alerts_file):
            try:
                with open(self.alerts_file, 'r') as f:
                    for line in f:
                        if line.strip():
                            alerts.append(json.loads(line))
            except Exception as e:
                logger.error(f"Error loading alerts: {e}")
        
        return alerts[-limit:]
    
    def load_blocked_ips(self):
        """Load list of blocked IPs"""
        blocked = []
        if os.path.exists(self.blocked_ips_file):
            try:
                with open(self.blocked_ips_file, 'r') as f:
                    for line in f:
                        if line.strip():
                            parts = line.strip().split(' - ')
                            if len(parts) == 2:
                                blocked.append({
                                    'timestamp': parts[0],
                                    'ip': parts[1]
                                })
            except Exception as e:
                logger.error(f"Error loading blocked IPs: {e}")
        
        return blocked
    
    def load_responses(self, limit=100):
        """Load recent response actions"""
        actions = []
        if os.path.exists(self.response_file):
            try:
                with open(self.response_file, 'r') as f:
                    for line in f:
                        if line.strip():
                            actions.append(json.loads(line))
            except Exception as e:
                logger.error(f"Error loading response actions: {e}")
        
        return actions[-limit:]
    
    def load_incidents(self):
        """Load open incident tickets"""
        incidents = []
        if os.path.exists(self.incidents_file):
            try:
                with open(self.incidents_file, 'r') as f:
                    for line in f:
                        if line.strip():
                            incident = json.loads(line)
                            incidents.append(incident)
            except Exception as e:
                logger.error(f"Error loading incidents: {e}")
        
        return incidents
    
    def get_statistics(self):
        """Calculate dashboard statistics"""
        alerts = self.load_alerts()
        blocked_ips = self.load_blocked_ips()
        responses = self.load_responses()
        incidents = self.load_incidents()
        
        # Threat distribution
        threat_types = Counter()
        severity_dist = Counter()
        top_attackers = Counter()
        
        for alert in alerts:
            threat_types[alert.get('message', 'Unknown')] += 1
            severity_dist[alert.get('severity', 'Unknown')] += 1
            top_attackers[alert.get('src_ip', 'Unknown')] += 1
        
        # Time-based data (last 24 hours)
        now = datetime.now()
        hourly_alerts = defaultdict(int)
        
        for alert in alerts:
            try:
                alert_time = datetime.fromisoformat(alert['timestamp'])
                hour = alert_time.strftime("%H:00")
                if (now - alert_time).total_seconds() < 86400:
                    hourly_alerts[hour] += 1
            except:
                pass
        
        # Calculate metrics
        total_alerts = len(alerts)
        critical_alerts = severity_dist.get(1, 0)
        high_alerts = severity_dist.get(2, 0)
        
        return {
            'total_alerts': total_alerts,
            'critical_alerts': critical_alerts,
            'high_alerts': high_alerts,
            'blocked_ips_count': len(blocked_ips),
            'open_incidents': len([i for i in incidents if i.get('status') == 'open']),
            'response_actions': len(responses),
            'threat_types': dict(threat_types.most_common(10)),
            'severity_distribution': dict(severity_dist),
            'top_attackers': dict(top_attackers.most_common(10)),
            'hourly_data': dict(sorted(hourly_alerts.items())),
            'latest_alerts': alerts[-20:],
            'blocked_ips': blocked_ips[-20:],
            'recent_responses': responses[-20:]
        }

# Initialize analyzer
analyzer = ThreatAnalyzer()

# ============================================
# ROUTES
# ============================================

@app.route('/')
def dashboard():
    """Main dashboard page"""
    return render_template('dashboard.html')

@app.route('/api/statistics')
def api_statistics():
    """API endpoint for statistics"""
    try:
        stats = analyzer.get_statistics()
        return jsonify(stats)
    except Exception as e:
        logger.error(f"Error getting statistics: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/alerts')
def api_alerts():
    """API endpoint for recent alerts"""
    limit = request.args.get('limit', 100, type=int)
    try:
        alerts = analyzer.load_alerts(limit=limit)
        return jsonify({
            'count': len(alerts),
            'alerts': alerts
        })
    except Exception as e:
        logger.error(f"Error getting alerts: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/blocked-ips')
def api_blocked_ips():
    """API endpoint for blocked IPs"""
    try:
        blocked = analyzer.load_blocked_ips()
        return jsonify({
            'count': len(blocked),
            'ips': blocked
        })
    except Exception as e:
        logger.error(f"Error getting blocked IPs: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/incidents')
def api_incidents():
    """API endpoint for incidents"""
    try:
        incidents = analyzer.load_incidents()
        open_incidents = [i for i in incidents if i.get('status') == 'open']
        return jsonify({
            'total': len(incidents),
            'open': len(open_incidents),
            'incidents': open_incidents
        })
    except Exception as e:
        logger.error(f"Error getting incidents: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/health')
def api_health():
    """API endpoint for system health"""
    try:
        stats = analyzer.get_statistics()
        
        # Determine system status
        if stats['critical_alerts'] > 10:
            status = 'critical'
        elif stats['critical_alerts'] > 0 or stats['high_alerts'] > 20:
            status = 'warning'
        else:
            status = 'healthy'
        
        return jsonify({
            'status': status,
            'timestamp': datetime.now().isoformat(),
            'metrics': {
                'alerts_1h': sum([v for k, v in stats['hourly_data'].items()])
                if stats['hourly_data'] else 0,
                'critical_alerts': stats['critical_alerts'],
                'blocked_ips': stats['blocked_ips_count'],
                'incidents': stats['open_incidents']
            }
        })
    except Exception as e:
        logger.error(f"Error getting health: {e}")
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    # Create templates directory if it doesn't exist
    os.makedirs('templates', exist_ok=True)
    os.makedirs('static', exist_ok=True)
    
    # Run Flask app
    app.run(host='0.0.0.0', port=5000, debug=False)

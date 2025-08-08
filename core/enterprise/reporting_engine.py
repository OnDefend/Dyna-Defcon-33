"""
Enterprise Reporting Engine for AODS Phase 4
Advanced reporting and dashboard capabilities for enterprise deployment
"""

import json
import time
import sqlite3
import logging
from typing import Dict, List, Any, Optional, Union
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from pathlib import Path
from enum import Enum
import pandas as pd
import numpy as np
from collections import defaultdict, Counter
import base64
import io

logger = logging.getLogger(__name__)

class ReportType(Enum):
    """Types of reports available."""
    EXECUTIVE_SUMMARY = "executive_summary"
    SECURITY_POSTURE = "security_posture"
    COMPLIANCE = "compliance"
    VULNERABILITY_TRENDS = "vulnerability_trends"
    PERFORMANCE_METRICS = "performance_metrics"
    AUDIT_REPORT = "audit_report"
    CUSTOM = "custom"

class ChartType(Enum):
    """Types of charts available."""
    BAR_CHART = "bar_chart"
    LINE_CHART = "line_chart"
    PIE_CHART = "pie_chart"
    HEAT_MAP = "heat_map"
    SCATTER_PLOT = "scatter_plot"
    TIMELINE = "timeline"
    GAUGE = "gauge"
    TABLE = "table"

class ExportFormat(Enum):
    """Export formats supported."""
    PDF = "pdf"
    EXCEL = "excel"
    CSV = "csv"
    JSON = "json"
    HTML = "html"

@dataclass
class ReportConfig:
    """Report configuration."""
    report_id: str
    name: str
    description: str
    report_type: str
    organization_id: str
    created_by: str
    parameters: Dict[str, Any]
    schedule: Optional[Dict[str, Any]]
    recipients: List[str]
    is_active: bool
    created_at: str
    updated_at: str

@dataclass
class Dashboard:
    """Dashboard configuration."""
    dashboard_id: str
    name: str
    description: str
    organization_id: str
    created_by: str
    layout: Dict[str, Any]
    widgets: List[Dict[str, Any]]
    filters: Dict[str, Any]
    refresh_interval: int
    is_public: bool
    created_at: str
    updated_at: str

@dataclass
class Widget:
    """Dashboard widget configuration."""
    widget_id: str
    dashboard_id: str
    name: str
    widget_type: str
    chart_type: str
    data_source: str
    query: Dict[str, Any]
    position: Dict[str, Any]
    size: Dict[str, Any]
    styling: Dict[str, Any]
    refresh_interval: int

@dataclass
class ReportExecution:
    """Report execution record."""
    execution_id: str
    report_id: str
    organization_id: str
    executed_by: str
    execution_start: str
    execution_end: Optional[str]
    status: str
    parameters: Dict[str, Any]
    output_format: str
    output_path: Optional[str]
    error_message: Optional[str]

class ReportingDatabase:
    """Database manager for reporting data."""
    
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_database()
    
    def _init_database(self):
        """Initialize reporting database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Report configurations table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS report_configs (
                report_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT,
                report_type TEXT NOT NULL,
                organization_id TEXT NOT NULL,
                created_by TEXT NOT NULL,
                parameters TEXT,
                schedule TEXT,
                recipients TEXT,
                is_active BOOLEAN DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        ''')
        
        # Dashboards table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS dashboards (
                dashboard_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT,
                organization_id TEXT NOT NULL,
                created_by TEXT NOT NULL,
                layout TEXT,
                widgets TEXT,
                filters TEXT,
                refresh_interval INTEGER DEFAULT 300,
                is_public BOOLEAN DEFAULT 0,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        ''')
        
        # Report executions table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS report_executions (
                execution_id TEXT PRIMARY KEY,
                report_id TEXT NOT NULL,
                organization_id TEXT NOT NULL,
                executed_by TEXT NOT NULL,
                execution_start TEXT NOT NULL,
                execution_end TEXT,
                status TEXT NOT NULL,
                parameters TEXT,
                output_format TEXT,
                output_path TEXT,
                error_message TEXT,
                FOREIGN KEY (report_id) REFERENCES report_configs (report_id)
            )
        ''')
        
        # Report templates table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS report_templates (
                template_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT,
                report_type TEXT NOT NULL,
                template_data TEXT NOT NULL,
                is_system BOOLEAN DEFAULT 0,
                created_at TEXT NOT NULL
            )
        ''')
        
        # Create indexes
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_reports_org ON report_configs(organization_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_dashboards_org ON dashboards(organization_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_executions_report ON report_executions(report_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_executions_time ON report_executions(execution_start)')
        
        conn.commit()
        conn.close()
        
        logger.info(f"Reporting database initialized: {self.db_path}")

class DataConnector:
    """Data connector for accessing AODS data."""
    
    def __init__(self, base_dir: Path):
        self.base_dir = base_dir
        
        # Database connections
        self.vulnerability_db = None
        self.analytics_db = None
        self.auth_db = None
        
        self._connect_databases()
    
    def _connect_databases(self):
        """Connect to AODS databases."""
        try:
            # Connect to vulnerability trends database
            trends_db_path = self.base_dir / "analytics" / "trends" / "vulnerability_trends.db"
            if trends_db_path.exists():
                self.vulnerability_db = sqlite3.connect(trends_db_path)
            
            # Connect to threat intelligence database
            intel_db_path = self.base_dir / "analytics" / "threat_intelligence" / "threat_intelligence.db"
            if intel_db_path.exists():
                self.analytics_db = sqlite3.connect(intel_db_path)
            
            # Connect to authentication database
            auth_db_path = self.base_dir / "enterprise" / "auth" / "auth.db"
            if auth_db_path.exists():
                self.auth_db = sqlite3.connect(auth_db_path)
            
            logger.info("Database connections established")
            
        except Exception as e:
            logger.error(f"Database connection error: {e}")
    
    def get_vulnerability_data(self, organization_id: str, days: int = 30) -> List[Dict[str, Any]]:
        """Get vulnerability data for organization."""
        if not self.vulnerability_db:
            return []
        
        try:
            cursor = self.vulnerability_db.cursor()
            
            cutoff_date = datetime.now() - timedelta(days=days)
            
            cursor.execute('''
                SELECT * FROM vulnerabilities 
                WHERE detected_at >= ?
                ORDER BY detected_at DESC
            ''', (cutoff_date.isoformat(),))
            
            columns = [desc[0] for desc in cursor.description]
            vulnerabilities = []
            
            for row in cursor.fetchall():
                vuln_dict = dict(zip(columns, row))
                # Filter by organization if needed (APK naming or metadata)
                vulnerabilities.append(vuln_dict)
            
            return vulnerabilities
            
        except Exception as e:
            logger.error(f"Error getting vulnerability data: {e}")
            return []
    
    def get_scan_statistics(self, organization_id: str, days: int = 30) -> Dict[str, Any]:
        """Get scan statistics for organization."""
        vulnerabilities = self.get_vulnerability_data(organization_id, days)
        
        if not vulnerabilities:
            return {
                "total_scans": 0,
                "total_vulnerabilities": 0,
                "unique_apks": 0,
                "severity_distribution": {},
                "top_vulnerability_types": [],
                "trend_data": []
            }
        
        # Calculate statistics
        unique_apks = set(v.get('apk_name', 'unknown') for v in vulnerabilities)
        severity_counts = Counter(v.get('severity', 'unknown') for v in vulnerabilities)
        vuln_type_counts = Counter(v.get('vulnerability_type', 'unknown') for v in vulnerabilities)
        
        # Generate trend data (by day)
        trend_data = self._generate_trend_data(vulnerabilities, days)
        
        return {
            "total_scans": len(unique_apks),
            "total_vulnerabilities": len(vulnerabilities),
            "unique_apks": len(unique_apks),
            "severity_distribution": dict(severity_counts),
            "top_vulnerability_types": vuln_type_counts.most_common(10),
            "trend_data": trend_data
        }
    
    def get_compliance_data(self, organization_id: str) -> Dict[str, Any]:
        """Get compliance-related data."""
        vulnerabilities = self.get_vulnerability_data(organization_id, 90)  # Last 90 days
        
        # Map vulnerabilities to compliance frameworks
        compliance_mapping = {
            "OWASP_TOP_10": {
                "A01_Broken_Access_Control": ["path_traversal", "privilege_escalation"],
                "A02_Cryptographic_Failures": ["weak_encryption", "hardcoded_key"],
                "A03_Injection": ["sql_injection", "command_injection"],
                "A07_Identity_Authentication_Failures": ["authentication_bypass"],
                "A09_Security_Logging_Failures": ["debug_enabled"]
            },
            "NIST_CYBERSECURITY": {
                "IDENTIFY": ["asset_discovery"],
                "PROTECT": ["encryption", "access_control"],
                "DETECT": ["monitoring", "logging"],
                "RESPOND": ["incident_response"],
                "RECOVER": ["backup", "recovery"]
            }
        }
        
        compliance_scores = {}
        
        for framework, categories in compliance_mapping.items():
            framework_issues = defaultdict(int)
            
            for vuln in vulnerabilities:
                vuln_type = vuln.get('vulnerability_type', '')
                
                for category, vuln_types in categories.items():
                    if any(vtype in vuln_type for vtype in vuln_types):
                        framework_issues[category] += 1
            
            # Calculate compliance score (simple scoring)
            total_categories = len(categories)
            categories_with_issues = len(framework_issues)
            score = max(0, 100 - (categories_with_issues / total_categories * 100))
            
            compliance_scores[framework] = {
                "score": round(score, 1),
                "issues_by_category": dict(framework_issues),
                "total_issues": sum(framework_issues.values())
            }
        
        return compliance_scores
    
    def get_performance_metrics(self, organization_id: str, days: int = 7) -> Dict[str, Any]:
        """Get system performance metrics."""
        # Simulate performance metrics (in real implementation, would come from monitoring)
        return {
            "scan_performance": {
                "average_scan_time": 45.3,
                "scans_per_hour": 12,
                "queue_length": 3,
                "success_rate": 98.5
            },
            "system_health": {
                "cpu_utilization": 65.2,
                "memory_utilization": 72.8,
                "disk_utilization": 45.1,
                "uptime_percentage": 99.9
            },
            "cache_performance": {
                "hit_rate": 78.5,
                "miss_rate": 21.5,
                "eviction_rate": 5.2
            }
        }
    
    def _generate_trend_data(self, vulnerabilities: List[Dict[str, Any]], days: int) -> List[Dict[str, Any]]:
        """Generate trend data for vulnerabilities."""
        trend_data = []
        
        # Group by day
        daily_counts = defaultdict(int)
        for vuln in vulnerabilities:
            detected_at = vuln.get('detected_at', '')
            if detected_at:
                try:
                    date = datetime.fromisoformat(detected_at).date()
                    daily_counts[date.isoformat()] += 1
                except:
                    continue
        
        # Fill in missing days
        start_date = datetime.now().date() - timedelta(days=days)
        for i in range(days):
            date = start_date + timedelta(days=i)
            date_str = date.isoformat()
            
            trend_data.append({
                "date": date_str,
                "count": daily_counts.get(date_str, 0)
            })
        
        return trend_data

class ChartGenerator:
    """Generate charts and visualizations."""
    
    def __init__(self):
        self.chart_configs = {
            ChartType.BAR_CHART: self._generate_bar_chart,
            ChartType.LINE_CHART: self._generate_line_chart,
            ChartType.PIE_CHART: self._generate_pie_chart,
            ChartType.HEAT_MAP: self._generate_heat_map,
            ChartType.TIMELINE: self._generate_timeline,
            ChartType.GAUGE: self._generate_gauge,
            ChartType.TABLE: self._generate_table
        }
    
    def generate_chart(self, chart_type: ChartType, data: Dict[str, Any], 
                      config: Dict[str, Any] = None) -> Dict[str, Any]:
        """Generate chart based on type and data."""
        if chart_type not in self.chart_configs:
            raise ValueError(f"Unsupported chart type: {chart_type}")
        
        generator_func = self.chart_configs[chart_type]
        return generator_func(data, config or {})
    
    def _generate_bar_chart(self, data: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Generate bar chart configuration."""
        return {
            "type": "bar",
            "data": {
                "labels": data.get("labels", []),
                "datasets": [{
                    "label": config.get("label", "Data"),
                    "data": data.get("values", []),
                    "backgroundColor": config.get("colors", ["#3498db", "#e74c3c", "#f39c12", "#2ecc71"]),
                    "borderColor": config.get("border_colors", ["#2980b9", "#c0392b", "#d68910", "#27ae60"]),
                    "borderWidth": 1
                }]
            },
            "options": {
                "responsive": True,
                "plugins": {
                    "title": {
                        "display": True,
                        "text": config.get("title", "Chart")
                    },
                    "legend": {
                        "display": config.get("show_legend", True)
                    }
                },
                "scales": {
                    "y": {
                        "beginAtZero": True
                    }
                }
            }
        }
    
    def _generate_line_chart(self, data: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Generate line chart configuration."""
        return {
            "type": "line",
            "data": {
                "labels": data.get("labels", []),
                "datasets": [{
                    "label": config.get("label", "Trend"),
                    "data": data.get("values", []),
                    "borderColor": config.get("line_color", "#3498db"),
                    "backgroundColor": config.get("fill_color", "rgba(52, 152, 219, 0.1)"),
                    "fill": config.get("fill", True),
                    "tension": 0.4
                }]
            },
            "options": {
                "responsive": True,
                "plugins": {
                    "title": {
                        "display": True,
                        "text": config.get("title", "Trend Chart")
                    }
                },
                "scales": {
                    "y": {
                        "beginAtZero": True
                    }
                }
            }
        }
    
    def _generate_pie_chart(self, data: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Generate pie chart configuration."""
        return {
            "type": "pie",
            "data": {
                "labels": data.get("labels", []),
                "datasets": [{
                    "data": data.get("values", []),
                    "backgroundColor": config.get("colors", [
                        "#e74c3c", "#f39c12", "#f1c40f", "#2ecc71", 
                        "#3498db", "#9b59b6", "#34495e", "#95a5a6"
                    ])
                }]
            },
            "options": {
                "responsive": True,
                "plugins": {
                    "title": {
                        "display": True,
                        "text": config.get("title", "Distribution")
                    },
                    "legend": {
                        "position": config.get("legend_position", "right")
                    }
                }
            }
        }
    
    def _generate_heat_map(self, data: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Generate heat map configuration."""
        return {
            "type": "heatmap",
            "data": data.get("matrix", []),
            "options": {
                "responsive": True,
                "title": config.get("title", "Heat Map"),
                "colorScale": config.get("color_scale", "RdYlBu"),
                "showScale": config.get("show_scale", True)
            }
        }
    
    def _generate_timeline(self, data: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Generate timeline configuration."""
        return {
            "type": "timeline",
            "data": {
                "events": data.get("events", []),
                "title": config.get("title", "Timeline")
            },
            "options": {
                "responsive": True,
                "height": config.get("height", 400)
            }
        }
    
    def _generate_gauge(self, data: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Generate gauge chart configuration."""
        value = data.get("value", 0)
        max_value = data.get("max_value", 100)
        
        return {
            "type": "gauge",
            "data": {
                "value": value,
                "max": max_value,
                "title": config.get("title", "Gauge"),
                "unit": config.get("unit", "%")
            },
            "options": {
                "responsive": True,
                "thresholds": config.get("thresholds", [
                    {"value": 70, "color": "#2ecc71"},  # Green
                    {"value": 90, "color": "#f39c12"},  # Orange
                    {"value": 100, "color": "#e74c3c"}  # Red
                ])
            }
        }
    
    def _generate_table(self, data: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Generate table configuration."""
        return {
            "type": "table",
            "data": {
                "columns": data.get("columns", []),
                "rows": data.get("rows", []),
                "title": config.get("title", "Data Table")
            },
            "options": {
                "responsive": True,
                "pagination": config.get("pagination", True),
                "sorting": config.get("sorting", True),
                "filtering": config.get("filtering", True)
            }
        }

class ReportGenerator:
    """Generate various types of reports."""
    
    def __init__(self, data_connector: DataConnector, chart_generator: ChartGenerator):
        self.data_connector = data_connector
        self.chart_generator = chart_generator
    
    def generate_executive_summary(self, organization_id: str, 
                                 parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Generate executive summary report."""
        days = parameters.get('days', 30)
        
        # Get data
        scan_stats = self.data_connector.get_scan_statistics(organization_id, days)
        compliance_data = self.data_connector.get_compliance_data(organization_id)
        performance_data = self.data_connector.get_performance_metrics(organization_id)
        
        # Calculate risk score
        total_vulns = scan_stats['total_vulnerabilities']
        high_severity = scan_stats['severity_distribution'].get('high', 0)
        critical_severity = scan_stats['severity_distribution'].get('critical', 0)
        
        risk_score = min(100, (critical_severity * 10 + high_severity * 5) / max(total_vulns, 1) * 100)
        
        # Generate charts
        severity_chart = self.chart_generator.generate_chart(
            ChartType.PIE_CHART,
            {
                "labels": list(scan_stats['severity_distribution'].keys()),
                "values": list(scan_stats['severity_distribution'].values())
            },
            {"title": "Vulnerability Severity Distribution"}
        )
        
        trend_chart = self.chart_generator.generate_chart(
            ChartType.LINE_CHART,
            {
                "labels": [item['date'] for item in scan_stats['trend_data']],
                "values": [item['count'] for item in scan_stats['trend_data']]
            },
            {"title": f"Vulnerability Trends (Last {days} Days)"}
        )
        
        risk_gauge = self.chart_generator.generate_chart(
            ChartType.GAUGE,
            {"value": risk_score, "max_value": 100},
            {"title": "Security Risk Score", "unit": "%"}
        )
        
        return {
            "report_type": "executive_summary",
            "generated_at": datetime.now().isoformat(),
            "organization_id": organization_id,
            "period": f"Last {days} days",
            "summary": {
                "total_scans": scan_stats['total_scans'],
                "total_vulnerabilities": scan_stats['total_vulnerabilities'],
                "risk_score": round(risk_score, 1),
                "compliance_average": round(np.mean([
                    data['score'] for data in compliance_data.values()
                ]), 1) if compliance_data else 0
            },
            "charts": {
                "severity_distribution": severity_chart,
                "vulnerability_trends": trend_chart,
                "risk_gauge": risk_gauge
            },
            "key_metrics": {
                "scans_per_day": round(scan_stats['total_scans'] / days, 1),
                "vulnerabilities_per_scan": round(total_vulns / max(scan_stats['total_scans'], 1), 1),
                "top_vulnerability_types": scan_stats['top_vulnerability_types'][:5]
            },
            "compliance_summary": compliance_data,
            "recommendations": self._generate_executive_recommendations(scan_stats, compliance_data, risk_score)
        }
    
    def generate_security_posture_report(self, organization_id: str, 
                                       parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Generate detailed security posture report."""
        days = parameters.get('days', 30)
        
        scan_stats = self.data_connector.get_scan_statistics(organization_id, days)
        compliance_data = self.data_connector.get_compliance_data(organization_id)
        
        # Generate detailed charts
        vuln_types_chart = self.chart_generator.generate_chart(
            ChartType.BAR_CHART,
            {
                "labels": [item[0] for item in scan_stats['top_vulnerability_types'][:10]],
                "values": [item[1] for item in scan_stats['top_vulnerability_types'][:10]]
            },
            {"title": "Top Vulnerability Types"}
        )
        
        compliance_chart = self.chart_generator.generate_chart(
            ChartType.BAR_CHART,
            {
                "labels": list(compliance_data.keys()),
                "values": [data['score'] for data in compliance_data.values()]
            },
            {"title": "Compliance Framework Scores"}
        )
        
        return {
            "report_type": "security_posture",
            "generated_at": datetime.now().isoformat(),
            "organization_id": organization_id,
            "period": f"Last {days} days",
            "vulnerability_analysis": {
                "total_vulnerabilities": scan_stats['total_vulnerabilities'],
                "severity_breakdown": scan_stats['severity_distribution'],
                "top_types": scan_stats['top_vulnerability_types']
            },
            "compliance_analysis": compliance_data,
            "charts": {
                "vulnerability_types": vuln_types_chart,
                "compliance_scores": compliance_chart
            },
            "security_metrics": {
                "vulnerability_density": round(scan_stats['total_vulnerabilities'] / max(scan_stats['unique_apks'], 1), 2),
                "critical_vulnerability_rate": round(
                    scan_stats['severity_distribution'].get('critical', 0) / max(scan_stats['total_vulnerabilities'], 1) * 100, 1
                ),
                "remediation_priority": self._calculate_remediation_priority(scan_stats)
            }
        }
    
    def generate_compliance_report(self, organization_id: str, 
                                 parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Generate compliance report."""
        framework = parameters.get('framework', 'all')
        
        compliance_data = self.data_connector.get_compliance_data(organization_id)
        vulnerability_data = self.data_connector.get_vulnerability_data(organization_id, 90)
        
        # Filter by framework if specified
        if framework != 'all' and framework in compliance_data:
            compliance_data = {framework: compliance_data[framework]}
        
        # Generate compliance charts
        charts = {}
        for fw_name, fw_data in compliance_data.items():
            charts[f"{fw_name}_score"] = self.chart_generator.generate_chart(
                ChartType.GAUGE,
                {"value": fw_data['score'], "max_value": 100},
                {"title": f"{fw_name} Compliance Score", "unit": "%"}
            )
            
            if fw_data['issues_by_category']:
                charts[f"{fw_name}_issues"] = self.chart_generator.generate_chart(
                    ChartType.BAR_CHART,
                    {
                        "labels": list(fw_data['issues_by_category'].keys()),
                        "values": list(fw_data['issues_by_category'].values())
                    },
                    {"title": f"{fw_name} Issues by Category"}
                )
        
        return {
            "report_type": "compliance",
            "generated_at": datetime.now().isoformat(),
            "organization_id": organization_id,
            "framework_filter": framework,
            "compliance_scores": compliance_data,
            "charts": charts,
            "detailed_findings": self._generate_compliance_findings(vulnerability_data),
            "remediation_roadmap": self._generate_compliance_remediation(compliance_data)
        }
    
    def _generate_executive_recommendations(self, scan_stats: Dict[str, Any], 
                                          compliance_data: Dict[str, Any], 
                                          risk_score: float) -> List[str]:
        """Generate executive recommendations."""
        recommendations = []
        
        if risk_score > 70:
            recommendations.append("🚨 HIGH PRIORITY: Immediate attention required for critical vulnerabilities")
        
        if scan_stats['severity_distribution'].get('critical', 0) > 0:
            recommendations.append("⚠️ Address critical vulnerabilities immediately")
        
        top_vuln_type = scan_stats['top_vulnerability_types'][0][0] if scan_stats['top_vulnerability_types'] else None
        if top_vuln_type:
            recommendations.append(f"🎯 Focus remediation efforts on {top_vuln_type}")
        
        # Compliance recommendations
        for framework, data in compliance_data.items():
            if data['score'] < 80:
                recommendations.append(f"📋 Improve {framework} compliance (current: {data['score']:.1f}%)")
        
        if not recommendations:
            recommendations.append("✅ Security posture is good - maintain current practices")
        
        return recommendations
    
    def _calculate_remediation_priority(self, scan_stats: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Calculate remediation priority based on vulnerability data."""
        priorities = []
        
        for vuln_type, count in scan_stats['top_vulnerability_types'][:5]:
            # Simple priority calculation
            severity_weight = 1.0
            if 'critical' in vuln_type or 'injection' in vuln_type:
                severity_weight = 3.0
            elif 'high' in vuln_type or 'crypto' in vuln_type:
                severity_weight = 2.0
            
            priority_score = count * severity_weight
            
            priorities.append({
                "vulnerability_type": vuln_type,
                "count": count,
                "priority_score": priority_score,
                "recommended_action": self._get_remediation_action(vuln_type)
            })
        
        return sorted(priorities, key=lambda x: x['priority_score'], reverse=True)
    
    def _get_remediation_action(self, vuln_type: str) -> str:
        """Get recommended remediation action for vulnerability type."""
        actions = {
            "sql_injection": "Implement parameterized queries and input validation",
            "xss": "Implement output encoding and Content Security Policy",
            "weak_encryption": "Upgrade to strong encryption algorithms",
            "hardcoded_secrets": "Remove hardcoded credentials and use secure storage",
            "exported_components": "Review and restrict component exports",
            "debug_enabled": "Disable debug mode in production builds"
        }
        
        for key, action in actions.items():
            if key in vuln_type.lower():
                return action
        
        return "Review and apply security best practices"
    
    def _generate_compliance_findings(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate detailed compliance findings."""
        # Group vulnerabilities by compliance categories
        findings = {
            "authentication_issues": [],
            "encryption_issues": [],
            "access_control_issues": [],
            "data_protection_issues": [],
            "logging_issues": []
        }
        
        for vuln in vulnerabilities:
            vuln_type = vuln.get('vulnerability_type', '').lower()
            
            if 'auth' in vuln_type or 'login' in vuln_type:
                findings["authentication_issues"].append(vuln)
            elif 'crypt' in vuln_type or 'encrypt' in vuln_type:
                findings["encryption_issues"].append(vuln)
            elif 'access' in vuln_type or 'permission' in vuln_type:
                findings["access_control_issues"].append(vuln)
            elif 'data' in vuln_type or 'privacy' in vuln_type:
                findings["data_protection_issues"].append(vuln)
            elif 'log' in vuln_type or 'debug' in vuln_type:
                findings["logging_issues"].append(vuln)
        
        return findings
    
    def _generate_compliance_remediation(self, compliance_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate compliance remediation roadmap."""
        roadmap = {}
        
        for framework, data in compliance_data.items():
            framework_roadmap = []
            
            for category, issue_count in data['issues_by_category'].items():
                if issue_count > 0:
                    priority = "HIGH" if issue_count > 5 else "MEDIUM" if issue_count > 2 else "LOW"
                    framework_roadmap.append({
                        "category": category,
                        "issue_count": issue_count,
                        "priority": priority,
                        "estimated_effort": self._estimate_remediation_effort(category, issue_count)
                    })
            
            roadmap[framework] = sorted(framework_roadmap, 
                                      key=lambda x: {"HIGH": 3, "MEDIUM": 2, "LOW": 1}[x["priority"]], 
                                      reverse=True)
        
        return roadmap
    
    def _estimate_remediation_effort(self, category: str, issue_count: int) -> str:
        """Estimate remediation effort."""
        base_effort = {
            "low": "1-2 days",
            "medium": "1-2 weeks", 
            "high": "2-4 weeks"
        }
        
        if issue_count <= 2:
            return base_effort["low"]
        elif issue_count <= 5:
            return base_effort["medium"]
        else:
            return base_effort["high"]

class EnterpriseReportingEngine:
    """Main enterprise reporting engine."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.base_dir = Path(config.get('base_dir', '.'))
        self.reports_dir = self.base_dir / "enterprise" / "reports"
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize components
        self.db = ReportingDatabase(self.reports_dir / "reporting.db")
        self.data_connector = DataConnector(self.base_dir)
        self.chart_generator = ChartGenerator()
        self.report_generator = ReportGenerator(self.data_connector, self.chart_generator)
        
        logger.info("Enterprise Reporting Engine initialized")
    
    def create_report_config(self, name: str, report_type: str, organization_id: str,
                           created_by: str, parameters: Dict[str, Any] = None,
                           schedule: Dict[str, Any] = None, 
                           recipients: List[str] = None) -> str:
        """Create new report configuration."""
        try:
            report_id = f"report_{int(time.time() * 1000)}"
            
            conn = sqlite3.connect(self.db.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO report_configs
                (report_id, name, description, report_type, organization_id,
                 created_by, parameters, schedule, recipients, is_active, 
                 created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                report_id, name, f"Auto-generated {report_type} report",
                report_type, organization_id, created_by,
                json.dumps(parameters or {}), json.dumps(schedule or {}),
                json.dumps(recipients or []), True,
                datetime.now().isoformat(), datetime.now().isoformat()
            ))
            
            conn.commit()
            conn.close()
            
            logger.info(f"Report configuration created: {report_id}")
            return report_id
            
        except Exception as e:
            logger.error(f"Failed to create report config: {e}")
            raise
    
    def execute_report(self, report_id: str, executed_by: str, 
                      output_format: str = "json") -> Dict[str, Any]:
        """Execute report generation."""
        try:
            # Get report configuration
            config = self._get_report_config(report_id)
            if not config:
                raise ValueError("Report configuration not found")
            
            execution_id = f"exec_{int(time.time() * 1000)}"
            
            # Record execution start
            self._record_execution_start(execution_id, report_id, config['organization_id'], 
                                       executed_by, output_format, json.loads(config['parameters']))
            
            # Generate report based on type
            report_data = self._generate_report_by_type(
                config['report_type'], 
                config['organization_id'],
                json.loads(config['parameters'])
            )
            
            # Save report output
            output_path = self._save_report_output(execution_id, report_data, output_format)
            
            # Record execution completion
            self._record_execution_completion(execution_id, "completed", output_path)
            
            logger.info(f"Report execution completed: {execution_id}")
            
            return {
                "execution_id": execution_id,
                "report_data": report_data,
                "output_path": output_path,
                "status": "completed"
            }
            
        except Exception as e:
            logger.error(f"Report execution failed: {e}")
            self._record_execution_completion(execution_id, "failed", None, str(e))
            raise
    
    def get_dashboard_data(self, dashboard_id: str, user_id: str) -> Dict[str, Any]:
        """Get dashboard data for rendering."""
        try:
            # Get dashboard configuration
            dashboard = self._get_dashboard_config(dashboard_id)
            if not dashboard:
                raise ValueError("Dashboard not found")
            
            # Get data for each widget
            widget_data = {}
            widgets = json.loads(dashboard['widgets']) if dashboard['widgets'] else []
            
            for widget in widgets:
                widget_id = widget['widget_id']
                try:
                    data = self._get_widget_data(widget, dashboard['organization_id'])
                    widget_data[widget_id] = data
                except Exception as e:
                    logger.error(f"Failed to get data for widget {widget_id}: {e}")
                    widget_data[widget_id] = {"error": str(e)}
            
            return {
                "dashboard_id": dashboard_id,
                "name": dashboard['name'],
                "layout": json.loads(dashboard['layout']) if dashboard['layout'] else {},
                "widgets": widgets,
                "widget_data": widget_data,
                "last_updated": datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Failed to get dashboard data: {e}")
            raise
    
    def _generate_report_by_type(self, report_type: str, organization_id: str, 
                               parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Generate report based on type."""
        generators = {
            ReportType.EXECUTIVE_SUMMARY.value: self.report_generator.generate_executive_summary,
            ReportType.SECURITY_POSTURE.value: self.report_generator.generate_security_posture_report,
            ReportType.COMPLIANCE.value: self.report_generator.generate_compliance_report
        }
        
        if report_type not in generators:
            raise ValueError(f"Unsupported report type: {report_type}")
        
        return generators[report_type](organization_id, parameters)
    
    def _get_report_config(self, report_id: str) -> Optional[Dict[str, Any]]:
        """Get report configuration."""
        try:
            conn = sqlite3.connect(self.db.db_path)
            cursor = conn.cursor()
            
            cursor.execute('SELECT * FROM report_configs WHERE report_id = ?', (report_id,))
            row = cursor.fetchone()
            conn.close()
            
            if row:
                columns = [desc[0] for desc in cursor.description]
                return dict(zip(columns, row))
            
            return None
            
        except Exception as e:
            logger.error(f"Error getting report config: {e}")
            return None
    
    def _get_dashboard_config(self, dashboard_id: str) -> Optional[Dict[str, Any]]:
        """Get dashboard configuration."""
        try:
            conn = sqlite3.connect(self.db.db_path)
            cursor = conn.cursor()
            
            cursor.execute('SELECT * FROM dashboards WHERE dashboard_id = ?', (dashboard_id,))
            row = cursor.fetchone()
            conn.close()
            
            if row:
                columns = [desc[0] for desc in cursor.description]
                return dict(zip(columns, row))
            
            return None
            
        except Exception as e:
            logger.error(f"Error getting dashboard config: {e}")
            return None
    
    def _get_widget_data(self, widget: Dict[str, Any], organization_id: str) -> Dict[str, Any]:
        """Get data for dashboard widget."""
        data_source = widget.get('data_source', 'vulnerabilities')
        query = widget.get('query', {})
        
        if data_source == 'vulnerabilities':
            days = query.get('days', 30)
            return self.data_connector.get_scan_statistics(organization_id, days)
        elif data_source == 'compliance':
            return self.data_connector.get_compliance_data(organization_id)
        elif data_source == 'performance':
            days = query.get('days', 7)
            return self.data_connector.get_performance_metrics(organization_id, days)
        else:
            return {"error": f"Unknown data source: {data_source}"}
    
    def _record_execution_start(self, execution_id: str, report_id: str, 
                              organization_id: str, executed_by: str,
                              output_format: str, parameters: Dict[str, Any]):
        """Record report execution start."""
        try:
            conn = sqlite3.connect(self.db.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO report_executions
                (execution_id, report_id, organization_id, executed_by,
                 execution_start, status, parameters, output_format)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                execution_id, report_id, organization_id, executed_by,
                datetime.now().isoformat(), "running",
                json.dumps(parameters), output_format
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Failed to record execution start: {e}")
    
    def _record_execution_completion(self, execution_id: str, status: str, 
                                   output_path: Optional[str], 
                                   error_message: Optional[str] = None):
        """Record report execution completion."""
        try:
            conn = sqlite3.connect(self.db.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                UPDATE report_executions
                SET execution_end = ?, status = ?, output_path = ?, error_message = ?
                WHERE execution_id = ?
            ''', (
                datetime.now().isoformat(), status, output_path, 
                error_message, execution_id
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Failed to record execution completion: {e}")
    
    def _save_report_output(self, execution_id: str, report_data: Dict[str, Any], 
                           output_format: str) -> str:
        """Save report output to file."""
        try:
            output_dir = self.reports_dir / "output"
            output_dir.mkdir(exist_ok=True)
            
            if output_format == "json":
                output_path = output_dir / f"{execution_id}.json"
                with open(output_path, 'w') as f:
                    json.dump(report_data, f, indent=2)
            else:
                # For other formats, save as JSON for now
                output_path = output_dir / f"{execution_id}.json"
                with open(output_path, 'w') as f:
                    json.dump(report_data, f, indent=2)
            
            return str(output_path)
            
        except Exception as e:
            logger.error(f"Failed to save report output: {e}")
            raise

# Global reporting engine instance
reporting_engine = None

def initialize_reporting_engine(config: Dict[str, Any]) -> EnterpriseReportingEngine:
    """Initialize global reporting engine."""
    global reporting_engine
    reporting_engine = EnterpriseReportingEngine(config)
    return reporting_engine

def get_reporting_engine() -> Optional[EnterpriseReportingEngine]:
    """Get global reporting engine instance."""
    return reporting_engine 
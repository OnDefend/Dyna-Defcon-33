#!/usr/bin/env python3
"""
Output Formatters for AODS Unified Reporting Framework

Comprehensive formatters for converting report data into various output formats
including JSON, HTML, PDF, XML, and Markdown with rich styling and formatting.

Features:
- Multi-format output support
- Template-based formatting
- Rich styling and visualization
- Interactive elements (where supported)
- Performance-optimized rendering
- Customizable templates
"""

import json
import logging
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Any, Union
from datetime import datetime
from pathlib import Path
import base64

# Optional imports for enhanced formatting
try:
    from jinja2 import Template, Environment, FileSystemLoader
    JINJA2_AVAILABLE = True
except ImportError:
    JINJA2_AVAILABLE = False

try:
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib import colors
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

from .data_structures import (
    ReportFormat, SeverityLevel, SecurityFinding, ReportSection,
    ReportMetadata, ExecutiveSummary
)

logger = logging.getLogger(__name__)

class BaseFormatter:
    """Base class for all report formatters."""
    
    def __init__(self, template_path: Optional[str] = None):
        self.template_path = template_path
        self.logger = logging.getLogger(self.__class__.__name__)
    
    def format(self, report_data: Dict[str, Any]) -> str:
        """Format report data into target format."""
        raise NotImplementedError("Subclasses must implement format method")
    
    def validate_input(self, report_data: Dict[str, Any]) -> bool:
        """Validate input report data."""
        required_fields = ['metadata', 'sections']
        return all(field in report_data for field in required_fields)

class JSONFormatter(BaseFormatter):
    """JSON formatter for structured report output."""
    
    def format(self, report_data: Dict[str, Any]) -> str:
        """Format report as JSON with proper serialization."""
        if not self.validate_input(report_data):
            raise ValueError("Invalid report data structure")
        
        # Ensure all datetime objects are serialized properly
        serializable_data = self._make_serializable(report_data)
        
        return json.dumps(serializable_data, indent=2, ensure_ascii=False)
    
    def _make_serializable(self, obj: Any) -> Any:
        """Make object JSON serializable."""
        if isinstance(obj, datetime):
            return obj.isoformat()
        elif isinstance(obj, dict):
            return {key: self._make_serializable(value) for key, value in obj.items()}
        elif isinstance(obj, list):
            return [self._make_serializable(item) for item in obj]
        elif hasattr(obj, '__dict__'):
            return self._make_serializable(obj.__dict__)
        elif isinstance(obj, (SeverityLevel,)):
            return obj.value
        # Fix for rich.Text objects that can't be JSON serialized
        elif hasattr(obj, '__class__') and obj.__class__.__name__ == 'Text':
            # Convert rich.Text objects to strings
            return str(obj.plain) if hasattr(obj, 'plain') else str(obj)
        # Handle other rich objects that might not be serializable
        elif hasattr(obj, '__module__') and hasattr(obj, '__class__') and 'rich' in str(obj.__module__):
            # Convert any rich object to string representation
            return str(obj)
        return obj

class HTMLFormatter(BaseFormatter):
    """Enhanced HTML formatter consolidating all AODS HTML generation features."""
    
    def __init__(self, template_path: Optional[str] = None, include_css: bool = True, report_style: str = "enhanced"):
        super().__init__(template_path)
        self.include_css = include_css
        self.report_style = report_style  # "basic", "enhanced", "detailed"
        self.template_env = None
        
        if JINJA2_AVAILABLE and template_path:
            template_dir = Path(template_path).parent
            self.template_env = Environment(loader=FileSystemLoader(str(template_dir)))
    
    def format(self, report_data: Dict[str, Any]) -> str:
        """Format report as HTML with styling and interactivity."""
        if not self.validate_input(report_data):
            raise ValueError("Invalid report data structure")
        
        if self.template_env and self.template_path:
            return self._format_with_template(report_data)
        else:
            # Route to appropriate formatter based on report style
            if self.report_style == "detailed" and 'vulnerabilities' in report_data:
                return self._format_detailed_vulnerability_report(report_data)
            elif self.report_style == "enhanced":
                return self._format_enhanced_report(report_data)
            else:
                return self._format_with_builtin_template(report_data)
    
    def _format_with_template(self, report_data: Dict[str, Any]) -> str:
        """Format using Jinja2 template."""
        try:
            template_name = Path(self.template_path).name
            template = self.template_env.get_template(template_name)
            return template.render(**report_data)
        except Exception as e:
            self.logger.warning(f"Template rendering failed: {e}, falling back to built-in template")
            return self._format_with_builtin_template(report_data)
    
    def _format_with_builtin_template(self, report_data: Dict[str, Any]) -> str:
        """Format using built-in HTML template."""
        metadata = report_data.get('metadata', {})
        sections = report_data.get('sections', [])
        
        html_parts = []
        
        # HTML header with CSS
        html_parts.append(self._generate_html_header(metadata.get('title', 'Security Report')))
        
        # Executive summary
        if 'executive_summary' in report_data:
            html_parts.append(self._format_executive_summary(report_data['executive_summary']))
        
        # Report sections
        for section in sections:
            html_parts.append(self._format_section(section))
        
        # Statistics and charts
        if 'statistics' in report_data:
            html_parts.append(self._format_statistics(report_data['statistics']))
        
        # HTML footer
        html_parts.append(self._generate_html_footer())
        
        return '\n'.join(html_parts)
    
    def _generate_html_header(self, title: str) -> str:
        """Generate HTML header with CSS styling."""
        css_styles = ""
        if self.include_css:
            css_styles = """
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; line-height: 1.6; }
                .header { background: #2c3e50; color: white; padding: 20px; margin-bottom: 30px; border-radius: 8px; }
                .header h1 { margin: 0; font-size: 2.5em; }
                .header .subtitle { opacity: 0.8; margin-top: 10px; }
                .section { margin: 30px 0; padding: 20px; border: 1px solid #ddd; border-radius: 8px; }
                .section h2 { color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }
                .section h3 { color: #34495e; margin-top: 25px; }
                .finding { margin: 15px 0; padding: 15px; border-left: 4px solid #bdc3c7; background: #f8f9fa; }
                .finding.critical { border-left-color: #e74c3c; background: #fdf2f2; }
                .finding.high { border-left-color: #f39c12; background: #fef9e7; }
                .finding.medium { border-left-color: #f1c40f; background: #fffbdd; }
                .finding.low { border-left-color: #2ecc71; background: #eafaf1; }
                .finding.info { border-left-color: #3498db; background: #e8f4fd; }
                .finding-title { font-weight: bold; color: #2c3e50; margin-bottom: 8px; }
                .finding-meta { font-size: 0.9em; color: #7f8c8d; margin-bottom: 10px; }
                .finding-description { margin-bottom: 10px; }
                .finding-recommendation { background: #e8f5e8; padding: 10px; border-radius: 4px; margin-top: 10px; }
                .severity-critical { color: #e74c3c; font-weight: bold; }
                .severity-high { color: #f39c12; font-weight: bold; }
                .severity-medium { color: #f1c40f; font-weight: bold; }
                .severity-low { color: #2ecc71; font-weight: bold; }
                .severity-info { color: #3498db; font-weight: bold; }
                .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }
                .stat-card { background: #f8f9fa; padding: 20px; border-radius: 8px; text-align: center; border: 1px solid #e9ecef; }
                .stat-value { font-size: 2em; font-weight: bold; color: #2c3e50; }
                .stat-label { color: #7f8c8d; margin-top: 5px; }
                .chart-container { margin: 20px 0; text-align: center; }
                table { width: 100%; border-collapse: collapse; margin: 20px 0; }
                th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
                th { background-color: #f8f9fa; font-weight: bold; }
                .footer { margin-top: 50px; padding: 20px; background: #f8f9fa; border-radius: 8px; text-align: center; color: #7f8c8d; }
            </style>
            """
        
        return f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>{title}</title>
            {css_styles}
        </head>
        <body>
            <div class="header">
                <h1>{title}</h1>
                <div class="subtitle">Generated by AODS Framework on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
            </div>
        """
    
    def _format_executive_summary(self, summary: Dict[str, Any]) -> str:
        """Format executive summary section."""
        html = ['<div class="section">']
        html.append('<h2>Executive Summary</h2>')
        
        # Risk overview
        risk_score = summary.get('overall_risk_score', 0)
        html.append('<div class="stats-grid">')
        html.append(f'<div class="stat-card"><div class="stat-value">{risk_score:.1f}</div><div class="stat-label">Risk Score</div></div>')
        html.append(f'<div class="stat-card"><div class="stat-value">{summary.get("total_vulnerabilities", 0)}</div><div class="stat-label">Total Vulnerabilities</div></div>')
        html.append(f'<div class="stat-card"><div class="stat-value">{summary.get("critical_vulnerabilities", 0)}</div><div class="stat-label">Critical</div></div>')
        html.append(f'<div class="stat-card"><div class="stat-value">{summary.get("high_vulnerabilities", 0)}</div><div class="stat-label">High</div></div>')
        html.append('</div>')
        
        # Security posture
        posture = summary.get('security_posture', 'Unknown')
        html.append(f'<p><strong>Security Posture:</strong> {posture}</p>')
        
        # Top categories
        if 'top_vulnerability_categories' in summary:
            html.append('<h3>Top Vulnerability Categories</h3>')
            html.append('<table>')
            html.append('<tr><th>Category</th><th>Count</th><th>Percentage</th></tr>')
            
            for category in summary['top_vulnerability_categories'][:5]:
                html.append(f'<tr><td>{category.get("category", "Unknown")}</td>')
                html.append(f'<td>{category.get("count", 0)}</td>')
                html.append(f'<td>{category.get("percentage", 0):.1f}%</td></tr>')
            
            html.append('</table>')
        
        html.append('</div>')
        return '\n'.join(html)
    
    def _format_section(self, section: Dict[str, Any]) -> str:
        """Format individual report section."""
        html = ['<div class="section">']
        html.append(f'<h2>{section.get("title", "Untitled Section")}</h2>')
        
        # Section content
        content = section.get('content', '')
        if content:
            html.append(f'<p>{content}</p>')
        
        # Section findings
        findings = section.get('findings', [])
        if findings:
            html.append('<h3>Security Findings</h3>')
            for finding in findings:
                html.append(self._format_finding(finding))
        
        # Subsections
        subsections = section.get('subsections', [])
        for subsection in subsections:
            html.append(self._format_section(subsection))
        
        html.append('</div>')
        return '\n'.join(html)
    
    def _format_finding(self, finding: Dict[str, Any]) -> str:
        """Format individual security finding."""
        severity = finding.get('severity', 'info').lower()
        
        html = [f'<div class="finding {severity}">']
        html.append(f'<div class="finding-title">{finding.get("title", "Untitled Finding")}</div>')
        
        # Finding metadata
        meta_parts = []
        if 'severity' in finding:
            meta_parts.append(f'<span class="severity-{severity}">{finding["severity"].upper()}</span>')
        if 'confidence' in finding:
            meta_parts.append(f'Confidence: {finding["confidence"]*100:.0f}%')
        if 'location' in finding:
            meta_parts.append(f'Location: {finding["location"]}')
        
        if meta_parts:
            html.append(f'<div class="finding-meta">{" | ".join(meta_parts)}</div>')
        
        # Description
        description = finding.get('description', '')
        if description:
            html.append(f'<div class="finding-description">{description}</div>')
        
        # Evidence
        evidence = finding.get('evidence', '')
        if evidence:
            html.append(f'<div><strong>Evidence:</strong> <code>{evidence}</code></div>')
        
        # Recommendation
        recommendation = finding.get('recommendation', '')
        if recommendation:
            html.append(f'<div class="finding-recommendation"><strong>Recommendation:</strong> {recommendation}</div>')
        
        html.append('</div>')
        return '\n'.join(html)
    
    def _format_statistics(self, statistics: Dict[str, Any]) -> str:
        """Format statistics section."""
        html = ['<div class="section">']
        html.append('<h2>Analysis Statistics</h2>')
        
        # Statistics grid
        html.append('<div class="stats-grid">')
        
        stats_items = [
            ('Total Findings', statistics.get('total_findings', 0)),
            ('Average Confidence', f"{statistics.get('average_confidence', 0):.1f}%"),
            ('Risk Score', f"{statistics.get('risk_score', 0):.1f}"),
            ('Unique Files', statistics.get('unique_files', 0))
        ]
        
        for label, value in stats_items:
            html.append(f'<div class="stat-card"><div class="stat-value">{value}</div><div class="stat-label">{label}</div></div>')
        
        html.append('</div>')
        html.append('</div>')
        
        return '\n'.join(html)
    
    def _generate_html_footer(self) -> str:
        """Generate HTML footer."""
        return """
            <div class="footer">
                <p>Report generated by AODS (Automated OWASP Dynamic Scan) Framework</p>
                <p>For more information, visit the AODS documentation</p>
            </div>
        </body>
        </html>
        """
    
    def _format_detailed_vulnerability_report(self, report_data: Dict[str, Any]) -> str:
        """Format detailed vulnerability report with all enhanced features."""
        metadata = report_data.get('report_metadata', {})
        executive_summary = report_data.get('executive_summary', {})
        vulnerabilities = report_data.get('vulnerabilities', [])
        
        package_name = metadata.get('package_name', 'Application')
        
        # Generate modern HTML with enhanced styling
        html_parts = []
        
        # Enhanced header with modern styling
        html_parts.append(self._generate_enhanced_html_header(f"AODS Detailed Security Report - {package_name}"))
        
        # Executive summary dashboard
        html_parts.append(self._format_enhanced_executive_summary(executive_summary))
        
        # Vulnerability cards with code evidence
        html_parts.append(self._format_vulnerability_cards(vulnerabilities))
        
        # Enhanced footer with JavaScript
        html_parts.append(self._generate_enhanced_html_footer())
        
        return '\n'.join(html_parts)
    
    def _generate_enhanced_html_header(self, title: str) -> str:
        """Generate modern HTML header with enhanced styling."""
        return f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
        }}
        
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }}
        
        .header {{
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            padding: 30px;
            border-radius: 15px;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.1);
            margin-bottom: 30px;
            text-align: center;
        }}
        
        .vulnerability-card {{
            background: rgba(255, 255, 255, 0.95);
            margin: 20px 0;
            border-radius: 12px;
            overflow: hidden;
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.1);
            border-left: 5px solid #bdc3c7;
        }}
        
        .vulnerability-card.critical {{
            border-left-color: #e74c3c;
        }}
        
        .vulnerability-card.high {{
            border-left-color: #f39c12;
        }}
        
        .vulnerability-card.medium {{
            border-left-color: #f1c40f;
        }}
        
        .vulnerability-card.low {{
            border-left-color: #2ecc71;
        }}
        
        .dashboard {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 30px 0;
        }}
        
        .dashboard-card {{
            background: rgba(255, 255, 255, 0.9);
            padding: 25px;
            border-radius: 12px;
            text-align: center;
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.1);
        }}
        
        .number {{
            font-size: 2.5rem;
            font-weight: bold;
            margin-bottom: 10px;
        }}
        
        .summary-box {{
            background: rgba(255, 255, 255, 0.9);
            padding: 25px;
            border-radius: 12px;
            margin: 20px 0;
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.1);
        }}
        
        .severity-badge {{
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.9rem;
            font-weight: bold;
            text-transform: uppercase;
            color: white;
        }}
        
        .severity-badge.critical {{
            background: #e74c3c;
        }}
        
        .severity-badge.high {{
            background: #f39c12;
        }}
        
        .severity-badge.medium {{
            background: #f1c40f;
        }}
        
        .severity-badge.low {{
            background: #2ecc71;
        }}
        
        .metadata-badge {{
            padding: 3px 8px;
            border-radius: 12px;
            font-size: 0.8rem;
            font-weight: normal;
            margin: 2px;
            display: inline-block;
        }}
        
        .cwe-badge {{
            background: #3498db;
            color: white;
        }}
        
        .masvs-badge {{
            background: #9b59b6;
            color: white;
        }}
        
        .file-badge {{
            background: #34495e;
            color: white;
        }}
        
        .line-badge {{
            background: #e67e22;
            color: white;
        }}
        
        .vuln-header {{
            padding: 20px 20px 10px 20px;
            border-bottom: 1px solid #ecf0f1;
        }}
        
        .vuln-header h3 {{
            margin: 0 0 10px 0;
            color: #2c3e50;
        }}
        
        .vuln-meta {{
            display: flex;
            flex-wrap: wrap;
            gap: 5px;
            align-items: center;
        }}
        
        .vuln-content {{
            padding: 20px;
        }}
        
        .description-section {{
            margin-bottom: 20px;
        }}
        
        .description-section h4 {{
            color: #2c3e50;
            margin-bottom: 10px;
            font-size: 1.1rem;
        }}
        
        .evidence-section {{
            background: #f8f9fa;
            padding: 15px;
            border-radius: 8px;
            margin: 15px 0;
            border-left: 4px solid #3498db;
        }}
        
        .evidence-section h4 {{
            color: #2c3e50;
            margin-bottom: 15px;
            font-size: 1.1rem;
        }}
        
        .evidence-item {{
            background: #ffffff;
            border: 1px solid #e0e0e0;
            border-radius: 6px;
            margin: 10px 0;
            padding: 15px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        
        .evidence-header {{
            color: #495057;
            margin-bottom: 8px;
            font-weight: 600;
        }}
        
        .code-block {{
            background: #2c3e50;
            color: #ecf0f1;
            padding: 15px;
            border-radius: 6px;
            margin: 10px 0;
            overflow-x: auto;
        }}
        
        .code-block strong {{
            color: #3498db;
            display: block;
            margin-bottom: 8px;
        }}
        
        .code-block pre {{
            margin: 0;
            font-family: 'Courier New', monospace;
            font-size: 0.9rem;
            white-space: pre-wrap;
            word-wrap: break-word;
        }}
        
        .evidence-item {{
            background: #e8f4fd;
            padding: 10px;
            border-radius: 4px;
            margin: 8px 0;
            border-left: 3px solid #3498db;
        }}
        
        .evidence-item strong {{
            color: #2980b9;
        }}
        
        .recommendations-section {{
            background: #e8f5e8;
            padding: 15px;
            border-radius: 8px;
            margin: 15px 0;
            border-left: 4px solid #27ae60;
        }}
        
        .recommendations-section h4 {{
            color: #27ae60;
            margin-bottom: 15px;
            font-size: 1.1rem;
        }}
        
        .recommendations-list {{
            margin: 10px 0;
            padding-left: 20px;
        }}
        
        .recommendations-list li {{
            margin: 8px 0;
            line-height: 1.5;
        }}
        
        .remediation-code {{
            background: #2c3e50;
            color: #ecf0f1;
            padding: 15px;
            border-radius: 6px;
            margin: 10px 0;
        }}
        
        .remediation-code strong {{
            color: #27ae60;
            display: block;
            margin-bottom: 8px;
        }}
        
        .remediation-code pre {{
            margin: 0;
            font-family: 'Courier New', monospace;
            font-size: 0.9rem;
            white-space: pre-wrap;
        }}
        
        .threat-intelligence {{
            background: #fef9e7;
            padding: 15px;
            border-radius: 8px;
            margin: 15px 0;
            border-left: 4px solid #f39c12;
        }}
        
        .threat-intelligence h4 {{
            color: #f39c12;
            margin-bottom: 15px;
            font-size: 1.1rem;
        }}
        
        .threat-intelligence p {{
            margin: 8px 0;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{title}</h1>
            <div class="subtitle">Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
        </div>
"""
    
    def _format_enhanced_executive_summary(self, summary: Dict[str, Any]) -> str:
        """Format enhanced executive summary with dashboard."""
        severity_breakdown = summary.get('severity_breakdown', {})
        total_vulns = summary.get('total_vulnerabilities', 0)
        
        html = []
        html.append('<div class="summary-box">')
        html.append('<h2>📊 Executive Summary</h2>')
        html.append(f'<p>Total Vulnerabilities: <strong>{total_vulns}</strong></p>')
        html.append(f'<p>Risk Score: <strong>{summary.get("risk_score", 0):.1f}</strong></p>')
        html.append('</div>')
        
        html.append('<div class="dashboard">')
        
        for severity, count in severity_breakdown.items():
            color_map = {
                'Critical': '#e74c3c',
                'High': '#f39c12', 
                'Medium': '#f1c40f',
                'Low': '#2ecc71',
                'Info': '#3498db'
            }
            color = color_map.get(severity, '#7f8c8d')
            
            html.append(f'''
            <div class="dashboard-card">
                <h3>{severity}</h3>
                <div class="number" style="color: {color};">{count}</div>
            </div>
            ''')
        
        html.append('</div>')
        return '\n'.join(html)
    
    def _format_vulnerability_cards(self, vulnerabilities: List[Dict]) -> str:
        """Format vulnerability cards with complete details including CWE, MASVS, recommendations, and code snippets."""
        if not vulnerabilities:
            return '<div class="summary-box"><p>No vulnerabilities found.</p></div>'
        
        html = []
        
        for i, vuln in enumerate(vulnerabilities):
            severity = vuln.get('severity', 'Medium').lower()
            
            # Build metadata badges
            metadata_badges = []
            if vuln.get('cwe_id'):
                metadata_badges.append(f'<span class="metadata-badge cwe-badge">{vuln["cwe_id"]}</span>')
            if vuln.get('masvs_control'):
                metadata_badges.append(f'<span class="metadata-badge masvs-badge">{vuln["masvs_control"]}</span>')
            if vuln.get('file_path') and vuln['file_path'] != 'unknown':
                metadata_badges.append(f'<span class="metadata-badge file-badge">📁 {vuln["file_path"]}</span>')
            if vuln.get('line_number', 0) > 0:
                metadata_badges.append(f'<span class="metadata-badge line-badge">📍 Line {vuln["line_number"]}</span>')
            
            # Format evidence/code snippets
            evidence_section = ""
            evidence = vuln.get('evidence', [])
            code_snippet = vuln.get('code_snippet', '')
            surrounding_context = vuln.get('surrounding_context', '')
            
            # Normalize evidence to list format
            if evidence and not isinstance(evidence, list):
                evidence = [evidence]
            
            if code_snippet or (evidence and any(evidence)) or surrounding_context:
                evidence_section = '''
                <div class="evidence-section">
                    <h4>🔍 Code Evidence</h4>'''
                
                # Show vulnerable code if available
                if code_snippet:
                    evidence_section += f'''
                    <div class="code-block">
                        <strong>Vulnerable Code:</strong>
                        <pre><code>{self._escape_html(code_snippet)}</code></pre>
                    </div>'''
                
                # Show surrounding context (often more informative than the snippet)
                if surrounding_context:
                    context_content = surrounding_context.strip()
                    if len(context_content) > 50000:
                        context_display = context_content[:50000] + "\n\n... [Content truncated for browser performance]"
                    else:
                        context_display = context_content
                        
                    evidence_section += f'''
                    <div class="code-block">
                        <strong>Context & Analysis:</strong>
                        <pre><code>{self._escape_html(context_display)}</code></pre>
                    </div>'''
                
                # Only show evidence if it's different from code_snippet
                if evidence and any(evidence):
                    for j, ev in enumerate(evidence):
                        if ev and str(ev).strip():
                            evidence_content = str(ev).strip()
                            
                            # Skip if evidence is identical to code_snippet (avoid duplication)
                            if code_snippet and evidence_content == code_snippet.strip():
                                continue
                                
                            if len(evidence_content) > 20000:
                                evidence_display = evidence_content[:20000] + "\n\n... [Evidence truncated for browser performance]"
                            else:
                                evidence_display = evidence_content
                            
                            evidence_section += f'''
                            <div class="evidence-item">
                                <div class="evidence-header">
                                    <strong>Additional Evidence {j+1}:</strong>
                                </div>
                                <div class="code-block">
                                    <pre><code>{self._escape_html(evidence_display)}</code></pre>
                                </div>
                            </div>'''
                
                evidence_section += '</div>'
            
            # Format recommendations
            recommendations_section = ""
            recommendations = vuln.get('recommendations', [])
            remediation_code = vuln.get('remediation_code', '')
            
            if recommendations or remediation_code:
                recommendations_section = '''
                <div class="recommendations-section">
                    <h4>💡 Recommendations</h4>'''
                
                if recommendations:
                    recommendations_section += '<ul class="recommendations-list">'
                    for rec in recommendations:
                        if rec and str(rec).strip():
                            recommendations_section += f'<li>{self._escape_html(str(rec))}</li>'
                    recommendations_section += '</ul>'
                
                if remediation_code:
                    recommendations_section += f'''
                    <div class="remediation-code">
                        <strong>Code Fix Example:</strong>
                        <pre><code>{self._escape_html(remediation_code)}</code></pre>
                    </div>'''
                
                recommendations_section += '</div>'
            
            # Format threat intelligence
            threat_intel = vuln.get('threat_intelligence', {})
            threat_section = ""
            if threat_intel and threat_intel.get('risk_assessment'):
                confidence = threat_intel.get('correlation_confidence', 0)
                threat_section = f'''
                <div class="threat-intelligence">
                    <h4>🔍 Threat Intelligence</h4>
                    <p><strong>Risk Assessment:</strong> {threat_intel.get('risk_assessment', 'UNKNOWN')}</p>
                    <p><strong>Confidence:</strong> {confidence:.1%}</p>
                </div>'''
            
            html.append(f'''
            <div class="vulnerability-card {severity}">
                <div class="vuln-header">
                    <h3>{vuln.get('title', 'Unknown Vulnerability')}</h3>
                    <div class="vuln-meta">
                        <span class="severity-badge {severity}">{vuln.get('severity', 'Medium')}</span>
                        {' '.join(metadata_badges)}
                    </div>
                </div>
                <div class="vuln-content">
                    <div class="description-section">
                        <h4>📋 Description</h4>
                        <p>{self._escape_html(str(vuln.get('description', 'No description available')))}</p>
                    </div>
                    {evidence_section}
                    {recommendations_section}
                    {threat_section}
                </div>
            </div>
            ''')
        
        return '\n'.join(html)
    
    def _generate_enhanced_html_footer(self) -> str:
        """Generate enhanced footer."""
        return """
    </div>
</body>
</html>
"""
    
    def _truncate_text(self, text: str, max_length: int) -> str:
        """Truncate text to maximum length with ellipsis."""
        if len(text) <= max_length:
            return text
        return text[:max_length-3] + "..."
    
    def _escape_html(self, text: str) -> str:
        """Escape HTML special characters."""
        import html
        return html.escape(str(text))
    
    def _format_enhanced_report(self, report_data: Dict[str, Any]) -> str:
        """Format enhanced report with modern styling."""
        return self._format_with_builtin_template(report_data)

class PDFFormatter(BaseFormatter):
    """PDF formatter for printable reports."""
    
    def __init__(self, template_path: Optional[str] = None, page_size: str = "A4"):
        super().__init__(template_path)
        self.page_size = A4 if page_size == "A4" else letter
        
        if not REPORTLAB_AVAILABLE:
            raise ImportError("ReportLab is required for PDF generation. Install with: pip install reportlab")
    
    def format(self, report_data: Dict[str, Any]) -> bytes:
        """Format report as PDF document."""
        if not self.validate_input(report_data):
            raise ValueError("Invalid report data structure")
        
        # Create PDF document in memory
        from io import BytesIO
        buffer = BytesIO()
        
        doc = SimpleDocTemplate(buffer, pagesize=self.page_size)
        styles = getSampleStyleSheet()
        story = []
        
        # Title page
        story.extend(self._create_title_page(report_data.get('metadata', {}), styles))
        
        # Executive summary
        if 'executive_summary' in report_data:
            story.extend(self._create_executive_summary_pdf(report_data['executive_summary'], styles))
        
        # Report sections
        for section in report_data.get('sections', []):
            story.extend(self._create_section_pdf(section, styles))
        
        # Build PDF
        doc.build(story)
        pdf_data = buffer.getvalue()
        buffer.close()
        
        return pdf_data
    
    def _create_title_page(self, metadata: Dict[str, Any], styles) -> List:
        """Create PDF title page."""
        story = []
        
        # Title
        title = metadata.get('title', 'Security Analysis Report')
        story.append(Paragraph(title, styles['Title']))
        story.append(Spacer(1, 20))
        
        # Metadata table
        metadata_data = [
            ['Report Type', metadata.get('report_type', 'Unknown')],
            ['Generated By', metadata.get('generated_by', 'AODS Framework')],
            ['Generated At', metadata.get('generated_at', 'Unknown')],
            ['Total Findings', str(metadata.get('total_findings', 0))],
            ['Risk Score', f"{metadata.get('risk_score', 0):.1f}"]
        ]
        
        metadata_table = Table(metadata_data, colWidths=[2*72, 3*72])
        metadata_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 14),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        story.append(metadata_table)
        story.append(Spacer(1, 50))
        
        return story
    
    def _create_executive_summary_pdf(self, summary: Dict[str, Any], styles) -> List:
        """Create executive summary for PDF."""
        story = []
        
        story.append(Paragraph("Executive Summary", styles['Heading1']))
        story.append(Spacer(1, 12))
        
        # Summary statistics
        summary_text = f"""
        Overall Risk Score: {summary.get('overall_risk_score', 0):.1f}/100<br/>
        Total Vulnerabilities: {summary.get('total_vulnerabilities', 0)}<br/>
        Critical: {summary.get('critical_vulnerabilities', 0)} | 
        High: {summary.get('high_vulnerabilities', 0)} | 
        Medium: {summary.get('medium_vulnerabilities', 0)} | 
        Low: {summary.get('low_vulnerabilities', 0)}
        """
        
        story.append(Paragraph(summary_text, styles['Normal']))
        story.append(Spacer(1, 20))
        
        # Security posture
        posture = summary.get('security_posture', 'Unknown')
        story.append(Paragraph(f"<b>Security Posture:</b> {posture}", styles['Normal']))
        story.append(Spacer(1, 12))
        
        return story
    
    def _create_section_pdf(self, section: Dict[str, Any], styles) -> List:
        """Create section for PDF."""
        story = []
        
        # Section title
        title = section.get('title', 'Untitled Section')
        story.append(Paragraph(title, styles['Heading1']))
        story.append(Spacer(1, 12))
        
        # Section content
        content = section.get('content', '')
        if content:
            story.append(Paragraph(content, styles['Normal']))
            story.append(Spacer(1, 12))
        
        # Findings
        findings = section.get('findings', [])
        if findings:
            story.append(Paragraph("Security Findings", styles['Heading2']))
            
            for finding in findings[:10]:  # Limit for PDF size
                story.extend(self._create_finding_pdf(finding, styles))
        
        return story
    
    def _create_finding_pdf(self, finding: Dict[str, Any], styles) -> List:
        """Create finding for PDF."""
        story = []
        
        # Finding title
        title = finding.get('title', 'Untitled Finding')
        severity = finding.get('severity', 'info').upper()
        story.append(Paragraph(f"<b>{title}</b> [{severity}]", styles['Heading3']))
        
        # Description
        description = finding.get('description', '')
        if description:
            story.append(Paragraph(description, styles['Normal']))
        
        # Location and evidence
        location = finding.get('location', '')
        evidence = finding.get('evidence', '')
        
        if location or evidence:
            details = []
            if location:
                details.append(f"Location: {location}")
            if evidence:
                details.append(f"Evidence: {evidence}")
            
            story.append(Paragraph("<br/>".join(details), styles['Normal']))
        
        story.append(Spacer(1, 12))
        return story

class XMLFormatter(BaseFormatter):
    """XML formatter for structured data exchange."""
    
    def format(self, report_data: Dict[str, Any]) -> str:
        """Format report as XML document."""
        if not self.validate_input(report_data):
            raise ValueError("Invalid report data structure")
        
        # Create root element
        root = ET.Element("SecurityReport")
        
        # Add metadata
        metadata_elem = ET.SubElement(root, "Metadata")
        metadata = report_data.get('metadata', {})
        for key, value in metadata.items():
            elem = ET.SubElement(metadata_elem, key.replace(' ', '_'))
            elem.text = str(value)
        
        # Add executive summary
        if 'executive_summary' in report_data:
            summary_elem = ET.SubElement(root, "ExecutiveSummary")
            self._add_dict_to_xml(summary_elem, report_data['executive_summary'])
        
        # Add sections
        sections_elem = ET.SubElement(root, "Sections")
        for section in report_data.get('sections', []):
            section_elem = ET.SubElement(sections_elem, "Section")
            self._add_section_to_xml(section_elem, section)
        
        # Add statistics
        if 'statistics' in report_data:
            stats_elem = ET.SubElement(root, "Statistics")
            self._add_dict_to_xml(stats_elem, report_data['statistics'])
        
        # Format XML with indentation
        self._indent_xml(root)
        
        return ET.tostring(root, encoding='unicode', method='xml')
    
    def _add_dict_to_xml(self, parent: ET.Element, data: Dict[str, Any]) -> None:
        """Add dictionary data to XML element."""
        for key, value in data.items():
            if isinstance(value, dict):
                child_elem = ET.SubElement(parent, key.replace(' ', '_'))
                self._add_dict_to_xml(child_elem, value)
            elif isinstance(value, list):
                list_elem = ET.SubElement(parent, key.replace(' ', '_'))
                for i, item in enumerate(value):
                    if isinstance(item, dict):
                        item_elem = ET.SubElement(list_elem, f"Item_{i}")
                        self._add_dict_to_xml(item_elem, item)
                    else:
                        item_elem = ET.SubElement(list_elem, f"Item_{i}")
                        item_elem.text = str(item)
            else:
                elem = ET.SubElement(parent, key.replace(' ', '_'))
                elem.text = str(value)
    
    def _add_section_to_xml(self, section_elem: ET.Element, section: Dict[str, Any]) -> None:
        """Add section data to XML."""
        # Basic section info
        for key in ['id', 'title', 'content', 'order']:
            if key in section:
                elem = ET.SubElement(section_elem, key.title())
                elem.text = str(section[key])
        
        # Findings
        if 'findings' in section:
            findings_elem = ET.SubElement(section_elem, "Findings")
            for finding in section['findings']:
                finding_elem = ET.SubElement(findings_elem, "Finding")
                self._add_dict_to_xml(finding_elem, finding)
        
        # Subsections
        if 'subsections' in section:
            subsections_elem = ET.SubElement(section_elem, "Subsections")
            for subsection in section['subsections']:
                subsection_elem = ET.SubElement(subsections_elem, "Subsection")
                self._add_section_to_xml(subsection_elem, subsection)
    
    def _indent_xml(self, elem: ET.Element, level: int = 0) -> None:
        """Add indentation to XML for pretty printing."""
        indent = "\n" + level * "  "
        if len(elem):
            if not elem.text or not elem.text.strip():
                elem.text = indent + "  "
            if not elem.tail or not elem.tail.strip():
                elem.tail = indent
            for elem in elem:
                self._indent_xml(elem, level + 1)
            if not elem.tail or not elem.tail.strip():
                elem.tail = indent
        else:
            if level and (not elem.tail or not elem.tail.strip()):
                elem.tail = indent

class MarkdownFormatter(BaseFormatter):
    """Markdown formatter for documentation-friendly output."""
    
    def format(self, report_data: Dict[str, Any]) -> str:
        """Format report as Markdown document."""
        if not self.validate_input(report_data):
            raise ValueError("Invalid report data structure")
        
        markdown_parts = []
        
        # Title and metadata
        metadata = report_data.get('metadata', {})
        title = metadata.get('title', 'Security Analysis Report')
        markdown_parts.append(f"# {title}\n")
        
        # Metadata table
        markdown_parts.append("## Report Information\n")
        markdown_parts.append("| Field | Value |")
        markdown_parts.append("|-------|-------|")
        
        for key, value in metadata.items():
            if key != 'title':
                formatted_key = key.replace('_', ' ').title()
                markdown_parts.append(f"| {formatted_key} | {value} |")
        
        markdown_parts.append("")
        
        # Executive summary
        if 'executive_summary' in report_data:
            markdown_parts.append(self._format_executive_summary_md(report_data['executive_summary']))
        
        # Sections
        for section in report_data.get('sections', []):
            markdown_parts.append(self._format_section_md(section))
        
        # Statistics
        if 'statistics' in report_data:
            markdown_parts.append(self._format_statistics_md(report_data['statistics']))
        
        return '\n'.join(markdown_parts)
    
    def _format_executive_summary_md(self, summary: Dict[str, Any]) -> str:
        """Format executive summary as Markdown."""
        md = ["## Executive Summary\n"]
        
        # Key metrics
        md.append("### Key Metrics\n")
        md.append(f"- **Risk Score**: {summary.get('overall_risk_score', 0):.1f}/100")
        md.append(f"- **Total Vulnerabilities**: {summary.get('total_vulnerabilities', 0)}")
        md.append(f"- **Critical**: {summary.get('critical_vulnerabilities', 0)}")
        md.append(f"- **High**: {summary.get('high_vulnerabilities', 0)}")
        md.append(f"- **Medium**: {summary.get('medium_vulnerabilities', 0)}")
        md.append(f"- **Low**: {summary.get('low_vulnerabilities', 0)}")
        md.append("")
        
        # Security posture
        posture = summary.get('security_posture', 'Unknown')
        md.append(f"**Security Posture**: {posture}\n")
        
        # Top categories
        if 'top_vulnerability_categories' in summary:
            md.append("### Top Vulnerability Categories\n")
            md.append("| Category | Count | Percentage |")
            md.append("|----------|-------|------------|")
            
            for category in summary['top_vulnerability_categories'][:5]:
                md.append(f"| {category.get('category', 'Unknown')} | {category.get('count', 0)} | {category.get('percentage', 0):.1f}% |")
            
            md.append("")
        
        return '\n'.join(md)
    
    def _format_section_md(self, section: Dict[str, Any]) -> str:
        """Format section as Markdown."""
        md = []
        
        # Section title
        title = section.get('title', 'Untitled Section')
        md.append(f"## {title}\n")
        
        # Content
        content = section.get('content', '')
        if content:
            md.append(f"{content}\n")
        
        # Findings
        findings = section.get('findings', [])
        if findings:
            md.append("### Security Findings\n")
            
            for finding in findings:
                md.append(self._format_finding_md(finding))
        
        # Subsections
        for subsection in section.get('subsections', []):
            subsection_md = self._format_section_md(subsection)
            # Increase heading level for subsections
            subsection_md = subsection_md.replace('## ', '### ')
            md.append(subsection_md)
        
        return '\n'.join(md)
    
    def _format_finding_md(self, finding: Dict[str, Any]) -> str:
        """Format finding as Markdown."""
        md = []
        
        # Finding title with severity
        title = finding.get('title', 'Untitled Finding')
        severity = finding.get('severity', 'info').upper()
        severity_emoji = {
            'CRITICAL': '🔴',
            'HIGH': '🟠', 
            'MEDIUM': '🟡',
            'LOW': '🟢',
            'INFO': '🔵'
        }.get(severity, '⚪')
        
        md.append(f"#### {severity_emoji} {title} [{severity}]\n")
        
        # Description
        description = finding.get('description', '')
        if description:
            md.append(f"{description}\n")
        
        # Details
        details = []
        if 'location' in finding:
            details.append(f"**Location**: `{finding['location']}`")
        if 'confidence' in finding:
            details.append(f"**Confidence**: {finding['confidence']*100:.0f}%")
        if 'category' in finding:
            details.append(f"**Category**: {finding['category']}")
        
        if details:
            md.append('\n'.join(details))
            md.append("")
        
        # Evidence
        evidence = finding.get('evidence', '')
        if evidence:
            md.append(f"**Evidence**:\n```\n{evidence}\n```\n")
        
        # Recommendation
        recommendation = finding.get('recommendation', '')
        if recommendation:
            md.append(f"**Recommendation**: {recommendation}\n")
        
        md.append("---\n")
        
        return '\n'.join(md)
    
    def _format_statistics_md(self, statistics: Dict[str, Any]) -> str:
        """Format statistics as Markdown."""
        md = ["## Analysis Statistics\n"]
        
        # Key statistics
        md.append("| Metric | Value |")
        md.append("|--------|-------|")
        md.append(f"| Total Findings | {statistics.get('total_findings', 0)} |")
        md.append(f"| Average Confidence | {statistics.get('average_confidence', 0):.1f}% |")
        md.append(f"| Risk Score | {statistics.get('risk_score', 0):.1f} |")
        md.append(f"| Unique Files | {statistics.get('unique_files', 0)} |")
        md.append("")
        
        return '\n'.join(md)

# Formatter factory
class FormatterFactory:
    """Factory for creating appropriate formatters."""
    
    FORMATTERS = {
        ReportFormat.JSON: JSONFormatter,
        ReportFormat.HTML: HTMLFormatter,
        ReportFormat.PDF: PDFFormatter,
        ReportFormat.XML: XMLFormatter,
        ReportFormat.MARKDOWN: MarkdownFormatter
    }
    
    @classmethod
    def create_formatter(cls, format_type: ReportFormat, **kwargs) -> BaseFormatter:
        """Create formatter for specified format."""
        formatter_class = cls.FORMATTERS.get(format_type)
        
        if not formatter_class:
            raise ValueError(f"Unsupported format: {format_type}")
        
        return formatter_class(**kwargs)
    
    @classmethod
    def get_supported_formats(cls) -> List[ReportFormat]:
        """Get list of supported formats."""
        return list(cls.FORMATTERS.keys()) 
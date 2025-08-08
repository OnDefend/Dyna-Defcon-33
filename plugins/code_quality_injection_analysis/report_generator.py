"""
Report Generator for Code Quality & Injection Analysis Plugin

This module generates comprehensive reports for injection vulnerability analysis.
"""

import logging
from typing import List, Dict, Any, Optional
from datetime import datetime
from pathlib import Path

from .data_structures import CodeVulnerability, AnalysisResult, VulnerabilityType

logger = logging.getLogger(__name__)

class CodeQualityInjectionReportGenerator:
    """Generates detailed reports for code quality and injection analysis"""
    
    def __init__(self):
        """Initialize the report generator"""
        self.logger = logging.getLogger(__name__)
    
    def generate_report(self, result: AnalysisResult) -> Dict[str, Any]:
        """
        Generate comprehensive analysis report
        
        Args:
            result: Analysis results to generate report from
            
        Returns:
            Dict[str, Any]: Complete report structure
        """
        report = {
            "analysis_metadata": self._generate_metadata(result),
            "executive_summary": self._generate_executive_summary(result),
            "vulnerability_details": self._generate_vulnerability_details(result),
            "pattern_analysis": self._generate_pattern_analysis(result),
            "recommendations": self._generate_recommendations(result),
            "appendix": self._generate_appendix(result)
        }
        
        return report
    
    def _generate_metadata(self, result: AnalysisResult) -> Dict[str, Any]:
        """Generate analysis metadata"""
        return {
            "analysis_timestamp": datetime.now().isoformat(),
            "total_files_analyzed": result.total_files_analyzed,
            "analysis_duration": f"{result.analysis_duration:.2f} seconds",
            "total_vulnerabilities": len(result.vulnerabilities),
            "tool_version": "AODS v1.0",
            "analysis_type": "Code Quality & Injection Analysis"
        }
    
    def _generate_executive_summary(self, result: AnalysisResult) -> Dict[str, Any]:
        """Generate executive summary"""
        vulns = result.vulnerabilities
        
        if not vulns:
            return {
                "status": "SECURE",
                "risk_level": "LOW",
                "total_issues": 0,
                "critical_issues": 0,
                "high_issues": 0,
                "summary": "No injection vulnerabilities detected."
            }
        
        # Count by severity
        severity_counts = {}
        for vuln in vulns:
            severity = vuln.severity
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        critical_count = severity_counts.get("CRITICAL", 0)
        high_count = severity_counts.get("HIGH", 0)
        
        # Determine overall risk level
        if critical_count > 0:
            risk_level = "CRITICAL"
            status = "VULNERABLE"
        elif high_count > 5:
            risk_level = "HIGH"
            status = "VULNERABLE"
        elif high_count > 0:
            risk_level = "MEDIUM"
            status = "AT_RISK"
        else:
            risk_level = "LOW"
            status = "SECURE"
        
        return {
            "status": status,
            "risk_level": risk_level,
            "total_issues": len(vulns),
            "critical_issues": critical_count,
            "high_issues": high_count,
            "severity_distribution": severity_counts,
            "risk_score": result.summary.get("risk_score", 0),
            "summary": self._generate_summary_text(len(vulns), critical_count, high_count)
        }
    
    def _generate_summary_text(self, total: int, critical: int, high: int) -> str:
        """Generate summary text"""
        if total == 0:
            return "No injection vulnerabilities detected in the analyzed code."
        
        text = f"Found {total} potential injection vulnerabilit{'y' if total == 1 else 'ies'}. "
        
        if critical > 0:
            text += f"{critical} critical issue{'s' if critical != 1 else ''} require immediate attention. "
        
        if high > 0:
            text += f"{high} high severity issue{'s' if high != 1 else ''} should be addressed promptly."
        
        return text
    
    def _generate_vulnerability_details(self, result: AnalysisResult) -> List[Dict[str, Any]]:
        """Generate detailed vulnerability information"""
        vulnerabilities = []
        
        for vuln in result.vulnerabilities:
            vuln_detail = {
                "id": f"CQIA-{abs(hash(f'{vuln.location}:{vuln.line_number}'))}",
                "type": vuln.vuln_type,
                "severity": vuln.severity,
                "confidence": vuln.confidence,
                "location": {
                    "file": Path(vuln.location).name,
                    "full_path": vuln.location,
                    "line_number": vuln.line_number
                },
                "description": vuln.description,
                "vulnerable_code": vuln.value,
                "context": vuln.context,
                "mastg_reference": self._get_mastg_reference(vuln.vuln_type),
                "cwe_reference": self._get_cwe_reference(vuln.vuln_type),
                "impact": self._get_impact_description(vuln),
                "remediation": self._get_remediation_advice(vuln),
                "test_payload": vuln.payload if hasattr(vuln, 'payload') and vuln.payload else None
            }
            vulnerabilities.append(vuln_detail)
        
        # Sort by severity and confidence
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        vulnerabilities.sort(key=lambda x: (severity_order.get(x["severity"], 5), -x["confidence"]))
        
        return vulnerabilities
    
    def _generate_pattern_analysis(self, result: AnalysisResult) -> Dict[str, Any]:
        """Generate pattern analysis summary"""
        patterns_matched = result.patterns_matched
        
        analysis = {
            "total_patterns_matched": sum(patterns_matched.values()),
            "pattern_breakdown": patterns_matched,
            "most_common_vulnerabilities": self._get_most_common_vulnerabilities(patterns_matched),
            "pattern_coverage": self._calculate_pattern_coverage(patterns_matched)
        }
        
        return analysis
    
    def _generate_recommendations(self, result: AnalysisResult) -> Dict[str, Any]:
        """Generate security recommendations"""
        vulns = result.vulnerabilities
        
        # General recommendations
        general_recommendations = [
            "Implement input validation and sanitization for all user inputs",
            "Use parameterized queries for database operations",
            "Enable security features in WebView configurations",
            "Implement proper error handling to prevent information disclosure",
            "Use secure coding practices and frameworks",
            "Conduct regular security code reviews"
        ]
        
        # Specific recommendations based on found vulnerabilities
        specific_recommendations = []
        vuln_types = set(vuln.vuln_type for vuln in vulns)
        
        if VulnerabilityType.SQL_INJECTION.value in vuln_types:
            specific_recommendations.append({
                "type": "SQL Injection",
                "priority": "HIGH",
                "recommendation": "Replace dynamic SQL queries with parameterized statements or prepared statements"
            })
        
        if VulnerabilityType.XSS_WEBVIEW.value in vuln_types:
            specific_recommendations.append({
                "type": "XSS in WebView",
                "priority": "HIGH",
                "recommendation": "Disable JavaScript in WebViews or implement proper input sanitization"
            })
        
        if VulnerabilityType.COMMAND_INJECTION.value in vuln_types:
            specific_recommendations.append({
                "type": "Command Injection",
                "priority": "CRITICAL",
                "recommendation": "Avoid executing system commands with user input. Use safe alternatives"
            })
        
        return {
            "priority_actions": self._get_priority_actions(vulns),
            "general_recommendations": general_recommendations,
            "specific_recommendations": specific_recommendations,
            "security_best_practices": self._get_security_best_practices()
        }
    
    def _generate_appendix(self, result: AnalysisResult) -> Dict[str, Any]:
        """Generate report appendix"""
        return {
            "mastg_references": self._get_all_mastg_references(),
            "cwe_references": self._get_all_cwe_references(),
            "analysis_configuration": self._get_analysis_configuration(),
            "glossary": self._get_glossary(),
            "errors_encountered": result.errors if result.errors else []
        }
    
    def _get_mastg_reference(self, vuln_type: str) -> str:
        """Get MASTG reference for vulnerability type"""
        mastg_mapping = {
            VulnerabilityType.SQL_INJECTION.value: "MASTG-TEST-0019: Testing SQL Injection",
            VulnerabilityType.XSS_WEBVIEW.value: "MASTG-TEST-0020: Testing Cross-Site Scripting",
            VulnerabilityType.CODE_INJECTION.value: "MASTG-TEST-0021: Testing Code Injection",
            VulnerabilityType.OBJECT_INJECTION.value: "MASTG-TEST-0022: Testing Object Injection",
            VulnerabilityType.PATH_TRAVERSAL.value: "MASTG-TEST-0023: Testing Path Traversal",
            VulnerabilityType.COMMAND_INJECTION.value: "MASTG-TEST-0024: Testing Command Injection"
        }
        return mastg_mapping.get(vuln_type, "MASTG-TEST-0025: General Injection Testing")
    
    def _get_cwe_reference(self, vuln_type: str) -> str:
        """Get CWE reference for vulnerability type"""
        cwe_mapping = {
            VulnerabilityType.SQL_INJECTION.value: "CWE-89: SQL Injection",
            VulnerabilityType.XSS_WEBVIEW.value: "CWE-79: Cross-site Scripting",
            VulnerabilityType.CODE_INJECTION.value: "CWE-94: Code Injection",
            VulnerabilityType.OBJECT_INJECTION.value: "CWE-502: Deserialization of Untrusted Data",
            VulnerabilityType.PATH_TRAVERSAL.value: "CWE-22: Path Traversal",
            VulnerabilityType.COMMAND_INJECTION.value: "CWE-78: Command Injection"
        }
        return cwe_mapping.get(vuln_type, "CWE-74: Injection")
    
    def _get_impact_description(self, vuln: CodeVulnerability) -> str:
        """Get impact description for vulnerability"""
        impact_mapping = {
            VulnerabilityType.SQL_INJECTION.value: "Could allow unauthorized database access, data theft, or data manipulation",
            VulnerabilityType.XSS_WEBVIEW.value: "Could allow script injection, session hijacking, or phishing attacks",
            VulnerabilityType.CODE_INJECTION.value: "Could allow arbitrary code execution on the device",
            VulnerabilityType.OBJECT_INJECTION.value: "Could allow remote code execution through object deserialization",
            VulnerabilityType.PATH_TRAVERSAL.value: "Could allow unauthorized file system access",
            VulnerabilityType.COMMAND_INJECTION.value: "Could allow arbitrary system command execution"
        }
        return impact_mapping.get(vuln.vuln_type, "Could compromise application security")
    
    def _get_remediation_advice(self, vuln: CodeVulnerability) -> str:
        """Get specific remediation advice"""
        remediation_mapping = {
            VulnerabilityType.SQL_INJECTION.value: "Use parameterized queries, validate input, implement proper escaping",
            VulnerabilityType.XSS_WEBVIEW.value: "Sanitize input, disable JavaScript if not needed, use secure WebView settings",
            VulnerabilityType.CODE_INJECTION.value: "Validate and sanitize all input, avoid dynamic code execution",
            VulnerabilityType.OBJECT_INJECTION.value: "Use safe serialization methods, validate deserialized objects",
            VulnerabilityType.PATH_TRAVERSAL.value: "Validate file paths, use canonicalization, implement access controls",
            VulnerabilityType.COMMAND_INJECTION.value: "Avoid system command execution, use safe alternatives, validate input"
        }
        return remediation_mapping.get(vuln.vuln_type, "Implement proper input validation and security controls")
    
    def _get_most_common_vulnerabilities(self, patterns_matched: Dict[str, int]) -> List[Dict[str, Any]]:
        """Get most common vulnerability types"""
        sorted_patterns = sorted(patterns_matched.items(), key=lambda x: x[1], reverse=True)
        return [{"type": k, "count": v} for k, v in sorted_patterns[:5]]
    
    def _calculate_pattern_coverage(self, patterns_matched: Dict[str, int]) -> float:
        """Calculate pattern coverage percentage"""
        total_patterns = 6  # Total vulnerability types we check for
        matched_types = len([v for v in patterns_matched.values() if v > 0])
        return (matched_types / total_patterns) * 100 if total_patterns > 0 else 0
    
    def _get_priority_actions(self, vulns: List[CodeVulnerability]) -> List[str]:
        """Get priority actions based on vulnerabilities"""
        actions = []
        
        critical_count = len([v for v in vulns if v.severity == "CRITICAL"])
        high_count = len([v for v in vulns if v.severity == "HIGH"])
        
        if critical_count > 0:
            actions.append(f"Immediately address {critical_count} critical injection vulnerabilities")
        
        if high_count > 0:
            actions.append(f"Prioritize fixing {high_count} high-severity injection issues")
        
        if len(vulns) > 10:
            actions.append("Consider implementing automated security testing in CI/CD pipeline")
        
        return actions
    
    def _get_security_best_practices(self) -> List[str]:
        """Get general security best practices"""
        return [
            "Implement defense in depth with multiple security layers",
            "Use secure coding standards and guidelines",
            "Conduct regular security training for developers",
            "Implement automated security testing tools",
            "Perform regular penetration testing",
            "Keep dependencies and frameworks updated",
            "Use static analysis tools in development workflow"
        ]
    
    def _get_all_mastg_references(self) -> List[Dict[str, str]]:
        """Get all relevant MASTG references"""
        return [
            {"test_id": "MASTG-TEST-0019", "title": "Testing SQL Injection"},
            {"test_id": "MASTG-TEST-0020", "title": "Testing Cross-Site Scripting"},
            {"test_id": "MASTG-TEST-0021", "title": "Testing Code Injection"},
            {"test_id": "MASTG-TEST-0022", "title": "Testing Object Injection"},
            {"test_id": "MASTG-TEST-0023", "title": "Testing Path Traversal"},
            {"test_id": "MASTG-TEST-0024", "title": "Testing Command Injection"}
        ]
    
    def _get_all_cwe_references(self) -> List[Dict[str, str]]:
        """Get all relevant CWE references"""
        return [
            {"cwe_id": "CWE-89", "title": "SQL Injection"},
            {"cwe_id": "CWE-79", "title": "Cross-site Scripting"},
            {"cwe_id": "CWE-94", "title": "Code Injection"},
            {"cwe_id": "CWE-502", "title": "Deserialization of Untrusted Data"},
            {"cwe_id": "CWE-22", "title": "Path Traversal"},
            {"cwe_id": "CWE-78", "title": "Command Injection"}
        ]
    
    def _get_analysis_configuration(self) -> Dict[str, Any]:
        """Get analysis configuration details"""
        return {
            "patterns_checked": [
                "SQL injection patterns",
                "XSS WebView patterns",
                "Code injection patterns",
                "Object injection patterns",
                "Path traversal patterns",
                "Command injection patterns",
                "Unsafe coding patterns"
            ],
            "file_types_analyzed": ["Java", "Kotlin"],
            "analysis_scope": "Static code analysis"
        }
    
    def _get_glossary(self) -> Dict[str, str]:
        """Get glossary of terms"""
        return {
            "SQL Injection": "A code injection technique that exploits vulnerabilities in database queries",
            "XSS": "Cross-Site Scripting - injection of malicious scripts into web applications",
            "Code Injection": "Injection and execution of arbitrary code within an application",
            "Object Injection": "Injection of malicious objects through deserialization vulnerabilities",
            "Path Traversal": "Accessing files and directories outside of intended boundaries",
            "Command Injection": "Execution of arbitrary system commands through vulnerable applications",
            "MASTG": "Mobile Application Security Testing Guide",
            "CWE": "Common Weakness Enumeration - community-developed security vulnerability categories"
        } 
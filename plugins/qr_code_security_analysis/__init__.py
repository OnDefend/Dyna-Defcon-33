"""
QR Code Security Analysis Plugin

This plugin provides comprehensive QR code vulnerability detection including:
- Static analysis of QR code libraries
- Dynamic monitoring of QR code scanning APIs
- Behavioral testing of QR code input validation
- Detection of malicious QR code patterns

Author: AODS Security Team
Version: 1.0.0
"""

from typing import Dict, Any, List
import logging
from core.apk_ctx import APKContext
from .qr_static_analyzer import QRCodeStaticAnalyzer
from .qr_dynamic_analyzer import QRCodeDynamicAnalyzer
from .qr_vulnerability_detector import QRCodeVulnerabilityDetector

logger = logging.getLogger(__name__)

class QRCodeSecurityPlugin:
    """Main plugin class for QR code security analysis."""
    
    def __init__(self):
        """Initialize the QR code security plugin."""
        self.static_analyzer = QRCodeStaticAnalyzer()
        self.dynamic_analyzer = QRCodeDynamicAnalyzer()
        self.vulnerability_detector = QRCodeVulnerabilityDetector()
        self.logger = logger
    
    def analyze(self, apk_ctx: APKContext) -> Dict[str, Any]:
        """
        Perform comprehensive QR code security analysis.
        
        Args:
            apk_ctx: The APK context for analysis
            
        Returns:
            Dictionary containing QR code security analysis results
        """
        try:
            self.logger.info("Starting QR code security analysis")
            
            results = {
                "plugin_name": "qr_code_security_analysis",
                "version": "1.0.0",
                "static_analysis": {},
                "dynamic_analysis": {},
                "vulnerabilities": [],
                "security_assessment": {},
                "recommendations": []
            }
            
            # Static analysis of QR code libraries and implementations
            static_results = self.static_analyzer.analyze_qr_libraries(apk_ctx)
            results["static_analysis"] = static_results
            
            # Dynamic analysis (if runtime analysis is enabled)
            if hasattr(apk_ctx, 'dynamic_analysis_enabled') and apk_ctx.dynamic_analysis_enabled:
                dynamic_results = self.dynamic_analyzer.analyze_qr_runtime(apk_ctx)
                results["dynamic_analysis"] = dynamic_results
            
            # Vulnerability detection based on static and dynamic findings
            vulnerabilities = self.vulnerability_detector.detect_qr_vulnerabilities(
                static_results, results.get("dynamic_analysis", {})
            )
            results["vulnerabilities"] = vulnerabilities
            
            # Generate security assessment and recommendations
            assessment = self._generate_security_assessment(results)
            results["security_assessment"] = assessment
            results["recommendations"] = self._generate_recommendations(vulnerabilities)
            
            self.logger.info(f"QR code analysis completed: {len(vulnerabilities)} vulnerabilities found")
            return results
            
        except Exception as e:
            self.logger.error(f"QR code security analysis failed: {e}")
            return {
                "plugin_name": "qr_code_security_analysis",
                "error": str(e),
                "vulnerabilities": []
            }
    
    def _generate_security_assessment(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate overall security assessment for QR code functionality."""
        vulnerability_count = len(results.get("vulnerabilities", []))
        static_findings = results.get("static_analysis", {})
        
        risk_level = "LOW"
        if vulnerability_count >= 3:
            risk_level = "HIGH"
        elif vulnerability_count >= 1:
            risk_level = "MEDIUM"
        
        return {
            "risk_level": risk_level,
            "vulnerability_count": vulnerability_count,
            "qr_libraries_detected": static_findings.get("libraries_found", 0),
            "has_camera_permission": static_findings.get("has_camera_permission", False),
            "secure_implementation": vulnerability_count == 0
        }
    
    def _generate_recommendations(self, vulnerabilities: List[Dict[str, Any]]) -> List[str]:
        """Generate security recommendations based on detected vulnerabilities."""
        recommendations = []
        
        if not vulnerabilities:
            recommendations.append("No QR code vulnerabilities detected - good security posture")
            return recommendations
        
        # Analyze vulnerability types and generate specific recommendations
        vuln_types = set(v.get("type", "") for v in vulnerabilities)
        
        if "url_injection" in vuln_types:
            recommendations.extend([
                "Implement URL scheme validation for QR code content",
                "Sanitize QR code URLs before processing",
                "Block dangerous URL schemes (javascript:, file:, data:)"
            ])
        
        if "intent_injection" in vuln_types:
            recommendations.extend([
                "Validate intent URIs from QR codes before launching",
                "Implement whitelist of allowed intent actions",
                "Use explicit intents instead of implicit ones where possible"
            ])
        
        if "camera_permission_abuse" in vuln_types:
            recommendations.extend([
                "Request camera permission only when QR scanning is needed",
                "Implement proper permission handling and user consent",
                "Provide clear explanation of camera usage to users"
            ])
        
        if "input_validation_bypass" in vuln_types:
            recommendations.extend([
                "Implement robust input validation for QR code content",
                "Use content length limits and character filtering",
                "Validate QR code format and structure before processing"
            ])
        
        return recommendations

# Plugin metadata for AODS integration
PLUGIN_INFO = {
    "name": "qr_code_security_analysis",
    "version": "1.0.0",
    "description": "Comprehensive QR code security vulnerability detection",
    "author": "AODS Security Team",
    "category": "ADVANCED_SECURITY_ANALYSIS",
    "tags": ["qr_code", "camera", "input_validation", "url_security"],
    "requires_dynamic": False,
    "supports_dynamic": True,
    "priority": "NORMAL"
}

def run(apk_ctx: APKContext) -> Dict[str, Any]:
    """
    AODS-compatible run function for QR code security analysis.
    
    This is the main entry point that AODS calls for this plugin.
    
    Args:
        apk_ctx: The APK context for analysis
        
    Returns:
        Dictionary containing QR code security analysis results
    """
    plugin = QRCodeSecurityPlugin()
    return plugin.analyze(apk_ctx)

def create_plugin():
    """Factory function to create plugin instance."""
    return QRCodeSecurityPlugin()
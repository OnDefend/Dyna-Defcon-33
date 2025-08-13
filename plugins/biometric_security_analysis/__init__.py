"""
Biometric Security Analysis Plugin

This plugin provides comprehensive biometric authentication vulnerability detection including:
- Static analysis of biometric API usage
- Dynamic monitoring of fingerprint authentication flows
- Authentication bypass testing
- Biometric implementation security analysis

Author: AODS Security Team
Version: 1.0.0
"""

from typing import Dict, Any, List
import logging
from core.apk_ctx import APKContext
from .biometric_static_analyzer import BiometricStaticAnalyzer
from .biometric_dynamic_analyzer import BiometricDynamicAnalyzer
from .biometric_vulnerability_detector import BiometricVulnerabilityDetector

logger = logging.getLogger(__name__)

class BiometricSecurityPlugin:
    """Main plugin class for biometric security analysis."""
    
    def __init__(self):
        """Initialize the biometric security plugin."""
        self.static_analyzer = BiometricStaticAnalyzer()
        self.dynamic_analyzer = BiometricDynamicAnalyzer()
        self.vulnerability_detector = BiometricVulnerabilityDetector()
        self.logger = logger
    
    def analyze(self, apk_ctx: APKContext) -> Dict[str, Any]:
        """
        Perform comprehensive biometric security analysis.
        
        Args:
            apk_ctx: The APK context for analysis
            
        Returns:
            Dictionary containing biometric security analysis results
        """
        try:
            self.logger.info("Starting biometric security analysis")
            
            results = {
                "plugin_name": "biometric_security_analysis",
                "version": "1.0.0",
                "static_analysis": {},
                "dynamic_analysis": {},
                "vulnerabilities": [],
                "security_assessment": {},
                "recommendations": []
            }
            
            # Static analysis of biometric API usage
            static_results = self.static_analyzer.analyze_biometric_apis(apk_ctx)
            results["static_analysis"] = static_results
            
            # Dynamic analysis (if runtime analysis is enabled)
            if hasattr(apk_ctx, 'dynamic_analysis_enabled') and apk_ctx.dynamic_analysis_enabled:
                dynamic_results = self.dynamic_analyzer.analyze_biometric_runtime(apk_ctx)
                results["dynamic_analysis"] = dynamic_results
            
            # Vulnerability detection based on static and dynamic findings
            vulnerabilities = self.vulnerability_detector.detect_biometric_vulnerabilities(
                static_results, results.get("dynamic_analysis", {})
            )
            results["vulnerabilities"] = vulnerabilities
            
            # Generate security assessment and recommendations
            assessment = self._generate_security_assessment(results)
            results["security_assessment"] = assessment
            results["recommendations"] = self._generate_recommendations(vulnerabilities)
            
            self.logger.info(f"Biometric analysis completed: {len(vulnerabilities)} vulnerabilities found")
            return results
            
        except Exception as e:
            self.logger.error(f"Biometric security analysis failed: {e}")
            return {
                "plugin_name": "biometric_security_analysis",
                "error": str(e),
                "vulnerabilities": []
            }
    
    def _generate_security_assessment(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate overall security assessment for biometric functionality."""
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
            "biometric_apis_detected": static_findings.get("apis_found", 0),
            "has_biometric_permission": static_findings.get("has_biometric_permission", False),
            "uses_crypto_object": static_findings.get("uses_crypto_object", False),
            "secure_implementation": vulnerability_count == 0
        }
    
    def _generate_recommendations(self, vulnerabilities: List[Dict[str, Any]]) -> List[str]:
        """Generate security recommendations based on detected vulnerabilities."""
        recommendations = []
        
        if not vulnerabilities:
            recommendations.append("No biometric vulnerabilities detected - good security posture")
            return recommendations
        
        # Analyze vulnerability types and generate specific recommendations
        vuln_types = set(v.get("type", "") for v in vulnerabilities)
        
        if "biometric_bypass" in vuln_types:
            recommendations.extend([
                "Implement proper authentication state management",
                "Use CryptoObject for cryptographic operations",
                "Validate authentication results before granting access"
            ])
        
        if "weak_biometric_implementation" in vuln_types:
            recommendations.extend([
                "Use androidx.biometric.BiometricPrompt for modern implementations",
                "Implement proper error handling for biometric failures",
                "Add fallback authentication mechanisms"
            ])
        
        if "insecure_fallback" in vuln_types:
            recommendations.extend([
                "Implement strong fallback authentication (PIN/Pattern)",
                "Ensure fallback methods meet security requirements",
                "Avoid storing fallback credentials insecurely"
            ])
        
        if "auth_state_manipulation" in vuln_types:
            recommendations.extend([
                "Store authentication state securely",
                "Use encrypted storage for sensitive auth data",
                "Implement tamper detection for auth state"
            ])
        
        return recommendations

# Plugin metadata for AODS integration
PLUGIN_INFO = {
    "name": "biometric_security_analysis",
    "version": "1.0.0",
    "description": "Comprehensive biometric authentication vulnerability detection",
    "author": "AODS Security Team",
    "category": "ADVANCED_SECURITY_ANALYSIS",
    "tags": ["biometric", "fingerprint", "authentication", "bypass"],
    "requires_dynamic": False,
    "supports_dynamic": True,
    "priority": "NORMAL"
}

def run(apk_ctx: APKContext) -> Dict[str, Any]:
    """
    AODS-compatible run function for biometric security analysis.
    
    This is the main entry point that AODS calls for this plugin.
    
    Args:
        apk_ctx: The APK context for analysis
        
    Returns:
        Dictionary containing biometric security analysis results
    """
    plugin = BiometricSecurityPlugin()
    return plugin.analyze(apk_ctx)

def create_plugin():
    """Factory function to create plugin instance."""
    return BiometricSecurityPlugin()
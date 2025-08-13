"""
Enhanced Static Analysis Main Orchestrator

This module coordinates all analysis engines and manages the overall static analysis process.
"""

import logging
from typing import Dict, List, Any

from core.apk_ctx import APKContext
from core.enhanced_static_analyzer import get_enhanced_static_analyzer
from .secret_analyzer import SecretAnalysisEngine
from .security_analyzer import SecurityFindingsEngine
from .manifest_analyzer import ManifestAnalysisEngine
from .code_quality_analyzer import CodeQualityMetricsEngine

logger = logging.getLogger(__name__)

class EnhancedStaticAnalysisOrchestrator:
    """
    Main orchestrator for enhanced static analysis.
    
    Coordinates multiple analysis engines to provide comprehensive static analysis capabilities.
    """
    
    def __init__(self):
        """Initialize the orchestrator with all analysis engines."""
        self.secret_analyzer = SecretAnalysisEngine()
        self.security_analyzer = SecurityFindingsEngine()
        self.manifest_analyzer = ManifestAnalysisEngine()
        self.code_quality_analyzer = CodeQualityMetricsEngine()
        
        # Get the enhanced static analyzer from core
        self.core_analyzer = get_enhanced_static_analyzer()
        
    def analyze_apk(self, apk_ctx: APKContext) -> Dict[str, Any]:
        """
        Perform comprehensive static analysis on the APK.
        
        Args:
            apk_ctx: The APKContext instance containing APK path and metadata
            
        Returns:
            Dict[str, Any]: Comprehensive analysis results
        """
        logger.info("Starting enhanced static analysis orchestration")
        
        try:
            # Perform core analysis using the enhanced static analyzer
            core_results = self.core_analyzer.analyze_apk(apk_ctx)
            
            # Initialize results structure
            results = {
                "core_analysis": core_results,
                "secret_analysis": [],
                "security_findings": [],
                "manifest_analysis": {},
                "code_quality_metrics": {},
                "risk_assessment": {},
                "analysis_metadata": {
                    "timestamp": self._get_timestamp(),
                    "analyzer_version": "2.0.0",
                    "analysis_type": "enhanced_static"
                }
            }
            
            # Extract and process core analysis results
            if core_results:
                # Process secret analysis
                if "secret_analysis" in core_results:
                    results["secret_analysis"] = self.secret_analyzer.process_secret_analysis(
                        core_results["secret_analysis"]
                    )
                
                # Process security findings
                if "security_findings" in core_results:
                    results["security_findings"] = self.security_analyzer.process_security_findings(
                        core_results["security_findings"]
                    )
                
                # Process manifest analysis
                if "manifest_analysis" in core_results:
                    results["manifest_analysis"] = self.manifest_analyzer.process_manifest_analysis(
                        core_results["manifest_analysis"]
                    )
                
                # Process code quality metrics
                if "code_quality_metrics" in core_results:
                    results["code_quality_metrics"] = self.code_quality_analyzer.process_code_quality(
                        core_results["code_quality_metrics"]
                    )
                
                # Generate risk assessment
                results["risk_assessment"] = self._generate_risk_assessment(results)
            
            logger.info("Enhanced static analysis orchestration completed successfully")
            return results
            
        except Exception as e:
            logger.error(f"Enhanced static analysis orchestration failed: {str(e)}")
            return {
                "error": str(e),
                "analysis_metadata": {
                    "timestamp": self._get_timestamp(),
                    "analyzer_version": "2.0.0",
                    "analysis_type": "enhanced_static",
                    "status": "failed"
                }
            }
    
    def _generate_risk_assessment(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate comprehensive risk assessment based on analysis results.
        
        Args:
            results: Analysis results from all engines
            
        Returns:
            Dict[str, Any]: Risk assessment data
        """
        security_findings = results.get("security_findings", [])
        secret_analysis = results.get("secret_analysis", [])
        manifest_analysis = results.get("manifest_analysis", {})
        
        # Count findings by severity
        critical_count = len([f for f in security_findings if f.severity == "CRITICAL"])
        high_count = len([f for f in security_findings if f.severity == "HIGH"])
        medium_count = len([f for f in security_findings if f.severity == "MEDIUM"])
        low_count = len([f for f in security_findings if f.severity == "LOW"])
        
        # Count high-confidence secrets
        high_confidence_secrets = len([s for s in secret_analysis if s.confidence >= 0.7])
        
        # Calculate overall risk score
        risk_score = self._calculate_risk_score(
            critical_count, high_count, medium_count, low_count, high_confidence_secrets
        )
        
        # Determine overall risk level
        if risk_score >= 0.8 or critical_count > 0:
            overall_risk = "CRITICAL"
        elif risk_score >= 0.6 or high_count > 2:
            overall_risk = "HIGH"
        elif risk_score >= 0.4 or medium_count > 5:
            overall_risk = "MEDIUM"
        elif risk_score >= 0.2 or low_count > 10:
            overall_risk = "LOW"
        else:
            overall_risk = "MINIMAL"
        
        return {
            "overall_risk": overall_risk,
            "risk_score": risk_score,
            "critical_issues": critical_count,
            "high_issues": high_count,
            "medium_issues": medium_count,
            "low_issues": low_count,
            "total_issues": len(security_findings),
            "high_confidence_secrets": high_confidence_secrets,
            "total_secrets": len(secret_analysis),
            "manifest_issues": self._count_manifest_issues(manifest_analysis)
        }
    
    def _calculate_risk_score(self, critical: int, high: int, medium: int, low: int, secrets: int) -> float:
        """
        Calculate numerical risk score based on findings.
        
        Args:
            critical: Number of critical findings
            high: Number of high findings
            medium: Number of medium findings
            low: Number of low findings
            secrets: Number of high-confidence secrets
            
        Returns:
            float: Risk score between 0.0 and 1.0
        """
        # Weight different finding types
        score = (
            critical * 0.25 +
            high * 0.15 +
            medium * 0.08 +
            low * 0.02 +
            secrets * 0.20
        )
        
        # Normalize to 0-1 range
        return min(1.0, score)
    
    def _count_manifest_issues(self, manifest_analysis: Dict[str, Any]) -> int:
        """
        Count manifest-related security issues.
        
        Args:
            manifest_analysis: Manifest analysis results
            
        Returns:
            int: Number of manifest issues
        """
        issues = 0
        
        security_features = manifest_analysis.get("security_features", {})
        
        # Check for common security issues
        if security_features.get("debuggable", False):
            issues += 1
        if security_features.get("allow_backup", True):
            issues += 1
        if security_features.get("uses_cleartext_traffic", True):
            issues += 1
        
        # Count dangerous permissions
        permissions = manifest_analysis.get("permissions", [])
        dangerous_perms = [
            p for p in permissions
            if any(danger in p.get("name", "") for danger in [
                "CAMERA", "LOCATION", "RECORD_AUDIO", "READ_SMS", "CONTACTS"
            ])
        ]
        issues += len(dangerous_perms)
        
        # Count exported components
        for component_type in ["activities", "services", "receivers", "providers"]:
            components = manifest_analysis.get(component_type, [])
            exported = [c for c in components if c.get("exported", False)]
            issues += len(exported)
        
        return issues
    
    def _get_timestamp(self) -> str:
        """Get current timestamp for analysis metadata."""
        import datetime
        return datetime.datetime.now().isoformat() 
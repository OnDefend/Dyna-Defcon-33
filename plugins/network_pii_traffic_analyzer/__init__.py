"""
Network PII Traffic Analyzer Plugin

This plugin provides comprehensive analysis of network traffic for PII leakage
in Android applications implementing MASVS network security requirements.
"""

import logging
import subprocess
import os
import re
from typing import Dict, List, Any, Optional, Tuple, Union, Set
from pathlib import Path
from datetime import datetime

from rich.text import Text
from rich.console import Console

from core.apk_ctx import APKContext

from .data_structures import (
    ComprehensivePIIAnalysisResult, PIINetworkFinding, NetworkEndpoint,
    FileAnalysisResult, PIIContext, PIIConfiguration, AnalysisError,
    PIIType, SeverityLevel, TransmissionMethod, FileType,
    AnalysisCategory, TransmissionRisk, PrivacyImpactAssessment
)
from .pii_pattern_library import PIIPatternLibrary
from .network_pii_analyzer import NetworkPIIAnalyzer
from .file_analyzers import (
    SourceFileAnalyzer, ResourceFileAnalyzer, 
    ManifestAnalyzer, ConfigurationAnalyzer
)
from .confidence_calculator import PIIConfidenceCalculator
from .formatters import PIIAnalysisFormatter, PIIReportGenerator, NetworkPIIFormatter

logger = logging.getLogger(__name__)

# Plugin metadata
PLUGIN_METADATA = {
    "name": "Network PII Traffic Analyzer",
    "description": "Comprehensive network traffic analysis for PII leakage detection",
    "version": "2.0.0",
    "author": "AODS Development Team",
    "category": "NETWORK_PRIVACY",
    "priority": "HIGH",
    "timeout": 120,
    "mode": "comprehensive",
    "requires_device": True,
    "requires_network": True,
    "invasive": False,
    "execution_time_estimate": 90,
    "dependencies": ["mitmproxy", "adb"],
    "modular_architecture": True,
    "components": [
        "network_pii_analyzer",
        "pii_pattern_library", 
        "file_analyzers",
        "confidence_calculator"
    ],
    "security_controls": ["MASVS-NETWORK-1", "MASVS-PRIVACY-1"],
    "owasp_categories": ["M2", "M4"]
}

class NetworkPIITrafficAnalyzer:
    """
    Unified interface for modular network PII traffic analysis.
    
    This class orchestrates all analysis components and provides a clean
    interface for the main plugin while maintaining backward compatibility.
    """
    
    def __init__(self, config: Optional[PIIConfiguration] = None, 
                 console: Optional[Any] = None):
        """
        Initialize the modular PII traffic analyzer.
        
        Args:
            config: Configuration for analysis behavior
            console: Rich console for output (optional)
        """
        self.config = config or PIIConfiguration()
        self.console = console
        
        # Initialize components with dependency injection
        self._initialize_components()
        
        # Analysis state
        self.analysis_start_time: Optional[datetime] = None
        self.current_analysis_context: Optional[PIIContext] = None
        
        logger.debug("Modular Network PII Traffic Analyzer initialized")
    
    def _initialize_components(self) -> None:
        """Initialize all analysis components with proper dependencies."""
        try:
            # Initialize pattern library (foundation component)
            self.pattern_library = PIIPatternLibrary()
            
            # Initialize confidence calculator
            self.confidence_calculator = PIIConfidenceCalculator()
            
            # Initialize core analyzer with dependencies
            self.network_analyzer = NetworkPIIAnalyzer(
                config=self.config,
                pattern_library=self.pattern_library,
                confidence_calculator=self.confidence_calculator
            )
            
            # Initialize file analyzers with shared dependencies
            analyzer_kwargs = {
                'pattern_library': self.pattern_library,
                'confidence_calculator': self.confidence_calculator
            }
            
            self.source_analyzer = SourceFileAnalyzer(**analyzer_kwargs)
            self.resource_analyzer = ResourceFileAnalyzer(**analyzer_kwargs)
            self.manifest_analyzer = ManifestAnalyzer(**analyzer_kwargs)
            self.config_analyzer = ConfigurationAnalyzer(**analyzer_kwargs)
            
            # Initialize formatters
            self.formatter = PIIAnalysisFormatter(console=self.console)
            self.report_generator = PIIReportGenerator(formatter=self.formatter)
            
            logger.debug("All PII analysis components initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize PII analysis components: {e}")
            raise AnalysisError(f"Component initialization failed: {e}")
    
    def analyze_apk(self, apk_path: str, package_name: Optional[str] = None,
                    deep_scan: bool = True) -> ComprehensivePIIAnalysisResult:
        """
        Perform comprehensive PII analysis on an APK file.
        
        Args:
            apk_path: Path to the APK file
            package_name: Package name for analysis context
            deep_scan: Whether to perform deep analysis
            
        Returns:
            Comprehensive analysis results
        """
        logger.debug(f"Starting PII analysis for APK: {apk_path}")
        self.analysis_start_time = datetime.now()
        
        try:
            # Create analysis context
            context = PIIContext(
                package_name=package_name,
                apk_path=apk_path,
                analysis_mode="deep" if deep_scan else "basic",
                config=self.config
            )
            self.current_analysis_context = context
            
            # Validate APK exists
            if not Path(apk_path).exists():
                raise AnalysisError(f"APK file not found: {apk_path}")
            
            # Initialize result container
            result = ComprehensivePIIAnalysisResult(
                package_name=package_name,
                analysis_timestamp=self.analysis_start_time
            )
            
            # Progress tracking
            self.formatter.print_progress_update("Initializing PII analysis", "info")
            
            # Perform modular analysis
            self._analyze_source_files(context, result)
            self._analyze_resource_files(context, result)
            self._analyze_manifest_file(context, result)
            self._analyze_configuration_files(context, result)
            self._perform_network_analysis(context, result)
            
            # Post-processing and enrichment
            self._enrich_analysis_results(result)
            self._calculate_risk_assessment(result)
            self._generate_recommendations(result)
            
            # Finalize results
            result.analysis_duration = (datetime.now() - self.analysis_start_time).total_seconds()
            result.files_analyzed = len(result.file_results)
            
            logger.debug(f"PII analysis completed in {result.analysis_duration:.2f}s")
            return result
            
        except Exception as e:
            logger.error(f"PII analysis failed: {e}")
            duration = (datetime.now() - self.analysis_start_time).total_seconds()
            return self._create_error_result(str(e), duration, package_name)
    
    def _analyze_source_files(self, context: PIIContext, 
                             result: ComprehensivePIIAnalysisResult) -> None:
        """Analyze source code files for PII patterns."""
        self.formatter.print_progress_update("Analyzing source files", "info")
        
        try:
            source_results = self.source_analyzer.analyze_source_files(context)
            
            for file_result in source_results:
                result.file_results.append(file_result)
                result.all_pii_findings.extend(file_result.pii_findings)
                result.network_endpoints.extend(file_result.network_endpoints)
                
                # Alert for high-priority findings
                for finding in file_result.pii_findings:
                    if finding.severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH]:
                        self.formatter.print_finding_alert(finding)
            
            logger.debug(f"Analyzed {len(source_results)} source files")
            
        except Exception as e:
            logger.error(f"Source file analysis failed: {e}")
            # Continue with other analysis types
    
    def _analyze_resource_files(self, context: PIIContext, 
                               result: ComprehensivePIIAnalysisResult) -> None:
        """Analyze resource files for PII patterns."""
        self.formatter.print_progress_update("Analyzing resource files", "info")
        
        try:
            resource_results = self.resource_analyzer.analyze_resource_files(context)
            
            for file_result in resource_results:
                result.file_results.append(file_result)
                result.all_pii_findings.extend(file_result.pii_findings)
                result.network_endpoints.extend(file_result.network_endpoints)
                
                # Alert for configuration-based findings
                for finding in file_result.pii_findings:
                    if finding.severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH]:
                        self.formatter.print_finding_alert(finding)
            
            logger.debug(f"Analyzed {len(resource_results)} resource files")
            
        except Exception as e:
            logger.error(f"Resource file analysis failed: {e}")
            # Continue with other analysis types
    
    def _analyze_manifest_file(self, context: PIIContext, 
                              result: ComprehensivePIIAnalysisResult) -> None:
        """Analyze AndroidManifest.xml for PII-related patterns."""
        self.formatter.print_progress_update("Analyzing manifest file", "info")
        
        try:
            manifest_result = self.manifest_analyzer.analyze_manifest(context)
            
            if manifest_result:
                result.file_results.append(manifest_result)
                result.all_pii_findings.extend(manifest_result.pii_findings)
                result.network_endpoints.extend(manifest_result.network_endpoints)
                
                # Manifest findings are often high priority
                for finding in manifest_result.pii_findings:
                    self.formatter.print_finding_alert(finding)
            
            logger.debug("Manifest analysis completed")
            
        except Exception as e:
            logger.error(f"Manifest analysis failed: {e}")
            # Continue with other analysis types
    
    def _analyze_configuration_files(self, context: PIIContext, 
                                   result: ComprehensivePIIAnalysisResult) -> None:
        """Analyze configuration files for PII patterns."""
        self.formatter.print_progress_update("Analyzing configuration files", "info")
        
        try:
            config_results = self.config_analyzer.analyze_configuration_files(context)
            
            for file_result in config_results:
                result.file_results.append(file_result)
                result.all_pii_findings.extend(file_result.pii_findings)
                result.network_endpoints.extend(file_result.network_endpoints)
                
                # Configuration files often contain sensitive data
                for finding in file_result.pii_findings:
                    if finding.severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH]:
                        self.formatter.print_finding_alert(finding)
            
            logger.debug(f"Analyzed {len(config_results)} configuration files")
            
        except Exception as e:
            logger.error(f"Configuration analysis failed: {e}")
            # Continue with other analysis types
    
    def _perform_network_analysis(self, context: PIIContext, 
                                 result: ComprehensivePIIAnalysisResult) -> None:
        """Perform comprehensive network PII analysis."""
        self.formatter.print_progress_update("Performing network analysis", "info")
        
        try:
            # Extract all network endpoints from file analyses
            all_endpoints = result.network_endpoints.copy()
            
            # Perform deep network analysis
            network_results = self.network_analyzer.analyze_network_communications(
                context, all_endpoints
            )
            
            # Merge network analysis results
            result.all_pii_findings.extend(network_results.network_findings)
            result.network_endpoints = network_results.analyzed_endpoints
            
            logger.debug(f"Network analysis completed with {len(network_results.network_findings)} findings")
            
        except Exception as e:
            logger.error(f"Network analysis failed: {e}")
            # Continue with result processing
    
    def _enrich_analysis_results(self, result: ComprehensivePIIAnalysisResult) -> None:
        """Enrich analysis results with additional context and metadata."""
        self.formatter.print_progress_update("Enriching analysis results", "info")
        
        try:
            # Calculate summary statistics
            result.total_findings = len(result.all_pii_findings)
            
            # Group findings by severity
            severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            for finding in result.all_pii_findings:
                severity = finding.severity.value
                if severity in severity_counts:
                    severity_counts[severity] += 1
            
            result.critical_findings = severity_counts["critical"]
            result.high_findings = severity_counts["high"]
            result.medium_findings = severity_counts["medium"]
            result.low_findings = severity_counts["low"]
            
            # Calculate overall risk level
            result.overall_risk_level = self._calculate_overall_risk_level(result)
            result.risk_score = self._calculate_risk_score(result)
            
            # Calculate privacy risk percentage
            result.privacy_risk_percentage = self._calculate_privacy_risk_percentage(result)
            
            # Extract MASVS controls
            result.masvs_controls = list(set([
                finding.masvs_control for finding in result.all_pii_findings
                if finding.masvs_control
            ]))
            
            # Identify compliance violations
            result.compliance_violations = self._identify_compliance_violations(result)
            
            logger.debug("Analysis results enriched successfully")
            
        except Exception as e:
            logger.error(f"Result enrichment failed: {e}")
    
    def _calculate_risk_assessment(self, result: ComprehensivePIIAnalysisResult) -> None:
        """Calculate detailed risk assessment for transmission methods."""
        self.formatter.print_progress_update("Calculating risk assessment", "info")
        
        try:
            # Group findings by PII type and transmission method
            risk_combinations = {}
            
            for finding in result.all_pii_findings:
                key = (finding.pii_type, finding.transmission_method)
                if key not in risk_combinations:
                    risk_combinations[key] = []
                risk_combinations[key].append(finding)
            
            # Create transmission risk objects
            for (pii_type, trans_method), findings in risk_combinations.items():
                risk = self._create_transmission_risk(pii_type, trans_method, findings)
                result.transmission_risks.append(risk)
            
            # Sort by risk score
            result.transmission_risks.sort(key=lambda r: r.overall_risk_score, reverse=True)
            
            logger.debug(f"Risk assessment completed with {len(result.transmission_risks)} risk scenarios")
            
        except Exception as e:
            logger.error(f"Risk assessment calculation failed: {e}")
    
    def _generate_recommendations(self, result: ComprehensivePIIAnalysisResult) -> None:
        """Generate security recommendations based on findings."""
        self.formatter.print_progress_update("Generating recommendations", "info")
        
        try:
            recommendations = set()
            
            # Critical and high severity findings
            critical_high_findings = [
                f for f in result.all_pii_findings 
                if f.severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH]
            ]
            
            if critical_high_findings:
                recommendations.add("Immediately review and remediate critical/high severity PII exposures")
            
            # Insecure transmission methods
            insecure_transmissions = [
                f for f in result.all_pii_findings
                if f.transmission_method in [TransmissionMethod.HTTP, TransmissionMethod.SMS]
            ]
            
            if insecure_transmissions:
                recommendations.add("Migrate insecure PII transmissions to encrypted channels (HTTPS)")
            
            # Device identifiers
            device_id_findings = [
                f for f in result.all_pii_findings
                if f.pii_type in [PIIType.ANDROID_ID, PIIType.IMEI, PIIType.ADVERTISING_ID]
            ]
            
            if device_id_findings:
                recommendations.add("Consider using privacy-preserving identifiers instead of persistent device IDs")
            
            # Location data
            location_findings = [
                f for f in result.all_pii_findings
                if f.pii_type in [PIIType.GPS_COORDINATES, PIIType.ADDRESS]
            ]
            
            if location_findings:
                recommendations.add("Implement location data minimization and user consent mechanisms")
            
            # Authentication data
            auth_findings = [
                f for f in result.all_pii_findings
                if f.pii_type in [PIIType.API_KEY, PIIType.PASSWORD, PIIType.JWT_TOKEN]
            ]
            
            if auth_findings:
                recommendations.add("Secure authentication credentials and implement proper token management")
            
            # Network security
            if result.network_endpoints:
                insecure_endpoints = [e for e in result.network_endpoints if not e.uses_tls]
                if insecure_endpoints:
                    recommendations.add("Enable TLS encryption for all network communications")
            
            # Privacy compliance
            recommendations.add("Review data collection practices for privacy regulation compliance (GDPR/CCPA)")
            recommendations.add("Implement proper user consent and data minimization practices")
            
            result.recommendations = list(recommendations)
            
            logger.debug(f"Generated {len(result.recommendations)} security recommendations")
            
        except Exception as e:
            logger.error(f"Recommendation generation failed: {e}")
            result.recommendations = ["Review findings and implement appropriate security measures"]
    
    def _create_transmission_risk(self, pii_type: PIIType, trans_method: TransmissionMethod,
                                 findings: List[PIINetworkFinding]) -> TransmissionRisk:
        """Create a transmission risk object for a PII type and method combination."""
        # Calculate risk factors
        finding_severities = [f.severity for f in findings]
        avg_confidence = sum(f.confidence for f in findings) / len(findings)
        
        # Determine risk level
        if any(s == SeverityLevel.CRITICAL for s in finding_severities):
            risk_level = "CRITICAL"
            overall_score = 0.9 + (avg_confidence * 0.1)
        elif any(s == SeverityLevel.HIGH for s in finding_severities):
            risk_level = "HIGH"
            overall_score = 0.7 + (avg_confidence * 0.2)
        elif any(s == SeverityLevel.MEDIUM for s in finding_severities):
            risk_level = "MEDIUM"
            overall_score = 0.4 + (avg_confidence * 0.3)
        else:
            risk_level = "LOW"
            overall_score = 0.1 + (avg_confidence * 0.3)
        
        # Create risk factors
        risk_factors = [
            f"Found in {len(findings)} location(s)",
            f"Transmission method: {trans_method.value}",
            f"PII sensitivity: {self._get_pii_sensitivity(pii_type)}"
        ]
        
        # Create mitigation strategies
        mitigation_strategies = [
            "Encrypt sensitive data before transmission",
            "Use secure communication protocols (HTTPS)",
            "Implement data minimization practices",
            "Add user consent mechanisms"
        ]
        
        return TransmissionRisk(
            pii_type=pii_type,
            transmission_method=trans_method,
            risk_level=risk_level,
            risk_factors=risk_factors,
            mitigation_strategies=mitigation_strategies,
            exposure_likelihood=self._calculate_exposure_likelihood(trans_method),
            impact_severity=self._calculate_impact_severity(pii_type),
            detection_difficulty=self._calculate_detection_difficulty(findings),
            overall_risk_score=min(overall_score, 1.0)
        )
    
    def _calculate_overall_risk_level(self, result: ComprehensivePIIAnalysisResult) -> str:
        """Calculate overall risk level based on findings."""
        if result.critical_findings > 0:
            return "CRITICAL"
        elif result.high_findings > 0:
            return "HIGH"
        elif result.medium_findings > 0:
            return "MEDIUM"
        elif result.low_findings > 0:
            return "LOW"
        else:
            return "INFO"
    
    def _calculate_risk_score(self, result: ComprehensivePIIAnalysisResult) -> float:
        """Calculate numerical risk score."""
        if result.total_findings == 0:
            return 0.0
        
        # Weight findings by severity
        score = (
            (result.critical_findings * 1.0) +
            (result.high_findings * 0.7) +
            (result.medium_findings * 0.4) +
            (result.low_findings * 0.1)
        ) / result.total_findings
        
        return min(score, 1.0)
    
    def _calculate_privacy_risk_percentage(self, result: ComprehensivePIIAnalysisResult) -> float:
        """Calculate privacy risk as a percentage."""
        if result.total_findings == 0:
            return 0.0
        
        # Calculate based on high-risk PII types
        high_risk_types = [PIIType.PERSONAL_IDENTIFIER, PIIType.AUTHENTICATION_DATA, PIIType.BIOMETRIC_DATA]
        high_risk_findings = sum(
            1 for finding in result.all_pii_findings
            if finding.pii_type in high_risk_types
        )
        
        return (high_risk_findings / result.total_findings) * 100.0
    
    def _identify_compliance_violations(self, result: ComprehensivePIIAnalysisResult) -> List[str]:
        """Identify potential compliance violations."""
        violations = []
        
        # Check for GDPR-related issues
        personal_data_findings = [
            f for f in result.all_pii_findings
            if f.pii_type in [PIIType.PERSONAL_IDENTIFIER, PIIType.EMAIL, PIIType.PHONE_NUMBER]
        ]
        
        if personal_data_findings:
            violations.append("GDPR: Personal data processing without clear consent mechanism")
        
        # Check for CCPA-related issues
        device_id_findings = [
            f for f in result.all_pii_findings
            if f.pii_type in [PIIType.ANDROID_ID, PIIType.IMEI, PIIType.ADVERTISING_ID]
        ]
        
        if device_id_findings:
            violations.append("CCPA: Device identifier collection may require user disclosure")
        
        # Check for children's privacy (COPPA)
        if len(result.all_pii_findings) > 10:  # Heuristic for data collection intensity
            violations.append("COPPA: Extensive data collection may not be appropriate for children's apps")
        
        # Check for insecure transmission
        insecure_findings = [
            f for f in result.all_pii_findings
            if f.transmission_method == TransmissionMethod.HTTP
        ]
        
        if insecure_findings:
            violations.append("Security: PII transmitted over insecure connections")
        
        return violations
    
    def _create_error_result(self, error_message: str, duration: float, 
                           package_name: Optional[str]) -> ComprehensivePIIAnalysisResult:
        """Create an error result when analysis fails."""
        result = ComprehensivePIIAnalysisResult(
            package_name=package_name,
            analysis_timestamp=self.analysis_start_time or datetime.now()
        )
        
        result.analysis_duration = duration
        result.overall_risk_level = "ERROR"
        result.recommendations = [f"Analysis failed: {error_message}"]
        
        return result
    
    # Helper methods
    def _get_pii_sensitivity(self, pii_type: PIIType) -> str:
        """Get sensitivity level for PII type."""
        high_sensitivity = [PIIType.AUTHENTICATION_DATA, PIIType.BIOMETRIC_DATA, PIIType.PERSONAL_IDENTIFIER]
        medium_sensitivity = [PIIType.DEVICE_IDENTIFIER, PIIType.LOCATION_DATA, PIIType.BEHAVIORAL_DATA]
        
        if pii_type in high_sensitivity:
            return "HIGH"
        elif pii_type in medium_sensitivity:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _calculate_exposure_likelihood(self, trans_method: TransmissionMethod) -> float:
        """Calculate exposure likelihood for transmission method."""
        likelihood_map = {
            TransmissionMethod.HTTP: 0.9,
            TransmissionMethod.SMS: 0.8,
            TransmissionMethod.EMAIL: 0.6,
            TransmissionMethod.FTP: 0.7,
            TransmissionMethod.HTTPS: 0.2,
            TransmissionMethod.WEBSOCKET: 0.3,
            TransmissionMethod.UNKNOWN: 0.5
        }
        return likelihood_map.get(trans_method, 0.5)
    
    def _calculate_impact_severity(self, pii_type: PIIType) -> float:
        """Calculate impact severity for PII type."""
        severity_map = {
            PIIType.AUTHENTICATION_DATA: 1.0,
            PIIType.BIOMETRIC_DATA: 0.95,
            PIIType.PERSONAL_IDENTIFIER: 0.9,
            PIIType.DEVICE_IDENTIFIER: 0.6,
            PIIType.LOCATION_DATA: 0.7,
            PIIType.BEHAVIORAL_DATA: 0.5,
            PIIType.NETWORK_IDENTIFIER: 0.4,
            PIIType.SYSTEM_IDENTIFIER: 0.3
        }
        return severity_map.get(pii_type, 0.4)
    
    def _calculate_detection_difficulty(self, findings: List[PIINetworkFinding]) -> float:
        """Calculate difficulty of detecting this PII exposure."""
        avg_confidence = sum(f.confidence for f in findings) / len(findings)
        return 1.0 - avg_confidence  # Higher confidence = easier detection = lower difficulty
    
    # Public interface methods for backward compatibility
    def get_analysis_summary(self, result: ComprehensivePIIAnalysisResult) -> str:
        """Get formatted analysis summary."""
        return self.formatter.format_comprehensive_report(result)
    
    def export_json_report(self, result: ComprehensivePIIAnalysisResult, 
                          output_path: str) -> None:
        """Export analysis results to JSON."""
        self.formatter.export_json_report(result, output_path)
    
    def get_summary_table(self, result: ComprehensivePIIAnalysisResult):
        """Get Rich table summary."""
        return self.formatter.create_summary_table(result)
    
    def print_progress(self, message: str, status: str = "info") -> None:
        """Print progress message."""
        self.formatter.print_progress_update(message, status)

# Factory function for backward compatibility
def create_network_pii_analyzer(config: Optional[PIIConfiguration] = None,
                               console: Optional[Any] = None) -> NetworkPIITrafficAnalyzer:
    """Factory function to create a NetworkPIITrafficAnalyzer instance."""
    return NetworkPIITrafficAnalyzer(config=config, console=console)

# Main function for backward compatibility with original plugin interface
def main(apk_context) -> Dict[str, Any]:
    """
    Main function for backward compatibility with original plugin interface.
    
    Args:
        apk_context: Mock or actual APK context with package_name and apk_path attributes
        
    Returns:
        Dict containing analysis results in the expected format
    """
    try:
        # Create analyzer instance
        analyzer = NetworkPIITrafficAnalyzer()
        
        # Perform analysis
        package_name = getattr(apk_context, 'package_name', 'unknown')
        apk_path = getattr(apk_context, 'apk_path', 'unknown')
        
        result = analyzer.analyze_apk(apk_path, package_name)
        
        # Convert to backward-compatible format
        findings = []
        for finding in result.all_pii_findings:
            findings.append({
                'id': finding.finding_id,
                'type': finding.pii_type.value,
                'severity': finding.severity.value,
                'confidence': finding.confidence,
                'description': finding.description,
                'location': finding.location,
                'evidence': finding.evidence,
                'remediation': finding.remediation,
                'masvs_control': finding.masvs_control,
                'transmission_method': finding.transmission_method.value
            })
        
        network_endpoints = []
        for endpoint in result.network_endpoints:
            network_endpoints.append({
                'url': endpoint.url,
                'method': endpoint.method,
                'protocol': endpoint.protocol,
                'uses_tls': endpoint.uses_tls,
                'parameters': endpoint.parameters,
                'risk_level': endpoint.risk_level
            })
        
        return {
            'plugin_name': 'network_pii_traffic_analyzer',
            'version': '2.0.0',
            'package_name': package_name,
            'analysis_timestamp': result.analysis_timestamp.isoformat(),
            'summary': {
                'total_findings': result.total_findings,
                'critical_findings': result.critical_findings,
                'high_findings': result.high_findings,
                'medium_findings': result.medium_findings,
                'low_findings': result.low_findings,
                'risk_level': result.overall_risk_level,
                'risk_score': result.risk_score
            },
            'findings': findings,
            'network_endpoints': network_endpoints,
            'privacy_assessment': {
                'privacy_risk_percentage': result.privacy_risk_percentage,
                'compliance_violations': result.compliance_violations
            },
            'recommendations': result.recommendations,
            'analysis_duration': result.analysis_duration,
            'files_analyzed': result.files_analyzed
        }
        
    except Exception as e:
        logger.error(f"Error in main function: {e}")
        return {
            'plugin_name': 'network_pii_traffic_analyzer',
            'version': '2.0.0',
            'package_name': getattr(apk_context, 'package_name', 'unknown'),
            'error': str(e),
            'summary': {
                'total_findings': 0,
                'critical_findings': 0,
                'high_findings': 0,
                'medium_findings': 0,
                'low_findings': 0,
                'risk_level': 'UNKNOWN',
                'risk_score': 0.0
            },
            'findings': [],
            'network_endpoints': [],
            'recommendations': [],
            'analysis_duration': 0.0,
            'files_analyzed': 0
        }

# Export main interface
__all__ = [
    'NetworkPIITrafficAnalyzer',
    'create_network_pii_analyzer',
    'main',
    'PIIConfiguration',
    'ComprehensivePIIAnalysisResult',
    'PIINetworkFinding',
    'NetworkEndpoint',
    'NetworkPIIFormatter'
] 

# Plugin compatibility functions
def run(apk_ctx):
    """
    Main plugin entry point for compatibility with plugin manager.
    
    Args:
        apk_ctx: APK context object
        
    Returns:
        Tuple of (plugin_name, result)
    """
    try:
        from rich.text import Text
        
        # Create analyzer with correct parameters
        analyzer = NetworkPIITrafficAnalyzer()
        
        # Extract APK information
        package_name = getattr(apk_ctx, 'package_name', 'unknown')
        apk_path = getattr(apk_ctx, 'apk_path', 'unknown')
        
        # Perform analysis
        result = analyzer.analyze_apk(apk_path, package_name)
        
        # Format results
        if hasattr(result, 'all_pii_findings') and result.all_pii_findings:
            findings_text = Text()
            findings_text.append(f"Network PII Traffic Analysis - {len(result.all_pii_findings)} findings\n", style="bold blue")
            
            for finding in result.all_pii_findings[:10]:  # Limit to first 10 findings
                findings_text.append(f"• {finding.description}\n", style="yellow")
        else:
            findings_text = Text("Network PII Traffic Analysis completed - No PII detected", style="green")
            
        return "Network PII Traffic Analysis", findings_text
        
    except Exception as e:
        logger.error(f"Network PII traffic analysis failed: {e}")
        error_text = Text(f"Network PII Traffic Analysis Error: {str(e)}", style="red")
        return "Network PII Traffic Analysis", error_text

def run_plugin(apk_ctx):
    """
    Plugin interface function expected by the plugin manager.
    
    Args:
        apk_ctx: APK context object
        
    Returns:
        Tuple of (plugin_name, result)
    """
    return run(apk_ctx)

# Add run functions to exports
__all__.append('run')
__all__.append('run_plugin')

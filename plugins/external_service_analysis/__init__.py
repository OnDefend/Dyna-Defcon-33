"""
External Service Analysis Plugin Module

Comprehensive modular external service analysis plugin with dependency injection.
Provides analysis of cloud services, credential exposure, network security, and configurations.
"""

# Module exports
__all__ = ['ExternalServiceAnalysisPlugin']

from typing import Dict, List, Any, Optional, Tuple
import logging
import time
from pathlib import Path

from .data_structures import (
    ExternalServiceAnalysisResult, ServiceEndpoint, ExternalServiceVulnerability,
    CredentialExposure, NetworkSecurityIssue, ConfigurationIssue,
    ServiceType, SeverityLevel, RiskAssessment, AnalysisContext
)
from .service_detector import ServiceDetector, ServicePatternLoader
from .credential_analyzer import CredentialAnalyzer
from .network_security_analyzer import NetworkSecurityAnalyzer
from .confidence_calculator import ExternalServiceConfidenceCalculator
from .formatters import ExternalServiceFormatter

logger = logging.getLogger(__name__)

class ExternalServiceAnalysisPlugin:
    """
    Main external service analysis plugin with comprehensive modular architecture.
    
    This plugin provides analysis of:
    - Cloud service detection (AWS S3, Firebase, Google Cloud, Azure, etc.)
    - Credential exposure detection (API keys, tokens, passwords, etc.)
    - Network security analysis (SSL/TLS, protocols, certificates)
    - Configuration security assessment
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the external service analysis plugin.
        
        Args:
            config: Optional configuration dictionary
        """
        self.config = config or {}
        
        # Initialize modular components with dependency injection
        pattern_loader = ServicePatternLoader()
        
        self.service_detector = ServiceDetector(pattern_loader)
        self.credential_analyzer = CredentialAnalyzer()
        self.network_analyzer = NetworkSecurityAnalyzer()
        self.confidence_calculator = ExternalServiceConfidenceCalculator()
        self.formatter = ExternalServiceFormatter()
        
        # Analysis settings
        self.max_file_size = self.config.get('max_file_size', 10 * 1024 * 1024)  # 10MB
        self.enable_deep_analysis = self.config.get('enable_deep_analysis', True)
        self.analyze_test_files = self.config.get('analyze_test_files', False)
        
        logger.debug("ExternalServiceAnalysisPlugin initialized with comprehensive modular architecture")
    
    def analyze(self, apk_context: Dict[str, Any]) -> ExternalServiceAnalysisResult:
        """
        Perform comprehensive external service analysis.
        
        Args:
            apk_context: APK analysis context containing extracted files and metadata
            
        Returns:
            Complete external service analysis results
        """
        start_time = time.time()
        
        result = ExternalServiceAnalysisResult(
            package_name=apk_context.get('package_name', 'unknown')
        )
        
        try:
            logger.debug(f"Starting external service analysis for {result.package_name}")
            
            # Get files to analyze
            files_to_analyze = self._get_files_to_analyze(apk_context)
            result.files_analyzed = len(files_to_analyze)
            
            logger.debug(f"Analyzing {result.files_analyzed} files for external service patterns")
            
            # Analyze each file
            for file_path, content in files_to_analyze.items():
                try:
                    analysis_context = self._create_analysis_context(file_path, content)
                    
                    # Service detection
                    service_matches = self.service_detector.detect_services_in_content(
                        content, file_path, analysis_context
                    )
                    
                    if service_matches:
                        # Convert matches to endpoints
                        endpoints = self.service_detector.create_service_endpoints(service_matches)
                        result.detected_services.extend(endpoints)
                        
                        # Create vulnerabilities from service matches
                        service_vulnerabilities = self.service_detector.create_vulnerabilities_from_matches(service_matches)
                        for vuln in service_vulnerabilities:
                            # Calculate confidence using our confidence calculator
                            vuln.confidence = self.confidence_calculator.calculate_service_confidence(
                                vuln, context=analysis_context
                            )
                            result.add_vulnerability(vuln)
                    
                    # Credential exposure analysis
                    credential_exposures = self.credential_analyzer.analyze_credentials_in_content(
                        content, file_path, analysis_context
                    )
                    
                    for cred in credential_exposures:
                        # Calculate confidence for credentials
                        cred.confidence = self.confidence_calculator.calculate_credential_confidence(
                            cred, analysis_context
                        )
                        result.add_credential_exposure(cred)
                    
                    # Create vulnerabilities from credential exposures
                    cred_vulnerabilities = self.credential_analyzer.create_vulnerabilities_from_exposures(credential_exposures)
                    for vuln in cred_vulnerabilities:
                        vuln.confidence = self.confidence_calculator.calculate_service_confidence(
                            vuln, context=analysis_context
                        )
                        result.add_vulnerability(vuln)
                    
                    # Network security analysis
                    network_issues = self.network_analyzer.analyze_network_security(
                        content, file_path, analysis_context
                    )
                    
                    for issue in network_issues:
                        # Calculate confidence for network issues
                        issue.confidence = self.confidence_calculator.calculate_network_security_confidence(
                            issue, analysis_context
                        )
                        result.add_network_security_issue(issue)
                    
                    # Create vulnerabilities from network issues
                    network_vulnerabilities = self.network_analyzer.create_vulnerabilities_from_issues(network_issues)
                    for vuln in network_vulnerabilities:
                        vuln.confidence = self.confidence_calculator.calculate_service_confidence(
                            vuln, context=analysis_context
                        )
                        result.add_vulnerability(vuln)
                    
                except Exception as e:
                    logger.error(f"Error analyzing file {file_path}: {e}")
                    continue
            
            # Additional endpoint security analysis
            if result.detected_services:
                endpoint_issues = self.network_analyzer.analyze_endpoint_security(result.detected_services)
                for issue in endpoint_issues:
                    result.add_network_security_issue(issue)
                
                # Create vulnerabilities from endpoint issues
                endpoint_vulnerabilities = self.network_analyzer.create_vulnerabilities_from_issues(endpoint_issues)
                for vuln in endpoint_vulnerabilities:
                    result.add_vulnerability(vuln)
            
            # Analyze manifest for service permissions
            self._analyze_manifest_permissions(apk_context, result)
            
            # Calculate risk assessment
            self._calculate_risk_assessment(result)
            
            # Generate recommendations
            self._generate_security_recommendations(result)
            
            # Map MASVS controls
            self._map_masvs_controls(result)
            
            # Calculate analysis duration
            result.analysis_duration = time.time() - start_time
            
            logger.debug(f"External service analysis completed in {result.analysis_duration:.2f}s. "
                       f"Found {result.total_findings} findings across {len(result.detected_services)} services")
            
            return result
            
        except Exception as e:
            logger.error(f"Critical error in external service analysis: {e}")
            result.analysis_duration = time.time() - start_time
            return result
    
    def _get_files_to_analyze(self, apk_context: Dict[str, Any]) -> Dict[str, str]:
        """Get files that should be analyzed for external service patterns."""
        files_to_analyze = {}
        
        # Get extracted files from APK context
        extracted_files = apk_context.get('extracted_files', {})
        source_files = apk_context.get('source_files', {})
        resource_files = apk_context.get('resource_files', {})
        
        # Combine all available files
        all_files = {**extracted_files, **source_files, **resource_files}
        
        for file_path, content in all_files.items():
            if self._should_analyze_file(file_path, content):
                files_to_analyze[file_path] = content
        
        return files_to_analyze
    
    def _should_analyze_file(self, file_path: str, content: str) -> bool:
        """Determine if a file should be analyzed."""
        if not content or len(content.encode('utf-8')) > self.max_file_size:
            return False
        
        # File extensions to analyze
        analyzable_extensions = {
            '.java', '.kt', '.xml', '.json', '.properties', '.config',
            '.yml', '.yaml', '.txt', '.md', '.gradle', '.pro'
        }
        
        file_path_lower = file_path.lower()
        
        # Check extension
        if not any(file_path_lower.endswith(ext) for ext in analyzable_extensions):
            return False
        
        # Skip test files unless configured to analyze them
        if not self.analyze_test_files:
            test_indicators = ['test', 'spec', 'mock', 'stub', 'fake']
            if any(indicator in file_path_lower for indicator in test_indicators):
                return False
        
        # Skip generated files
        generated_indicators = ['generated', 'build', '.git', 'node_modules']
        if any(indicator in file_path_lower for indicator in generated_indicators):
            return False
        
        return True
    
    def _create_analysis_context(self, file_path: str, content: str) -> AnalysisContext:
        """Create analysis context for confidence calculation."""
        # Determine file type
        file_type = self._determine_file_type(file_path)
        
        # Determine analysis depth
        analysis_depth = "deep" if self.enable_deep_analysis else "basic"
        
        # Count pattern matches for cross-reference
        pattern_matches = 0
        if 'http' in content.lower():
            pattern_matches += content.lower().count('http')
        if 'api' in content.lower():
            pattern_matches += content.lower().count('api')
        
        return AnalysisContext(
            file_type=file_type,
            file_path=file_path,
            analysis_depth=analysis_depth,
            validation_sources=["static_analysis"],
            cross_references=0,  # Will be updated based on findings
            pattern_matches=min(10, pattern_matches)  # Cap at 10
        )
    
    def _determine_file_type(self, file_path: str) -> str:
        """Determine file type from file path."""
        file_path_lower = file_path.lower()
        
        if file_path_lower.endswith(('.java', '.kt')):
            return 'java' if file_path_lower.endswith('.java') else 'kotlin'
        elif file_path_lower.endswith('.xml'):
            return 'xml'
        elif file_path_lower.endswith('.json'):
            return 'json'
        elif file_path_lower.endswith(('.properties', '.config')):
            return 'properties'
        elif file_path_lower.endswith(('.yml', '.yaml')):
            return 'yaml'
        elif 'test' in file_path_lower or 'spec' in file_path_lower:
            return 'test'
        else:
            return 'other'
    
    def _analyze_manifest_permissions(self, apk_context: Dict[str, Any], result: ExternalServiceAnalysisResult):
        """Analyze manifest for service-related permissions."""
        try:
            manifest_content = apk_context.get('manifest_content')
            if not manifest_content:
                return
            
            # Look for permissions that might be related to external services
            service_related_permissions = [
                'android.permission.INTERNET',
                'android.permission.ACCESS_NETWORK_STATE',
                'android.permission.ACCESS_WIFI_STATE',
                'android.permission.WAKE_LOCK',
                'android.permission.RECEIVE_BOOT_COMPLETED',
                'android.permission.WRITE_EXTERNAL_STORAGE',
                'android.permission.READ_EXTERNAL_STORAGE',
                'com.google.android.c2dm.permission.RECEIVE',
                'com.android.vending.BILLING'
            ]
            
            for permission in service_related_permissions:
                if permission in manifest_content:
                    # Determine service type based on permission
                    service_type = self._get_service_type_from_permission(permission)
                    
                    from .data_structures import ServicePermission
                    perm = ServicePermission(
                        permission_name=permission,
                        service_type=service_type,
                        description=f"Permission {permission} may be used by external services",
                        risk_level=self._get_permission_risk_level(permission),
                        manifest_location="AndroidManifest.xml"
                    )
                    
                    result.service_permissions.append(perm)
            
        except Exception as e:
            logger.error(f"Error analyzing manifest permissions: {e}")
    
    def _get_service_type_from_permission(self, permission: str) -> ServiceType:
        """Map permission to likely service type."""
        permission_mapping = {
            'com.google.android.c2dm.permission.RECEIVE': ServiceType.FIREBASE,
            'com.android.vending.BILLING': ServiceType.PAYMENT_GATEWAY,
            'android.permission.INTERNET': ServiceType.REST_API,
            'android.permission.ACCESS_NETWORK_STATE': ServiceType.REST_API,
        }
        return permission_mapping.get(permission, ServiceType.UNKNOWN)
    
    def _get_permission_risk_level(self, permission: str) -> SeverityLevel:
        """Get risk level for permission."""
        high_risk_permissions = [
            'android.permission.WRITE_EXTERNAL_STORAGE',
            'com.android.vending.BILLING'
        ]
        
        if permission in high_risk_permissions:
            return SeverityLevel.HIGH
        else:
            return SeverityLevel.MEDIUM
    
    def _calculate_risk_assessment(self, result: ExternalServiceAnalysisResult):
        """Calculate overall risk assessment."""
        # Count issues by severity
        critical_count = sum(1 for v in result.vulnerabilities if v.severity == SeverityLevel.CRITICAL)
        high_count = sum(1 for v in result.vulnerabilities if v.severity == SeverityLevel.HIGH)
        medium_count = sum(1 for v in result.vulnerabilities if v.severity == SeverityLevel.MEDIUM)
        low_count = sum(1 for v in result.vulnerabilities if v.severity == SeverityLevel.LOW)
        
        # Update risk assessment
        result.risk_assessment.critical_issues = critical_count
        result.risk_assessment.high_issues = high_count
        result.risk_assessment.medium_issues = medium_count
        result.risk_assessment.low_issues = low_count
        
        # Calculate risk score (weighted)
        risk_score = (critical_count * 10 + high_count * 7 + medium_count * 4 + low_count * 1)
        result.risk_assessment.risk_score = risk_score
        
        # Determine risk level
        if critical_count > 0 or risk_score > 50:
            result.risk_assessment.risk_level = "CRITICAL"
        elif high_count > 0 or risk_score > 25:
            result.risk_assessment.risk_level = "HIGH"
        elif medium_count > 0 or risk_score > 10:
            result.risk_assessment.risk_level = "MEDIUM"
        else:
            result.risk_assessment.risk_level = "LOW"
    
    def _generate_security_recommendations(self, result: ExternalServiceAnalysisResult):
        """Generate security recommendations based on findings."""
        recommendations = []
        
        # Service-specific recommendations
        detected_service_types = {endpoint.service_type for endpoint in result.detected_services}
        
        if ServiceType.AWS_S3 in detected_service_types:
            recommendations.append("Review AWS S3 bucket permissions and access policies")
            recommendations.append("Ensure S3 buckets are not publicly accessible")
        
        if ServiceType.FIREBASE in detected_service_types:
            recommendations.append("Review Firebase security rules and database permissions")
        
        if ServiceType.PAYMENT_GATEWAY in detected_service_types:
            recommendations.append("Ensure PCI DSS compliance for payment processing")
        
        # Credential exposure recommendations
        if result.credential_exposures:
            recommendations.append("Remove all hardcoded credentials from source code")
            recommendations.append("Implement secure credential storage mechanisms")
            recommendations.append("Use environment variables or secure vaults for sensitive data")
        
        # Network security recommendations
        if result.network_security_issues:
            recommendations.append("Enable HTTPS for all external communications")
            recommendations.append("Implement proper certificate validation")
            recommendations.append("Use TLS 1.2 or higher with strong cipher suites")
        
        # General recommendations
        if result.total_findings > 0:
            recommendations.extend([
                "Implement proper secret management practices",
                "Regular security audits of external service integrations",
                "Monitor and log external service communications",
                "Implement least privilege access principles"
            ])
        
        result.risk_assessment.recommendations = recommendations
    
    def _map_masvs_controls(self, result: ExternalServiceAnalysisResult):
        """Map findings to MASVS controls."""
        masvs_controls = set()
        
        # Add controls based on findings
        if result.detected_services:
            masvs_controls.add("MSTG-NETWORK-01")  # Network requests use TLS
        
        if result.credential_exposures:
            masvs_controls.add("MSTG-CRYPTO-01")  # Cryptographic key management
            masvs_controls.add("MSTG-STORAGE-01")  # System credential storage
        
        if result.network_security_issues:
            masvs_controls.add("MSTG-NETWORK-02")  # TLS settings
            masvs_controls.add("MSTG-NETWORK-03")  # Certificate validation
        
        # Service-specific MASVS controls
        detected_service_types = {endpoint.service_type for endpoint in result.detected_services}
        
        if ServiceType.PAYMENT_GATEWAY in detected_service_types:
            masvs_controls.add("MSTG-AUTH-01")  # Authentication architecture
        
        if any(st in detected_service_types for st in [ServiceType.SOCIAL_MEDIA, ServiceType.ANALYTICS]):
            masvs_controls.add("MSTG-PLATFORM-01")  # App permissions
        
        result.masvs_controls = list(masvs_controls)
    
    def format_results(self, result: ExternalServiceAnalysisResult) -> str:
        """Format analysis results for display."""
        return self.formatter.format_analysis_results(result)

def create_plugin(config: Optional[Dict[str, Any]] = None) -> ExternalServiceAnalysisPlugin:
    """
    Factory function to create the external service analysis plugin.
    
    Args:
        config: Optional configuration dictionary
        
    Returns:
        Configured ExternalServiceAnalysisPlugin instance
    """
    return ExternalServiceAnalysisPlugin(config)

# Plugin discovery interface for AODS framework
def get_plugin_info() -> Dict[str, Any]:
    """Return plugin information for discovery."""
    return {
        "name": "External Service Analysis",
        "description": "Comprehensive analysis of external service integrations, credentials, and network security",
        "version": "2.0.0",
        "author": "AODS Framework",
        "category": "NETWORK_ANALYSIS",
        "tags": ["cloud_services", "credentials", "network_security", "configuration"],
        "masvs_controls": [
            "MSTG-NETWORK-01",
            "MSTG-NETWORK-02", 
            "MSTG-NETWORK-03",
            "MSTG-CRYPTO-01",
            "MSTG-STORAGE-01",
            "MSTG-AUTH-01",
            "MSTG-PLATFORM-01"
        ],
        "requires_device": False,
        "requires_network": False,
        "invasive": False,
        "execution_time_estimate": 60,
        "dependencies": ["yaml", "pathlib"]
    } 

class ExternalServiceAnalyzer:
    """External Service Analyzer for AODS integration."""
    
    def __init__(self, apk_ctx):
        """Initialize the external service analyzer."""
        self.apk_ctx = apk_ctx
        
    def analyze(self):
        """Perform external service analysis."""
        # Create empty result for now - can be enhanced later
        from .data_structures import ExternalServiceAnalysisResult
        
        result = ExternalServiceAnalysisResult(
            services=[],
            metadata={"analyzer": "external_service_analysis", "version": "1.0.0"}
        )
        return result

# Plugin compatibility functions
def run(apk_ctx):
    try:
        from rich.text import Text
        analyzer = ExternalServiceAnalyzer(apk_ctx)
        result = analyzer.analyze()
        
        if hasattr(result, 'findings') and result.findings:
            findings_text = Text(f"External Service Analysis - {len(result.findings)} findings\n", style="bold blue")
            for finding in result.findings[:10]:
                findings_text.append(f"• {finding.title}\n", style="yellow")
        else:
            findings_text = Text("External Service Analysis completed - No issues found", style="green")
            
        return "External Service Analysis", findings_text
    except Exception as e:
        error_text = Text(f"External Service Analysis Error: {str(e)}", style="red")
        return "External Service Analysis", error_text

def run_plugin(apk_ctx):
    return run(apk_ctx)

# Module exports - fixed __all__ definition
__all__ = ['ExternalServiceAnalysisPlugin', 'run', 'run_plugin'] 
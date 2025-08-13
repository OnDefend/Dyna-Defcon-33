#!/usr/bin/env python3
"""
Network Communication Tests Plugin - Modular Architecture

This module provides comprehensive network communication security testing
for Android applications implementing MASVS-NETWORK requirements.

Features:
- Network Security Configuration analysis
- Certificate pinning validation  
- Cleartext traffic detection
- URL scheme analysis
- TLS configuration assessment
- confidence calculation
- Rich text reporting

Modular Components:
- data_structures.py: Core data classes and enums
- network_security_config_analyzer.py: NSC analysis
- certificate_pinning_analyzer.py: Certificate pinning detection
- cleartext_traffic_analyzer.py: Cleartext traffic analysis
- url_scheme_analyzer.py: URL scheme validation
- tls_configuration_analyzer.py: TLS config assessment
- confidence_calculator.py: confidence calculation
- formatter.py: Rich text output formatting

MASVS Controls: MASVS-NETWORK-1, MASVS-NETWORK-2

"""

import logging
import time
from typing import Tuple, Union, Optional
from datetime import datetime

from rich.text import Text

from core.apk_ctx import APKContext
from .data_structures import (
    NetworkCommunicationAnalysisResult, NetworkCommunicationConfig,
    NetworkTestResult, NetworkTestFinding, NetworkTestType, 
    TestStatus, SeverityLevel, MasvsControl
)

logger = logging.getLogger(__name__)

# Plugin metadata
PLUGIN_METADATA = {
    "name": "Network Communication Tests",
    "description": "Comprehensive MASVS network communication security testing with modular architecture",
    "version": "2.0.0",
    "author": "AODS Development Team",
    "category": "NETWORK_SECURITY",
    "priority": "HIGH",
    "timeout": 120,
    "mode": "comprehensive",
    "requires_device": True,
    "requires_network": False,
    "invasive": False,
    "execution_time_estimate": 90,
    "dependencies": ["adb"],
    "modular_architecture": True,
    "components": [
        "network_security_config_analyzer",
        "certificate_pinning_analyzer",
        "cleartext_traffic_analyzer",
        "url_scheme_analyzer",
        "tls_configuration_analyzer",
        "confidence_calculator",
        "formatter",
        "data_structures"
    ],
    "masvs_controls": ["MASVS-NETWORK-1", "MASVS-NETWORK-2"],
    "test_types": ["network_security_config", "certificate_pinning", "cleartext_traffic", "url_schemes", "tls_configuration"]
}

PLUGIN_CHARACTERISTICS = {
    "mode": "safe",
    "category": "NETWORK",
    "targets": ["network_security", "communication_protocols"],
    "modular": True
}

class NetworkCommunicationTestsPlugin:
    """
    Main Network Communication Tests plugin using modular architecture.
    
    Orchestrates comprehensive network security testing through specialized
    analyzer components with professional confidence calculation.
    """
    
    def __init__(self, apk_ctx: APKContext, config: Optional[NetworkCommunicationConfig] = None):
        """Initialize the network communication tests plugin."""
        self.apk_ctx = apk_ctx
        self.config = config or NetworkCommunicationConfig()
        self.logger = logging.getLogger(__name__)
        
        # Analysis state
        self.analysis_start_time = None
        self.test_results = []
        
    def analyze(self) -> NetworkCommunicationAnalysisResult:
        """
        Perform comprehensive network communication security analysis.
        
        Returns:
            NetworkCommunicationAnalysisResult: Complete analysis results
        """
        self.analysis_start_time = time.time()
        
        if not self.apk_ctx.package_name:
            self.logger.error("Package name not available for network tests")
            return self._create_error_result("Package name not available")
        
        try:
            # Initialize results
            analysis_result = NetworkCommunicationAnalysisResult(
                overall_status=TestStatus.PASS,
                overall_severity=SeverityLevel.INFO
            )
            
            # Test 1: Network Security Configuration Analysis
            if self.config.enable_network_security_config_test:
                nsc_result = self._test_network_security_config()
                analysis_result.test_results.append(nsc_result)
            
            # Test 2: Certificate Pinning Detection
            if self.config.enable_certificate_pinning_test:
                cert_result = self._test_certificate_pinning()
                analysis_result.test_results.append(cert_result)
            
            # Test 3: Cleartext Traffic Detection
            if self.config.enable_cleartext_traffic_test:
                cleartext_result = self._test_cleartext_traffic()
                analysis_result.test_results.append(cleartext_result)
            
            # Test 4: URL Scheme Analysis
            if self.config.enable_url_schemes_test:
                url_result = self._test_url_schemes()
                analysis_result.test_results.append(url_result)
            
            # Test 5: TLS Configuration Assessment
            if self.config.enable_tls_configuration_test and hasattr(self.apk_ctx, 'drozer') and self.apk_ctx.drozer:
                tls_result = self._test_tls_configuration()
                analysis_result.test_results.append(tls_result)
            
            # Calculate execution time
            analysis_result.execution_time = time.time() - self.analysis_start_time
            
            # Calculate statistics and overall status
            analysis_result.calculate_statistics()
            
            # Generate findings from test results
            self._generate_findings(analysis_result)
            
            return analysis_result
            
        except Exception as e:
            self.logger.error(f"Network communication analysis failed: {e}", exc_info=True)
            return self._create_error_result(f"Analysis failed: {str(e)}")
    
    def _test_network_security_config(self) -> NetworkTestResult:
        """Test for Network Security Configuration."""
        self.logger.debug("Testing Network Security Configuration...")
        
        result = NetworkTestResult(
            test="Network Security Configuration",
            test_type=NetworkTestType.NETWORK_SECURITY_CONFIG,
            status=TestStatus.PASS  # Will be updated based on test results
        )
        
        try:
            import subprocess
            
            # Check for network security configuration files
            check_cmd = (
                f"adb shell run-as {self.apk_ctx.package_name} sh -c "
                f"\"find /data/data/{self.apk_ctx.package_name} -name '*.xml' -exec grep -l 'network\\|ssl\\|tls\\|certificate' {{}} \\;\""
            )
            
            subprocess_result = subprocess.run(
                check_cmd, shell=True, capture_output=True, text=True, timeout=self.config.timeout_seconds
            )
            
            if subprocess_result.returncode == 0 and subprocess_result.stdout.strip():
                config_files = subprocess_result.stdout.strip().split("\n")
                if config_files and config_files[0] != "":
                    result.status = TestStatus.PASS
                    result.evidence = config_files[:self.config.max_evidence_items]
                    result.recommendations.append("Verify network security configuration enforces secure practices")
                else:
                    result.status = TestStatus.FAIL
                    result.issues.append("No explicit network security configuration detected")
                    result.recommendations.append("Implement network security configuration to enforce HTTPS and certificate pinning")
            else:
                result.status = TestStatus.WARNING
                result.issues.append("Unable to access network security configuration files")
                result.recommendations.append("Verify network security configuration is properly implemented")
                
        except Exception as e:
            result.status = TestStatus.ERROR
            result.error_message = str(e)
            result.issues.append(f"Network security configuration test failed: {str(e)}")
            
        return result
    
    def _test_certificate_pinning(self) -> NetworkTestResult:
        """Test for certificate pinning implementation."""
        self.logger.debug("Testing Certificate Pinning...")
        
        result = NetworkTestResult(
            test="Certificate Pinning",
            test_type=NetworkTestType.CERTIFICATE_PINNING,
            status=TestStatus.PASS  # Will be updated based on test results
        )
        
        try:
            import subprocess
            
            # Look for certificate pinning indicators
            pinning_patterns = [
                "CertificatePinner",
                "PinningTrustManager", 
                "X509TrustManager",
                "certificate.*pin",
                "ssl.*pin",
                "pinning"
            ]
            
            search_cmd = (
                f"adb shell run-as {self.apk_ctx.package_name} sh -c "
                f"\"find /data/data/{self.apk_ctx.package_name} -type f \\( -name '*.dex' -o -name '*.jar' -o -name '*.so' \\) "
                f"-exec strings {{}} \\; 2>/dev/null | grep -E -i '({'|'.join(pinning_patterns)})' | head -10\""
            )
            
            subprocess_result = subprocess.run(
                search_cmd, shell=True, capture_output=True, text=True, timeout=self.config.timeout_seconds
            )
            
            if subprocess_result.returncode == 0 and subprocess_result.stdout.strip():
                pinning_indicators = subprocess_result.stdout.strip().split("\n")
                result.status = TestStatus.PASS
                result.evidence = pinning_indicators[:self.config.max_evidence_items]
                result.recommendations.append("Certificate pinning implementation detected - verify proper configuration")
            else:
                result.status = TestStatus.FAIL
                result.issues.append("No certificate pinning implementation detected")
                result.recommendations.append("Implement certificate or public key pinning for critical connections")
                
        except Exception as e:
            result.status = TestStatus.ERROR
            result.error_message = str(e)
            result.issues.append(f"Certificate pinning test failed: {str(e)}")
            
        return result
    
    def _test_cleartext_traffic(self) -> NetworkTestResult:
        """Test for cleartext traffic vulnerabilities."""
        self.logger.debug("Testing Cleartext Traffic...")
        
        result = NetworkTestResult(
            test="Cleartext Traffic",
            test_type=NetworkTestType.CLEARTEXT_TRAFFIC,
            status=TestStatus.PASS  # Will be updated based on test results
        )
        
        try:
            import subprocess
            
            # Look for cleartext HTTP URLs and insecure protocols
            cleartext_patterns = [
                "http://",
                "ftp://",
                "telnet://",
                "rlogin://",
                "ldap://"
            ]
            
            search_cmd = (
                f"adb shell run-as {self.apk_ctx.package_name} sh -c "
                f"\"find /data/data/{self.apk_ctx.package_name} -type f -exec grep -l -E '({'|'.join(cleartext_patterns)})' {{}} \\; 2>/dev/null | head -10\""
            )
            
            subprocess_result = subprocess.run(
                search_cmd, shell=True, capture_output=True, text=True, timeout=self.config.timeout_seconds
            )
            
            if subprocess_result.returncode == 0 and subprocess_result.stdout.strip():
                cleartext_files = subprocess_result.stdout.strip().split("\n")
                result.status = TestStatus.FAIL
                result.issues.append("Cleartext protocol usage detected")
                result.evidence = cleartext_files[:self.config.max_evidence_items]
                result.recommendations.append("Replace cleartext protocols with secure alternatives (HTTPS, SFTP, etc.)")
            else:
                result.status = TestStatus.PASS
                result.recommendations.append("No obvious cleartext protocol usage detected")
                
        except Exception as e:
            result.status = TestStatus.ERROR
            result.error_message = str(e)
            result.issues.append(f"Cleartext traffic test failed: {str(e)}")
            
        return result
    
    def _test_url_schemes(self) -> NetworkTestResult:
        """Test for URL scheme security."""
        self.logger.debug("Testing URL Schemes...")
        
        result = NetworkTestResult(
            test="URL Schemes",
            test_type=NetworkTestType.URL_SCHEMES,
            status=TestStatus.PASS  # Will be updated based on test results
        )
        
        try:
            import subprocess
            
            # Look for custom URL schemes and insecure patterns
            url_patterns = [
                "://",
                "intent://",
                "file://",
                "content://",
                "android_asset://"
            ]
            
            search_cmd = (
                f"adb shell run-as {self.apk_ctx.package_name} sh -c "
                f"\"find /data/data/{self.apk_ctx.package_name} -type f -exec grep -h -E '({'|'.join(url_patterns)})' {{}} \\; 2>/dev/null | head -20\""
            )
            
            subprocess_result = subprocess.run(
                search_cmd, shell=True, capture_output=True, text=True, timeout=self.config.timeout_seconds
            )
            
            if subprocess_result.returncode == 0 and subprocess_result.stdout.strip():
                url_schemes = subprocess_result.stdout.strip().split("\n")
                result.status = TestStatus.WARNING
                result.evidence = url_schemes[:self.config.max_evidence_items]
                result.recommendations.append("Review URL scheme usage for security implications")
                result.recommendations.append("Validate and sanitize all URL scheme inputs")
            else:
                result.status = TestStatus.PASS
                result.recommendations.append("No suspicious URL scheme usage detected")
                
        except Exception as e:
            result.status = TestStatus.ERROR
            result.error_message = str(e)
            result.issues.append(f"URL scheme test failed: {str(e)}")
            
        return result
    
    def _test_tls_configuration(self) -> NetworkTestResult:
        """Test TLS configuration using Drozer."""
        self.logger.debug("Testing TLS Configuration...")
        
        result = NetworkTestResult(
            test="TLS Configuration",
            test_type=NetworkTestType.TLS_CONFIGURATION,
            status=TestStatus.PASS  # Will be updated based on test results
        )
        
        try:
            # Note: This would require actual Drozer integration
            # For now, we'll create a basic implementation
            result.status = TestStatus.WARNING
            result.recommendations.append("Manual TLS configuration review recommended")
            result.recommendations.append("Verify TLS 1.2+ is enforced for all connections")
            result.recommendations.append("Check for weak cipher suites and protocol vulnerabilities")
            
        except Exception as e:
            result.status = TestStatus.ERROR
            result.error_message = str(e)
            result.issues.append(f"TLS configuration test failed: {str(e)}")
            
        return result
    
    def _generate_findings(self, analysis_result: NetworkCommunicationAnalysisResult):
        """Generate findings from test results."""
        for test_result in analysis_result.test_results:
            if test_result.status in [TestStatus.FAIL, TestStatus.WARNING]:
                # Determine severity based on test type and status
                if test_result.test_type == NetworkTestType.CLEARTEXT_TRAFFIC and test_result.status == TestStatus.FAIL:
                    severity = SeverityLevel.HIGH
                elif test_result.status == TestStatus.FAIL:
                    severity = SeverityLevel.MEDIUM
                else:
                    severity = SeverityLevel.LOW
                
                # Create finding
                finding = NetworkTestFinding(
                    test_type=test_result.test_type,
                    title=f"{test_result.test} Issues",
                    description=f"Issues found in {test_result.test.lower()}",
                    severity=severity,
                    status=test_result.status,
                    evidence=test_result.evidence,
                    recommendations=test_result.recommendations,
                    masvs_control=MasvsControl.MASVS_NETWORK_1,
                    confidence=0.8  # Base confidence
                )
                
                analysis_result.findings.append(finding)
    
    def _create_error_result(self, error_message: str) -> NetworkCommunicationAnalysisResult:
        """Create error result for failed analysis."""
        result = NetworkCommunicationAnalysisResult(
            overall_status=TestStatus.ERROR,
            overall_severity=SeverityLevel.HIGH
        )
        
        error_test = NetworkTestResult(
            test="Analysis Error",
            test_type=NetworkTestType.NETWORK_SECURITY_CONFIG,
            status=TestStatus.ERROR,
            error_message=error_message
        )
        error_test.issues.append(error_message)
        
        result.test_results.append(error_test)
        result.calculate_statistics()
        
        return result

def run(apk_ctx) -> Tuple[str, Union[str, Text]]:
    """
    Main plugin execution function.
    
    Args:
        apk_ctx: APK context containing analysis targets
        
    Returns:
        Tuple[str, Union[str, Text]]: Analysis results
    """
    plugin_name = "MASVS-NETWORK: Network Communication Security"
    
    try:
        # Initialize and run analysis
        plugin = NetworkCommunicationTestsPlugin(apk_ctx)
        analysis_result = plugin.analyze()
        
        # Format results (simplified for now)
        from rich.text import Text
        output = Text()
        
        # Header
        output.append("🌐 MASVS-NETWORK: Network Communication Security Analysis\n", style="bold blue")
        output.append("=" * 60 + "\n\n", style="blue")
        
        # Overall status
        status_style = "green" if analysis_result.overall_status == TestStatus.PASS else "red"
        output.append(f"Overall Status: {analysis_result.overall_status.value.upper()}\n", style=f"bold {status_style}")
        output.append(f"Tests: {analysis_result.passed_tests} passed, {analysis_result.failed_tests} failed\n\n")
        
        # Test results
        for i, test_result in enumerate(analysis_result.test_results, 1):
            status_icon = "✅" if test_result.status == TestStatus.PASS else "❌"
            output.append(f"{i}. {status_icon} {test_result.test}\n", style="bold")
            
            if test_result.issues:
                output.append("   Issues:\n", style="red")
                for issue in test_result.issues:
                    output.append(f"   • {issue}\n", style="red")
            
            if test_result.recommendations:
                output.append("   Recommendations:\n", style="yellow")
                for rec in test_result.recommendations:
                    output.append(f"   • {rec}\n", style="yellow")
            
            output.append("\n")
        
        return plugin_name, output
        
    except Exception as e:
        logger.error(f"Network communication tests failed: {e}", exc_info=True)
        error_output = Text()
        error_output.append(f"Network Communication Tests - ERROR\n\n", style="bold red")
        error_output.append(f"Analysis failed: {str(e)}\n", style="red")
        
        return plugin_name, error_output

def run_plugin(apk_ctx) -> Tuple[str, Union[str, Text]]:
    """Plugin interface function expected by the plugin manager."""
    return run(apk_ctx)

# Export for modular compatibility
__all__ = [
    'run',
    'run_plugin',
    'NetworkCommunicationTestsPlugin',
    'PLUGIN_METADATA',
    'PLUGIN_CHARACTERISTICS'
]

# Legacy compatibility export
PLUGIN_INFO = PLUGIN_METADATA 
#!/usr/bin/env python3
"""
Android Security Coordinator

Lightweight coordinator that intelligently leverages existing AODS plugins
to provide comprehensive Android security analysis without duplication.

This coordinator identifies which existing plugins cover which Android
security areas and orchestrates their execution for complete coverage.
"""

import logging
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass

from .data_structures import (
    AndroidSecurityConfig,
    AndroidSecurityAnalysisResult,
    AndroidVulnerability,
    AndroidVulnerabilityType,
    AndroidSeverityLevel
)

logger = logging.getLogger(__name__)

@dataclass
class PluginCoverageMap:
    """Maps Android security areas to existing AODS plugins."""
    
    storage_security: List[str] = None
    webview_security: List[str] = None  
    component_security: List[str] = None
    platform_security: List[str] = None
    vulnerability_detection: List[str] = None
    
    def __post_init__(self):
        # Map existing AODS plugins to Android security areas
        self.storage_security = [
            "enhanced_data_storage_modular",
            "insecure_data_storage", 
            "cryptography_tests"
        ]
        
        self.webview_security = [
            "webview_security_analysis"
        ]
        
        self.component_security = [
            "component_exploitation_plugin",
            "improper_platform_usage"
        ]
        
        self.platform_security = [
            "improper_platform_usage",
            "enhanced_manifest_analysis"
        ]
        
        self.vulnerability_detection = [
            "advanced_vulnerability_detection",
            "injection_vulnerabilities"
        ]

@dataclass 
class ConsolidatedResults:
    """Consolidated results from multiple plugin executions."""
    
    vulnerabilities: List[AndroidVulnerability]
    storage_issues: List[AndroidVulnerability]
    webview_issues: List[AndroidVulnerability]
    component_issues: List[AndroidVulnerability]
    platform_issues: List[AndroidVulnerability]
    
    critical_count: int
    high_count: int
    coverage_percentage: float

class AndroidSecurityCoordinator:
    """
    Coordinates existing AODS plugins for comprehensive Android security analysis.
    
    This coordinator avoids duplication by intelligently mapping Android
    security requirements to existing plugin capabilities.
    """
    
    def __init__(self, config: AndroidSecurityConfig):
        """Initialize the coordinator."""
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Plugin coverage mapping
        self.coverage_map = PluginCoverageMap()
        
        # Deduplication tracking
        self.seen_vulnerabilities = set()
        
    def consolidate_results(self, plugin_results: Dict[str, Any], apk_ctx) -> ConsolidatedResults:
        """
        Consolidate results from multiple plugin executions.
        
        Args:
            plugin_results: Results from executed plugins
            apk_ctx: Application context
            
        Returns:
            Consolidated and deduplicated security analysis results
        """
        self.logger.info("Consolidating results from multiple plugins...")
        
        # Initialize consolidated collections
        all_vulnerabilities = []
        storage_issues = []
        webview_issues = []
        component_issues = []
        platform_issues = []
        
        # Process each plugin result
        for plugin_name, result in plugin_results.items():
            processed_vulns = self._process_plugin_result(plugin_name, result)
            
            # Categorize vulnerabilities
            for vuln in processed_vulns:
                # Add to main collection if not duplicate
                if not self._is_duplicate(vuln):
                    all_vulnerabilities.append(vuln)
                    
                    # Categorize by type
                    if self._is_storage_vulnerability(vuln):
                        storage_issues.append(vuln)
                    elif self._is_webview_vulnerability(vuln):
                        webview_issues.append(vuln)
                    elif self._is_component_vulnerability(vuln):
                        component_issues.append(vuln)
                    elif self._is_platform_vulnerability(vuln):
                        platform_issues.append(vuln)
        
        # Calculate metrics
        critical_count = len([v for v in all_vulnerabilities if self._get_severity(v) == AndroidSeverityLevel.CRITICAL])
        high_count = len([v for v in all_vulnerabilities if self._get_severity(v) == AndroidSeverityLevel.HIGH])
        
        # Calculate coverage percentage based on categories covered
        coverage_percentage = self._calculate_coverage_percentage(all_vulnerabilities)
        
        self.logger.info(f"Consolidated {len(all_vulnerabilities)} unique vulnerabilities")
        self.logger.info(f"Coverage achieved: {coverage_percentage:.1f}%")
        
        return ConsolidatedResults(
            vulnerabilities=all_vulnerabilities,
            storage_issues=storage_issues,
            webview_issues=webview_issues,
            component_issues=component_issues,
            platform_issues=platform_issues,
            critical_count=critical_count,
            high_count=high_count,
            coverage_percentage=coverage_percentage
        )
    
    def _process_plugin_result(self, plugin_name: str, result: Any) -> List[AndroidVulnerability]:
        """Process result from a single plugin into standardized format."""
        
        vulnerabilities = []
        
        try:
            # Handle different plugin result formats
            if isinstance(result, tuple) and len(result) >= 2:
                # Format: (formatted_output, confidence)
                formatted_output, confidence = result[0], result[1]
                
                # Extract vulnerabilities from formatted output
                vulns = self._extract_vulnerabilities_from_output(formatted_output, plugin_name, confidence)
                vulnerabilities.extend(vulns)
                
            elif isinstance(result, dict):
                # Handle dictionary results
                vulns = self._extract_vulnerabilities_from_dict(result, plugin_name)
                vulnerabilities.extend(vulns)
                
            elif isinstance(result, list):
                # Handle list of vulnerabilities
                for item in result:
                    vuln = self._convert_to_android_vulnerability(item, plugin_name)
                    if vuln:
                        vulnerabilities.append(vuln)
                        
        except Exception as e:
            self.logger.warning(f"Failed to process result from {plugin_name}: {e}")
        
        return vulnerabilities
    
    def _extract_vulnerabilities_from_output(self, output: Any, plugin_name: str, confidence: float) -> List[AndroidVulnerability]:
        """Extract vulnerabilities from plugin output."""
        
        vulnerabilities = []
        
        # This is a simplified extraction - in practice would need more sophisticated parsing
        # based on each plugin's specific output format
        
        try:
            output_str = str(output)
            
            # Look for common vulnerability indicators
            if 'SharedPreferences' in output_str and 'MODE_WORLD_READABLE' in output_str:
                vuln = self._create_vulnerability(
                    "SHARED_PREFS_001",
                    AndroidVulnerabilityType.INSECURE_SHARED_PREFERENCES,
                    "Insecure SharedPreferences Usage",
                    "SharedPreferences using MODE_WORLD_READABLE detected",
                    AndroidSeverityLevel.HIGH,
                    confidence,
                    plugin_name
                )
                vulnerabilities.append(vuln)
                
            # Add more extraction logic based on actual plugin outputs
            
        except Exception as e:
            self.logger.debug(f"Error extracting vulnerabilities from {plugin_name} output: {e}")
        
        return vulnerabilities
    
    def _extract_vulnerabilities_from_dict(self, result_dict: Dict[str, Any], plugin_name: str) -> List[AndroidVulnerability]:
        """Extract vulnerabilities from dictionary result."""
        
        vulnerabilities = []
        
        # Handle common dictionary structures from AODS plugins
        if 'vulnerabilities' in result_dict:
            for vuln_data in result_dict['vulnerabilities']:
                vuln = self._convert_to_android_vulnerability(vuln_data, plugin_name)
                if vuln:
                    vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _convert_to_android_vulnerability(self, vuln_data: Any, plugin_name: str) -> Optional[AndroidVulnerability]:
        """Convert plugin-specific vulnerability data to AndroidVulnerability."""
        
        try:
            # Handle different vulnerability data formats
            if isinstance(vuln_data, dict):
                return AndroidVulnerability(
                    vulnerability_id=vuln_data.get('id', f"{plugin_name}_001"),
                    vulnerability_type=self._map_vulnerability_type(vuln_data.get('type', 'unknown')),
                    title=vuln_data.get('title', 'Security Issue'),
                    description=vuln_data.get('description', 'Security vulnerability detected'),
                    severity=self._map_severity(vuln_data.get('severity', 'MEDIUM')),
                    confidence=vuln_data.get('confidence', 0.8),
                    location=vuln_data.get('location', 'Unknown'),
                    file_path=vuln_data.get('file_path'),
                    line_number=vuln_data.get('line_number'),
                    evidence=vuln_data.get('evidence', ''),
                    detection_method=f"Plugin: {plugin_name}"
                )
                
        except Exception as e:
            self.logger.debug(f"Error converting vulnerability data: {e}")
        
        return None
    
    def _create_vulnerability(self, vuln_id: str, vuln_type: AndroidVulnerabilityType,
                            title: str, description: str, severity: AndroidSeverityLevel,
                            confidence: float, plugin_name: str) -> AndroidVulnerability:
        """Create a standardized AndroidVulnerability object."""
        
        return AndroidVulnerability(
            vulnerability_id=vuln_id,
            vulnerability_type=vuln_type,
            title=title,
            description=description,
            severity=severity,
            confidence=confidence,
            location="Unknown",
            detection_method=f"Plugin: {plugin_name}"
        )
    
    def _is_duplicate(self, vulnerability: AndroidVulnerability) -> bool:
        """Check if vulnerability is a duplicate."""
        
        # Create a simple fingerprint for deduplication
        fingerprint = f"{vulnerability.vulnerability_type.value}:{vulnerability.title}:{vulnerability.location}"
        
        if fingerprint in self.seen_vulnerabilities:
            return True
        
        self.seen_vulnerabilities.add(fingerprint)
        return False
    
    def _is_storage_vulnerability(self, vuln: AndroidVulnerability) -> bool:
        """Check if vulnerability is storage-related."""
        storage_types = {
            AndroidVulnerabilityType.INSECURE_SHARED_PREFERENCES,
            AndroidVulnerabilityType.INSECURE_FILE_STORAGE,
            AndroidVulnerabilityType.WORLD_READABLE_FILES,
            AndroidVulnerabilityType.EXTERNAL_STORAGE_MISUSE
        }
        return vuln.vulnerability_type in storage_types
    
    def _is_webview_vulnerability(self, vuln: AndroidVulnerability) -> bool:
        """Check if vulnerability is WebView-related."""
        webview_types = {
            AndroidVulnerabilityType.WEBVIEW_VULNERABILITIES,
            AndroidVulnerabilityType.WEBVIEW_JAVASCRIPT_INJECTION,
            AndroidVulnerabilityType.WEBVIEW_FILE_ACCESS
        }
        return vuln.vulnerability_type in webview_types
    
    def _is_component_vulnerability(self, vuln: AndroidVulnerability) -> bool:
        """Check if vulnerability is component-related."""
        component_types = {
            AndroidVulnerabilityType.EXPORTED_COMPONENTS,
            AndroidVulnerabilityType.UNPROTECTED_ACTIVITIES,
            AndroidVulnerabilityType.UNPROTECTED_SERVICES
        }
        return vuln.vulnerability_type in component_types
    
    def _is_platform_vulnerability(self, vuln: AndroidVulnerability) -> bool:
        """Check if vulnerability is platform-related."""
        platform_types = {
            AndroidVulnerabilityType.DEBUG_ENABLED,
            AndroidVulnerabilityType.BACKUP_ENABLED,
            AndroidVulnerabilityType.INSECURE_DEEP_LINKS
        }
        return vuln.vulnerability_type in platform_types
    
    def _get_severity(self, vuln: AndroidVulnerability) -> AndroidSeverityLevel:
        """Get severity of vulnerability."""
        return vuln.severity if hasattr(vuln, 'severity') else AndroidSeverityLevel.MEDIUM
    
    def _map_vulnerability_type(self, type_str: str) -> AndroidVulnerabilityType:
        """Map string vulnerability type to enum."""
        
        type_mapping = {
            'shared_preferences': AndroidVulnerabilityType.INSECURE_SHARED_PREFERENCES,
            'file_storage': AndroidVulnerabilityType.INSECURE_FILE_STORAGE,
            'webview': AndroidVulnerabilityType.WEBVIEW_VULNERABILITIES,
            'component': AndroidVulnerabilityType.EXPORTED_COMPONENTS,
            'logging': AndroidVulnerabilityType.INSECURE_LOGGING
        }
        
        return type_mapping.get(type_str.lower(), AndroidVulnerabilityType.INSECURE_FILE_STORAGE)
    
    def _map_severity(self, severity_str: str) -> AndroidSeverityLevel:
        """Map string severity to enum."""
        
        severity_mapping = {
            'critical': AndroidSeverityLevel.CRITICAL,
            'high': AndroidSeverityLevel.HIGH,
            'medium': AndroidSeverityLevel.MEDIUM,
            'low': AndroidSeverityLevel.LOW,
            'info': AndroidSeverityLevel.INFO
        }
        
        return severity_mapping.get(severity_str.lower(), AndroidSeverityLevel.MEDIUM)
    
    def _calculate_coverage_percentage(self, vulnerabilities: List[AndroidVulnerability]) -> float:
        """Calculate coverage percentage based on vulnerability types found."""
        
        # Define the main Android security categories we expect to cover
        expected_categories = {
            'storage', 'webview', 'component', 'platform', 'logging'
        }
        
        # Check which categories we have vulnerabilities for
        found_categories = set()
        
        for vuln in vulnerabilities:
            if self._is_storage_vulnerability(vuln):
                found_categories.add('storage')
            elif self._is_webview_vulnerability(vuln):
                found_categories.add('webview')
            elif self._is_component_vulnerability(vuln):
                found_categories.add('component')
            elif self._is_platform_vulnerability(vuln):
                found_categories.add('platform')
            elif vuln.vulnerability_type == AndroidVulnerabilityType.INSECURE_LOGGING:
                found_categories.add('logging')
        
        # Calculate coverage percentage
        coverage = len(found_categories) / len(expected_categories) * 100
        
        return coverage 
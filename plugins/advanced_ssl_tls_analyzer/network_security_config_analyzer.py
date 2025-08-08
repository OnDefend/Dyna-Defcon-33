#!/usr/bin/env python3
"""
Network Security Configuration Analyzer Module

This module provides comprehensive Android Network Security Configuration (NSC) 
analysis for SSL/TLS security assessment, including domain-specific configurations,
trust anchor validation, and compliance checking.

Key Features:
- Android Network Security Configuration XML parsing
- Domain-specific security policy analysis
- Trust anchor configuration validation
- Certificate transparency requirement checking
- Cleartext traffic policy assessment
- Debug override security analysis
- Compliance validation against Android security best practices
- Comprehensive vulnerability reporting with CWE mapping

MASVS Controls:
- MSTG-NETWORK-1: Network communication uses secure channels
- MSTG-NETWORK-2: TLS settings are aligned with current best practices
- MSTG-NETWORK-3: Certificate validation is properly implemented

"""

import logging
import xml.etree.ElementTree as ET
from typing import Dict, List, Any, Optional, Tuple, Set
from pathlib import Path
import re
from dataclasses import dataclass, field
from enum import Enum

from core.shared_infrastructure.dependency_injection import AnalysisContext
from core.shared_infrastructure.analysis_exceptions import NetworkSecurityConfigError, safe_execute, ErrorContext
from .data_structures import (
    NetworkSecurityConfigAnalysis, NetworkSecurityConfigCompliance,
    SSLTLSVulnerability, SSLTLSSeverity
)
from .confidence_calculator import SSLTLSConfidenceCalculator

# Import unified deduplication framework
from core.unified_deduplication_framework import (
    deduplicate_findings, 
    DeduplicationStrategy,
    create_deduplication_engine
)

class TrustAnchorType(Enum):
    """Trust anchor configuration types."""
    SYSTEM = "system"
    USER = "user"
    CUSTOM = "custom"

class CleartextTrafficPolicy(Enum):
    """Cleartext traffic policy options."""
    PERMITTED = "permitted"
    DENIED = "denied"
    INHERITED = "inherited"

@dataclass
class DomainConfiguration:
    """Domain-specific NSC configuration."""
    domains: List[str] = field(default_factory=list)
    subdomains_included: bool = True
    cleartext_permitted: Optional[bool] = None
    trust_anchors: List[str] = field(default_factory=list)
    certificate_pinning: bool = False
    pin_sets: List[Dict[str, Any]] = field(default_factory=list)
    certificate_transparency_required: bool = False

@dataclass
class NSCSecurityIssue:
    """Network Security Configuration security issue."""
    issue_type: str
    severity: SSLTLSSeverity
    description: str
    affected_domains: List[str] = field(default_factory=list)
    recommendation: str = ""
    cwe_id: str = ""

class NetworkSecurityConfigAnalyzer:
    """
    Comprehensive Network Security Configuration analyzer.
    
    Provides enterprise-grade analysis of Android Network Security Configuration
    including domain policies, trust anchors, and security compliance validation.
    """
    
    def __init__(self, context: AnalysisContext, confidence_calculator: SSLTLSConfidenceCalculator, logger: logging.Logger):
        """Initialize NSC analyzer with dependency injection."""
        self.context = context
        self.confidence_calculator = confidence_calculator
        self.logger = logger
        self.apk_ctx = context.apk_ctx
        
        # NSC analysis patterns
        self.nsc_patterns = self._initialize_nsc_patterns()
        
        # Analysis statistics
        self.stats = {
            'nsc_files_found': 0,
            'domain_configs_analyzed': 0,
            'security_issues_found': 0,
            'compliance_violations': 0
        }
    
    def analyze_network_security_config(self) -> NetworkSecurityConfigAnalysis:
        """
        Perform comprehensive Network Security Configuration analysis.
        
        Returns:
            NetworkSecurityConfigAnalysis containing complete NSC assessment
        """
        self.logger.info("Starting comprehensive Network Security Configuration analysis...")
        
        analysis = NetworkSecurityConfigAnalysis()
        
        try:
            # Find and parse NSC files
            nsc_files = safe_execute(
                lambda: self._find_nsc_files(),
                ErrorContext(component_name="nsc_analyzer", operation="file_discovery")
            )
            
            if nsc_files:
                analysis.nsc_file_found = True
                analysis.file_path = str(nsc_files[0])  # Primary NSC file
                self.stats['nsc_files_found'] = len(nsc_files)
                
                # Analyze each NSC file
                for nsc_file in nsc_files:
                    nsc_analysis = safe_execute(
                        lambda: self._analyze_nsc_file(nsc_file),
                        ErrorContext(component_name="nsc_analyzer", operation="file_analysis", 
                                   additional_context={"file": str(nsc_file)})
                    )
                    
                    if nsc_analysis:
                        self._merge_nsc_analysis(analysis, nsc_analysis)
                
                # Perform security assessment
                self._assess_nsc_security(analysis)
                
                # Check compliance
                analysis.compliance_status = self._assess_compliance(analysis)
                
                # Calculate security score
                analysis.security_score = self._calculate_security_score(analysis)
                
                # Generate recommendations
                analysis.recommendations = self._generate_recommendations(analysis)
                
            else:
                # No NSC file found - analyze implications
                self._analyze_missing_nsc(analysis)
            
            self.logger.info(f"NSC analysis completed: {len(analysis.compliance_issues)} compliance issues found")
            
        except Exception as e:
            self.logger.error(f"Error during NSC analysis: {e}")
            # Create error compliance issue
            error_issue = {
                'type': 'ANALYSIS_ERROR',
                'description': f"NSC analysis failed: {str(e)}",
                'severity': 'HIGH'
            }
            analysis.compliance_issues.append(error_issue)
        
        return analysis
    
    def _find_nsc_files(self) -> List[Path]:
        """Find Network Security Configuration files in the APK."""
        nsc_files = []
        
        if not hasattr(self.apk_ctx, 'decompiled_apk_dir') or not self.apk_ctx.decompiled_apk_dir:
            return nsc_files
        
        # Common NSC file locations
        search_paths = [
            self.apk_ctx.decompiled_apk_dir / "res" / "xml",
            self.apk_ctx.decompiled_apk_dir / "assets",
            self.apk_ctx.decompiled_apk_dir / "res" / "raw"
        ]
        
        # Common NSC file names
        nsc_filenames = [
            "network_security_config.xml",
            "network-security-config.xml", 
            "network_config.xml",
            "nsc.xml",
            "net_security_config.xml"
        ]
        
        for search_path in search_paths:
            if search_path.exists():
                # Search for standard NSC filenames
                for filename in nsc_filenames:
                    nsc_file = search_path / filename
                    if nsc_file.exists():
                        nsc_files.append(nsc_file)
                
                # Search for XML files containing NSC patterns
                for xml_file in search_path.glob("*.xml"):
                    if xml_file.name not in nsc_filenames:
                        try:
                            content = xml_file.read_text(encoding='utf-8', errors='ignore')
                            if self._contains_nsc_patterns(content):
                                nsc_files.append(xml_file)
                        except Exception as e:
                            self.logger.debug(f"Error reading potential NSC file {xml_file}: {e}")
        
        return list(set(nsc_files))  # Remove duplicates
    
    def _contains_nsc_patterns(self, content: str) -> bool:
        """Check if XML content contains NSC patterns."""
        nsc_indicators = [
            'network-security-config',
            'cleartextTrafficPermitted',
            'domain-config',
            'base-config',
            'trust-anchors',
            'pin-set',
            'certificate-transparency-policy'
        ]
        
        return any(indicator in content for indicator in nsc_indicators)
    
    def _analyze_nsc_file(self, nsc_file: Path) -> Dict[str, Any]:
        """Analyze individual NSC file."""
        self.logger.info(f"Analyzing NSC file: {nsc_file.name}")
        
        nsc_analysis = {
            'file_path': str(nsc_file),
            'base_config': {},
            'domain_configs': [],
            'trust_anchors': [],
            'certificate_transparency': {},
            'cleartext_traffic': {},
            'debug_overrides': {},
            'pinning_configurations': [],
            'security_issues': [],
            'parse_errors': []
        }
        
        try:
            content = nsc_file.read_text(encoding='utf-8', errors='ignore')
            
            # Try XML parsing first
            try:
                root = ET.fromstring(content)
                self._parse_nsc_xml(root, nsc_analysis)
            except ET.ParseError as e:
                self.logger.warning(f"XML parsing failed for {nsc_file.name}: {e}")
                nsc_analysis['parse_errors'].append(f"XML parsing error: {str(e)}")
                # Fallback to pattern-based analysis
                self._analyze_nsc_patterns(content, nsc_analysis)
            
        except Exception as e:
            self.logger.error(f"Error analyzing NSC file {nsc_file}: {e}")
            nsc_analysis['parse_errors'].append(f"File reading error: {str(e)}")
        
        return nsc_analysis
    
    def _parse_nsc_xml(self, root: ET.Element, analysis: Dict[str, Any]) -> None:
        """Parse NSC XML structure."""
        # Analyze base configuration
        base_config = root.find('base-config')
        if base_config is not None:
            analysis['base_config'] = self._parse_base_config(base_config)
        
        # Analyze domain configurations
        for domain_config in root.findall('domain-config'):
            domain_analysis = self._parse_domain_config(domain_config)
            analysis['domain_configs'].append(domain_analysis)
            self.stats['domain_configs_analyzed'] += 1
        
        # Analyze debug overrides
        debug_overrides = root.find('debug-overrides')
        if debug_overrides is not None:
            analysis['debug_overrides'] = self._parse_debug_overrides(debug_overrides)
            
            # Debug overrides in production are a security issue
            security_issue = NSCSecurityIssue(
                issue_type="DEBUG_OVERRIDES_ENABLED",
                severity=SSLTLSSeverity.MEDIUM,
                description="Debug overrides are enabled in Network Security Configuration",
                recommendation="Remove debug-overrides in production builds",
                cwe_id="CWE-489"
            )
            analysis['security_issues'].append(security_issue)
            self.stats['security_issues_found'] += 1
    
    def _parse_base_config(self, base_config: ET.Element) -> Dict[str, Any]:
        """Parse base configuration element."""
        config = {
            'cleartext_permitted': None,
            'trust_anchors': [],
            'certificate_transparency_required': False
        }
        
        # Parse cleartext traffic permission
        cleartext_attr = base_config.get('cleartextTrafficPermitted')
        if cleartext_attr is not None:
            config['cleartext_permitted'] = cleartext_attr.lower() == 'true'
        
        # Parse trust anchors
        trust_anchors = base_config.find('trust-anchors')
        if trust_anchors is not None:
            config['trust_anchors'] = self._parse_trust_anchors(trust_anchors)
        
        # Parse certificate transparency
        ct_policy = base_config.find('certificate-transparency-policy')
        if ct_policy is not None:
            config['certificate_transparency_required'] = ct_policy.get('enabled', 'true').lower() == 'true'
        
        return config
    
    def _parse_domain_config(self, domain_config: ET.Element) -> DomainConfiguration:
        """Parse domain-specific configuration."""
        config = DomainConfiguration()
        
        # Parse cleartext traffic permission
        cleartext_attr = domain_config.get('cleartextTrafficPermitted')
        if cleartext_attr is not None:
            config.cleartext_permitted = cleartext_attr.lower() == 'true'
        
        # Parse domains
        for domain_elem in domain_config.findall('domain'):
            if domain_elem.text:
                config.domains.append(domain_elem.text.strip())
                # Check if subdomains are included
                include_subdomains = domain_elem.get('includeSubdomains', 'true')
                config.subdomains_included = include_subdomains.lower() == 'true'
        
        # Parse trust anchors
        trust_anchors = domain_config.find('trust-anchors')
        if trust_anchors is not None:
            config.trust_anchors = self._parse_trust_anchors(trust_anchors)
        
        # Parse certificate pinning
        pin_set = domain_config.find('pin-set')
        if pin_set is not None:
            config.certificate_pinning = True
            config.pin_sets = self._parse_pin_sets(pin_set)
        
        # Parse certificate transparency
        ct_policy = domain_config.find('certificate-transparency-policy')
        if ct_policy is not None:
            config.certificate_transparency_required = ct_policy.get('enabled', 'true').lower() == 'true'
        
        return config
    
    def _parse_trust_anchors(self, trust_anchors: ET.Element) -> List[Dict[str, Any]]:
        """Parse trust anchor configurations."""
        anchors = []
        
        for certificates in trust_anchors.findall('certificates'):
            src = certificates.get('src', '')
            overridePins = certificates.get('overridePins', 'false').lower() == 'true'
            
            anchor = {
                'type': src,
                'override_pins': overridePins,
                'description': self._get_trust_anchor_description(src)
            }
            anchors.append(anchor)
        
        return anchors
    
    def _parse_pin_sets(self, pin_set: ET.Element) -> List[Dict[str, Any]]:
        """Parse certificate pinning pin-sets."""
        pin_sets = []
        
        for pin in pin_set.findall('pin'):
            digest = pin.get('digest', 'SHA256')
            pin_value = pin.text.strip() if pin.text else ''
            
            if pin_value:
                pin_info = {
                    'digest': digest,
                    'value': pin_value,
                    'strength': self._assess_pin_strength(digest, pin_value)
                }
                pin_sets.append(pin_info)
        
        return pin_sets
    
    def _parse_debug_overrides(self, debug_overrides: ET.Element) -> Dict[str, Any]:
        """Parse debug override configurations."""
        overrides = {
            'enabled': True,
            'trust_anchors': [],
            'security_impact': 'HIGH'
        }
        
        # Parse debug trust anchors
        trust_anchors = debug_overrides.find('trust-anchors')
        if trust_anchors is not None:
            overrides['trust_anchors'] = self._parse_trust_anchors(trust_anchors)
        
        return overrides
    
    def _analyze_nsc_patterns(self, content: str, analysis: Dict[str, Any]) -> None:
        """Fallback pattern-based analysis for unparseable XML."""
        self.logger.info("Performing pattern-based NSC analysis...")
        
        # Check for cleartext traffic patterns
        if re.search(r'cleartextTrafficPermitted\s*=\s*["\']true["\']', content, re.IGNORECASE):
            security_issue = NSCSecurityIssue(
                issue_type="CLEARTEXT_TRAFFIC_PERMITTED",
                severity=SSLTLSSeverity.HIGH,
                description="Cleartext traffic is explicitly permitted",
                recommendation="Set cleartextTrafficPermitted to false",
                cwe_id="CWE-319"
            )
            analysis['security_issues'].append(security_issue)
        
        # Check for trust anchor configurations
        if re.search(r'certificates\s+src\s*=\s*["\']user["\']', content, re.IGNORECASE):
            security_issue = NSCSecurityIssue(
                issue_type="USER_TRUST_ANCHORS",
                severity=SSLTLSSeverity.MEDIUM,
                description="User-added CA certificates are trusted",
                recommendation="Consider restricting trust to system CAs only",
                cwe_id="CWE-295"
            )
            analysis['security_issues'].append(security_issue)
        
        # Check for debug overrides
        if re.search(r'debug-overrides', content, re.IGNORECASE):
            security_issue = NSCSecurityIssue(
                issue_type="DEBUG_OVERRIDES_FOUND",
                severity=SSLTLSSeverity.MEDIUM,
                description="Debug overrides detected in NSC",
                recommendation="Remove debug overrides from production builds",
                cwe_id="CWE-489"
            )
            analysis['security_issues'].append(security_issue)
    
    def _assess_nsc_security(self, analysis: NetworkSecurityConfigAnalysis) -> None:
        """Assess NSC security and identify issues."""
        security_issues = []
        
        # Check base configuration security
        if analysis.base_config:
            base_issues = self._assess_base_config_security(analysis.base_config)
            security_issues.extend(base_issues)
        
        # Check domain configuration security
        for domain_config in analysis.domain_configs:
            domain_issues = self._assess_domain_config_security(domain_config)
            security_issues.extend(domain_issues)
        
        # Check for risky trust anchor configurations
        trust_anchor_issues = self._assess_trust_anchor_security(analysis.trust_anchors)
        security_issues.extend(trust_anchor_issues)
        
        # Convert security issues to compliance issues
        for issue in security_issues:
            compliance_issue = {
                'type': issue.issue_type,
                'description': issue.description,
                'severity': issue.severity.value,
                'affected_domains': issue.affected_domains,
                'recommendation': issue.recommendation,
                'cwe_id': issue.cwe_id
            }
            analysis.compliance_issues.append(compliance_issue)
    
    def _assess_base_config_security(self, base_config: Dict[str, Any]) -> List[NSCSecurityIssue]:
        """Assess base configuration security."""
        issues = []
        
        # Check cleartext traffic permission
        if base_config.get('cleartext_permitted', False):
            issue = NSCSecurityIssue(
                issue_type="BASE_CLEARTEXT_PERMITTED",
                severity=SSLTLSSeverity.HIGH,
                description="Base configuration permits cleartext traffic for all domains",
                recommendation="Set cleartextTrafficPermitted to false in base-config",
                cwe_id="CWE-319"
            )
            issues.append(issue)
        
        # Check trust anchor configuration
        trust_anchors = base_config.get('trust_anchors', [])
        for anchor in trust_anchors:
            if anchor.get('type') == 'user':
                issue = NSCSecurityIssue(
                    issue_type="BASE_USER_TRUST_ANCHORS",
                    severity=SSLTLSSeverity.MEDIUM,
                    description="Base configuration trusts user-added CA certificates",
                    recommendation="Consider using system trust anchors only",
                    cwe_id="CWE-295"
                )
                issues.append(issue)
        
        return issues
    
    def _assess_domain_config_security(self, domain_config: Dict[str, Any]) -> List[NSCSecurityIssue]:
        """Assess domain-specific configuration security."""
        issues = []
        
        # Extract domain names if available
        domain_names = []
        if isinstance(domain_config, dict):
            domains = domain_config.get('domains', [])
            if isinstance(domains, list):
                domain_names = domains
        
        # Check for domain-specific cleartext permission
        if domain_config.get('cleartext_permitted', False):
            issue = NSCSecurityIssue(
                issue_type="DOMAIN_CLEARTEXT_PERMITTED",
                severity=SSLTLSSeverity.MEDIUM,
                description=f"Cleartext traffic permitted for specific domains",
                affected_domains=domain_names,
                recommendation="Use HTTPS for all network communications",
                cwe_id="CWE-319"
            )
            issues.append(issue)
        
        return issues
    
    def _assess_trust_anchor_security(self, trust_anchors: List[Dict[str, Any]]) -> List[NSCSecurityIssue]:
        """Assess trust anchor security configuration."""
        issues = []
        
        for anchor in trust_anchors:
            if anchor.get('type') == 'user' and not anchor.get('override_pins', False):
                issue = NSCSecurityIssue(
                    issue_type="TRUST_ANCHOR_USER_CAS",
                    severity=SSLTLSSeverity.MEDIUM,
                    description="Configuration trusts user-added CA certificates",
                    recommendation="Restrict trust to system CAs or implement certificate pinning",
                    cwe_id="CWE-295"
                )
                issues.append(issue)
        
        return issues
    
    def _analyze_missing_nsc(self, analysis: NetworkSecurityConfigAnalysis) -> None:
        """Analyze implications of missing NSC."""
        analysis.compliance_status = NetworkSecurityConfigCompliance.NOT_CONFIGURED
        
        # Missing NSC means default Android behavior
        missing_nsc_issue = {
            'type': 'NSC_NOT_CONFIGURED',
            'description': 'No Network Security Configuration found - using Android defaults',
            'severity': 'LOW',
            'recommendation': 'Consider implementing Network Security Configuration for enhanced security',
            'cwe_id': 'CWE-1188'
        }
        analysis.compliance_issues.append(missing_nsc_issue)
    
    def _assess_compliance(self, analysis: NetworkSecurityConfigAnalysis) -> NetworkSecurityConfigCompliance:
        """Assess overall NSC compliance status."""
        if not analysis.nsc_file_found:
            return NetworkSecurityConfigCompliance.NOT_CONFIGURED
        
        # Check for critical compliance issues
        critical_issues = [
            issue for issue in analysis.compliance_issues 
            if issue.get('severity') == 'CRITICAL'
        ]
        
        high_issues = [
            issue for issue in analysis.compliance_issues 
            if issue.get('severity') == 'HIGH'
        ]
        
        if critical_issues:
            return NetworkSecurityConfigCompliance.NON_COMPLIANT
        elif high_issues:
            return NetworkSecurityConfigCompliance.PARTIALLY_COMPLIANT
        else:
            return NetworkSecurityConfigCompliance.COMPLIANT
    
    def _calculate_security_score(self, analysis: NetworkSecurityConfigAnalysis) -> int:
        """Calculate NSC security score (0-100)."""
        if not analysis.nsc_file_found:
            return 50  # Default Android security
        
        base_score = 100
        
        # Deduct points for security issues
        for issue in analysis.compliance_issues:
            severity = issue.get('severity', 'LOW')
            if severity == 'CRITICAL':
                base_score -= 25
            elif severity == 'HIGH':
                base_score -= 15
            elif severity == 'MEDIUM':
                base_score -= 10
            elif severity == 'LOW':
                base_score -= 5
        
        # Bonus points for good practices
        if analysis.certificate_transparency.get('enabled', False):
            base_score += 5
        
        if analysis.pinning_configurations:
            base_score += 10
        
        return max(0, min(100, base_score))
    
    def _generate_recommendations(self, analysis: NetworkSecurityConfigAnalysis) -> List[str]:
        """Generate security recommendations based on analysis."""
        recommendations = []
        
        if not analysis.nsc_file_found:
            recommendations.extend([
                "Implement Network Security Configuration for enhanced security control",
                "Disable cleartext traffic by setting cleartextTrafficPermitted='false'",
                "Consider implementing certificate pinning for critical connections"
            ])
        else:
            # Generate specific recommendations based on findings
            if any(issue.get('type') == 'CLEARTEXT_TRAFFIC_PERMITTED' for issue in analysis.compliance_issues):
                recommendations.append("Disable cleartext traffic permission in Network Security Configuration")
            
            if any(issue.get('type') == 'DEBUG_OVERRIDES_ENABLED' for issue in analysis.compliance_issues):
                recommendations.append("Remove debug overrides from production builds")
            
            if not analysis.pinning_configurations:
                recommendations.append("Consider implementing certificate pinning for critical API endpoints")
            
            if any(issue.get('type') == 'USER_TRUST_ANCHORS' for issue in analysis.compliance_issues):
                recommendations.append("Restrict trust anchors to system CAs only")
        
        return recommendations
    
    def _get_trust_anchor_description(self, anchor_type: str) -> str:
        """Get description for trust anchor type."""
        descriptions = {
            'system': 'System trust store (recommended)',
            'user': 'User-added CA certificates (risky)',
            'custom': 'Custom certificate bundle'
        }
        return descriptions.get(anchor_type, f'Unknown trust anchor type: {anchor_type}')
    
    def _assess_pin_strength(self, digest: str, pin_value: str) -> str:
        """Assess certificate pin strength."""
        if digest.upper() == 'SHA256' and len(pin_value) >= 32:
            return 'HIGH'
        elif digest.upper() == 'SHA1':
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _merge_nsc_analysis(self, main_analysis: NetworkSecurityConfigAnalysis, file_analysis: Dict[str, Any]) -> None:
        """Merge individual file analysis into main analysis."""
        # Merge base config
        if file_analysis.get('base_config'):
            main_analysis.base_config.update(file_analysis['base_config'])
        
        # Merge domain configs
        main_analysis.domain_configs.extend(file_analysis.get('domain_configs', []))
        
        # Merge trust anchors
        main_analysis.trust_anchors.extend(file_analysis.get('trust_anchors', []))
        
        # Merge other configurations
        if file_analysis.get('certificate_transparency'):
            main_analysis.certificate_transparency.update(file_analysis['certificate_transparency'])
        
        if file_analysis.get('cleartext_traffic'):
            main_analysis.cleartext_traffic.update(file_analysis['cleartext_traffic'])
        
        if file_analysis.get('debug_overrides'):
            main_analysis.debug_overrides.update(file_analysis['debug_overrides'])
        
        # Merge pinning configurations
        main_analysis.pinning_configurations.extend(file_analysis.get('pinning_configurations', []))
    
    def _initialize_nsc_patterns(self) -> Dict[str, Any]:
        """Initialize NSC analysis patterns."""
        return {
            'cleartext_permitted': re.compile(r'cleartextTrafficPermitted\s*=\s*["\']true["\']', re.IGNORECASE),
            'cleartext_denied': re.compile(r'cleartextTrafficPermitted\s*=\s*["\']false["\']', re.IGNORECASE),
            'domain_config': re.compile(r'<domain-config[^>]*>', re.IGNORECASE),
            'pin_set': re.compile(r'<pin-set[^>]*>', re.IGNORECASE),
            'trust_anchors': re.compile(r'<trust-anchors[^>]*>', re.IGNORECASE),
            'debug_overrides': re.compile(r'<debug-overrides[^>]*>', re.IGNORECASE),
            'user_trust': re.compile(r'src\s*=\s*["\']user["\']', re.IGNORECASE)
        }
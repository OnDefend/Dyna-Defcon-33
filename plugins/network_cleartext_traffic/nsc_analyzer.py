#!/usr/bin/env python3
"""
Network Cleartext Traffic Analyzer - Network Security Configuration Analyzer

This module provides comprehensive analysis of Android Network Security Configuration (NSC)
files for cleartext traffic policies, certificate pinning, and trust anchor configuration.

Features:
- NSC XML file parsing and validation
- Cleartext traffic policy analysis
- Certificate pinning configuration detection
- Trust anchor validation
- Domain-specific configuration analysis
- Debug override detection

Classes:
    NSCAnalyzer: Main Network Security Configuration analysis engine
"""

import logging
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List, Optional, Any, Set
from datetime import datetime

from .data_structures import (
    NSCAnalysisResult, NetworkSecurityFinding, FindingType, RiskLevel,
    NSCConfigType
)
from .confidence_calculator import NetworkCleartextConfidenceCalculator

class NSCAnalyzer:
    """
    Network Security Configuration analyzer for Android applications.
    
    Analyzes Network Security Configuration files to identify cleartext traffic
    policies, certificate pinning configurations, and security misconfigurations.
    """
    
    def __init__(self, confidence_calculator: NetworkCleartextConfidenceCalculator):
        """
        Initialize NSC analyzer.
        
        Args:
            confidence_calculator: Confidence calculation engine
        """
        self.logger = logging.getLogger(__name__)
        self.confidence_calculator = confidence_calculator
        
        # NSC element patterns for analysis
        self.nsc_patterns = {
            'cleartext_permitted': re.compile(
                r'cleartextTrafficPermitted\s*=\s*["\']?(true|false)["\']?',
                re.IGNORECASE
            ),
            'domain_config': re.compile(r'<domain-config[^>]*>', re.IGNORECASE),
            'trust_anchors': re.compile(r'<trust-anchors[^>]*>', re.IGNORECASE),
            'pin_set': re.compile(r'<pin-set[^>]*>', re.IGNORECASE),
            'debug_overrides': re.compile(r'<debug-overrides[^>]*>', re.IGNORECASE),
            'base_config': re.compile(r'<base-config[^>]*>', re.IGNORECASE),
            'domain_element': re.compile(r'<domain[^>]*>([^<]+)</domain>', re.IGNORECASE),
            'pin_digest': re.compile(r'<pin[^>]*digest\s*=\s*["\']([^"\']+)["\'][^>]*>', re.IGNORECASE)
        }
        
        # Common NSC file locations
        self.nsc_search_paths = [
            "res/xml/network_security_config.xml",
            "res/xml/network_config.xml",
            "res/xml/security_config.xml",
            "res/xml/nsc.xml"
        ]
    
    def analyze_network_security_config(self, apk_path: Path) -> NSCAnalysisResult:
        """
        Analyze Network Security Configuration files in the APK.
        
        Args:
            apk_path: Path to extracted APK directory
            
        Returns:
            NSCAnalysisResult with comprehensive NSC analysis
        """
        result = NSCAnalysisResult()
        
        try:
            # Find NSC files
            nsc_files = self._find_nsc_files(apk_path)
            result.config_files = [str(f) for f in nsc_files]
            
            if not nsc_files:
                self.logger.info("No Network Security Configuration files found")
                return result
            
            result.config_found = True
            
            # Analyze each NSC file
            for nsc_file in nsc_files:
                self._analyze_nsc_file(nsc_file, result)
            
            # Perform comprehensive analysis
            self._analyze_overall_nsc_configuration(result)
            
            self.logger.info(f"NSC analysis completed for {len(nsc_files)} files")
            
        except Exception as e:
            self.logger.error(f"Error analyzing Network Security Configuration: {e}")
            result.validation_errors.append(f"Analysis error: {e}")
        
        return result
    
    def _find_nsc_files(self, apk_path: Path) -> List[Path]:
        """Find Network Security Configuration files in the APK"""
        nsc_files = []
        
        # Search in standard locations
        for search_path in self.nsc_search_paths:
            nsc_file = apk_path / search_path
            if nsc_file.exists():
                nsc_files.append(nsc_file)
        
        # Search for any XML files that might be NSC files
        res_xml_dir = apk_path / "res" / "xml"
        if res_xml_dir.exists():
            for xml_file in res_xml_dir.glob("*.xml"):
                if xml_file not in nsc_files:
                    # Check if file contains NSC-related content
                    if self._is_nsc_file(xml_file):
                        nsc_files.append(xml_file)
        
        return nsc_files
    
    def _is_nsc_file(self, xml_file: Path) -> bool:
        """Check if XML file contains Network Security Configuration content"""
        try:
            with open(xml_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read(2048)  # Read first 2KB
                
                # Look for NSC-specific elements
                nsc_indicators = [
                    'network-security-config',
                    'domain-config',
                    'base-config',
                    'debug-overrides',
                    'cleartextTrafficPermitted',
                    'trust-anchors',
                    'pin-set'
                ]
                
                return any(indicator in content for indicator in nsc_indicators)
                
        except Exception:
            return False
    
    def _analyze_nsc_file(self, nsc_file: Path, result: NSCAnalysisResult):
        """Analyze individual NSC file"""
        try:
            self.logger.debug(f"Analyzing NSC file: {nsc_file}")
            
            # Read file content for pattern analysis
            with open(nsc_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Parse XML
            tree = ET.parse(nsc_file)
            root = tree.getroot()
            
            # Analyze XML structure
            config_data = self._analyze_nsc_xml(root, str(nsc_file))
            result.parsed_configs.append(config_data)
            
            # Pattern-based analysis for additional detection
            self._analyze_nsc_patterns(content, str(nsc_file), result)
            
        except ET.ParseError as e:
            self.logger.error(f"XML parsing error in {nsc_file}: {e}")
            result.validation_errors.append(f"Parse error in {nsc_file}: {e}")
        except Exception as e:
            self.logger.error(f"Error analyzing {nsc_file}: {e}")
            result.validation_errors.append(f"Analysis error in {nsc_file}: {e}")
    
    def _analyze_nsc_xml(self, root: ET.Element, filename: str) -> Dict[str, Any]:
        """Analyze NSC XML structure"""
        config_data = {
            'filename': filename,
            'root_element': root.tag,
            'cleartext_permitted': None,
            'domain_configs': [],
            'base_config': {},
            'debug_overrides': {},
            'pin_sets': [],
            'trust_anchors': []
        }
        
        # Analyze base configuration
        base_config = root.find('base-config')
        if base_config is not None:
            config_data['base_config'] = self._analyze_config_element(base_config)
            
            # Check cleartext traffic setting in base config
            cleartext_attr = base_config.get('cleartextTrafficPermitted')
            if cleartext_attr is not None:
                config_data['cleartext_permitted'] = cleartext_attr.lower() == 'true'
        
        # Analyze domain configurations
        for domain_config in root.findall('domain-config'):
            domain_data = self._analyze_domain_config(domain_config)
            config_data['domain_configs'].append(domain_data)
        
        # Analyze debug overrides
        debug_overrides = root.find('debug-overrides')
        if debug_overrides is not None:
            config_data['debug_overrides'] = self._analyze_config_element(debug_overrides)
        
        # Analyze trust anchors at root level
        trust_anchors = root.find('trust-anchors')
        if trust_anchors is not None:
            config_data['trust_anchors'] = self._analyze_trust_anchors(trust_anchors)
        
        # Analyze pin sets
        for pin_set in root.findall('pin-set'):
            pin_data = self._analyze_pin_set(pin_set)
            config_data['pin_sets'].append(pin_data)
        
        return config_data
    
    def _analyze_config_element(self, config_element: ET.Element) -> Dict[str, Any]:
        """Analyze a configuration element (base-config, debug-overrides, etc.)"""
        config_data = {
            'cleartext_permitted': None,
            'trust_anchors': [],
            'pin_sets': []
        }
        
        # Check cleartext traffic permission
        cleartext_attr = config_element.get('cleartextTrafficPermitted')
        if cleartext_attr is not None:
            config_data['cleartext_permitted'] = cleartext_attr.lower() == 'true'
        
        # Analyze trust anchors
        trust_anchors = config_element.find('trust-anchors')
        if trust_anchors is not None:
            config_data['trust_anchors'] = self._analyze_trust_anchors(trust_anchors)
        
        # Analyze pin sets
        for pin_set in config_element.findall('pin-set'):
            pin_data = self._analyze_pin_set(pin_set)
            config_data['pin_sets'].append(pin_data)
        
        return config_data
    
    def _analyze_domain_config(self, domain_config: ET.Element) -> Dict[str, Any]:
        """Analyze domain-specific configuration"""
        domain_data = {
            'domains': [],
            'cleartext_permitted': None,
            'trust_anchors': [],
            'pin_sets': []
        }
        
        # Extract domains
        for domain in domain_config.findall('domain'):
            domain_name = domain.text
            if domain_name:
                domain_data['domains'].append(domain_name.strip())
        
        # Check cleartext traffic setting
        cleartext_attr = domain_config.get('cleartextTrafficPermitted')
        if cleartext_attr is not None:
            domain_data['cleartext_permitted'] = cleartext_attr.lower() == 'true'
        
        # Analyze trust anchors
        trust_anchors = domain_config.find('trust-anchors')
        if trust_anchors is not None:
            domain_data['trust_anchors'] = self._analyze_trust_anchors(trust_anchors)
        
        # Analyze pin sets
        for pin_set in domain_config.findall('pin-set'):
            pin_data = self._analyze_pin_set(pin_set)
            domain_data['pin_sets'].append(pin_data)
        
        return domain_data
    
    def _analyze_trust_anchors(self, trust_anchors: ET.Element) -> Dict[str, Any]:
        """Analyze trust anchors configuration"""
        trust_data = {
            'certificates': [],
            'override_pins': None
        }
        
        # Check override pins attribute
        override_pins = trust_anchors.get('overridePins')
        if override_pins is not None:
            trust_data['override_pins'] = override_pins.lower() == 'true'
        
        # Analyze certificates
        for certificates in trust_anchors.findall('certificates'):
            src = certificates.get('src')
            if src:
                trust_data['certificates'].append(src)
        
        return trust_data
    
    def _analyze_pin_set(self, pin_set: ET.Element) -> Dict[str, Any]:
        """Analyze pin set configuration"""
        pin_data = {
            'expiration': None,
            'pins': []
        }
        
        # Check expiration
        expiration = pin_set.get('expiration')
        if expiration:
            pin_data['expiration'] = expiration
        
        # Analyze pins
        for pin in pin_set.findall('pin'):
            digest = pin.get('digest')
            pin_value = pin.text
            if digest and pin_value:
                pin_data['pins'].append({
                    'digest': digest,
                    'value': pin_value.strip()
                })
        
        return pin_data
    
    def _analyze_nsc_patterns(self, content: str, filename: str, result: NSCAnalysisResult):
        """Analyze NSC content using pattern matching"""
        # Check for cleartext traffic configuration
        cleartext_matches = self.nsc_patterns['cleartext_permitted'].findall(content)
        for match in cleartext_matches:
            if match.lower() == 'true':
                if result.cleartext_permitted is None:
                    result.cleartext_permitted = True
                result.findings.append({
                    'type': 'CLEARTEXT_PERMITTED',
                    'message': 'Cleartext traffic explicitly permitted in NSC',
                    'severity': 'HIGH',
                    'location': filename,
                    'evidence': [f'cleartextTrafficPermitted="{match}"']
                })
            elif match.lower() == 'false':
                if result.cleartext_permitted is None:
                    result.cleartext_permitted = False
                result.findings.append({
                    'type': 'CLEARTEXT_DENIED',
                    'message': 'Cleartext traffic explicitly denied in NSC',
                    'severity': 'INFO',
                    'location': filename,
                    'evidence': [f'cleartextTrafficPermitted="{match}"']
                })
        
        # Check for certificate pinning
        if self.nsc_patterns['pin_set'].search(content):
            result.certificate_pinning = True
            result.findings.append({
                'type': 'CERTIFICATE_PINNING',
                'message': 'Certificate pinning configured in NSC',
                'severity': 'INFO',
                'location': filename,
                'evidence': ['pin-set element found']
            })
        
        # Check for trust anchors
        if self.nsc_patterns['trust_anchors'].search(content):
            result.trust_anchors_configured = True
            result.findings.append({
                'type': 'TRUST_ANCHORS',
                'message': 'Custom trust anchors configured in NSC',
                'severity': 'MEDIUM',
                'location': filename,
                'evidence': ['trust-anchors element found']
            })
        
        # Check for debug overrides
        if self.nsc_patterns['debug_overrides'].search(content):
            result.debug_overrides = True
            result.findings.append({
                'type': 'DEBUG_OVERRIDES',
                'message': 'Debug overrides configured in NSC',
                'severity': 'MEDIUM',
                'location': filename,
                'evidence': ['debug-overrides element found']
            })
        
        # Analyze domain configurations
        domain_matches = self.nsc_patterns['domain_element'].findall(content)
        for domain in domain_matches:
            domain_info = {
                'domain': domain,
                'config_type': 'domain_specific'
            }
            
            if domain_info not in result.domain_configs:
                result.domain_configs.append(domain_info)
    
    def _analyze_overall_nsc_configuration(self, result: NSCAnalysisResult):
        """Perform overall NSC configuration analysis"""
        if not result.config_found:
            return
        
        # Analyze security posture
        security_issues = []
        security_strengths = []
        
        # Cleartext traffic analysis
        if result.cleartext_permitted is True:
            security_issues.append({
                'type': 'NSC_CLEARTEXT_ENABLED',
                'message': 'Network Security Configuration permits cleartext traffic',
                'severity': 'HIGH',
                'remediation': [
                    'Set cleartextTrafficPermitted="false"',
                    'Use HTTPS for all network communications',
                    'Review domain-specific configurations'
                ]
            })
        elif result.cleartext_permitted is False:
            security_strengths.append({
                'type': 'NSC_CLEARTEXT_DISABLED',
                'message': 'Network Security Configuration denies cleartext traffic',
                'severity': 'INFO'
            })
        
        # Certificate pinning analysis
        if result.certificate_pinning:
            security_strengths.append({
                'type': 'NSC_PINNING_CONFIGURED',
                'message': 'Certificate pinning configured in NSC',
                'severity': 'INFO'
            })
        else:
            security_issues.append({
                'type': 'NSC_NO_PINNING',
                'message': 'No certificate pinning configured in NSC',
                'severity': 'MEDIUM',
                'remediation': [
                    'Implement certificate pinning for critical domains',
                    'Configure pin-set elements',
                    'Set appropriate pin expiration dates'
                ]
            })
        
        # Trust anchor analysis
        if result.trust_anchors_configured:
            # This can be good or bad depending on configuration
            security_issues.append({
                'type': 'NSC_CUSTOM_TRUST_ANCHORS',
                'message': 'Custom trust anchors configured - review for security',
                'severity': 'MEDIUM',
                'remediation': [
                    'Review custom trust anchor configuration',
                    'Ensure only necessary custom CAs are trusted',
                    'Validate trust anchor certificates'
                ]
            })
        
        # Debug overrides analysis
        if result.debug_overrides:
            security_issues.append({
                'type': 'NSC_DEBUG_OVERRIDES',
                'message': 'Debug overrides configured - ensure not in production',
                'severity': 'MEDIUM',
                'remediation': [
                    'Remove debug overrides from production builds',
                    'Use build variants for debug-specific configurations',
                    'Ensure debug overrides do not weaken security'
                ]
            })
        
        # Add findings
        result.findings.extend(security_issues)
        result.findings.extend(security_strengths)
        
        # Domain configuration analysis
        if result.domain_configs:
            for domain_config in result.domain_configs:
                result.findings.append({
                    'type': 'NSC_DOMAIN_CONFIG',
                    'message': f'Domain-specific configuration for {domain_config.get("domain", "unknown")}',
                    'severity': 'INFO',
                    'evidence': [f'Domain: {domain_config.get("domain", "unknown")}']
                })
    
    def generate_security_findings(self, result: NSCAnalysisResult) -> List[NetworkSecurityFinding]:
        """
        Generate NetworkSecurityFinding objects from NSC analysis.
        
        Args:
            result: NSC analysis result
            
        Returns:
            List of NetworkSecurityFinding objects with calculated confidence
        """
        security_findings = []
        
        for finding_data in result.findings:
            try:
                # Map finding type
                finding_type = self._map_finding_type(finding_data['type'])
                
                # Map severity
                severity = self._map_severity(finding_data['severity'])
                
                # Create security finding
                finding = NetworkSecurityFinding(
                    finding_type=finding_type,
                    severity=severity,
                    title=self._generate_finding_title(finding_data),
                    description=finding_data['message'],
                    location=finding_data.get('location', 'Network Security Configuration'),
                    evidence=finding_data.get('evidence', []),
                    remediation=finding_data.get('remediation', []),
                    masvs_control="MASVS-NETWORK-2",
                    mastg_reference="MASTG-TEST-0025",
                    detection_method="nsc_analysis"
                )
                
                # Calculate confidence
                finding.confidence = self.confidence_calculator.calculate_cleartext_confidence(
                    finding,
                    nsc_analysis=result,
                    context={'file_type': 'nsc_config', 'analysis_source': 'nsc_analyzer'}
                )
                
                security_findings.append(finding)
                
            except Exception as e:
                self.logger.error(f"Error creating NSC security finding: {e}")
                continue
        
        return security_findings
    
    def _map_finding_type(self, finding_type_str: str) -> FindingType:
        """Map string finding type to FindingType enum"""
        mapping = {
            'CLEARTEXT_PERMITTED': FindingType.CLEARTEXT_ENABLED,
            'CLEARTEXT_DENIED': FindingType.CLEARTEXT_DISABLED,
            'CERTIFICATE_PINNING': FindingType.CERTIFICATE_PINNING,
            'TRUST_ANCHORS': FindingType.TRUST_ANCHOR_ISSUE,
            'DEBUG_OVERRIDES': FindingType.NSC_MISCONFIGURED,
            'NSC_CLEARTEXT_ENABLED': FindingType.NSC_MISCONFIGURED,
            'NSC_CLEARTEXT_DISABLED': FindingType.NSC_SECURE,
            'NSC_PINNING_CONFIGURED': FindingType.CERTIFICATE_PINNING,
            'NSC_NO_PINNING': FindingType.NSC_MISCONFIGURED,
            'NSC_CUSTOM_TRUST_ANCHORS': FindingType.TRUST_ANCHOR_ISSUE,
            'NSC_DEBUG_OVERRIDES': FindingType.NSC_MISCONFIGURED,
            'NSC_DOMAIN_CONFIG': FindingType.DOMAIN_CONFIG_ISSUE
        }
        
        return mapping.get(finding_type_str, FindingType.NSC_MISCONFIGURED)
    
    def _map_severity(self, severity_str: str) -> RiskLevel:
        """Map string severity to RiskLevel enum"""
        mapping = {
            'CRITICAL': RiskLevel.CRITICAL,
            'HIGH': RiskLevel.HIGH,
            'MEDIUM': RiskLevel.MEDIUM,
            'LOW': RiskLevel.LOW,
            'INFO': RiskLevel.INFO
        }
        
        return mapping.get(severity_str.upper(), RiskLevel.MEDIUM)
    
    def _generate_finding_title(self, finding_data: Dict[str, Any]) -> str:
        """Generate appropriate title for finding"""
        finding_type = finding_data['type']
        
        titles = {
            'CLEARTEXT_PERMITTED': 'NSC Permits Cleartext Traffic',
            'CLEARTEXT_DENIED': 'NSC Denies Cleartext Traffic',
            'CERTIFICATE_PINNING': 'Certificate Pinning Configured',
            'TRUST_ANCHORS': 'Custom Trust Anchors',
            'DEBUG_OVERRIDES': 'Debug Overrides Present',
            'NSC_CLEARTEXT_ENABLED': 'NSC Enables Cleartext Traffic',
            'NSC_CLEARTEXT_DISABLED': 'NSC Disables Cleartext Traffic',
            'NSC_PINNING_CONFIGURED': 'Certificate Pinning Active',
            'NSC_NO_PINNING': 'No Certificate Pinning',
            'NSC_CUSTOM_TRUST_ANCHORS': 'Custom Trust Anchors Configured',
            'NSC_DEBUG_OVERRIDES': 'Debug Configuration Overrides',
            'NSC_DOMAIN_CONFIG': 'Domain-Specific Configuration'
        }
        
        return titles.get(finding_type, 'NSC Security Finding')
    
    def get_nsc_security_summary(self, result: NSCAnalysisResult) -> Dict[str, Any]:
        """
        Get summary of NSC security configuration.
        
        Args:
            result: NSC analysis result
            
        Returns:
            Dictionary with NSC security summary
        """
        if not result.config_found:
            return {
                'configured': False,
                'security_level': 'UNKNOWN',
                'recommendation': 'Implement Network Security Configuration'
            }
        
        # Calculate security score
        security_score = 0
        max_score = 100
        
        # Cleartext traffic (40 points)
        if result.cleartext_permitted is False:
            security_score += 40
        elif result.cleartext_permitted is True:
            security_score -= 20
        
        # Certificate pinning (30 points)
        if result.certificate_pinning:
            security_score += 30
        
        # Trust anchors (20 points)
        if result.trust_anchors_configured:
            security_score += 10  # Can be good or bad
        else:
            security_score += 20  # Default system trust is generally good
        
        # Debug overrides (10 points penalty)
        if result.debug_overrides:
            security_score -= 10
        
        # Ensure score is within bounds
        security_score = max(0, min(max_score, security_score))
        
        # Determine security level
        if security_score >= 80:
            security_level = 'HIGH'
        elif security_score >= 60:
            security_level = 'MEDIUM'
        elif security_score >= 40:
            security_level = 'LOW'
        else:
            security_level = 'POOR'
        
        return {
            'configured': True,
            'security_level': security_level,
            'security_score': security_score,
            'cleartext_permitted': result.cleartext_permitted,
            'certificate_pinning': result.certificate_pinning,
            'trust_anchors_configured': result.trust_anchors_configured,
            'debug_overrides': result.debug_overrides,
            'config_files_count': len(result.config_files),
            'domain_configs_count': len(result.domain_configs),
            'validation_errors': len(result.validation_errors)
        } 
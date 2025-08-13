#!/usr/bin/env python3
"""
Component Analyzer for Improper Platform Usage Analysis

This module provides comprehensive Android component security analysis
including activities, services, broadcast receivers, and content providers.

Features:
- Individual component security assessment
- Export and permission validation
- Intent filter security analysis
- Component interaction analysis
- Attack vector identification
- Comprehensive vulnerability reporting
- Advanced anti-debugging security control validation

"""

import logging
import re
from typing import Dict, List, Optional, Any
from pathlib import Path
import yaml

from core.shared_infrastructure.analysis_exceptions import AnalysisError
from core.shared_infrastructure.dependency_injection import AnalysisContext
from .data_structures import (
    ComponentAnalysis, PlatformUsageVulnerability, VulnerabilitySeverity,
    ComponentType, ProtectionLevel, RiskLevel, AnalysisSource, ConfidenceEvidence
)
from .confidence_calculator import PlatformUsageConfidenceCalculator

logger = logging.getLogger(__name__)

class ComponentAnalyzer:
    """
    Comprehensive Android component security analyzer.
    
    Provides detailed security analysis for Android components including
    vulnerability detection, risk assessment, attack vector identification,
    and advanced anti-debugging security control validation.
    """
    
    def __init__(self, context: AnalysisContext, confidence_calculator: PlatformUsageConfidenceCalculator):
        """
        Initialize component analyzer.
        
        Args:
            context: Analysis context with dependency injection
            confidence_calculator: Evidence-based confidence calculator
        """
        self.context = context
        self.confidence_calculator = confidence_calculator
        self.logger = context.logger if hasattr(context, 'logger') else logger
        
        # Load configuration
        self.config = self._load_configuration()
        
        # Vulnerability patterns from configuration
        self.vulnerability_patterns = self.config.get('vulnerability_patterns', {})
        
        # Component security patterns
        self.component_patterns = self.config.get('component_patterns', {})
        
        # High-risk intent actions
        self.high_risk_actions = {
            action['action']: action for action in self.config.get('high_risk_intent_actions', [])
        }
        
        # NEW: Anti-debugging patterns
        self.anti_debugging_patterns = self.config.get('anti_debugging_patterns', {})
        self.anti_debugging_gaps = self.config.get('anti_debugging_gaps', {})
        
        # Enable anti-debugging analysis if configured
        self.enable_anti_debugging_analysis = self.config.get('analysis_configuration', {}).get('enable_anti_debugging_analysis', True)
        
        self.logger.info("Component analyzer initialized with anti-debugging security control validation")
    
    def _load_configuration(self) -> Dict[str, Any]:
        """Load configuration from external YAML file."""
        try:
            config_path = Path(__file__).parent / 'platform_patterns_config.yaml'
            if config_path.exists():
                with open(config_path, 'r', encoding='utf-8') as f:
                    return yaml.safe_load(f)
            else:
                self.logger.warning(f"Configuration file not found: {config_path}")
                return {}
        except Exception as e:
            self.logger.error(f"Failed to load configuration: {e}")
            return {}

    def analyze_components(self, components: List[ComponentAnalysis]) -> List[PlatformUsageVulnerability]:
        """
        Analyze components for security vulnerabilities including anti-debugging controls.
        
        Args:
            components: List of components to analyze
            
        Returns:
            List of vulnerabilities found
        """
        vulnerabilities = []
        
        try:
            self.logger.info(f"Analyzing {len(components)} components for security vulnerabilities")
            
            for component in components:
                component_vulns = self._analyze_single_component(component)
                vulnerabilities.extend(component_vulns)
                
                # NEW: Anti-debugging security control analysis
                if self.enable_anti_debugging_analysis:
                    anti_debug_vulns = self._analyze_component_anti_debugging_controls(component)
                    vulnerabilities.extend(anti_debug_vulns)
            
            self.logger.info(f"Component analysis completed. Found {len(vulnerabilities)} vulnerabilities.")
            return vulnerabilities
            
        except Exception as e:
            self.logger.error(f"Component analysis failed: {e}")
            return []
    
    def _analyze_single_component(self, component: ComponentAnalysis) -> List[PlatformUsageVulnerability]:
        """Analyze single component for vulnerabilities."""
        vulnerabilities = []
        
        try:
            # Analyze based on component type
            if component.component_type == ComponentType.ACTIVITY:
                vulnerabilities.extend(self._analyze_activity_security(component))
            elif component.component_type == ComponentType.SERVICE:
                vulnerabilities.extend(self._analyze_service_security(component))
            elif component.component_type == ComponentType.RECEIVER:
                vulnerabilities.extend(self._analyze_receiver_security(component))
            elif component.component_type == ComponentType.PROVIDER:
                vulnerabilities.extend(self._analyze_provider_security(component))
            
            # Common component security checks
            vulnerabilities.extend(self._analyze_common_component_issues(component))
            
            return vulnerabilities
            
        except Exception as e:
            self.logger.error(f"Single component analysis failed for {component.component_name}: {e}")
            return []

    def _analyze_component_anti_debugging_controls(self, component: ComponentAnalysis) -> List[PlatformUsageVulnerability]:
        """
        Analyze component for anti-debugging security controls.
        
        Args:
            component: Component to analyze
            
        Returns:
            List of anti-debugging related vulnerabilities
        """
        vulnerabilities = []
        
        try:
            # Check for debug-related security configurations
            debug_issues = self._check_debug_configuration_issues(component)
            vulnerabilities.extend(debug_issues)
            
            # Analyze anti-debugging mechanism implementation
            anti_debug_analysis = self._analyze_anti_debugging_mechanisms(component)
            vulnerabilities.extend(anti_debug_analysis)
            
            # Check for tamper detection mechanisms
            tamper_analysis = self._analyze_tamper_detection_mechanisms(component)
            vulnerabilities.extend(tamper_analysis)
            
            # Validate integrity protection mechanisms
            integrity_analysis = self._analyze_integrity_protection_mechanisms(component)
            vulnerabilities.extend(integrity_analysis)
            
            return vulnerabilities
            
        except Exception as e:
            self.logger.error(f"Anti-debugging analysis failed for {component.component_name}: {e}")
            return []

    def _check_debug_configuration_issues(self, component: ComponentAnalysis) -> List[PlatformUsageVulnerability]:
        """Check for debug configuration security issues."""
        vulnerabilities = []
        
        try:
            # Check if component has debug-related configurations
            debug_flags = getattr(component, 'debug_flags', {})
            
            # Analyze debug mode enablement
            if debug_flags.get('debuggable', False):
                # Create evidence for confidence calculation
                evidence = ConfidenceEvidence(
                    pattern_type='debug_configuration',
                    pattern_strength='critical',
                    analysis_source=AnalysisSource.MANIFEST_ANALYSIS,
                    context_relevance='high',
                    validation_methods=['manifest_analysis'],
                    cross_validation_sources=1,
                    component_exposure='debug_access',
                    permission_protection='none'
                )
                
                confidence = self.confidence_calculator.calculate_confidence(evidence)
                
                vulnerability = PlatformUsageVulnerability(
                    vulnerability_id=f"DEBUG_ENABLED_{component.component_name}",
                    title="Debug Mode Enabled",
                    severity=VulnerabilitySeverity.HIGH,
                    confidence=confidence,
                    description=f"Component '{component.component_name}' has debug mode enabled, "
                               f"allowing debugger attachment and runtime manipulation.",
                    component_type=component.component_type,
                    component_name=component.component_name,
                    location=f"AndroidManifest.xml - {component.component_name}",
                    evidence=f"android:debuggable=\"true\" detected",
                    attack_vectors=[
                        "Debugger attachment",
                        "Runtime code modification",
                        "Memory inspection",
                        "Method hooking",
                        "Process manipulation"
                    ],
                    remediation="Set android:debuggable=\"false\" for production builds and implement anti-debugging mechanisms",
                    masvs_refs=["MSTG-RESILIENCE-2"],
                    cwe_id="CWE-489",
                    risk_score=85,
                    analysis_source=AnalysisSource.MANIFEST_ANALYSIS,
                    pattern_type="debug_configuration_issues"
                )
                
                vulnerabilities.append(vulnerability)
            
            return vulnerabilities
            
        except Exception as e:
            self.logger.error(f"Debug configuration analysis failed: {e}")
            return []

    def _analyze_anti_debugging_mechanisms(self, component: ComponentAnalysis) -> List[PlatformUsageVulnerability]:
        """Analyze anti-debugging mechanism implementation."""
        vulnerabilities = []
        
        try:
            # Check for implemented anti-debugging mechanisms
            anti_debug_mechanisms = []
            
            # Analyze component source/manifest for anti-debugging patterns
            component_source = getattr(component, 'source_content', '')
            
            # Check for debug detection mechanisms
            debug_patterns = self.anti_debugging_patterns.get('debug_detection_mechanisms', [])
            for pattern_info in debug_patterns:
                pattern = pattern_info.get('pattern', '')
                if pattern and re.search(pattern, component_source, re.IGNORECASE):
                    anti_debug_mechanisms.append({
                        'type': 'debug_detection',
                        'mechanism': pattern_info.get('description', 'Unknown'),
                        'strength': pattern_info.get('strength', 'unknown'),
                        'reliability': pattern_info.get('reliability', 0.5)
                    })
            
            # Check for process monitoring mechanisms
            process_patterns = self.anti_debugging_patterns.get('process_monitoring_mechanisms', [])
            for pattern_info in process_patterns:
                pattern = pattern_info.get('pattern', '')
                if pattern and re.search(pattern, component_source, re.IGNORECASE):
                    anti_debug_mechanisms.append({
                        'type': 'process_monitoring',
                        'mechanism': pattern_info.get('description', 'Unknown'),
                        'strength': pattern_info.get('strength', 'unknown'),
                        'reliability': pattern_info.get('reliability', 0.5)
                    })
            
            # Check for timing-based detection
            timing_patterns = self.anti_debugging_patterns.get('timing_based_detection', [])
            for pattern_info in timing_patterns:
                pattern = pattern_info.get('pattern', '')
                if pattern and re.search(pattern, component_source, re.IGNORECASE):
                    anti_debug_mechanisms.append({
                        'type': 'timing_detection',
                        'mechanism': pattern_info.get('description', 'Unknown'),
                        'strength': pattern_info.get('strength', 'unknown'),
                        'reliability': pattern_info.get('reliability', 0.5)
                    })
            
            # Assess anti-debugging strength
            if not anti_debug_mechanisms:
                # Missing anti-debugging protection
                evidence = ConfidenceEvidence(
                    pattern_type='missing_anti_debugging',
                    pattern_strength='none',
                    analysis_source=AnalysisSource.STATIC_ANALYSIS,
                    context_relevance='high',
                    validation_methods=['pattern_analysis', 'source_analysis'],
                    cross_validation_sources=2,
                    component_exposure='debugging_vulnerable',
                    permission_protection='insufficient'
                )
                
                confidence = self.confidence_calculator.calculate_confidence(evidence)
                
                vulnerability = PlatformUsageVulnerability(
                    vulnerability_id=f"MISSING_ANTI_DEBUG_{component.component_name}",
                    title="Missing Anti-Debugging Protection",
                    severity=VulnerabilitySeverity.HIGH,
                    confidence=confidence,
                    description=f"Component '{component.component_name}' lacks anti-debugging mechanisms, "
                               f"making it vulnerable to runtime analysis and manipulation.",
                    component_type=component.component_type,
                    component_name=component.component_name,
                    location=f"Component: {component.component_name}",
                    evidence="No anti-debugging mechanisms detected",
                    attack_vectors=[
                        "Debugger attachment",
                        "Dynamic analysis",
                        "Method hooking",
                        "Runtime manipulation",
                        "Reverse engineering"
                    ],
                    remediation="Implement comprehensive anti-debugging mechanisms including debugger detection, "
                               "process monitoring, timing checks, and integrity validation",
                    masvs_refs=["MSTG-RESILIENCE-2"],
                    cwe_id="CWE-489",
                    risk_score=75,
                    analysis_source=AnalysisSource.STATIC_ANALYSIS,
                    pattern_type="anti_debugging_mechanisms"
                )
                
                vulnerabilities.append(vulnerability)
                
            elif len(anti_debug_mechanisms) < 3:
                # Weak anti-debugging protection
                evidence = ConfidenceEvidence(
                    pattern_type='weak_anti_debugging',
                    pattern_strength='weak',
                    analysis_source=AnalysisSource.STATIC_ANALYSIS,
                    context_relevance='medium',
                    validation_methods=['pattern_analysis'],
                    cross_validation_sources=1,
                    component_exposure='partially_protected',
                    permission_protection='basic'
                )
                
                confidence = self.confidence_calculator.calculate_confidence(evidence)
                
                vulnerability = PlatformUsageVulnerability(
                    vulnerability_id=f"WEAK_ANTI_DEBUG_{component.component_name}",
                    title="Weak Anti-Debugging Implementation",
                    severity=VulnerabilitySeverity.MEDIUM,
                    confidence=confidence,
                    description=f"Component '{component.component_name}' has limited anti-debugging mechanisms. "
                               f"Only {len(anti_debug_mechanisms)} protection layer(s) detected.",
                    component_type=component.component_type,
                    component_name=component.component_name,
                    location=f"Component: {component.component_name}",
                    evidence=f"Limited anti-debugging: {[m['mechanism'] for m in anti_debug_mechanisms]}",
                    attack_vectors=[
                        "Advanced debugging bypass",
                        "Multi-vector analysis",
                        "Sophisticated tooling",
                        "Layer-specific bypass"
                    ],
                    remediation="Strengthen anti-debugging protection with additional detection layers and "
                               "implement multiple concurrent protection mechanisms",
                    masvs_refs=["MSTG-RESILIENCE-2"],
                    cwe_id="CWE-489",
                    risk_score=55,
                    analysis_source=AnalysisSource.STATIC_ANALYSIS,
                    pattern_type="anti_debugging_mechanisms"
                )
                
                vulnerabilities.append(vulnerability)
            
            return vulnerabilities
            
        except Exception as e:
            self.logger.error(f"Anti-debugging mechanism analysis failed: {e}")
            return []

    def _analyze_tamper_detection_mechanisms(self, component: ComponentAnalysis) -> List[PlatformUsageVulnerability]:
        """Analyze tamper detection mechanism implementation."""
        vulnerabilities = []
        
        try:
            # Check for anti-tampering mechanisms
            tamper_mechanisms = []
            component_source = getattr(component, 'source_content', '')
            
            # Check for anti-tampering patterns
            tamper_patterns = self.anti_debugging_patterns.get('anti_tampering_mechanisms', [])
            for pattern_info in tamper_patterns:
                pattern = pattern_info.get('pattern', '')
                if pattern and re.search(pattern, component_source, re.IGNORECASE):
                    tamper_mechanisms.append({
                        'type': 'tamper_detection',
                        'mechanism': pattern_info.get('description', 'Unknown'),
                        'strength': pattern_info.get('strength', 'unknown'),
                        'reliability': pattern_info.get('reliability', 0.5)
                    })
            
            # Assess tamper detection strength
            if not tamper_mechanisms:
                # Missing tamper detection
                evidence = ConfidenceEvidence(
                    pattern_type='missing_tamper_detection',
                    pattern_strength='none',
                    analysis_source=AnalysisSource.STATIC_ANALYSIS,
                    context_relevance='high',
                    validation_methods=['pattern_analysis'],
                    cross_validation_sources=1,
                    component_exposure='tamper_vulnerable',
                    permission_protection='insufficient'
                )
                
                confidence = self.confidence_calculator.calculate_confidence(evidence)
                
                vulnerability = PlatformUsageVulnerability(
                    vulnerability_id=f"MISSING_TAMPER_DETECT_{component.component_name}",
                    title="Missing Anti-Tampering Protection",
                    severity=VulnerabilitySeverity.HIGH,
                    confidence=confidence,
                    description=f"Component '{component.component_name}' lacks tamper detection mechanisms, "
                               f"making it vulnerable to code modification and integrity attacks.",
                    component_type=component.component_type,
                    component_name=component.component_name,
                    location=f"Component: {component.component_name}",
                    evidence="No tamper detection mechanisms detected",
                    attack_vectors=[
                        "Code modification",
                        "Binary patching",
                        "Runtime tampering",
                        "Signature bypass",
                        "Integrity violation"
                    ],
                    remediation="Implement tamper detection mechanisms including integrity checks, "
                               "signature validation, and checksum verification",
                    masvs_refs=["MSTG-RESILIENCE-1"],
                    cwe_id="CWE-913",
                    risk_score=80,
                    analysis_source=AnalysisSource.STATIC_ANALYSIS,
                    pattern_type="anti_tampering_mechanisms"
                )
                
                vulnerabilities.append(vulnerability)
            
            return vulnerabilities
            
        except Exception as e:
            self.logger.error(f"Tamper detection analysis failed: {e}")
            return []

    def _analyze_integrity_protection_mechanisms(self, component: ComponentAnalysis) -> List[PlatformUsageVulnerability]:
        """Analyze integrity protection mechanism implementation."""
        vulnerabilities = []
        
        try:
            # Check for integrity protection mechanisms
            integrity_mechanisms = []
            component_source = getattr(component, 'source_content', '')
            
            # Look for integrity validation patterns
            integrity_patterns = [
                r'signature.*verify',
                r'checksum.*validation',
                r'hash.*verification',
                r'integrity.*check',
                r'CertificateFactory',
                r'MessageDigest',
                r'Signature.*verify'
            ]
            
            for pattern in integrity_patterns:
                if re.search(pattern, component_source, re.IGNORECASE):
                    integrity_mechanisms.append(pattern)
            
            # Assess integrity protection
            if not integrity_mechanisms:
                # Missing integrity protection
                evidence = ConfidenceEvidence(
                    pattern_type='missing_integrity_protection',
                    pattern_strength='none',
                    analysis_source=AnalysisSource.STATIC_ANALYSIS,
                    context_relevance='medium',
                    validation_methods=['pattern_analysis'],
                    cross_validation_sources=1,
                    component_exposure='integrity_vulnerable',
                    permission_protection='insufficient'
                )
                
                confidence = self.confidence_calculator.calculate_confidence(evidence)
                
                vulnerability = PlatformUsageVulnerability(
                    vulnerability_id=f"MISSING_INTEGRITY_PROTECT_{component.component_name}",
                    title="Missing Integrity Protection",
                    severity=VulnerabilitySeverity.MEDIUM,
                    confidence=confidence,
                    description=f"Component '{component.component_name}' lacks integrity protection mechanisms, "
                               f"potentially allowing undetected modifications.",
                    component_type=component.component_type,
                    component_name=component.component_name,
                    location=f"Component: {component.component_name}",
                    evidence="No integrity protection mechanisms detected",
                    attack_vectors=[
                        "Silent modification",
                        "Code injection",
                        "Data corruption",
                        "Malicious payload insertion"
                    ],
                    remediation="Implement integrity protection including signature verification, "
                               "checksum validation, and cryptographic verification",
                    masvs_refs=["MSTG-RESILIENCE-1"],
                    cwe_id="CWE-354",
                    risk_score=65,
                    analysis_source=AnalysisSource.STATIC_ANALYSIS,
                    pattern_type="integrity_protection_mechanisms"
                )
                
                vulnerabilities.append(vulnerability)
            
            return vulnerabilities
            
        except Exception as e:
            self.logger.error(f"Integrity protection analysis failed: {e}")
            return []

    def _analyze_activity_security(self, component: ComponentAnalysis) -> List[PlatformUsageVulnerability]:
        """Analyze activity-specific security issues."""
        vulnerabilities = []
        
        try:
            # Check for exported activity without permission protection
            if component.exported and component.protection_level == ProtectionLevel.UNPROTECTED:
                # Create evidence for confidence calculation
                evidence = ConfidenceEvidence(
                    pattern_type='exported_component_issues',
                    pattern_strength='high',
                    analysis_source=AnalysisSource.MANIFEST_ANALYSIS,
                    context_relevance='high',
                    validation_methods=['manifest_analysis', 'static_analysis'],
                    cross_validation_sources=2,
                    component_exposure='exported',
                    permission_protection='none'
                )
                
                confidence = self.confidence_calculator.calculate_confidence(evidence)
                
                vulnerability = PlatformUsageVulnerability(
                    vulnerability_id=f"ACTIVITY_EXPORTED_NO_PERM_{component.component_name}",
                    title="Exported Activity Without Permission Protection",
                    severity=VulnerabilitySeverity.HIGH,
                    confidence=confidence,
                    description=f"Activity '{component.component_name}' is exported but lacks permission protection, "
                               f"allowing other applications to launch it without authorization.",
                    component_type=component.component_type,
                    component_name=component.component_name,
                    location=f"AndroidManifest.xml - {component.component_name}",
                    evidence=f"android:exported=\"true\" with no permission requirement",
                    attack_vectors=[
                        "Unauthorized activity launching",
                        "Intent-based attacks",
                        "UI manipulation",
                        "Data exposure through activity results"
                    ],
                    remediation="Add permission requirement: android:permission=\"your.permission.NAME\" "
                               "or set android:exported=\"false\" if not needed by other apps",
                    masvs_refs=["MSTG-PLATFORM-01"],
                    cwe_id="CWE-926",
                    risk_score=75,
                    analysis_source=AnalysisSource.MANIFEST_ANALYSIS,
                    pattern_type="exported_component_issues"
                )
                
                vulnerabilities.append(vulnerability)
            
            # Check for deep link vulnerabilities
            vulnerabilities.extend(self._analyze_activity_deep_links(component))
            
            # Check for intent filter issues
            vulnerabilities.extend(self._analyze_activity_intent_filters(component))
            
            return vulnerabilities
            
        except Exception as e:
            self.logger.error(f"Activity security analysis failed: {e}")
            return []
    
    def _analyze_service_security(self, component: ComponentAnalysis) -> List[PlatformUsageVulnerability]:
        """Analyze service-specific security issues."""
        vulnerabilities = []
        
        try:
            # Check for exported service without permission
            if component.exported and not component.permissions:
                evidence = ConfidenceEvidence(
                    component_isolation={
                        'exported': True,
                        'has_permissions': False,
                        'component_type': 'service'
                    },
                    pattern_type='service_security',
                    analysis_source=AnalysisSource.MANIFEST_ANALYSIS
                )
                
                confidence = self.confidence_calculator.calculate_confidence(evidence)
                
                vulnerability = PlatformUsageVulnerability(
                    vulnerability_id=f"SERVICE_EXPORTED_NO_PERM_{component.component_name}",
                    title="Exported Service Without Permission Protection",
                    severity=VulnerabilitySeverity.CRITICAL,
                    confidence=confidence,
                    description=f"Service '{component.component_name}' is exported but lacks permission protection, "
                               f"allowing other applications to bind to or start the service.",
                    component_type=component.component_type,
                    component_name=component.component_name,
                    location=f"AndroidManifest.xml - {component.component_name}",
                    evidence=f"android:exported=\"true\" with no permission requirement",
                    attack_vectors=[
                        "Unauthorized service binding",
                        "Service hijacking",
                        "Resource abuse",
                        "Data manipulation",
                        "Denial of service"
                    ],
                    remediation="Add permission requirement: android:permission=\"your.permission.NAME\" "
                               "or set android:exported=\"false\" if not needed by other apps",
                    masvs_refs=["MSTG-PLATFORM-02"],
                    cwe_id="CWE-926",
                    risk_score=90,
                    analysis_source=AnalysisSource.MANIFEST_ANALYSIS,
                    pattern_type="service_security"
                )
                
                vulnerabilities.append(vulnerability)
            
            # Check for service intent filter issues
            vulnerabilities.extend(self._analyze_service_intent_filters(component))
            
            return vulnerabilities
            
        except Exception as e:
            self.logger.error(f"Service security analysis failed: {e}")
            return []
    
    def _analyze_receiver_security(self, component: ComponentAnalysis) -> List[PlatformUsageVulnerability]:
        """Analyze broadcast receiver-specific security issues."""
        vulnerabilities = []
        
        try:
            # Check for exported receiver without permission
            if component.exported and not component.permissions:
                evidence = ConfidenceEvidence(
                    component_isolation={
                        'exported': True,
                        'has_permissions': False,
                        'component_type': 'receiver'
                    },
                    pattern_type='receiver_security',
                    analysis_source=AnalysisSource.MANIFEST_ANALYSIS
                )
                
                confidence = self.confidence_calculator.calculate_confidence(evidence)
                
                vulnerability = PlatformUsageVulnerability(
                    vulnerability_id=f"RECEIVER_EXPORTED_NO_PERM_{component.component_name}",
                    title="Exported Broadcast Receiver Without Permission Protection",
                    severity=VulnerabilitySeverity.HIGH,
                    confidence=confidence,
                    description=f"Broadcast receiver '{component.component_name}' is exported but lacks permission protection, "
                               f"allowing other applications to send broadcasts to it.",
                    component_type=component.component_type,
                    component_name=component.component_name,
                    location=f"AndroidManifest.xml - {component.component_name}",
                    evidence=f"android:exported=\"true\" with no permission requirement",
                    attack_vectors=[
                        "Intent spoofing",
                        "Broadcast injection",
                        "Data manipulation",
                        "Denial of service",
                        "Privilege escalation"
                    ],
                    remediation="Add permission requirement: android:permission=\"your.permission.NAME\" "
                               "or set android:exported=\"false\" if not needed by other apps",
                    masvs_refs=["MSTG-PLATFORM-02"],
                    cwe_id="CWE-926",
                    risk_score=80,
                    analysis_source=AnalysisSource.MANIFEST_ANALYSIS,
                    pattern_type="receiver_security"
                )
                
                vulnerabilities.append(vulnerability)
            
            # Check for high-risk broadcast actions
            vulnerabilities.extend(self._analyze_receiver_high_risk_actions(component))
            
            return vulnerabilities
            
        except Exception as e:
            self.logger.error(f"Receiver security analysis failed: {e}")
            return []
    
    def _analyze_provider_security(self, component: ComponentAnalysis) -> List[PlatformUsageVulnerability]:
        """Analyze content provider-specific security issues."""
        vulnerabilities = []
        
        try:
            # Check for exported provider without permission
            if component.exported and not component.permissions:
                evidence = ConfidenceEvidence(
                    component_isolation={
                        'exported': True,
                        'has_permissions': False,
                        'component_type': 'provider'
                    },
                    pattern_type='content_provider_security',
                    analysis_source=AnalysisSource.MANIFEST_ANALYSIS
                )
                
                confidence = self.confidence_calculator.calculate_confidence(evidence)
                
                vulnerability = PlatformUsageVulnerability(
                    vulnerability_id=f"PROVIDER_EXPORTED_NO_PERM_{component.component_name}",
                    title="Exported Content Provider Without Permission Protection",
                    severity=VulnerabilitySeverity.CRITICAL,
                    confidence=confidence,
                    description=f"Content provider '{component.component_name}' is exported but lacks permission protection, "
                               f"allowing other applications to access potentially sensitive data.",
                    component_type=component.component_type,
                    component_name=component.component_name,
                    location=f"AndroidManifest.xml - {component.component_name}",
                    evidence=f"android:exported=\"true\" with no permission requirement",
                    attack_vectors=[
                        "Unauthorized data access",
                        "Data manipulation",
                        "SQL injection",
                        "Path traversal",
                        "Information disclosure",
                        "Data corruption"
                    ],
                    remediation="Add permission requirements: android:readPermission and android:writePermission "
                               "or set android:exported=\"false\" if not needed by other apps",
                    masvs_refs=["MSTG-PLATFORM-02"],
                    cwe_id="CWE-926",
                    risk_score=95,
                    analysis_source=AnalysisSource.MANIFEST_ANALYSIS,
                    pattern_type="content_provider_security"
                )
                
                vulnerabilities.append(vulnerability)
            
            return vulnerabilities
            
        except Exception as e:
            self.logger.error(f"Provider security analysis failed: {e}")
            return []
    
    def _analyze_common_component_issues(self, component: ComponentAnalysis) -> List[PlatformUsageVulnerability]:
        """Analyze common component security issues."""
        vulnerabilities = []
        
        try:
            # Check for wildcard intent filters
            for intent_filter in component.intent_filters:
                if intent_filter.has_wildcards:
                    evidence = ConfidenceEvidence(
                        validation_coverage={
                            'has_wildcards': True,
                            'intent_filter_count': len(component.intent_filters)
                        },
                        pattern_type='wildcard_patterns',
                        analysis_source=AnalysisSource.MANIFEST_ANALYSIS
                    )
                    
                    confidence = self.confidence_calculator.calculate_confidence(evidence)
                    
                    vulnerability = PlatformUsageVulnerability(
                        vulnerability_id=f"WILDCARD_INTENT_FILTER_{component.component_name}",
                        title="Wildcard Intent Filter Pattern",
                        severity=VulnerabilitySeverity.HIGH,
                        confidence=confidence,
                        description=f"Component '{component.component_name}' uses wildcard patterns in intent filters, "
                                   f"which may allow unintended intent matching and potential security bypass.",
                        component_type=component.component_type,
                        component_name=component.component_name,
                        location=f"AndroidManifest.xml - {component.component_name}",
                        evidence=f"Intent filter contains wildcard patterns: {intent_filter.security_issues}",
                        attack_vectors=[
                            "Intent filter bypass",
                            "Unintended intent matching",
                            "Security control circumvention",
                            "Application behavior manipulation"
                        ],
                        remediation="Use specific intent filter patterns instead of wildcards. "
                                   "Implement proper input validation for intent data.",
                        masvs_refs=["MSTG-PLATFORM-02"],
                        cwe_id="CWE-20",
                        risk_score=70,
                        analysis_source=AnalysisSource.MANIFEST_ANALYSIS,
                        pattern_type="wildcard_patterns"
                    )
                    
                    vulnerabilities.append(vulnerability)
            
            # Check for sensitive scheme usage
            for intent_filter in component.intent_filters:
                if intent_filter.has_sensitive_schemes:
                    evidence = ConfidenceEvidence(
                        validation_coverage={
                            'has_sensitive_schemes': True,
                            'data_schemes': intent_filter.data_schemes
                        },
                        pattern_type='sensitive_schemes',
                        analysis_source=AnalysisSource.MANIFEST_ANALYSIS
                    )
                    
                    confidence = self.confidence_calculator.calculate_confidence(evidence)
                    
                    vulnerability = PlatformUsageVulnerability(
                        vulnerability_id=f"SENSITIVE_SCHEME_{component.component_name}",
                        title="Security-Sensitive URL Scheme Usage",
                        severity=VulnerabilitySeverity.MEDIUM,
                        confidence=confidence,
                        description=f"Component '{component.component_name}' handles security-sensitive URL schemes "
                                   f"which may expose the application to various attacks.",
                        component_type=component.component_type,
                        component_name=component.component_name,
                        location=f"AndroidManifest.xml - {component.component_name}",
                        evidence=f"Handles sensitive schemes: {intent_filter.data_schemes}",
                        attack_vectors=[
                            "File system access",
                            "Content provider attacks",
                            "Resource manipulation",
                            "Local file inclusion"
                        ],
                        remediation="Implement proper validation for sensitive scheme handling. "
                                   "Use secure alternatives where possible.",
                        masvs_refs=["MSTG-PLATFORM-11"],
                        cwe_id="CWE-20",
                        risk_score=60,
                        analysis_source=AnalysisSource.MANIFEST_ANALYSIS,
                        pattern_type="sensitive_schemes"
                    )
                    
                    vulnerabilities.append(vulnerability)
            
            return vulnerabilities
            
        except Exception as e:
            self.logger.error(f"Common component issues analysis failed: {e}")
            return []
    
    def _analyze_activity_deep_links(self, component: ComponentAnalysis) -> List[PlatformUsageVulnerability]:
        """Analyze activity deep link vulnerabilities."""
        vulnerabilities = []
        
        try:
            for intent_filter in component.intent_filters:
                # Check for VIEW action with data schemes (deep links)
                if 'android.intent.action.VIEW' in intent_filter.actions and intent_filter.data_schemes:
                    
                    # Check for insecure deep link patterns
                    security_issues = []
                    
                    # HTTP schemes
                    if 'http' in intent_filter.data_schemes:
                        security_issues.append("Uses insecure HTTP scheme")
                    
                    # Wildcard hosts
                    if any('*' in host for host in intent_filter.data_hosts):
                        security_issues.append("Uses wildcard host patterns")
                    
                    # Root path or wildcard paths
                    if any(path in ['/', '*'] for path in intent_filter.data_paths):
                        security_issues.append("Uses broad path patterns")
                    
                    if security_issues:
                        evidence = ConfidenceEvidence(
                            validation_coverage={
                                'has_deep_links': True,
                                'security_issues': security_issues,
                                'schemes': intent_filter.data_schemes
                            },
                            pattern_type='deep_link_vulnerabilities',
                            analysis_source=AnalysisSource.MANIFEST_ANALYSIS
                        )
                        
                        confidence = self.confidence_calculator.calculate_confidence(evidence)
                        
                        vulnerability = PlatformUsageVulnerability(
                            vulnerability_id=f"INSECURE_DEEP_LINK_{component.component_name}",
                            title="Insecure Deep Link Implementation",
                            severity=VulnerabilitySeverity.HIGH,
                            confidence=confidence,
                            description=f"Activity '{component.component_name}' implements deep links with "
                                       f"security vulnerabilities that may allow attacks.",
                            component_type=component.component_type,
                            component_name=component.component_name,
                            location=f"AndroidManifest.xml - {component.component_name}",
                            evidence=f"Deep link security issues: {', '.join(security_issues)}",
                            attack_vectors=[
                                "URL manipulation",
                                "Parameter injection",
                                "Man-in-the-middle attacks" if 'http' in intent_filter.data_schemes else None,
                                "Domain hijacking" if any('*' in host for host in intent_filter.data_hosts) else None,
                                "Path traversal" if any('*' in path for path in intent_filter.data_paths) else None
                            ],
                            remediation="Use HTTPS schemes, specific host patterns, and implement proper "
                                       "input validation for deep link parameters.",
                            masvs_refs=["MSTG-PLATFORM-11"],
                            cwe_id="CWE-20",
                            risk_score=75,
                            analysis_source=AnalysisSource.MANIFEST_ANALYSIS,
                            pattern_type="deep_link_vulnerabilities"
                        )
                        
                        # Remove None values from attack vectors
                        vulnerability.attack_vectors = [av for av in vulnerability.attack_vectors if av is not None]
                        
                        vulnerabilities.append(vulnerability)
            
            return vulnerabilities
            
        except Exception as e:
            self.logger.error(f"Activity deep link analysis failed: {e}")
            return []
    
    def _analyze_activity_intent_filters(self, component: ComponentAnalysis) -> List[PlatformUsageVulnerability]:
        """Analyze activity intent filter security."""
        vulnerabilities = []
        
        try:
            for intent_filter in component.intent_filters:
                # Check for high-risk actions
                for action in intent_filter.actions:
                    if action in self.high_risk_actions:
                        action_config = self.high_risk_actions[action]
                        
                        if action_config.get('risk_level') in ['HIGH', 'CRITICAL']:
                            evidence = ConfidenceEvidence(
                                validation_coverage={
                                    'high_risk_action': action,
                                    'exported': component.exported,
                                    'has_permissions': bool(component.permissions)
                                },
                                pattern_type='intent_filter_issues',
                                analysis_source=AnalysisSource.MANIFEST_ANALYSIS
                            )
                            
                            confidence = self.confidence_calculator.calculate_confidence(evidence)
                            
                            vulnerability = PlatformUsageVulnerability(
                                vulnerability_id=f"HIGH_RISK_ACTION_{component.component_name}_{action.replace('.', '_')}",
                                title=f"High-Risk Intent Action: {action}",
                                severity=VulnerabilitySeverity.MEDIUM,
                                confidence=confidence,
                                description=f"Activity '{component.component_name}' handles high-risk intent action "
                                           f"'{action}' which may expose the application to security risks.",
                                component_type=component.component_type,
                                component_name=component.component_name,
                                location=f"AndroidManifest.xml - {component.component_name}",
                                evidence=f"Handles intent action: {action}",
                                attack_vectors=action_config.get('security_concerns', []),
                                remediation="Ensure proper input validation and permission checks for high-risk intent actions.",
                                masvs_refs=["MSTG-PLATFORM-02"],
                                cwe_id="CWE-20",
                                risk_score=50,
                                analysis_source=AnalysisSource.MANIFEST_ANALYSIS,
                                pattern_type="intent_filter_issues"
                            )
                            
                            vulnerabilities.append(vulnerability)
            
            return vulnerabilities
            
        except Exception as e:
            self.logger.error(f"Activity intent filter analysis failed: {e}")
            return []
    
    def _analyze_service_intent_filters(self, component: ComponentAnalysis) -> List[PlatformUsageVulnerability]:
        """Analyze service intent filter security."""
        vulnerabilities = []
        
        try:
            # Services with intent filters are inherently more risky
            if component.intent_filters and component.exported:
                evidence = ConfidenceEvidence(
                    component_isolation={
                        'exported': True,
                        'has_intent_filters': True,
                        'component_type': 'service'
                    },
                    pattern_type='service_security',
                    analysis_source=AnalysisSource.MANIFEST_ANALYSIS
                )
                
                confidence = self.confidence_calculator.calculate_confidence(evidence)
                
                vulnerability = PlatformUsageVulnerability(
                    vulnerability_id=f"SERVICE_INTENT_FILTER_{component.component_name}",
                    title="Exported Service with Intent Filters",
                    severity=VulnerabilitySeverity.MEDIUM,
                    confidence=confidence,
                    description=f"Service '{component.component_name}' is exported and has intent filters, "
                               f"increasing the attack surface for potential service hijacking.",
                    component_type=component.component_type,
                    component_name=component.component_name,
                    location=f"AndroidManifest.xml - {component.component_name}",
                    evidence=f"Exported service with {len(component.intent_filters)} intent filters",
                    attack_vectors=[
                        "Service hijacking",
                        "Intent-based service manipulation",
                        "Resource abuse",
                        "Denial of service"
                    ],
                    remediation="Consider using explicit intents for service communication. "
                               "Add permission requirements if the service must be exported.",
                    masvs_refs=["MSTG-PLATFORM-02"],
                    cwe_id="CWE-926",
                    risk_score=65,
                    analysis_source=AnalysisSource.MANIFEST_ANALYSIS,
                    pattern_type="service_security"
                )
                
                vulnerabilities.append(vulnerability)
            
            return vulnerabilities
            
        except Exception as e:
            self.logger.error(f"Service intent filter analysis failed: {e}")
            return []
    
    def _analyze_receiver_high_risk_actions(self, component: ComponentAnalysis) -> List[PlatformUsageVulnerability]:
        """Analyze receiver high-risk action handling."""
        vulnerabilities = []
        
        try:
            for intent_filter in component.intent_filters:
                for action in intent_filter.actions:
                    if action in self.high_risk_actions:
                        action_config = self.high_risk_actions[action]
                        
                        if action_config.get('risk_level') in ['HIGH', 'CRITICAL']:
                            evidence = ConfidenceEvidence(
                                component_isolation={
                                    'exported': component.exported,
                                    'has_permissions': bool(component.permissions),
                                    'high_risk_action': action
                                },
                                pattern_type='receiver_security',
                                analysis_source=AnalysisSource.MANIFEST_ANALYSIS
                            )
                            
                            confidence = self.confidence_calculator.calculate_confidence(evidence)
                            
                            # Determine severity based on action and protection
                            if action in ['android.intent.action.SMS_RECEIVED'] and not component.permissions:
                                severity = VulnerabilitySeverity.CRITICAL
                                risk_score = 95
                            elif action in ['android.intent.action.BOOT_COMPLETED'] and not component.permissions:
                                severity = VulnerabilitySeverity.HIGH
                                risk_score = 85
                            else:
                                severity = VulnerabilitySeverity.MEDIUM
                                risk_score = 70
                            
                            vulnerability = PlatformUsageVulnerability(
                                vulnerability_id=f"RECEIVER_HIGH_RISK_{component.component_name}_{action.replace('.', '_')}",
                                title=f"High-Risk Broadcast Action: {action}",
                                severity=severity,
                                confidence=confidence,
                                description=f"Broadcast receiver '{component.component_name}' handles high-risk "
                                           f"broadcast action '{action}' which may expose sensitive functionality.",
                                component_type=component.component_type,
                                component_name=component.component_name,
                                location=f"AndroidManifest.xml - {component.component_name}",
                                evidence=f"Handles broadcast action: {action}",
                                attack_vectors=action_config.get('security_concerns', []),
                                remediation=f"Add appropriate permission requirements for {action} handling. "
                                           f"Implement proper input validation and security checks.",
                                masvs_refs=["MSTG-PLATFORM-02"],
                                cwe_id="CWE-926",
                                risk_score=risk_score,
                                analysis_source=AnalysisSource.MANIFEST_ANALYSIS,
                                pattern_type="receiver_security"
                            )
                            
                            vulnerabilities.append(vulnerability)
            
            return vulnerabilities
            
        except Exception as e:
            self.logger.error(f"Receiver high-risk action analysis failed: {e}")
            return []

def create_component_analyzer(context: AnalysisContext, 
                            confidence_calculator: PlatformUsageConfidenceCalculator) -> ComponentAnalyzer:
    """
    Factory function to create component analyzer with dependency injection.
    
    Args:
        context: Analysis context
        confidence_calculator: Evidence-based confidence calculator
        
    Returns:
        Configured component analyzer
    """
    return ComponentAnalyzer(context, confidence_calculator)
"""
PWA and Cordova Security Analyzer

This module provides comprehensive security analysis for Progressive Web Apps (PWA)
and Cordova/PhoneGap applications within the cross-platform analysis framework.

Features:
- PWA security analysis with service worker assessment
- Cordova/PhoneGap security analysis with plugin validation
- WebApp Manifest security assessment
- Device API security analysis
- Hybrid app bridge security assessment
- Cache security analysis
- Web technology security integration
"""

import logging
import re
import json
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path

from .data_structures import (
    CrossPlatformFinding, FrameworkDetectionResult, LibraryInfo,
    ConfidenceEvidence, Framework, VulnerabilityType, Severity, DetectionMethod
)
from .confidence_calculator import CrossPlatformConfidenceCalculator

class PWAAnalyzer:
    """
    Comprehensive PWA and Cordova security analyzer with professional confidence system.
    
    Analyzes Progressive Web Apps and Cordova applications for security vulnerabilities including:
    - Service Worker security issues
    - WebApp Manifest vulnerabilities
    - Cordova plugin security problems
    - Device API security concerns
    - Hybrid app bridge vulnerabilities
    """
    
    def __init__(self):
        """Initialize the PWA analyzer."""
        self.logger = logging.getLogger(__name__)
        self.confidence_calculator = CrossPlatformConfidenceCalculator()
        
        # PWA and Cordova detection patterns
        self.detection_patterns = {
            'pwa_indicators': [
                r'navigator\.serviceWorker',
                r'self\.addEventListener',
                r'manifest\.json',
                r'workbox-',
                r'@angular/service-worker',
                r'sw\.js',
                r'service-worker\.js',
                r'offline\.html'
            ],
            'cordova_indicators': [
                r'cordova\.js',
                r'phonegap\.js',
                r'device\.platform',
                r'cordova\.file',
                r'cordova\.plugins',
                r'plugins/.*\.js',
                r'config\.xml',
                r'www/cordova'
            ],
            'version_patterns': [
                r'cordova:\s*([0-9.]+)',
                r'phonegap:\s*([0-9.]+)',
                r'"workbox-[^"]*":\s*"([^"]+)"'
            ]
        }
        
        # Security vulnerability patterns
        self.vulnerability_patterns = {
            'service_worker_security': [
                r'self\.addEventListener\s*\(\s*["\']fetch["\'].*response\s*=.*eval\s*\(',
                r'caches\.open\s*\([^)]*\+.*user',
                r'cache\.put\s*\([^)]*\+.*user.*,\s*[^)]*\+.*user',
                r'importScripts\s*\([^)]*\+.*user',
                r'self\.registration\.sync\.register\s*\([^)]*\+.*user',
                r'fetch\s*\([^)]*\+.*user.*\)\.then\s*\([^)]*eval',
                r'postMessage\s*\([^)]*\+.*user',
                r'clients\.claim\s*\(\s*\)(?![^;]*validate)'
            ],
            'manifest_security': [
                r'"start_url"\s*:\s*["\'][^"\']*\+.*user',
                r'"scope"\s*:\s*["\'][^"\']*\*',
                r'"background_sync"\s*:\s*["\'][^"\']*\+',
                r'"permissions"\s*:\s*\[[^\]]*\*',
                r'"protocol_handlers"\s*:\s*\[[^\]]*["\'][^"\']*\+',
                r'"shortcuts"\s*:\s*\[[^\]]*"url"\s*:\s*["\'][^"\']*\+',
                r'"share_target"\s*:\s*{[^}]*"action"\s*:\s*["\'][^"\']*\+'
            ],
            'cordova_plugin_security': [
                r'cordova\.exec\s*\([^)]*,\s*[^)]*,\s*["\'][^"\']*["\'],\s*["\'][^"\']*["\'],\s*\[[^\]]*\+.*user',
                r'cordova\.plugins\.[^.]+\.[^(]+\s*\([^)]*\+.*user',
                r'navigator\.plugins\.[^.]+\.[^(]+\s*\([^)]*\+.*user',
                r'device\.capture\.[^(]+\s*\([^)]*\+.*user',
                r'cordova\.file\..*\.getFile\s*\([^)]*\+.*user',
                r'window\.resolveLocalFileSystemURL\s*\([^)]*\+.*user',
                r'navigator\.geolocation\.getCurrentPosition\s*\([^)]*eval'
            ],
            'device_api_security': [
                r'navigator\.camera\.getPicture\s*\([^)]*destinationType\s*:\s*[^,]*,.*allowEdit\s*:\s*true',
                r'navigator\.contacts\.find\s*\([^\]]*\]\s*,\s*[^,]*,\s*[^,]*,\s*{[^}]*filter\s*:\s*["\'][^"\']*\+',
                r'navigator\.notification\.alert\s*\([^)]*\+.*user',
                r'navigator\.globalization\.[^(]+\s*\([^)]*\+.*user',
                r'window\.requestFileSystem\s*\([^)]*,\s*[^)]*,\s*[^)]*eval',
                r'Media\s*\([^)]*\+.*user.*\)\.play\s*\(\s*\)',
                r'navigator\.splashscreen\.show\s*\(\s*\)(?![^;]*timer)'
            ],
            'hybrid_bridge_security': [
                r'window\.webkit\.messageHandlers\.[^.]+\.postMessage\s*\([^)]*\+.*user',
                r'window\.external\.notify\s*\([^)]*\+.*user',
                r'window\.chrome\.webview\.postMessage\s*\([^)]*\+.*user',
                r'AndroidInterface\.[^(]+\s*\([^)]*\+.*user',
                r'window\.\$\{[^}]*\}\s*\([^)]*\+.*user',
                r'cordova\.require\s*\(["\'][^"\']*["\'].*\+.*user',
                r'PhoneGap\.[^.]+\.[^(]+\s*\([^)]*\+.*user'
            ]
        }
        
        self.logger.info("PWA analyzer initialized")
    
    def analyze(self, app_data: Dict, location: str = "pwa_app") -> List[CrossPlatformFinding]:
        """
        Analyze PWA/Cordova application for security vulnerabilities.
        
        Args:
            app_data: Application data including content and metadata
            location: Location identifier for the analysis
            
        Returns:
            List of security findings
        """
        try:
            self.logger.info("Starting PWA/Cordova security analysis")
            
            findings = []
            
            # Detect PWA/Cordova framework
            detection_result = self._detect_framework_advanced(app_data)
            if detection_result.confidence < 0.7:
                self.logger.warning("Low confidence PWA/Cordova detection")
                return findings
            
            # Progressive Web App Security Analysis 
            if self._is_pwa(app_data):
                pwa_findings = self._analyze_pwa_security_advanced(app_data, location)
                findings.extend(pwa_findings)
            
            # Cordova/PhoneGap Security Analysis 
            if self._is_cordova(app_data):
                cordova_findings = self._analyze_cordova_security_advanced(app_data, location)
                findings.extend(cordova_findings)
            
            # Hybrid App Bridge Security Assessment
            bridge_findings = self._analyze_hybrid_bridge_security(app_data, location)
            findings.extend(bridge_findings)
            
            # Web Technology Security Integration
            web_findings = self._analyze_web_technology_security(app_data, location)
            findings.extend(web_findings)
            
            self.logger.info(f"PWA/Cordova analysis completed: {len(findings)} findings")
            return findings
            
        except Exception as e:
            self.logger.error(f"PWA/Cordova analysis failed: {e}")
            return []
    
    def _detect_framework_advanced(self, app_data: Dict) -> FrameworkDetectionResult:
        """Advanced PWA/Cordova framework detection with professional confidence calculation."""
        try:
            detection_methods = []
            framework = Framework.PWA  # Default
            
            app_content = self._extract_app_content(app_data)
            
            # Collect detection evidence
            evidence = []
            
            # Check for PWA indicators
            pwa_score = 0
            for pattern in self.detection_patterns['pwa_indicators']:
                if re.search(pattern, app_content, re.IGNORECASE):
                    pwa_score += 1
                    detection_methods.append(f"PWA pattern: {pattern}")
                    evidence.append(f"pwa_pattern:{pattern}")
            
            # Check for Cordova indicators
            cordova_score = 0
            for pattern in self.detection_patterns['cordova_indicators']:
                if re.search(pattern, app_content, re.IGNORECASE):
                    cordova_score += 1
                    detection_methods.append(f"Cordova pattern: {pattern}")
                    evidence.append(f"cordova_pattern:{pattern}")
            
            # Determine framework type
            if cordova_score > pwa_score:
                framework = Framework.CORDOVA
            else:
                framework = Framework.PWA
            
            # Check for version patterns
            version = None
            for pattern in self.detection_patterns['version_patterns']:
                match = re.search(pattern, app_content, re.IGNORECASE)
                if match:
                    version = match.group(1)
                    detection_methods.append(f"Version pattern: {pattern}")
                    evidence.append(f"version_detected:{version}")
                    break
            
            # Calculate professional confidence using evidence-based approach
            total_patterns = max(pwa_score + cordova_score, 1)
            confidence_evidence = ConfidenceEvidence(
                pattern_reliability=0.82,  # PWA/Cordova patterns are reliable but context-dependent
                match_quality=total_patterns / 8.0,  # Quality based on pattern matches
                context_relevance=0.80,  # Good relevance for web app analysis
                validation_sources=[f"pwa_cordova_detection"],
                cross_validation=len(detection_methods)
            )
            
            confidence = self.confidence_calculator.calculate_confidence(
                'pwa_cordova_detection', confidence_evidence
            )
            
            return FrameworkDetectionResult(
                framework=framework,
                confidence=confidence,
                version=version,
                detection_methods=detection_methods,
                metadata={'detected_indicators': len(evidence), 'evidence': evidence}
            )
            
        except Exception as e:
            self.logger.error(f"Framework detection failed: {e}")
            return FrameworkDetectionResult(
                framework=Framework.PWA,
                confidence=0.0,
                version=None,
                detection_methods=[],
                metadata={}
            )
    
    def _analyze_pwa_security_advanced(self, app_data: Dict, location: str) -> List[CrossPlatformFinding]:
        """Advanced Progressive Web App security analysis."""
        findings = []
        
        try:
            app_content = self._extract_app_content(app_data)
            
            # Service Worker security analysis
            sw_findings = self._analyze_service_worker_security(app_content, location)
            findings.extend(sw_findings)
            
            # Web App Manifest security assessment
            manifest_findings = self._analyze_webapp_manifest_security(app_content, location)
            findings.extend(manifest_findings)
            
            # PWA-specific vulnerability patterns
            pwa_findings = self._analyze_pwa_vulnerabilities(app_content, location)
            findings.extend(pwa_findings)
            
            # Cache security analysis
            cache_findings = self._analyze_cache_security(app_content, location)
            findings.extend(cache_findings)
            
        except Exception as e:
            self.logger.error(f"PWA analysis failed: {e}")
        
        return findings
    
    def _analyze_service_worker_security(self, content: str, location: str) -> List[CrossPlatformFinding]:
        """Analyze Service Worker security vulnerabilities."""
        findings = []
        
        try:
            for pattern in self.vulnerability_patterns['service_worker_security']:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    context = self._get_code_context(content, match.start(), match.end())
                    
                    evidence = ConfidenceEvidence(
                        pattern_reliability=0.85,
                        match_quality=self._assess_service_worker_quality(match.group(), context),
                        context_relevance=0.80,
                        validation_sources=['service_worker_analysis'],
                        cross_validation=1
                    )
                    
                    confidence = self.confidence_calculator.calculate_confidence(
                        'service_worker_security', evidence
                    )
                    
                    severity = self._assess_service_worker_severity(match.group(), context)
                    vuln_type = self._classify_service_worker_vulnerability(match.group())
                    
                    findings.append(CrossPlatformFinding(
                        title=f"Service Worker Security Issue: {vuln_type}",
                        description=f"Service Worker security vulnerability: {match.group()}",
                        severity=severity,
                        vulnerability_type=VulnerabilityType.WEB_WORKER.value,
                        affected_component=f"{location}/service_worker",
                        code_snippet=context,
                        recommendation=self._get_service_worker_recommendation(vuln_type),
                        attack_vector="Service Worker manipulation",
                        cwe_id="CWE-79",
                        confidence=confidence,
                        evidence=evidence.__dict__
                    ))
                    
        except Exception as e:
            self.logger.error(f"Service Worker analysis failed: {e}")
        
        return findings
    
    def _analyze_webapp_manifest_security(self, content: str, location: str) -> List[CrossPlatformFinding]:
        """Analyze Web App Manifest security vulnerabilities."""
        findings = []
        
        try:
            for pattern in self.vulnerability_patterns['manifest_security']:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    context = self._get_code_context(content, match.start(), match.end())
                    
                    evidence = ConfidenceEvidence(
                        pattern_reliability=0.80,
                        match_quality=self._assess_manifest_quality(match.group(), context),
                        context_relevance=0.75,
                        validation_sources=['manifest_analysis'],
                        cross_validation=1
                    )
                    
                    confidence = self.confidence_calculator.calculate_confidence(
                        'manifest_security', evidence
                    )
                    
                    severity = self._assess_manifest_severity(match.group(), context)
                    vuln_type = self._classify_manifest_vulnerability(match.group())
                    
                    findings.append(CrossPlatformFinding(
                        title=f"Web App Manifest Security Issue: {vuln_type}",
                        description=f"Manifest security vulnerability: {match.group()}",
                        severity=severity,
                        vulnerability_type=VulnerabilityType.CONFIGURATION.value,
                        affected_component=f"{location}/manifest",
                        code_snippet=context,
                        recommendation=self._get_manifest_recommendation(vuln_type),
                        attack_vector="Manifest manipulation",
                        cwe_id="CWE-16",
                        confidence=confidence,
                        evidence=evidence.__dict__
                    ))
                    
        except Exception as e:
            self.logger.error(f"Manifest analysis failed: {e}")
        
        return findings
    
    def _analyze_cordova_security_advanced(self, app_data: Dict, location: str) -> List[CrossPlatformFinding]:
        """Advanced Cordova/PhoneGap security analysis."""
        findings = []
        
        try:
            app_content = self._extract_app_content(app_data)
            
            # Cordova plugin security analysis
            plugin_findings = self._analyze_cordova_plugin_security(app_content, location)
            findings.extend(plugin_findings)
            
            # Device API security analysis
            device_findings = self._analyze_device_api_security(app_content, location)
            findings.extend(device_findings)
            
            # Cordova configuration security
            config_findings = self._analyze_cordova_config_security(app_content, location)
            findings.extend(config_findings)
            
            # Native bridge security assessment
            bridge_findings = self._analyze_cordova_bridge_security(app_content, location)
            findings.extend(bridge_findings)
            
        except Exception as e:
            self.logger.error(f"Cordova analysis failed: {e}")
        
        return findings
    
    def _analyze_cordova_plugin_security(self, content: str, location: str) -> List[CrossPlatformFinding]:
        """Analyze Cordova plugin security vulnerabilities."""
        findings = []
        
        try:
            for pattern in self.vulnerability_patterns['cordova_plugin_security']:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    context = self._get_code_context(content, match.start(), match.end())
                    
                    evidence = ConfidenceEvidence(
                        pattern_reliability=0.85,
                        match_quality=self._assess_cordova_plugin_quality(match.group(), context),
                        context_relevance=0.80,
                        validation_sources=['cordova_plugin_analysis'],
                        cross_validation=1
                    )
                    
                    confidence = self.confidence_calculator.calculate_confidence(
                        'cordova_plugin_security', evidence
                    )
                    
                    severity = self._assess_cordova_plugin_severity(match.group(), context)
                    vuln_type = self._classify_cordova_plugin_vulnerability(match.group())
                    
                    findings.append(CrossPlatformFinding(
                        title=f"Cordova Plugin Security Issue: {vuln_type}",
                        description=f"Cordova plugin security vulnerability: {match.group()}",
                        severity=severity,
                        vulnerability_type=VulnerabilityType.NATIVE_INTERFACE.value,
                        affected_component=f"{location}/cordova_plugin",
                        code_snippet=context,
                        recommendation=self._get_cordova_plugin_recommendation(vuln_type),
                        attack_vector="Plugin interface manipulation",
                        cwe_id="CWE-20",
                        confidence=confidence,
                        evidence=evidence.__dict__
                    ))
                    
        except Exception as e:
            self.logger.error(f"Cordova plugin analysis failed: {e}")
        
        return findings
    
    def _analyze_device_api_security(self, content: str, location: str) -> List[CrossPlatformFinding]:
        """Analyze device API security vulnerabilities."""
        findings = []
        
        try:
            for pattern in self.vulnerability_patterns['device_api_security']:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    context = self._get_code_context(content, match.start(), match.end())
                    
                    evidence = ConfidenceEvidence(
                        pattern_reliability=0.80,
                        match_quality=self._assess_device_api_quality(match.group(), context),
                        context_relevance=0.75,
                        validation_sources=['device_api_analysis'],
                        cross_validation=1
                    )
                    
                    confidence = self.confidence_calculator.calculate_confidence(
                        'device_api_security', evidence
                    )
                    
                    severity = self._assess_device_api_severity(match.group(), context)
                    vuln_type = self._classify_device_api_vulnerability(match.group())
                    
                    findings.append(CrossPlatformFinding(
                        title=f"Device API Security Issue: {vuln_type}",
                        description=f"Device API security vulnerability: {match.group()}",
                        severity=severity,
                        vulnerability_type=VulnerabilityType.DEVICE_ACCESS.value,
                        affected_component=f"{location}/device_api",
                        code_snippet=context,
                        recommendation=self._get_device_api_recommendation(vuln_type),
                        attack_vector="Device API abuse",
                        cwe_id="CWE-200",
                        confidence=confidence,
                        evidence=evidence.__dict__
                    ))
                    
        except Exception as e:
            self.logger.error(f"Device API analysis failed: {e}")
        
        return findings
    
    def _analyze_hybrid_bridge_security(self, app_data: Dict, location: str) -> List[CrossPlatformFinding]:
        """Analyze hybrid app bridge security vulnerabilities."""
        findings = []
        
        try:
            app_content = self._extract_app_content(app_data)
            
            for pattern in self.vulnerability_patterns['hybrid_bridge_security']:
                matches = re.finditer(pattern, app_content, re.IGNORECASE)
                for match in matches:
                    context = self._get_code_context(app_content, match.start(), match.end())
                    
                    evidence = ConfidenceEvidence(
                        pattern_reliability=0.85,
                        match_quality=self._assess_bridge_quality(match.group(), context),
                        context_relevance=0.80,
                        validation_sources=['bridge_analysis'],
                        cross_validation=1
                    )
                    
                    confidence = self.confidence_calculator.calculate_confidence(
                        'hybrid_bridge_security', evidence
                    )
                    
                    severity = self._assess_bridge_severity(match.group(), context)
                    vuln_type = self._classify_bridge_vulnerability(match.group())
                    
                    findings.append(CrossPlatformFinding(
                        title=f"Hybrid Bridge Security Issue: {vuln_type}",
                        description=f"Hybrid bridge security vulnerability: {match.group()}",
                        severity=severity,
                        vulnerability_type=VulnerabilityType.BRIDGE_COMMUNICATION.value,
                        affected_component=f"{location}/hybrid_bridge",
                        code_snippet=context,
                        recommendation=self._get_bridge_recommendation(vuln_type),
                        attack_vector="Bridge communication manipulation",
                        cwe_id="CWE-502",
                        confidence=confidence,
                        evidence=evidence.__dict__
                    ))
                    
        except Exception as e:
            self.logger.error(f"Bridge analysis failed: {e}")
        
        return findings
    
    def _analyze_pwa_vulnerabilities(self, content: str, location: str) -> List[CrossPlatformFinding]:
        """Analyze PWA-specific vulnerability patterns."""
        findings = []
        
        try:
            # Check for insecure PWA patterns
            pwa_patterns = [
                (r'navigator\.serviceWorker\.register\s*\([^)]*\)\.then\([^)]*eval', 'eval_in_sw_registration'),
                (r'caches\.match\s*\([^)]*\+.*user.*\)', 'user_controlled_cache_key'),
                (r'self\.skipWaiting\s*\(\s*\)(?![^;]*validate)', 'unvalidated_skip_waiting'),
                (r'clients\.matchAll\s*\(\s*\)\.then\([^)]*eval', 'eval_in_clients_access'),
                (r'registration\.update\s*\(\s*\)(?![^;]*validate)', 'unvalidated_sw_update'),
                (r'navigator\.share\s*\([^)]*\+.*user', 'user_controlled_share_data')
            ]
            
            for pattern, vuln_type in pwa_patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    context = self._get_code_context(content, match.start(), match.end())
                    
                    evidence = ConfidenceEvidence(
                        pattern_reliability=0.80,
                        match_quality=self._assess_pwa_quality(match.group(), context, vuln_type),
                        context_relevance=0.75,
                        validation_sources=['pwa_vulnerability_analysis'],
                        cross_validation=1
                    )
                    
                    confidence = self.confidence_calculator.calculate_confidence(
                        'pwa_vulnerability', evidence
                    )
                    
                    severity = self._assess_pwa_severity(vuln_type, context)
                    
                    findings.append(CrossPlatformFinding(
                        title=f"PWA Vulnerability: {vuln_type.replace('_', ' ').title()}",
                        description=f"PWA security vulnerability: {match.group()}",
                        severity=severity,
                        vulnerability_type=VulnerabilityType.PWA_SPECIFIC.value,
                        affected_component=f"{location}/pwa",
                        code_snippet=context,
                        recommendation=self._get_pwa_recommendation(vuln_type),
                        attack_vector="PWA feature manipulation",
                        cwe_id="CWE-79",
                        confidence=confidence,
                        evidence=evidence.__dict__
                    ))
                    
        except Exception as e:
            self.logger.error(f"PWA vulnerability analysis failed: {e}")
        
        return findings
    
    def _analyze_cache_security(self, content: str, location: str) -> List[CrossPlatformFinding]:
        """Analyze cache security implementation."""
        findings = []
        
        try:
            cache_patterns = [
                (r'caches\.open\s*\([^)]*\+.*user.*\)', 'user_controlled_cache_name'),
                (r'cache\.addAll\s*\(\[.*\+.*user.*\]\)', 'user_controlled_cache_urls'),
                (r'cache\.put\s*\([^)]*eval.*,', 'eval_in_cache_key'),
                (r'caches\.delete\s*\([^)]*\+.*user.*\)', 'user_controlled_cache_deletion'),
                (r'cache\.match\s*\([^)]*\)\.then\([^)]*eval', 'eval_in_cache_response')
            ]
            
            for pattern, vuln_type in cache_patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    context = self._get_code_context(content, match.start(), match.end())
                    
                    evidence = ConfidenceEvidence(
                        pattern_reliability=0.75,
                        match_quality=self._assess_cache_quality(match.group(), context, vuln_type),
                        context_relevance=0.70,
                        validation_sources=['cache_security_analysis'],
                        cross_validation=1
                    )
                    
                    confidence = self.confidence_calculator.calculate_confidence(
                        'cache_security', evidence
                    )
                    
                    severity = self._assess_cache_severity(vuln_type, context)
                    
                    findings.append(CrossPlatformFinding(
                        title=f"Cache Security Issue: {vuln_type.replace('_', ' ').title()}",
                        description=f"Cache security vulnerability: {match.group()}",
                        severity=severity,
                        vulnerability_type=VulnerabilityType.CACHE_MANIPULATION.value,
                        affected_component=f"{location}/cache",
                        code_snippet=context,
                        recommendation=self._get_cache_recommendation(vuln_type),
                        attack_vector="Cache manipulation",
                        cwe_id="CWE-20",
                        confidence=confidence,
                        evidence=evidence.__dict__
                    ))
                    
        except Exception as e:
            self.logger.error(f"Cache security analysis failed: {e}")
        
        return findings
    
    def _analyze_cordova_config_security(self, content: str, location: str) -> List[CrossPlatformFinding]:
        """Analyze Cordova configuration security."""
        findings = []
        
        try:
            config_patterns = [
                (r'<access\s+origin\s*=\s*["\'][*]["\']', 'wildcard_access_origin'),
                (r'<allow-navigation\s+href\s*=\s*["\'][*]', 'wildcard_navigation'),
                (r'<allow-intent\s+href\s*=\s*["\'][*]', 'wildcard_intent'),
                (r'AllowInlineMediaPlayback\s*=\s*["\']true["\']', 'inline_media_playback'),
                (r'DisallowOverscroll\s*=\s*["\']false["\']', 'overscroll_enabled'),
                (r'webSecurity\s*=\s*["\']false["\']', 'web_security_disabled')
            ]
            
            for pattern, vuln_type in config_patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    context = self._get_code_context(content, match.start(), match.end())
                    
                    evidence = ConfidenceEvidence(
                        pattern_reliability=0.85,
                        match_quality=self._assess_config_quality(match.group(), context, vuln_type),
                        context_relevance=0.80,
                        validation_sources=['cordova_config_analysis'],
                        cross_validation=1
                    )
                    
                    confidence = self.confidence_calculator.calculate_confidence(
                        'cordova_config_security', evidence
                    )
                    
                    severity = self._assess_config_severity(vuln_type, context)
                    
                    findings.append(CrossPlatformFinding(
                        title=f"Cordova Config Security Issue: {vuln_type.replace('_', ' ').title()}",
                        description=f"Cordova configuration vulnerability: {match.group()}",
                        severity=severity,
                        vulnerability_type=VulnerabilityType.CONFIGURATION.value,
                        affected_component=f"{location}/cordova_config",
                        code_snippet=context,
                        recommendation=self._get_config_recommendation(vuln_type),
                        attack_vector="Configuration exploitation",
                        cwe_id="CWE-16",
                        confidence=confidence,
                        evidence=evidence.__dict__
                    ))
                    
        except Exception as e:
            self.logger.error(f"Config security analysis failed: {e}")
        
        return findings
    
    def _analyze_cordova_bridge_security(self, content: str, location: str) -> List[CrossPlatformFinding]:
        """Analyze Cordova native bridge security."""
        findings = []
        
        try:
            bridge_patterns = [
                (r'cordova\.exec\s*\([^)]*,\s*[^)]*,\s*["\'][^"\']*["\'],\s*["\'][^"\']*["\'],\s*null\)', 'null_exec_args'),
                (r'cordova\.callbackFromNative\s*\([^)]*\+.*user', 'user_controlled_callback'),
                (r'window\.handleOpenURL\s*=\s*function\([^)]*\)\s*{[^}]*eval', 'eval_in_url_handler'),
                (r'document\.addEventListener\s*\(\s*["\']deviceready["\'].*eval', 'eval_in_deviceready'),
                (r'window\.plugins\.[^.]+\s*=\s*[^;]*\+.*user', 'user_controlled_plugin_assignment')
            ]
            
            for pattern, vuln_type in bridge_patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    context = self._get_code_context(content, match.start(), match.end())
                    
                    evidence = ConfidenceEvidence(
                        pattern_reliability=0.80,
                        match_quality=self._assess_bridge_quality(match.group(), context),
                        context_relevance=0.75,
                        validation_sources=['cordova_bridge_analysis'],
                        cross_validation=1
                    )
                    
                    confidence = self.confidence_calculator.calculate_confidence(
                        'cordova_bridge_security', evidence
                    )
                    
                    severity = self._assess_bridge_severity(match.group(), context)
                    
                    findings.append(CrossPlatformFinding(
                        title=f"Cordova Bridge Security Issue: {vuln_type.replace('_', ' ').title()}",
                        description=f"Cordova bridge vulnerability: {match.group()}",
                        severity=severity,
                        vulnerability_type=VulnerabilityType.NATIVE_BRIDGE.value,
                        affected_component=f"{location}/cordova_bridge",
                        code_snippet=context,
                        recommendation=self._get_bridge_recommendation(vuln_type),
                        attack_vector="Native bridge manipulation",
                        cwe_id="CWE-20",
                        confidence=confidence,
                        evidence=evidence.__dict__
                    ))
                    
        except Exception as e:
            self.logger.error(f"Bridge security analysis failed: {e}")
        
        return findings
    
    def _analyze_web_technology_security(self, app_data: Dict, location: str) -> List[CrossPlatformFinding]:
        """Analyze web technology security integration."""
        findings = []
        
        try:
            app_content = self._extract_app_content(app_data)
            
            # Web storage security
            storage_findings = self._analyze_web_storage_security(app_content, location)
            findings.extend(storage_findings)
            
            # CSP analysis
            csp_findings = self._analyze_csp_security(app_content, location)
            findings.extend(csp_findings)
            
            # HTTPS enforcement
            https_findings = self._analyze_https_enforcement(app_content, location)
            findings.extend(https_findings)
            
        except Exception as e:
            self.logger.error(f"Web technology analysis failed: {e}")
        
        return findings
    
    def _analyze_web_storage_security(self, content: str, location: str) -> List[CrossPlatformFinding]:
        """Analyze web storage security patterns."""
        findings = []
        
        try:
            storage_patterns = [
                (r'localStorage\.setItem\s*\([^)]*password', 'password_in_localstorage'),
                (r'sessionStorage\.setItem\s*\([^)]*token', 'token_in_sessionstorage'),
                (r'localStorage\.getItem\s*\([^)]*\+.*user', 'user_controlled_storage_key'),
                (r'IndexedDB\.open\s*\([^)]*\+.*user', 'user_controlled_indexeddb'),
                (r'localStorage\.setItem\s*\([^)]*,.*eval', 'eval_in_storage_value')
            ]
            
            for pattern, vuln_type in storage_patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    context = self._get_code_context(content, match.start(), match.end())
                    
                    evidence = ConfidenceEvidence(
                        pattern_reliability=0.75,
                        match_quality=self._assess_storage_quality(match.group(), context, vuln_type),
                        context_relevance=0.70,
                        validation_sources=['web_storage_analysis'],
                        cross_validation=1
                    )
                    
                    confidence = self.confidence_calculator.calculate_confidence(
                        'web_storage_security', evidence
                    )
                    
                    severity = self._assess_storage_severity(vuln_type, context)
                    
                    findings.append(CrossPlatformFinding(
                        title=f"Web Storage Security Issue: {vuln_type.replace('_', ' ').title()}",
                        description=f"Web storage vulnerability: {match.group()}",
                        severity=severity,
                        vulnerability_type=VulnerabilityType.INSECURE_STORAGE.value,
                        affected_component=f"{location}/web_storage",
                        code_snippet=context,
                        recommendation=self._get_storage_recommendation(vuln_type),
                        attack_vector="Storage manipulation",
                        cwe_id="CWE-312",
                        confidence=confidence,
                        evidence=evidence.__dict__
                    ))
                    
        except Exception as e:
            self.logger.error(f"Storage security analysis failed: {e}")
        
        return findings
    
    def _analyze_csp_security(self, content: str, location: str) -> List[CrossPlatformFinding]:
        """Analyze Content Security Policy implementation."""
        findings = []
        
        try:
            csp_patterns = [
                (r'<meta[^>]+http-equiv\s*=\s*["\']Content-Security-Policy["\'][^>]*content\s*=\s*["\'][^"\']*unsafe-inline', 'unsafe_inline_csp'),
                (r'<meta[^>]+http-equiv\s*=\s*["\']Content-Security-Policy["\'][^>]*content\s*=\s*["\'][^"\']*unsafe-eval', 'unsafe_eval_csp'),
                (r'<meta[^>]+http-equiv\s*=\s*["\']Content-Security-Policy["\'][^>]*content\s*=\s*["\'][^"\']*\*', 'wildcard_csp'),
                (r'(?!.*Content-Security-Policy).*<head>', 'missing_csp_header')
            ]
            
            for pattern, vuln_type in csp_patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE | re.DOTALL)
                for match in matches:
                    context = self._get_code_context(content, match.start(), match.end())
                    
                    evidence = ConfidenceEvidence(
                        pattern_reliability=0.80,
                        match_quality=self._assess_csp_quality(match.group(), context, vuln_type),
                        context_relevance=0.75,
                        validation_sources=['csp_analysis'],
                        cross_validation=1
                    )
                    
                    confidence = self.confidence_calculator.calculate_confidence(
                        'csp_security', evidence
                    )
                    
                    severity = self._assess_csp_severity(vuln_type, context)
                    
                    findings.append(CrossPlatformFinding(
                        title=f"CSP Security Issue: {vuln_type.replace('_', ' ').title()}",
                        description=f"Content Security Policy vulnerability: {vuln_type}",
                        severity=severity,
                        vulnerability_type=VulnerabilityType.CSP_BYPASS.value,
                        affected_component=f"{location}/csp",
                        code_snippet=context,
                        recommendation=self._get_csp_recommendation(vuln_type),
                        attack_vector="CSP bypass",
                        cwe_id="CWE-1021",
                        confidence=confidence,
                        evidence=evidence.__dict__
                    ))
                    
        except Exception as e:
            self.logger.error(f"CSP analysis failed: {e}")
        
        return findings
    
    def _analyze_https_enforcement(self, content: str, location: str) -> List[CrossPlatformFinding]:
        """Analyze HTTPS enforcement patterns."""
        findings = []
        
        try:
            https_patterns = [
                (r'http://[^"\'\s]+', 'http_url_usage'),
                (r'fetch\s*\(\s*["\']http://', 'http_fetch_request'),
                (r'XMLHttpRequest.*open\s*\([^)]*["\']http://', 'http_xhr_request'),
                (r'WebSocket\s*\(\s*["\']ws://', 'insecure_websocket'),
                (r'<iframe[^>]+src\s*=\s*["\']http://', 'http_iframe_source')
            ]
            
            for pattern, vuln_type in https_patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    context = self._get_code_context(content, match.start(), match.end())
                    
                    evidence = ConfidenceEvidence(
                        pattern_reliability=0.85,
                        match_quality=self._assess_https_quality(match.group(), context, vuln_type),
                        context_relevance=0.80,
                        validation_sources=['https_analysis'],
                        cross_validation=1
                    )
                    
                    confidence = self.confidence_calculator.calculate_confidence(
                        'https_enforcement', evidence
                    )
                    
                    severity = self._assess_https_severity(vuln_type, context)
                    
                    findings.append(CrossPlatformFinding(
                        title=f"HTTPS Enforcement Issue: {vuln_type.replace('_', ' ').title()}",
                        description=f"Insecure communication: {match.group()}",
                        severity=severity,
                        vulnerability_type=VulnerabilityType.INSECURE_COMMUNICATION.value,
                        affected_component=f"{location}/https",
                        code_snippet=context,
                        recommendation=self._get_https_recommendation(vuln_type),
                        attack_vector="Man-in-the-middle attack",
                        cwe_id="CWE-319",
                        confidence=confidence,
                        evidence=evidence.__dict__
                    ))
                    
        except Exception as e:
            self.logger.error(f"HTTPS analysis failed: {e}")
        
        return findings
    
    # Helper methods for framework detection and content extraction
    
    def _is_pwa(self, app_data: Dict) -> bool:
        """Check if the application is a PWA."""
        content = self._extract_app_content(app_data)
        pwa_indicators = ['serviceWorker', 'manifest.json', 'workbox']
        return any(indicator in content for indicator in pwa_indicators)
    
    def _is_cordova(self, app_data: Dict) -> bool:
        """Check if the application is a Cordova app."""
        content = self._extract_app_content(app_data)
        cordova_indicators = ['cordova.js', 'phonegap.js', 'config.xml']
        return any(indicator in content for indicator in cordova_indicators)
    
    def _extract_app_content(self, app_data: Dict) -> str:
        """Extract application content for analysis."""
        if isinstance(app_data, dict):
            if 'content' in app_data:
                return str(app_data['content'])
            elif 'files' in app_data:
                return ' '.join(str(f) for f in app_data['files'].values())
            else:
                return str(app_data)
        return str(app_data)
    
    def _extract_version(self, content: str) -> Optional[str]:
        """Extract framework version from content."""
        for pattern in self.detection_patterns['version_patterns']:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                return match.group(1)
        return None
    
    def _get_code_context(self, content: str, start: int, end: int, context_lines: int = 3) -> str:
        """Get code context around a match."""
        lines = content[:start].count('\n')
        content_lines = content.split('\n')
        
        start_line = max(0, lines - context_lines)
        end_line = min(len(content_lines), lines + context_lines + 1)
        
        context = '\n'.join(content_lines[start_line:end_line])
        return context[:500]  # Limit context size
    
    # Assessment methods for different vulnerability types
    
    def _assess_service_worker_quality(self, match: str, context: str) -> float:
        """Assess service worker vulnerability match quality."""
        quality_score = 0.5
        if 'eval' in match.lower():
            quality_score += 0.3
        if 'user' in context.lower():
            quality_score += 0.2
        return min(quality_score, 1.0)
    
    def _assess_service_worker_severity(self, match: str, context: str) -> Severity:
        """Assess service worker vulnerability severity."""
        if 'eval' in match.lower():
            return Severity.HIGH
        elif 'user' in context.lower():
            return Severity.MEDIUM
        return Severity.LOW
    
    def _classify_service_worker_vulnerability(self, match: str) -> str:
        """Classify service worker vulnerability type."""
        if 'eval' in match.lower():
            return "Code Injection"
        elif 'cache' in match.lower():
            return "Cache Poisoning"
        elif 'fetch' in match.lower():
            return "Request Manipulation"
        return "Service Worker Abuse"
    
    def _get_service_worker_recommendation(self, vuln_type: str) -> str:
        """Get recommendation for service worker vulnerability."""
        recommendations = {
            "Code Injection": "Avoid using eval() in service workers. Use secure parsing methods.",
            "Cache Poisoning": "Validate cache keys and values. Implement proper input sanitization.",
            "Request Manipulation": "Validate fetch requests and implement proper URL filtering.",
            "Service Worker Abuse": "Implement proper service worker security controls."
        }
        return recommendations.get(vuln_type, "Review service worker implementation for security issues.")
    
    def _assess_manifest_quality(self, match: str, context: str) -> float:
        """Assess manifest vulnerability match quality."""
        quality_score = 0.5
        if 'user' in context.lower():
            quality_score += 0.3
        if any(char in match for char in ['*', '+']):
            quality_score += 0.2
        return min(quality_score, 1.0)
    
    def _assess_manifest_severity(self, match: str, context: str) -> Severity:
        """Assess manifest vulnerability severity."""
        if '*' in match:
            return Severity.HIGH
        elif 'user' in context.lower():
            return Severity.MEDIUM
        return Severity.LOW
    
    def _classify_manifest_vulnerability(self, match: str) -> str:
        """Classify manifest vulnerability type."""
        if 'start_url' in match.lower():
            return "Start URL Manipulation"
        elif 'scope' in match.lower():
            return "Scope Bypass"
        elif 'permissions' in match.lower():
            return "Permission Escalation"
        return "Manifest Configuration Issue"
    
    def _get_manifest_recommendation(self, vuln_type: str) -> str:
        """Get recommendation for manifest vulnerability."""
        recommendations = {
            "Start URL Manipulation": "Use static, validated start URLs. Avoid dynamic URL construction.",
            "Scope Bypass": "Define specific scopes. Avoid wildcard scope definitions.",
            "Permission Escalation": "Request minimal permissions. Validate permission usage.",
            "Manifest Configuration Issue": "Review manifest configuration for security best practices."
        }
        return recommendations.get(vuln_type, "Review manifest configuration for security issues.")
    
    def _assess_cordova_plugin_quality(self, match: str, context: str) -> float:
        """Assess Cordova plugin vulnerability match quality."""
        quality_score = 0.5
        if 'exec' in match.lower():
            quality_score += 0.3
        if 'user' in context.lower():
            quality_score += 0.2
        return min(quality_score, 1.0)
    
    def _assess_cordova_plugin_severity(self, match: str, context: str) -> Severity:
        """Assess Cordova plugin vulnerability severity."""
        if 'exec' in match.lower() and 'user' in context.lower():
            return Severity.HIGH
        elif 'file' in match.lower():
            return Severity.MEDIUM
        return Severity.LOW
    
    def _classify_cordova_plugin_vulnerability(self, match: str) -> str:
        """Classify Cordova plugin vulnerability type."""
        if 'exec' in match.lower():
            return "Plugin Execution Abuse"
        elif 'file' in match.lower():
            return "File System Access"
        elif 'device' in match.lower():
            return "Device Information Disclosure"
        return "Plugin Interface Abuse"
    
    def _get_cordova_plugin_recommendation(self, vuln_type: str) -> str:
        """Get recommendation for Cordova plugin vulnerability."""
        recommendations = {
            "Plugin Execution Abuse": "Validate all parameters passed to cordova.exec(). Implement input sanitization.",
            "File System Access": "Restrict file system access. Validate file paths and operations.",
            "Device Information Disclosure": "Minimize device information exposure. Implement proper access controls.",
            "Plugin Interface Abuse": "Validate plugin interface usage. Implement proper security controls."
        }
        return recommendations.get(vuln_type, "Review plugin implementation for security issues.")
    
    def _assess_device_api_quality(self, match: str, context: str) -> float:
        """Assess device API vulnerability match quality."""
        quality_score = 0.5
        if 'camera' in match.lower() or 'contacts' in match.lower():
            quality_score += 0.3
        if 'user' in context.lower():
            quality_score += 0.2
        return min(quality_score, 1.0)
    
    def _assess_device_api_severity(self, match: str, context: str) -> Severity:
        """Assess device API vulnerability severity."""
        sensitive_apis = ['camera', 'contacts', 'geolocation']
        if any(api in match.lower() for api in sensitive_apis):
            return Severity.HIGH
        return Severity.MEDIUM
    
    def _classify_device_api_vulnerability(self, match: str) -> str:
        """Classify device API vulnerability type."""
        if 'camera' in match.lower():
            return "Camera Access Abuse"
        elif 'contacts' in match.lower():
            return "Contact Information Disclosure"
        elif 'geolocation' in match.lower():
            return "Location Tracking"
        return "Device API Abuse"
    
    def _get_device_api_recommendation(self, vuln_type: str) -> str:
        """Get recommendation for device API vulnerability."""
        recommendations = {
            "Camera Access Abuse": "Implement proper camera access controls. Validate image processing.",
            "Contact Information Disclosure": "Minimize contact access. Implement data filtering.",
            "Location Tracking": "Request location permission appropriately. Implement location data protection.",
            "Device API Abuse": "Review device API usage for security best practices."
        }
        return recommendations.get(vuln_type, "Review device API implementation for security issues.")
    
    def _assess_bridge_quality(self, match: str, context: str) -> float:
        """Assess bridge vulnerability match quality."""
        quality_score = 0.5
        if 'webkit' in match.lower() or 'webview' in match.lower():
            quality_score += 0.3
        if 'user' in context.lower():
            quality_score += 0.2
        return min(quality_score, 1.0)
    
    def _assess_bridge_severity(self, match: str, context: str) -> Severity:
        """Assess bridge vulnerability severity."""
        if 'postMessage' in match and 'user' in context.lower():
            return Severity.HIGH
        elif 'webview' in match.lower():
            return Severity.MEDIUM
        return Severity.LOW
    
    def _classify_bridge_vulnerability(self, match: str) -> str:
        """Classify bridge vulnerability type."""
        if 'webkit' in match.lower():
            return "WebKit Bridge Abuse"
        elif 'webview' in match.lower():
            return "WebView Communication"
        elif 'postMessage' in match.lower():
            return "Message Injection"
        return "Bridge Communication Issue"
    
    def _get_bridge_recommendation(self, vuln_type: str) -> str:
        """Get recommendation for bridge vulnerability."""
        recommendations = {
            "WebKit Bridge Abuse": "Validate WebKit bridge communications. Implement message filtering.",
            "WebView Communication": "Secure WebView bridge. Validate all communications.",
            "Message Injection": "Validate message content. Implement proper message handling.",
            "Bridge Communication Issue": "Review bridge implementation for security best practices."
        }
        return recommendations.get(vuln_type, "Review bridge implementation for security issues.")
    
    # Additional assessment methods for other vulnerability types
    
    def _assess_pwa_quality(self, match: str, context: str, vuln_type: str) -> float:
        """Assess PWA vulnerability match quality."""
        return 0.7  # Base quality for PWA patterns
    
    def _assess_pwa_severity(self, vuln_type: str, context: str) -> Severity:
        """Assess PWA vulnerability severity."""
        high_risk = ['eval_in_sw_registration', 'user_controlled_cache_key']
        return Severity.HIGH if vuln_type in high_risk else Severity.MEDIUM
    
    def _get_pwa_recommendation(self, vuln_type: str) -> str:
        """Get recommendation for PWA vulnerability."""
        return f"Review PWA implementation for {vuln_type.replace('_', ' ')} security issues."
    
    def _assess_cache_quality(self, match: str, context: str, vuln_type: str) -> float:
        """Assess cache vulnerability match quality."""
        return 0.7  # Base quality for cache patterns
    
    def _assess_cache_severity(self, vuln_type: str, context: str) -> Severity:
        """Assess cache vulnerability severity."""
        return Severity.MEDIUM  # Most cache issues are medium severity
    
    def _get_cache_recommendation(self, vuln_type: str) -> str:
        """Get recommendation for cache vulnerability."""
        return f"Implement proper cache security for {vuln_type.replace('_', ' ')}."
    
    def _assess_config_quality(self, match: str, context: str, vuln_type: str) -> float:
        """Assess config vulnerability match quality."""
        return 0.8  # Config issues are usually clear
    
    def _assess_config_severity(self, vuln_type: str, context: str) -> Severity:
        """Assess config vulnerability severity."""
        high_risk = ['wildcard_access_origin', 'web_security_disabled']
        return Severity.HIGH if vuln_type in high_risk else Severity.MEDIUM
    
    def _get_config_recommendation(self, vuln_type: str) -> str:
        """Get recommendation for config vulnerability."""
        return f"Review Cordova configuration for {vuln_type.replace('_', ' ')} security."
    
    def _assess_storage_quality(self, match: str, context: str, vuln_type: str) -> float:
        """Assess storage vulnerability match quality."""
        return 0.7  # Base quality for storage patterns
    
    def _assess_storage_severity(self, vuln_type: str, context: str) -> Severity:
        """Assess storage vulnerability severity."""
        sensitive = ['password_in_localstorage', 'token_in_sessionstorage']
        return Severity.HIGH if vuln_type in sensitive else Severity.MEDIUM
    
    def _get_storage_recommendation(self, vuln_type: str) -> str:
        """Get recommendation for storage vulnerability."""
        return f"Implement secure storage practices for {vuln_type.replace('_', ' ')}."
    
    def _assess_csp_quality(self, match: str, context: str, vuln_type: str) -> float:
        """Assess CSP vulnerability match quality."""
        return 0.8  # CSP issues are usually clear
    
    def _assess_csp_severity(self, vuln_type: str, context: str) -> Severity:
        """Assess CSP vulnerability severity."""
        high_risk = ['unsafe_eval_csp', 'missing_csp_header']
        return Severity.HIGH if vuln_type in high_risk else Severity.MEDIUM
    
    def _get_csp_recommendation(self, vuln_type: str) -> str:
        """Get recommendation for CSP vulnerability."""
        return f"Implement proper Content Security Policy for {vuln_type.replace('_', ' ')}."
    
    def _assess_https_quality(self, match: str, context: str, vuln_type: str) -> float:
        """Assess HTTPS vulnerability match quality."""
        return 0.9  # HTTPS issues are very clear
    
    def _assess_https_severity(self, vuln_type: str, context: str) -> Severity:
        """Assess HTTPS vulnerability severity."""
        return Severity.HIGH  # All HTTPS issues are high risk
    
    def _get_https_recommendation(self, vuln_type: str) -> str:
        """Get recommendation for HTTPS vulnerability."""
        return f"Enforce HTTPS for all communications. Fix {vuln_type.replace('_', ' ')}." 
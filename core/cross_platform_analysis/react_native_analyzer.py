"""
React Native Security Analyzer

This module provides comprehensive security analysis for React Native applications
within the cross-platform analysis framework.

Features:
- React Native framework detection and version analysis
- JavaScript bundle security analysis
- Native bridge vulnerability assessment
- Third-party library vulnerability scanning
- AsyncStorage security analysis
- Metro bundler security validation
- React Navigation security assessment
- Performance security implications analysis
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


class ReactNativeAnalyzer:
    """
    Comprehensive React Native security analyzer with professional confidence system.
    
    Analyzes React Native applications for security vulnerabilities including:
    - JavaScript injection vulnerabilities
    - Native bridge security issues
    - Storage security problems
    - Third-party library vulnerabilities
    - Configuration security issues
    """
    
    def __init__(self):
        """Initialize the React Native analyzer."""
        self.logger = logging.getLogger(__name__)
        self.confidence_calculator = CrossPlatformConfidenceCalculator()
        
        # React Native detection patterns
        self.detection_patterns = {
            'framework_indicators': [
                r'react-native',
                r'@react-native/',
                r'ReactNative',
                r'RNModules',
                r'NativeModules\..*',
                r'bridge\.call',
                r'__fbBatchedBridge'
            ],
            'version_patterns': [
                r'"react-native":\s*"([^"]+)"',
                r'react-native@([0-9.]+)',
                r'ReactNative\s+([0-9.]+)'
            ],
            'file_patterns': [
                r'.*\.bundle$',
                r'.*index\.android\.bundle$',
                r'.*main\.jsbundle$',
                r'.*metro\.config\.js$',
                r'.*react-native\.config\.js$'
            ]
        }
        
        # Security vulnerability patterns
        self.vulnerability_patterns = {
            'javascript_injection': [
                r'dangerouslySetInnerHTML',
                r'eval\s*\(',
                r'Function\s*\(',
                r'setTimeout\s*\(\s*["\']',
                r'setInterval\s*\(\s*["\']',
                r'document\.write\s*\(',
                r'innerHTML\s*=\s*[^;]+\+',
                r'outerHTML\s*=\s*[^;]+\+'
            ],
            'native_bridge_vulnerabilities': [
                r'NativeModules\.[^.]+\.[^(]+\([^)]*\)',
                r'bridge\.call\([^)]*\)',
                r'ReactMethod\s*\(',
                r'@ReactMethod',
                r'WritableMap\s+.*put',
                r'ReadableMap\s+.*get',
                r'Promise\s*<[^>]*>\s*\w+\([^)]*\)'
            ],
            'insecure_storage': [
                r'AsyncStorage\.setItem\s*\(\s*["\'][^"\']*password',
                r'AsyncStorage\.setItem\s*\(\s*["\'][^"\']*token',
                r'AsyncStorage\.setItem\s*\(\s*["\'][^"\']*secret',
                r'AsyncStorage\.setItem\s*\(\s*["\'][^"\']*key',
                r'SecureStore\.setItemAsync\s*\(\s*["\'][^"\']*[^,]*,\s*[^,]+\s*\)',
                r'Keychain\.setInternetCredentials',
                r'@react-native-community/async-storage'
            ],
            'hardcoded_secrets': [
                r'["\'][A-Za-z0-9]{32,}["\']',
                r'api[_-]?key\s*[:=]\s*["\'][^"\']+["\']',
                r'secret[_-]?key\s*[:=]\s*["\'][^"\']+["\']',
                r'access[_-]?token\s*[:=]\s*["\'][^"\']+["\']',
                r'private[_-]?key\s*[:=]\s*["\'][^"\']+["\']'
            ],
            'network_security': [
                r'http://[^/\s]+',
                r'fetch\s*\(\s*["\']http://',
                r'XMLHttpRequest.*http://',
                r'allowsArbitraryLoads.*true',
                r'NSExceptionAllowsInsecureHTTPLoads.*YES'
            ],
            'third_party_vulnerabilities': [
                r'react-native-vector-icons',
                r'react-native-camera',
                r'react-native-image-picker',
                r'react-native-permissions',
                r'@react-native-community/.*'
            ]
        }
        
        # Known vulnerable libraries
        self.vulnerable_libraries = {
            'react-native-vector-icons': {
                'vulnerable_versions': ['<8.0.0'],
                'vulnerabilities': ['XSS via icon names'],
                'severity': 'medium'
            },
            'react-native-camera': {
                'vulnerable_versions': ['<4.0.0'],
                'vulnerabilities': ['Path traversal in image saving'],
                'severity': 'high'
            },
            'react-native-image-picker': {
                'vulnerable_versions': ['<3.0.0'],
                'vulnerabilities': ['Directory traversal'],
                'severity': 'high'
            }
        }
        
        self.logger.info("React Native analyzer initialized")
    
    def analyze(self, app_data: Dict, location: str = "react_native_app") -> List[CrossPlatformFinding]:
        """
        Analyze React Native application for security vulnerabilities.
        
        Args:
            app_data: Application data including content and metadata
            location: Location identifier for the analysis
            
        Returns:
            List of security findings
        """
        try:
            self.logger.info("Starting React Native security analysis")
            
            findings = []
            
            # Detect React Native framework
            detection_result = self._detect_react_native_advanced(app_data)
            if detection_result.confidence < 0.7:
                self.logger.warning("Low confidence React Native detection")
                return findings
            
            # Analyze JavaScript bundle security
            js_findings = self._analyze_js_bundle_advanced(app_data, location)
            findings.extend(js_findings)
            
            # Analyze React Native specific vulnerabilities
            rn_findings = self._analyze_react_native_vulnerabilities(app_data, location)
            findings.extend(rn_findings)
            
            # Advanced JavaScript Security Analysis 
            advanced_js_findings = self._analyze_advanced_javascript_security(app_data, location)
            findings.extend(advanced_js_findings)
            
            # Native Bridge Deep Analysis 
            bridge_deep_findings = self._analyze_native_bridge_deep_analysis(app_data, location)
            findings.extend(bridge_deep_findings)
            
            # Analyze third-party libraries
            lib_findings = self._analyze_third_party_libraries(app_data, location)
            findings.extend(lib_findings)
            
            # Analyze Metro bundler security
            metro_findings = self._analyze_metro_bundler_security(app_data, location)
            findings.extend(metro_findings)
            
            # Analyze React Navigation security
            nav_findings = self._analyze_react_navigation_security(app_data, location)
            findings.extend(nav_findings)
            
            # React Native Framework Version Compatibility Analysis 
            compatibility_findings = self._analyze_framework_compatibility(app_data, location)
            findings.extend(compatibility_findings)
            
            # Performance Security Analysis 
            performance_findings = self._analyze_performance_security(app_data, location)
            findings.extend(performance_findings)
            
            self.logger.info(f"React Native analysis completed: {len(findings)} findings")
            return findings
            
        except Exception as e:
            self.logger.error(f"React Native analysis failed: {e}")
            return []
    
    def _detect_react_native_advanced(self, app_data: Dict) -> FrameworkDetectionResult:
        """Advanced React Native framework detection with professional confidence calculation."""
        try:
            detection_methods = []
            app_content = self._extract_app_content(app_data)
            
            # Collect detection evidence
            evidence = []
            
            # Check for React Native indicators
            for pattern in self.detection_patterns['react_native_indicators']:
                if re.search(pattern, app_content, re.IGNORECASE):
                    detection_methods.append(f"RN pattern: {pattern}")
                    evidence.append(f"react_native_pattern:{pattern}")
            
            # Check for React Native libraries  
            for pattern in self.detection_patterns['react_native_libraries']:
                if re.search(pattern, app_content, re.IGNORECASE):
                    detection_methods.append(f"RN library: {pattern}")
                    evidence.append(f"react_native_library:{pattern}")
            
            # Check for Metro bundler artifacts
            for pattern in self.detection_patterns['metro_bundler']:
                if re.search(pattern, app_content, re.IGNORECASE):
                    detection_methods.append(f"Metro: {pattern}")
                    evidence.append(f"metro_bundler:{pattern}")
            
            # Check for version patterns
            version = None
            for pattern in self.detection_patterns['version_patterns']:
                match = re.search(pattern, app_content, re.IGNORECASE)
                if match:
                    version = match.group(1)
                    detection_methods.append(f"Version: {version}")
                    evidence.append(f"version_detected:{version}")
                    break
            
            # Calculate professional confidence using evidence-based approach
            confidence_evidence = ConfidenceEvidence(
                pattern_reliability=0.88,  # React Native patterns are highly reliable
                match_quality=len(evidence) / 10.0,  # Quality based on evidence count
                context_relevance=0.85,  # High relevance for cross-platform analysis
                validation_sources=[f"react_native_detection"],
                cross_validation=len(detection_methods)
            )
            
            confidence = self.confidence_calculator.calculate_confidence(
                'react_native_detection', confidence_evidence
            )
            
            return FrameworkDetectionResult(
                framework=Framework.REACT_NATIVE,
                confidence=confidence,
                version=version,
                detection_methods=detection_methods,
                metadata={'detected_indicators': len(evidence), 'evidence': evidence}
            )
            
        except Exception as e:
            self.logger.error(f"React Native detection failed: {e}")
            return FrameworkDetectionResult(
                framework=Framework.REACT_NATIVE,
                confidence=0.0,
                version=None,
                detection_methods=[],
                metadata={}
            )
    
    def _analyze_js_bundle_advanced(self, app_data: Dict, location: str) -> List[CrossPlatformFinding]:
        """Advanced JavaScript bundle security analysis."""
        findings = []
        
        try:
            app_content = self._extract_js_content_advanced(app_data)
            
            # Analyze JavaScript injection vulnerabilities
            js_injection_findings = self._analyze_javascript_injection(app_content, location)
            findings.extend(js_injection_findings)
            
            # Analyze hardcoded secrets
            secret_findings = self._analyze_hardcoded_secrets(app_content, location)
            findings.extend(secret_findings)
            
            # Analyze insecure random generation
            random_findings = self._analyze_random_generation(app_content, location)
            findings.extend(random_findings)
            
            # Analyze exposed methods
            method_findings = self._analyze_exposed_methods(app_content, location)
            findings.extend(method_findings)
            
            # Analyze data validation
            validation_findings = self._analyze_data_validation(app_content, location)
            findings.extend(validation_findings)
            
            # Analyze data validation
            validation_findings = self._analyze_data_validation(app_content, location)
            findings.extend(validation_findings)
            
        except Exception as e:
            self.logger.error(f"JavaScript bundle analysis failed: {e}")
        
        return findings
    
    def _analyze_javascript_injection(self, content: str, location: str) -> List[CrossPlatformFinding]:
        """Analyze JavaScript injection vulnerabilities."""
        findings = []
        
        for pattern in self.vulnerability_patterns['javascript_injection']:
            matches = list(re.finditer(pattern, content, re.IGNORECASE))
            
            for match in matches:
                context = self._get_code_context(content, match.start(), match.end())
                
                # Calculate professional confidence
                evidence = ConfidenceEvidence(
                    pattern_type="javascript_injection",
                    match_quality=self._assess_match_quality(match.group(), context),
                    context_relevance=0.9,  # JS injection is highly relevant in React Native
                    framework_specificity=0.85,
                    vulnerability_severity=Severity.HIGH.value,
                    detection_method=DetectionMethod.PATTERN_MATCHING.value,
                    code_context=context,
                    evidence_sources=["pattern_matching", "static_analysis"],
                    validation_methods=["context_analysis"]
                )
                
                confidence = self.confidence_calculator.calculate_confidence(evidence)
                severity = self._assess_js_injection_severity(match.group(), context)
                
                finding = CrossPlatformFinding(
                    framework=Framework.REACT_NATIVE.value,
                    vulnerability_type=VulnerabilityType.JAVASCRIPT_INJECTION.value,
                    component="JavaScript Bundle",
                    original_content=match.group(),
                    confidence=confidence,
                    location=location,
                    severity=severity,
                    description=f"Potential JavaScript injection vulnerability: {match.group()}",
                    remediation="Use proper input validation and sanitization. Avoid dynamic code execution.",
                    attack_vector="JavaScript injection through user input",
                    cwe_id="CWE-79",
                    detection_method=DetectionMethod.PATTERN_MATCHING.value,
                    evidence=[f"Pattern: {pattern}", f"Context: {context[:100]}"]
                )
                
                findings.append(finding)
        
        return findings
    
    def _analyze_native_bridge_deep(self, app_data: Dict, location: str) -> List[CrossPlatformFinding]:
        """Deep analysis of native bridge security."""
        findings = []
        
        try:
            app_content = self._extract_js_content_advanced(app_data)
            
            for pattern in self.vulnerability_patterns['native_bridge_vulnerabilities']:
                matches = list(re.finditer(pattern, app_content, re.IGNORECASE))
                
                for match in matches:
                    context = self._get_code_context(app_content, match.start(), match.end())
                    
                    # Calculate professional confidence for bridge vulnerability
                    evidence = ConfidenceEvidence(
                        pattern_type="native_bridge_vulnerability",
                        match_quality=self._assess_match_quality(match.group(), context),
                        context_relevance=0.8,
                        framework_specificity=0.9,  # Very specific to React Native
                        vulnerability_severity=Severity.HIGH.value,
                        detection_method=DetectionMethod.STATIC_ANALYSIS.value,
                        code_context=context,
                        evidence_sources=["bridge_analysis", "pattern_matching"],
                        validation_methods=["context_analysis", "bridge_validation"]
                    )
                    
                    confidence = self.confidence_calculator.calculate_confidence(evidence)
                    severity = self._assess_bridge_risk(match.group(), context)
                    
                    finding = CrossPlatformFinding(
                        framework=Framework.REACT_NATIVE.value,
                        vulnerability_type=VulnerabilityType.BRIDGE_VULNERABILITIES.value,
                        component="Native Bridge",
                        original_content=match.group(),
                        confidence=confidence,
                        location=location,
                        severity=severity,
                        description=f"Native bridge security issue: {match.group()}",
                        remediation="Validate all data passed through native bridge. Use proper access controls.",
                        attack_vector="Native bridge exploitation",
                        cwe_id="CWE-749",
                        detection_method=DetectionMethod.STATIC_ANALYSIS.value,
                        evidence=[f"Bridge pattern: {pattern}", f"Context: {context[:100]}"]
                    )
                    
                    findings.append(finding)
        
        except Exception as e:
            self.logger.error(f"Native bridge analysis failed: {e}")
        
        return findings
    
    def _analyze_react_native_vulnerabilities(self, app_data: Dict, location: str) -> List[CrossPlatformFinding]:
        """Analyze React Native specific vulnerabilities."""
        findings = []
        
        try:
            app_content = self._extract_js_content_advanced(app_data)
            
            # Analyze each vulnerability category
            for vuln_type, patterns in self.vulnerability_patterns.items():
                if vuln_type in ['javascript_injection', 'native_bridge_vulnerabilities']:
                    continue  # Already analyzed separately
                
                for pattern in patterns:
                    matches = list(re.finditer(pattern, app_content, re.IGNORECASE))
                    
                    for match in matches:
                        context = self._get_code_context(app_content, match.start(), match.end())
                        
                        # Calculate professional confidence
                        evidence = ConfidenceEvidence(
                            pattern_type=vuln_type,
                            match_quality=self._assess_match_quality(match.group(), context),
                            context_relevance=0.7,
                            framework_specificity=0.8,
                            vulnerability_severity=self._map_vulnerability_severity(vuln_type),
                            detection_method=DetectionMethod.PATTERN_MATCHING.value,
                            code_context=context,
                            evidence_sources=["pattern_matching"],
                            validation_methods=["context_analysis"]
                        )
                        
                        confidence = self.confidence_calculator.calculate_confidence(evidence)
                        severity = self._assess_rn_specific_severity(match.group(), context)
                        
                        finding = CrossPlatformFinding(
                            framework=Framework.REACT_NATIVE.value,
                            vulnerability_type=vuln_type,
                            component="React Native Application",
                            original_content=match.group(),
                            confidence=confidence,
                            location=location,
                            severity=severity,
                            description=f"React Native security issue ({vuln_type}): {match.group()}",
                            remediation=self._get_remediation_for_vulnerability(vuln_type),
                            attack_vector=self._get_attack_vector_for_vulnerability(vuln_type),
                            cwe_id=self._get_cwe_for_vulnerability(vuln_type),
                            detection_method=DetectionMethod.PATTERN_MATCHING.value,
                            evidence=[f"Pattern: {pattern}", f"Context: {context[:100]}"]
                        )
                        
                        findings.append(finding)
        
        except Exception as e:
            self.logger.error(f"React Native vulnerability analysis failed: {e}")
        
        return findings
    
    def _analyze_third_party_libraries(self, app_data: Dict, location: str) -> List[CrossPlatformFinding]:
        """Analyze third-party library vulnerabilities."""
        findings = []
        
        try:
            app_content = self._extract_js_content_advanced(app_data)
            
            # Analyze library versions
            version_findings = self._analyze_library_versions(app_content, location)
            findings.extend(version_findings)
            
            # Analyze dependency confusion
            confusion_findings = self._analyze_dependency_confusion(app_content, location)
            findings.extend(confusion_findings)
            
        except Exception as e:
            self.logger.error(f"Third-party library analysis failed: {e}")
        
        return findings
    
    def _analyze_library_versions(self, app_content: str, location: str) -> List[CrossPlatformFinding]:
        """Analyze library versions for known vulnerabilities."""
        findings = []
        
        for lib_name, lib_info in self.vulnerable_libraries.items():
            # Look for library usage
            lib_pattern = rf'{re.escape(lib_name)}'
            matches = list(re.finditer(lib_pattern, app_content, re.IGNORECASE))
            
            for match in matches:
                context = self._get_code_context(app_content, match.start(), match.end())
                
                # Calculate professional confidence for library vulnerability
                evidence = ConfidenceEvidence(
                    pattern_type="third_party_vulnerability",
                    match_quality=0.9,  # High match quality for known libraries
                    context_relevance=0.8,
                    framework_specificity=0.7,
                    vulnerability_severity=lib_info['severity'],
                    detection_method=DetectionMethod.DEPENDENCY_ANALYSIS.value,
                    code_context=context,
                    evidence_sources=["vulnerability_database", "dependency_analysis"],
                    validation_methods=["version_checking", "cve_mapping"]
                )
                
                confidence = self.confidence_calculator.calculate_confidence(evidence)
                
                finding = CrossPlatformFinding(
                    framework=Framework.REACT_NATIVE.value,
                    vulnerability_type=VulnerabilityType.THIRD_PARTY_VULNERABILITIES.value,
                    component=f"Third-party library: {lib_name}",
                    original_content=match.group(),
                    confidence=confidence,
                    location=location,
                    severity=lib_info['severity'],
                    description=f"Potentially vulnerable library: {lib_name}. Known vulnerabilities: {', '.join(lib_info['vulnerabilities'])}",
                    remediation=f"Update {lib_name} to a secure version. Check for latest security patches.",
                    attack_vector="Third-party library exploitation",
                    cwe_id="CWE-1035",
                    detection_method=DetectionMethod.DEPENDENCY_ANALYSIS.value,
                    evidence=[f"Library: {lib_name}", f"Vulnerabilities: {lib_info['vulnerabilities']}"]
                )
                
                findings.append(finding)
        
        return findings
    
    def _analyze_dependency_confusion(self, app_content: str, location: str) -> List[CrossPlatformFinding]:
        """Analyze dependency confusion vulnerabilities."""
        findings = []
        
        # Look for suspicious package patterns
        suspicious_patterns = [
            r'@[a-zA-Z0-9-]+/[a-zA-Z0-9-]+',  # Scoped packages
            r'file:\.\./',  # Local file dependencies
            r'git\+https?://',  # Git dependencies
        ]
        
        for pattern in suspicious_patterns:
            matches = list(re.finditer(pattern, app_content, re.IGNORECASE))
            
            for match in matches:
                context = self._get_code_context(app_content, match.start(), match.end())
                
                # Calculate professional confidence for dependency confusion
                evidence = ConfidenceEvidence(
                    pattern_type="dependency_confusion",
                    match_quality=0.6,  # Medium match quality - needs validation
                    context_relevance=0.7,
                    framework_specificity=0.6,
                    vulnerability_severity=Severity.MEDIUM.value,
                    detection_method=DetectionMethod.DEPENDENCY_ANALYSIS.value,
                    code_context=context,
                    evidence_sources=["dependency_analysis", "pattern_matching"],
                    validation_methods=["package_validation"]
                )
                
                confidence = self.confidence_calculator.calculate_confidence(evidence)
                
                finding = CrossPlatformFinding(
                    framework=Framework.REACT_NATIVE.value,
                    vulnerability_type=VulnerabilityType.THIRD_PARTY_VULNERABILITIES.value,
                    component="Dependency Management",
                    original_content=match.group(),
                    confidence=confidence,
                    location=location,
                    severity=Severity.MEDIUM.value,
                    description=f"Potential dependency confusion risk: {match.group()}",
                    remediation="Verify package sources and use package-lock files to prevent dependency confusion.",
                    attack_vector="Dependency confusion attack",
                    cwe_id="CWE-1021",
                    detection_method=DetectionMethod.DEPENDENCY_ANALYSIS.value,
                    evidence=[f"Suspicious dependency: {match.group()}", f"Context: {context[:100]}"]
                )
                
                findings.append(finding)
        
        return findings
    
    # Helper methods for analysis
    def _extract_js_content_advanced(self, app_data: Dict) -> str:
        """Extract JavaScript content from app data."""
        try:
            content = ""
            
            # Extract from various sources
            if 'content' in app_data:
                content += str(app_data['content'])
            
            if 'files' in app_data:
                for file_path, file_content in app_data['files'].items():
                    if any(ext in file_path.lower() for ext in ['.js', '.jsx', '.ts', '.tsx', '.json']):
                        content += f"\n{file_content}"
            
            if 'bundle_content' in app_data:
                content += f"\n{app_data['bundle_content']}"
            
            return content
            
        except Exception as e:
            self.logger.error(f"JavaScript content extraction failed: {e}")
            return ""
    
    def _get_code_context(self, content: str, start: int, end: int, lines: int = 3) -> str:
        """Get code context around a match."""
        try:
            context_start = max(0, start - lines * 10)
            context_end = min(len(content), end + lines * 10)
            return content[context_start:context_end]
        except Exception:
            return content[start:end]  # Fallback to just the match
    
    def _assess_match_quality(self, match: str, context: str) -> float:
        """Assess the quality of a pattern match."""
        try:
            # Basic quality assessment
            quality = 0.5
            
            # Longer matches are generally better
            if len(match) > 20:
                quality += 0.2
            elif len(match) > 10:
                quality += 0.1
            
            # Context relevance
            if any(keyword in context.lower() for keyword in ['security', 'validate', 'sanitize']):
                quality += 0.1
            
            # Avoid false positives in comments
            if '//' in context or '/*' in context:
                quality -= 0.2
            
            return max(0.1, min(1.0, quality))
            
        except Exception:
            return 0.5
    
    def _map_vulnerability_severity(self, vuln_type: str) -> str:
        """Map vulnerability type to severity."""
        severity_mapping = {
            'javascript_injection': Severity.HIGH.value,
            'native_bridge_vulnerabilities': Severity.HIGH.value,
            'insecure_storage': Severity.MEDIUM.value,
            'hardcoded_secrets': Severity.HIGH.value,
            'network_security': Severity.MEDIUM.value,
            'third_party_vulnerabilities': Severity.MEDIUM.value
        }
        return severity_mapping.get(vuln_type, Severity.MEDIUM.value)
    
    def _assess_js_injection_severity(self, match: str, context: str) -> str:
        """Assess JavaScript injection severity."""
        if 'eval(' in match or 'Function(' in match:
            return Severity.CRITICAL.value
        elif 'innerHTML' in match and '+' in context:
            return Severity.HIGH.value
        else:
            return Severity.MEDIUM.value
    
    def _assess_bridge_risk(self, match: str, context: str) -> str:
        """Assess native bridge risk level."""
        high_risk_indicators = ['WritableMap', 'Promise', '@ReactMethod']
        if any(indicator in match for indicator in high_risk_indicators):
            return Severity.HIGH.value
        else:
            return Severity.MEDIUM.value
    
    def _assess_rn_specific_severity(self, match: str, context: str) -> str:
        """Assess React Native specific vulnerability severity."""
        if 'AsyncStorage' in match and any(keyword in match.lower() for keyword in ['password', 'token', 'secret']):
            return Severity.HIGH.value
        elif 'http://' in match:
            return Severity.MEDIUM.value
        else:
            return Severity.MEDIUM.value
    
    def _get_remediation_for_vulnerability(self, vuln_type: str) -> str:
        """Get remediation guidance for vulnerability type."""
        remediation_mapping = {
            'insecure_storage': "Use secure storage mechanisms like react-native-keychain for sensitive data.",
            'hardcoded_secrets': "Move secrets to secure configuration or environment variables.",
            'network_security': "Use HTTPS for all network communications and implement certificate pinning.",
            'third_party_vulnerabilities': "Update all third-party libraries to latest secure versions."
        }
        return remediation_mapping.get(vuln_type, "Follow React Native security best practices.")
    
    def _get_attack_vector_for_vulnerability(self, vuln_type: str) -> str:
        """Get attack vector for vulnerability type."""
        attack_vector_mapping = {
            'insecure_storage': "Local data access",
            'hardcoded_secrets': "Source code analysis",
            'network_security': "Man-in-the-middle attack",
            'third_party_vulnerabilities': "Library exploitation"
        }
        return attack_vector_mapping.get(vuln_type, "Various attack vectors")
    
    def _get_cwe_for_vulnerability(self, vuln_type: str) -> str:
        """Get CWE ID for vulnerability type."""
        cwe_mapping = {
            'insecure_storage': "CWE-922",
            'hardcoded_secrets': "CWE-798",
            'network_security': "CWE-319",
            'third_party_vulnerabilities': "CWE-1035"
        }
        return cwe_mapping.get(vuln_type, "CWE-693")
    
    def _assess_performance_severity(self, match: str, context: str) -> str:
        """Assess performance issue severity."""
        if 'eval(' in match or 'while(true)' in match or 'for(' in match and 'true;' in match:
            return Severity.HIGH.value
        elif 'setInterval' in match and any(freq in context for freq in ['0', '1', '2']):
            return Severity.MEDIUM.value
        else:
            return Severity.LOW.value
    
    def _assess_secret_quality(self, secret_value: str) -> float:
        """Assess the quality of a detected secret."""
        quality = 0.5
        
        # Length assessment
        if len(secret_value) > 40:
            quality += 0.3
        elif len(secret_value) > 20:
            quality += 0.2
        elif len(secret_value) > 10:
            quality += 0.1
        
        # Character diversity
        if any(c.isupper() for c in secret_value):
            quality += 0.1
        if any(c.islower() for c in secret_value):
            quality += 0.1
        if any(c.isdigit() for c in secret_value):
            quality += 0.1
        if any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in secret_value):
            quality += 0.1
        
        return min(1.0, quality)
    
    # Additional analysis methods - Metro bundler, AsyncStorage, etc.
    def _analyze_metro_bundler_security(self, app_data: Dict, location: str) -> List[CrossPlatformFinding]:
        """Analyze Metro bundler security configuration."""
        findings = []
        
        try:
            app_content = self._extract_js_content_advanced(app_data)
            
            # Check for development mode indicators in production
            dev_patterns = [
                r'__DEV__\s*(?:===|==)\s*true',
                r'process\.env\.NODE_ENV\s*(?:===|==)\s*["\']development["\']',
                r'console\.(?:log|warn|error|debug)',
                r'debugger\s*;',
                r'React\.StrictMode'
            ]
            
            for pattern in dev_patterns:
                matches = re.finditer(pattern, app_content, re.IGNORECASE)
                for match in matches:
                    context = self._get_code_context(app_content, match.start(), match.end())
                    
                    evidence = ConfidenceEvidence(
                        pattern_reliability=0.85,
                        match_quality=self._assess_match_quality(match.group(), context),
                        context_relevance=0.9,
                        validation_sources=['metro_config', 'bundle_analysis'],
                        cross_validation=1
                    )
                    
                    confidence = self.confidence_calculator.calculate_confidence(
                        'metro_bundler_security', evidence
                    )
                    
                    findings.append(CrossPlatformFinding(
                        title="Development Code in Production Bundle",
                        description=f"Development-only code detected: {match.group()}",
                        severity=Severity.MEDIUM.value,
                        vulnerability_type=VulnerabilityType.INFORMATION_DISCLOSURE.value,
                        affected_component=f"{location}/metro_bundle",
                        code_snippet=context,
                        recommendation="Remove development code and debug statements from production builds",
                        attack_vector="Information disclosure through debug information",
                        cwe_id="CWE-489",
                        confidence=confidence,
                        evidence=evidence.__dict__
                    ))
            
            # Check for source map exposure
            sourcemap_patterns = [
                r'//# sourceMappingURL=',
                r'sourceMap\s*:\s*true',
                r'\.map\s*["\']'
            ]
            
            for pattern in sourcemap_patterns:
                matches = re.finditer(pattern, app_content, re.IGNORECASE)
                for match in matches:
                    context = self._get_code_context(app_content, match.start(), match.end())
                    
                    evidence = ConfidenceEvidence(
                        pattern_reliability=0.90,
                        match_quality=self._assess_match_quality(match.group(), context),
                        context_relevance=0.95,
                        validation_sources=['bundle_analysis', 'source_mapping'],
                        cross_validation=1
                    )
                    
                    confidence = self.confidence_calculator.calculate_confidence(
                        'source_map_exposure', evidence
                    )
                    
                    findings.append(CrossPlatformFinding(
                        title="Source Map Exposure",
                        description=f"Source maps may be exposed in production: {match.group()}",
                        severity=Severity.LOW.value,
                        vulnerability_type=VulnerabilityType.INFORMATION_DISCLOSURE.value,
                        affected_component=f"{location}/source_maps",
                        code_snippet=context,
                        recommendation="Disable source map generation for production builds",
                        attack_vector="Source code exposure through source maps",
                        cwe_id="CWE-200",
                        confidence=confidence,
                        evidence=evidence.__dict__
                    ))
            
        except Exception as e:
            self.logger.error(f"Metro bundler security analysis failed: {e}")
        
        return findings
    
    def _analyze_react_navigation_security(self, app_data: Dict, location: str) -> List[CrossPlatformFinding]:
        """Analyze React Navigation security issues."""
        findings = []
        
        try:
            app_content = self._extract_js_content_advanced(app_data)
            
            # Check for deep link vulnerabilities
            deep_link_patterns = [
                r'Linking\.openURL\s*\(\s*[^)]*\)',
                r'Linking\.getInitialURL\s*\(',
                r'NavigationActions\.navigate\s*\(\s*\{\s*routeName\s*:\s*[^}]*\}',
                r'navigation\.navigate\s*\(\s*["\'][^"\']*["\']',
                r'createStackNavigator\s*\(\s*\{[^}]*\}'
            ]
            
            for pattern in deep_link_patterns:
                matches = re.finditer(pattern, app_content, re.IGNORECASE)
                for match in matches:
                    context = self._get_code_context(app_content, match.start(), match.end())
                    
                    # Check if proper validation is present
                    validation_present = any(val_pattern in context for val_pattern in [
                        'validate', 'sanitize', 'check', 'verify', 'filter'
                    ])
                    
                    evidence = ConfidenceEvidence(
                        pattern_reliability=0.80,
                        match_quality=self._assess_match_quality(match.group(), context),
                        context_relevance=0.85 if not validation_present else 0.60,
                        validation_sources=['navigation_analysis', 'deep_link_check'],
                        cross_validation=1
                    )
                    
                    confidence = self.confidence_calculator.calculate_confidence(
                        'navigation_security', evidence
                    )
                    
                    severity = Severity.HIGH.value if not validation_present else Severity.MEDIUM.value
                    
                    findings.append(CrossPlatformFinding(
                        title="Potentially Unsafe Navigation",
                        description=f"Navigation without proper validation: {match.group()}",
                        severity=severity,
                        vulnerability_type=VulnerabilityType.IMPROPER_INPUT_VALIDATION.value,
                        affected_component=f"{location}/navigation",
                        code_snippet=context,
                        recommendation="Validate all navigation parameters and deep link URLs",
                        attack_vector="Deep link manipulation for unauthorized navigation",
                        cwe_id="CWE-20",
                        confidence=confidence,
                        evidence=evidence.__dict__
                    ))
            
            # Check for screen injection vulnerabilities
            screen_injection_patterns = [
                r'screenProps\s*=\s*\{[^}]*\}',
                r'navigation\.setParams\s*\(\s*\{[^}]*\}',
                r'this\.props\.navigation\.state\.params'
            ]
            
            for pattern in screen_injection_patterns:
                matches = re.finditer(pattern, app_content, re.IGNORECASE)
                for match in matches:
                    context = self._get_code_context(app_content, match.start(), match.end())
                    
                    evidence = ConfidenceEvidence(
                        pattern_reliability=0.75,
                        match_quality=self._assess_match_quality(match.group(), context),
                        context_relevance=0.80,
                        validation_sources=['screen_analysis', 'params_check'],
                        cross_validation=1
                    )
                    
                    confidence = self.confidence_calculator.calculate_confidence(
                        'screen_injection', evidence
                    )
                    
                    findings.append(CrossPlatformFinding(
                        title="Screen Parameter Injection Risk",
                        description=f"Potentially unsafe screen parameters: {match.group()}",
                        severity=Severity.MEDIUM.value,
                        vulnerability_type=VulnerabilityType.INJECTION.value,
                        affected_component=f"{location}/screen_params",
                        code_snippet=context,
                        recommendation="Sanitize and validate all screen parameters",
                        attack_vector="Parameter injection through navigation",
                        cwe_id="CWE-74",
                        confidence=confidence,
                        evidence=evidence.__dict__
                    ))
            
        except Exception as e:
            self.logger.error(f"React Navigation security analysis failed: {e}")
        
        return findings
    
    def _analyze_async_storage_security(self, app_data: Dict, location: str) -> List[CrossPlatformFinding]:
        """Analyze AsyncStorage security implementation."""
        findings = []
        
        try:
            app_content = self._extract_js_content_advanced(app_data)
            
            # Check for sensitive data in AsyncStorage
            sensitive_storage_patterns = [
                r'AsyncStorage\.setItem\s*\(\s*["\'][^"\']*(?:password|pwd|pass)[^"\']*["\']',
                r'AsyncStorage\.setItem\s*\(\s*["\'][^"\']*(?:token|jwt|auth)[^"\']*["\']',
                r'AsyncStorage\.setItem\s*\(\s*["\'][^"\']*(?:secret|key|credential)[^"\']*["\']',
                r'AsyncStorage\.setItem\s*\(\s*["\'][^"\']*(?:session|cookie)[^"\']*["\']',
                r'AsyncStorage\.multiSet\s*\(\s*\[.*(?:password|token|secret).*\]'
            ]
            
            for pattern in sensitive_storage_patterns:
                matches = re.finditer(pattern, app_content, re.IGNORECASE)
                for match in matches:
                    context = self._get_code_context(app_content, match.start(), match.end())
                    
                    # Check if encryption is applied
                    encryption_present = any(enc_pattern in context for enc_pattern in [
                        'encrypt', 'cipher', 'crypto', 'hash', 'secure'
                    ])
                    
                    evidence = ConfidenceEvidence(
                        pattern_reliability=0.90,
                        match_quality=self._assess_match_quality(match.group(), context),
                        context_relevance=0.95 if not encryption_present else 0.70,
                        validation_sources=['storage_analysis', 'encryption_check'],
                        cross_validation=1
                    )
                    
                    confidence = self.confidence_calculator.calculate_confidence(
                        'async_storage_security', evidence
                    )
                    
                    severity = Severity.HIGH.value if not encryption_present else Severity.MEDIUM.value
                    
                    findings.append(CrossPlatformFinding(
                        title="Sensitive Data in AsyncStorage",
                        description=f"Sensitive data stored in AsyncStorage: {match.group()}",
                        severity=severity,
                        vulnerability_type=VulnerabilityType.INSECURE_STORAGE.value,
                        affected_component=f"{location}/async_storage",
                        code_snippet=context,
                        recommendation="Use react-native-keychain or encrypt data before AsyncStorage",
                        attack_vector="Local storage access by malicious apps",
                        cwe_id="CWE-922",
                        confidence=confidence,
                        evidence=evidence.__dict__
                    ))
            
            # Check for AsyncStorage without error handling
            unsafe_storage_patterns = [
                r'AsyncStorage\.(?:setItem|getItem|removeItem)\s*\([^)]*\)\s*(?![.;].*catch)',
                r'AsyncStorage\.(?:multiSet|multiGet|multiRemove)\s*\([^)]*\)\s*(?![.;].*catch)'
            ]
            
            for pattern in unsafe_storage_patterns:
                matches = re.finditer(pattern, app_content, re.IGNORECASE)
                for match in matches:
                    context = self._get_code_context(app_content, match.start(), match.end())
                    
                    evidence = ConfidenceEvidence(
                        pattern_reliability=0.70,
                        match_quality=self._assess_match_quality(match.group(), context),
                        context_relevance=0.75,
                        validation_sources=['error_handling_analysis'],
                        cross_validation=1
                    )
                    
                    confidence = self.confidence_calculator.calculate_confidence(
                        'storage_error_handling', evidence
                    )
                    
                    findings.append(CrossPlatformFinding(
                        title="AsyncStorage Without Error Handling",
                        description=f"AsyncStorage operation without error handling: {match.group()}",
                        severity=Severity.LOW.value,
                        vulnerability_type=VulnerabilityType.IMPROPER_ERROR_HANDLING.value,
                        affected_component=f"{location}/async_storage_error",
                        code_snippet=context,
                        recommendation="Add proper error handling for all AsyncStorage operations",
                        attack_vector="Application crashes or data inconsistency",
                        cwe_id="CWE-754",
                        confidence=confidence,
                        evidence=evidence.__dict__
                    ))
            
        except Exception as e:
            self.logger.error(f"AsyncStorage security analysis failed: {e}")
        
        return findings
    
    def _analyze_performance_security(self, app_data: Dict, location: str) -> List[CrossPlatformFinding]:
        """Analyze performance-related security issues in React Native apps."""
        findings = []
        
        try:
            app_content = self._extract_js_content_advanced(app_data)
            
            # Performance security patterns
            performance_patterns = [
                r'while\s*\(\s*true\s*\)',
                r'for\s*\(\s*;;\s*\)',
                r'setInterval\s*\([^)]*,\s*[01]\s*\)',  # Very short intervals
                r'setTimeout\s*\([^)]*,\s*0\s*\)',      # Zero timeout
                r'JSON\.stringify\s*\([^)]*\)\.\s*length\s*>\s*[0-9]{6,}',  # Large JSON
                r'Array\s*\(\s*[0-9]{6,}\s*\)',        # Large arrays
                r'new\s+Array\s*\(\s*[0-9]{6,}\s*\)',
                r'Math\.random\s*\(\s*\)\s*<\s*0\.0001',  # Inefficient random
                r'\.map\s*\([^)]*\)\.map\s*\([^)]*\)\.map',  # Chained maps
                r'while\s*\([^)]*Math\.random\s*\(\s*\)'   # Random loops
            ]
            
            for pattern in performance_patterns:
                matches = re.finditer(pattern, app_content, re.IGNORECASE)
                for match in matches:
                    context = self._get_code_context(app_content, match.start(), match.end())
                    
                    evidence = ConfidenceEvidence(
                        pattern_reliability=0.78,
                        match_quality=self._assess_performance_security_quality(match.group(), context),
                        context_relevance=0.75,
                        validation_sources=['performance_security_analysis'],
                        cross_validation=1
                    )
                    
                    confidence = self.confidence_calculator.calculate_confidence(
                        'performance_security', evidence
                    )
                    
                    severity = self._assess_performance_severity(match.group(), context)
                    
                    findings.append(CrossPlatformFinding(
                        title="Performance Security Issue",
                        description=f"Performance-related security issue: {match.group()}",
                        severity=severity,
                        vulnerability_type=VulnerabilityType.DENIAL_OF_SERVICE.value,
                        affected_component=f"{location}/performance",
                        code_snippet=context,
                        recommendation="Optimize performance-critical code to prevent DoS conditions",
                        attack_vector="Performance-based denial of service",
                        cwe_id="CWE-400",
                        confidence=confidence,
                        evidence=evidence.__dict__
                    ))
            
            # Memory leak patterns
            memory_leak_patterns = [
                r'setInterval\s*\([^)]*\)(?![^;]*clearInterval)',
                r'setTimeout\s*\([^)]*\)(?![^;]*clearTimeout)',
                r'addEventListener\s*\([^)]*\)(?![^;]*removeEventListener)',
                r'new\s+Worker\s*\([^)]*\)(?![^;]*terminate)',
                r'WebSocket\s*\([^)]*\)(?![^;]*close)',
                r'XMLHttpRequest\s*\(\s*\)(?![^;]*abort)'
            ]
            
            for pattern in memory_leak_patterns:
                matches = re.finditer(pattern, app_content, re.IGNORECASE)
                for match in matches:
                    context = self._get_code_context(app_content, match.start(), match.end())
                    
                    evidence = ConfidenceEvidence(
                        pattern_reliability=0.75,
                        match_quality=0.7,
                        context_relevance=0.7,
                        validation_sources=['memory_leak_analysis'],
                        cross_validation=1
                    )
                    
                    confidence = self.confidence_calculator.calculate_confidence(
                        'memory_leak', evidence
                    )
                    
                    findings.append(CrossPlatformFinding(
                        title="Potential Memory Leak",
                        description=f"Potential memory leak pattern: {match.group()}",
                        severity=Severity.MEDIUM.value,
                        vulnerability_type=VulnerabilityType.RESOURCE_MANAGEMENT.value,
                        affected_component=f"{location}/memory_leak",
                        code_snippet=context,
                        recommendation="Ensure proper cleanup of resources to prevent memory leaks",
                        attack_vector="Memory exhaustion through resource leaks",
                        cwe_id="CWE-401",
                        confidence=confidence,
                        evidence=evidence.__dict__
                    ))
                    
        except Exception as e:
            self.logger.error(f"Performance security analysis failed: {e}")
        
        return findings
    
    def _assess_performance_security_quality(self, match: str, context: str) -> float:
        """Assess the quality of performance security pattern matches."""
        quality = 0.5
        
        # Check for dangerous patterns
        if 'while(true)' in match or 'for(;;)' in match:
            quality += 0.3
        
        # Check for very short intervals
        if any(interval in match for interval in ['0', '1', '2']):
            quality += 0.2
            
        # Check for large allocations
        if any(size in match for size in ['100000', '1000000']):
            quality += 0.2
            
        return min(quality, 1.0)
    
    def _analyze_hardcoded_secrets(self, content: str, location: str) -> List[CrossPlatformFinding]:
        """Analyze hardcoded secrets in JavaScript code."""
        findings = []
        
        try:
            # Enhanced secret detection patterns
            secret_patterns = [
                (r'(?:api[_-]?key|apikey)\s*[:=]\s*["\']([A-Za-z0-9+/]{16,})["\']', 'API Key'),
                (r'(?:secret[_-]?key|secretkey)\s*[:=]\s*["\']([A-Za-z0-9+/]{16,})["\']', 'Secret Key'),
                (r'(?:access[_-]?token|accesstoken)\s*[:=]\s*["\']([A-Za-z0-9+/]{16,})["\']', 'Access Token'),
                (r'(?:private[_-]?key|privatekey)\s*[:=]\s*["\']([A-Za-z0-9+/=]{20,})["\']', 'Private Key'),
                (r'(?:password|pwd)\s*[:=]\s*["\']([^"\']{8,})["\']', 'Password'),
                (r'(?:jwt[_-]?token|jwttoken)\s*[:=]\s*["\']([A-Za-z0-9+/=._-]{20,})["\']', 'JWT Token'),
                (r'(?:bearer[_-]?token|bearertoken)\s*[:=]\s*["\']([A-Za-z0-9+/=]{16,})["\']', 'Bearer Token'),
                (r'["\']([A-Za-z0-9+/]{40,})["\']', 'Long Base64 String')
            ]
            
            for pattern, secret_type in secret_patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    context = self._get_code_context(content, match.start(), match.end())
                    secret_value = match.group(1) if match.groups() else match.group()
                    
                    # Skip if it looks like a test value
                    if any(test_indicator in secret_value.lower() for test_indicator in [
                        'test', 'demo', 'example', 'placeholder', 'dummy', 'fake'
                    ]):
                        continue
                    
                    evidence = ConfidenceEvidence(
                        pattern_reliability=0.85,
                        match_quality=self._assess_secret_quality(secret_value),
                        context_relevance=0.90,
                        validation_sources=['secret_analysis', 'pattern_matching'],
                        cross_validation=1
                    )
                    
                    confidence = self.confidence_calculator.calculate_confidence(
                        'hardcoded_secrets', evidence
                    )
                    
                    findings.append(CrossPlatformFinding(
                        title=f"Hardcoded {secret_type}",
                        description=f"Hardcoded {secret_type.lower()} found in source code",
                        severity=Severity.HIGH.value,
                        vulnerability_type=VulnerabilityType.HARDCODED_CREDENTIALS.value,
                        affected_component=f"{location}/secrets",
                        code_snippet=context,
                        recommendation="Move secrets to environment variables or secure configuration",
                        attack_vector="Source code analysis reveals credentials",
                        cwe_id="CWE-798",
                        confidence=confidence,
                        evidence=evidence.__dict__
                    ))
            
        except Exception as e:
            self.logger.error(f"Hardcoded secrets analysis failed: {e}")
        
        return findings
    
    def _analyze_random_generation(self, content: str, location: str) -> List[CrossPlatformFinding]:
        """Analyze random number generation security."""
        findings = []
        
        try:
            # Check for weak random generation
            weak_random_patterns = [
                r'Math\.random\s*\(\s*\)',
                r'new\s+Date\(\)\s*\.getTime\(\)',
                r'Date\.now\(\)',
                r'Math\.floor\s*\(\s*Math\.random\s*\(\s*\)\s*\*'
            ]
            
            for pattern in weak_random_patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    context = self._get_code_context(content, match.start(), match.end())
                    
                    # Check if it's used for security purposes
                    security_context = any(sec_keyword in context.lower() for sec_keyword in [
                        'token', 'session', 'id', 'key', 'password', 'salt', 'nonce', 'uuid'
                    ])
                    
                    if security_context:
                        evidence = ConfidenceEvidence(
                            pattern_reliability=0.90,
                            match_quality=self._assess_match_quality(match.group(), context),
                            context_relevance=0.95,
                            validation_sources=['random_analysis', 'security_context'],
                            cross_validation=1
                        )
                        
                        confidence = self.confidence_calculator.calculate_confidence(
                            'weak_random', evidence
                        )
                        
                        findings.append(CrossPlatformFinding(
                            title="Weak Random Number Generation",
                            description=f"Cryptographically weak random generation: {match.group()}",
                            severity=Severity.HIGH.value,
                            vulnerability_type=VulnerabilityType.WEAK_CRYPTOGRAPHY.value,
                            affected_component=f"{location}/random",
                            code_snippet=context,
                            recommendation="Use crypto.getRandomValues() or react-native-crypto",
                            attack_vector="Predictable values in security contexts",
                            cwe_id="CWE-338",
                            confidence=confidence,
                            evidence=evidence.__dict__
                        ))
            
        except Exception as e:
            self.logger.error(f"Random generation analysis failed: {e}")
        
        return findings
    
    def _analyze_exposed_methods(self, content: str, location: str) -> List[CrossPlatformFinding]:
        """Analyze exposed methods that could be security risks."""
        findings = []
        
        try:
            # Check for exposed methods
            exposed_method_patterns = [
                r'(?:global|window)\s*\.\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*function',
                r'(?:global|window)\s*\[\s*["\']([^"\']+)["\']\s*\]\s*=\s*function',
                r'@ReactMethod\s*(?:public\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*\(',
                r'bridge\.registerCallableModule\s*\(\s*["\']([^"\']+)["\']'
            ]
            
            for pattern in exposed_method_patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    context = self._get_code_context(content, match.start(), match.end())
                    method_name = match.group(1) if match.groups() else match.group()
                    
                    # Check if method has security implications
                    security_sensitive = any(sec_keyword in method_name.lower() for sec_keyword in [
                        'exec', 'eval', 'system', 'shell', 'command', 'file', 'read', 'write', 'delete'
                    ])
                    
                    evidence = ConfidenceEvidence(
                        pattern_reliability=0.80,
                        match_quality=self._assess_match_quality(match.group(), context),
                        context_relevance=0.90 if security_sensitive else 0.60,
                        validation_sources=['method_analysis', 'exposure_check'],
                        cross_validation=1
                    )
                    
                    confidence = self.confidence_calculator.calculate_confidence(
                        'exposed_methods', evidence
                    )
                    
                    severity = Severity.HIGH.value if security_sensitive else Severity.MEDIUM.value
                    
                    findings.append(CrossPlatformFinding(
                        title="Exposed Method",
                        description=f"Method exposed to JavaScript context: {method_name}",
                        severity=severity,
                        vulnerability_type=VulnerabilityType.PRIVILEGE_ESCALATION.value,
                        affected_component=f"{location}/exposed_methods",
                        code_snippet=context,
                        recommendation="Minimize exposed methods and validate all inputs",
                        attack_vector="JavaScript injection to call exposed methods",
                        cwe_id="CWE-749",
                        confidence=confidence,
                        evidence=evidence.__dict__
                    ))
            
        except Exception as e:
            self.logger.error(f"Exposed methods analysis failed: {e}")
        
        return findings
    
    def _analyze_data_validation(self, content: str, location: str) -> List[CrossPlatformFinding]:
        """Analyze data validation implementations."""
        findings = []
        
        try:
            # Check for missing input validation
            validation_patterns = [
                r'JSON\.parse\s*\(\s*[^)]*\)\s*(?![.;].*catch)',
                r'parseInt\s*\(\s*[^)]*\)\s*(?!.*isNaN)',
                r'parseFloat\s*\(\s*[^)]*\)\s*(?!.*isNaN)',
                r'decodeURIComponent\s*\(\s*[^)]*\)\s*(?![.;].*catch)',
                r'atob\s*\(\s*[^)]*\)\s*(?![.;].*catch)',
                r'btoa\s*\(\s*[^)]*\)\s*(?![.;].*catch)'
            ]
            
            for pattern in validation_patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    context = self._get_code_context(content, match.start(), match.end())
                    
                    evidence = ConfidenceEvidence(
                        pattern_reliability=0.75,
                        match_quality=self._assess_match_quality(match.group(), context),
                        context_relevance=0.80,
                        validation_sources=['validation_analysis'],
                        cross_validation=1
                    )
                    
                    confidence = self.confidence_calculator.calculate_confidence(
                        'missing_validation', evidence
                    )
                    
                    findings.append(CrossPlatformFinding(
                        title="Missing Input Validation",
                        description=f"Operation without proper validation: {match.group()}",
                        severity=Severity.MEDIUM.value,
                        vulnerability_type=VulnerabilityType.IMPROPER_INPUT_VALIDATION.value,
                        affected_component=f"{location}/validation",
                        code_snippet=context,
                        recommendation="Add proper input validation and error handling",
                        attack_vector="Invalid input causing application errors",
                        cwe_id="CWE-20",
                        confidence=confidence,
                        evidence=evidence.__dict__
                    ))
            
        except Exception as e:
            self.logger.error(f"Data validation analysis failed: {e}")
        
        return findings
    
    def _analyze_native_bridge_deep(self, app_data: Dict, location: str) -> List[CrossPlatformFinding]:
        """Deep analysis of native bridge security."""
        findings = []
        
        try:
            app_content = self._extract_js_content_advanced(app_data)
            
            # Analyze native bridge vulnerabilities
            for pattern in self.vulnerability_patterns['native_bridge_vulnerabilities']:
                matches = re.finditer(pattern, app_content, re.IGNORECASE)
                for match in matches:
                    context = self._get_code_context(app_content, match.start(), match.end())
                    
                    evidence = ConfidenceEvidence(
                        pattern_reliability=0.85,
                        match_quality=self._assess_match_quality(match.group(), context),
                        context_relevance=0.90,
                        validation_sources=['bridge_analysis', 'pattern_matching'],
                        cross_validation=1
                    )
                    
                    confidence = self.confidence_calculator.calculate_confidence(
                        'native_bridge_vulnerabilities', evidence
                    )
                    
                    severity = self._assess_bridge_risk(match.group(), context)
                    
                    findings.append(CrossPlatformFinding(
                        title="Native Bridge Security Issue",
                        description=f"Potentially unsafe native bridge usage: {match.group()}",
                        severity=severity,
                        vulnerability_type=VulnerabilityType.UNSAFE_NATIVE_CODE.value,
                        affected_component=f"{location}/native_bridge",
                        code_snippet=context,
                        recommendation="Validate all data passed through native bridge",
                        attack_vector=self._get_attack_vector_for_vulnerability('native_bridge_vulnerabilities'),
                        cwe_id=self._get_cwe_for_vulnerability('native_bridge_vulnerabilities'),
                        confidence=confidence,
                        evidence=evidence.__dict__
                    ))
            
        except Exception as e:
            self.logger.error(f"Native bridge analysis failed: {e}")
        
        return findings
    
    def _analyze_react_native_vulnerabilities(self, app_data: Dict, location: str) -> List[CrossPlatformFinding]:
        """Analyze React Native specific vulnerabilities."""
        findings = []
        
        try:
            app_content = self._extract_js_content_advanced(app_data)
            
            # Analyze insecure storage
            for pattern in self.vulnerability_patterns['insecure_storage']:
                matches = re.finditer(pattern, app_content, re.IGNORECASE)
                for match in matches:
                    context = self._get_code_context(app_content, match.start(), match.end())
                    
                    evidence = ConfidenceEvidence(
                        pattern_reliability=0.90,
                        match_quality=self._assess_match_quality(match.group(), context),
                        context_relevance=0.95,
                        validation_sources=['storage_analysis', 'pattern_matching'],
                        cross_validation=1
                    )
                    
                    confidence = self.confidence_calculator.calculate_confidence(
                        'insecure_storage', evidence
                    )
                    
                    severity = self._assess_rn_specific_severity(match.group(), context)
                    
                    findings.append(CrossPlatformFinding(
                        title="Insecure Storage Usage",
                        description=f"Potentially insecure storage: {match.group()}",
                        severity=severity,
                        vulnerability_type=VulnerabilityType.INSECURE_STORAGE.value,
                        affected_component=f"{location}/storage",
                        code_snippet=context,
                        recommendation=self._get_remediation_for_vulnerability('insecure_storage'),
                        attack_vector=self._get_attack_vector_for_vulnerability('insecure_storage'),
                        cwe_id=self._get_cwe_for_vulnerability('insecure_storage'),
                        confidence=confidence,
                        evidence=evidence.__dict__
                    ))
            
            # Analyze network security
            for pattern in self.vulnerability_patterns['network_security']:
                matches = re.finditer(pattern, app_content, re.IGNORECASE)
                for match in matches:
                    context = self._get_code_context(app_content, match.start(), match.end())
                    
                    evidence = ConfidenceEvidence(
                        pattern_reliability=0.85,
                        match_quality=self._assess_match_quality(match.group(), context),
                        context_relevance=0.85,
                        validation_sources=['network_analysis', 'pattern_matching'],
                        cross_validation=1
                    )
                    
                    confidence = self.confidence_calculator.calculate_confidence(
                        'network_security', evidence
                    )
                    
                    findings.append(CrossPlatformFinding(
                        title="Insecure Network Communication",
                        description=f"Insecure network usage: {match.group()}",
                        severity=Severity.MEDIUM.value,
                        vulnerability_type=VulnerabilityType.INSECURE_COMMUNICATION.value,
                        affected_component=f"{location}/network",
                        code_snippet=context,
                        recommendation=self._get_remediation_for_vulnerability('network_security'),
                        attack_vector=self._get_attack_vector_for_vulnerability('network_security'),
                        cwe_id=self._get_cwe_for_vulnerability('network_security'),
                        confidence=confidence,
                        evidence=evidence.__dict__
                    ))
            
        except Exception as e:
            self.logger.error(f"React Native vulnerabilities analysis failed: {e}")
        
        return findings
    
    def _analyze_third_party_libraries(self, app_data: Dict, location: str) -> List[CrossPlatformFinding]:
        """Analyze third-party library vulnerabilities."""
        findings = []
        
        try:
            app_content = self._extract_js_content_advanced(app_data)
            
            # Check for vulnerable libraries
            for library_name, vuln_info in self.vulnerable_libraries.items():
                library_patterns = [
                    rf'["\']?{re.escape(library_name)}["\']?',
                    rf'import.*{re.escape(library_name)}',
                    rf'require\s*\(\s*["\'][^"\']*{re.escape(library_name)}[^"\']*["\']\s*\)'
                ]
                
                for pattern in library_patterns:
                    matches = re.finditer(pattern, app_content, re.IGNORECASE)
                    for match in matches:
                        context = self._get_code_context(app_content, match.start(), match.end())
                        
                        evidence = ConfidenceEvidence(
                            pattern_reliability=0.95,
                            match_quality=self._assess_match_quality(match.group(), context),
                            context_relevance=0.90,
                            validation_sources=['library_analysis', 'vulnerability_database'],
                            cross_validation=1
                        )
                        
                        confidence = self.confidence_calculator.calculate_confidence(
                            'third_party_vulnerabilities', evidence
                        )
                        
                        severity_mapping = {
                            'critical': Severity.CRITICAL.value,
                            'high': Severity.HIGH.value,
                            'medium': Severity.MEDIUM.value,
                            'low': Severity.LOW.value
                        }
                        severity = severity_mapping.get(vuln_info['severity'], Severity.MEDIUM.value)
                        
                        findings.append(CrossPlatformFinding(
                            title=f"Vulnerable Library: {library_name}",
                            description=f"Vulnerable library detected: {library_name}. {', '.join(vuln_info['vulnerabilities'])}",
                            severity=severity,
                            vulnerability_type=VulnerabilityType.VULNERABLE_COMPONENT.value,
                            affected_component=f"{location}/libraries/{library_name}",
                            code_snippet=context,
                            recommendation=f"Update {library_name} to a secure version (vulnerable: {', '.join(vuln_info['vulnerable_versions'])})",
                            attack_vector="Exploitation of known library vulnerabilities",
                            cwe_id="CWE-1035",
                            confidence=confidence,
                            evidence=evidence.__dict__
                        ))
            
            # Check for general third-party vulnerability patterns
            for pattern in self.vulnerability_patterns['third_party_vulnerabilities']:
                matches = re.finditer(pattern, app_content, re.IGNORECASE)
                for match in matches:
                    context = self._get_code_context(app_content, match.start(), match.end())
                    
                    evidence = ConfidenceEvidence(
                        pattern_reliability=0.70,
                        match_quality=self._assess_match_quality(match.group(), context),
                        context_relevance=0.75,
                        validation_sources=['library_pattern_analysis'],
                        cross_validation=1
                    )
                    
                    confidence = self.confidence_calculator.calculate_confidence(
                        'third_party_vulnerabilities', evidence
                    )
                    
                    findings.append(CrossPlatformFinding(
                        title="Third-Party Library Usage",
                        description=f"Third-party library usage detected: {match.group()}",
                        severity=Severity.LOW.value,
                        vulnerability_type=VulnerabilityType.VULNERABLE_COMPONENT.value,
                        affected_component=f"{location}/third_party",
                        code_snippet=context,
                        recommendation="Review and update all third-party libraries to latest secure versions",
                        attack_vector=self._get_attack_vector_for_vulnerability('third_party_vulnerabilities'),
                        cwe_id=self._get_cwe_for_vulnerability('third_party_vulnerabilities'),
                        confidence=confidence,
                        evidence=evidence.__dict__
                    ))
            
        except Exception as e:
            self.logger.error(f"Third-party library analysis failed: {e}")
        
        return findings
    
    def _analyze_javascript_injection(self, content: str, location: str) -> List[CrossPlatformFinding]:
        """Analyze JavaScript injection vulnerabilities."""
        findings = []
        
        try:
            # Analyze JavaScript injection vulnerabilities
            for pattern in self.vulnerability_patterns['javascript_injection']:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    context = self._get_code_context(content, match.start(), match.end())
                    
                    evidence = ConfidenceEvidence(
                        pattern_reliability=0.90,
                        match_quality=self._assess_match_quality(match.group(), context),
                        context_relevance=0.95,
                        validation_sources=['js_injection_analysis', 'pattern_matching'],
                        cross_validation=1
                    )
                    
                    confidence = self.confidence_calculator.calculate_confidence(
                        'javascript_injection', evidence
                    )
                    
                    severity = self._assess_js_injection_severity(match.group(), context)
                    
                    findings.append(CrossPlatformFinding(
                        title="JavaScript Injection Vulnerability",
                        description=f"Potential JavaScript injection: {match.group()}",
                        severity=severity,
                        vulnerability_type=VulnerabilityType.INJECTION.value,
                        affected_component=f"{location}/js_injection",
                        code_snippet=context,
                        recommendation="Sanitize and validate all user input before dynamic execution",
                        attack_vector="JavaScript code injection through user input",
                        cwe_id="CWE-79",
                        confidence=confidence,
                        evidence=evidence.__dict__
                    ))
            
        except Exception as e:
            self.logger.error(f"JavaScript injection analysis failed: {e}")
        
        return findings 
    
    def _analyze_advanced_javascript_security(self, app_data: Dict, location: str) -> List[CrossPlatformFinding]:
        """Advanced JavaScript security analysis with dynamic evaluation patterns."""
        findings = []
        
        try:
            app_content = self._extract_js_content_advanced(app_data)
            
            # Advanced dynamic code execution analysis
            dynamic_execution_patterns = [
                r'eval\s*\(\s*[^)]*(?:request|input|param|user)',
                r'Function\s*\(\s*[^)]*(?:request|input|param|user)',
                r'setTimeout\s*\(\s*["\'][^"\']*\+.*(?:request|input|param)',
                r'setInterval\s*\(\s*["\'][^"\']*\+.*(?:request|input|param)',
                r'new\s+Function\s*\([^)]*(?:request|input|param)',
                r'execScript\s*\([^)]*(?:request|input|param)',
                r'document\.write\s*\([^)]*(?:request|input|param)',
                r'innerHTML\s*=\s*[^;]*\+.*(?:request|input|param)'
            ]
            
            for pattern in dynamic_execution_patterns:
                matches = re.finditer(pattern, app_content, re.IGNORECASE)
                for match in matches:
                    context = self._get_code_context(app_content, match.start(), match.end())
                    
                    evidence = ConfidenceEvidence(
                        pattern_reliability=0.95,
                        match_quality=self._assess_dynamic_execution_quality(match.group(), context),
                        context_relevance=0.90,
                        validation_sources=['dynamic_execution_analysis', 'user_input_analysis'],
                        cross_validation=2
                    )
                    
                    confidence = self.confidence_calculator.calculate_confidence(
                        'dynamic_execution', evidence
                    )
                    
                    findings.append(CrossPlatformFinding(
                        title="Dynamic Code Execution Vulnerability",
                        description=f"Dynamic code execution with user input detected: {match.group()}",
                        severity=Severity.CRITICAL.value,
                        vulnerability_type=VulnerabilityType.INJECTION.value,
                        affected_component=f"{location}/dynamic_execution",
                        code_snippet=context,
                        recommendation="Avoid dynamic code execution with user input. Use safe alternatives like predefined function mappings.",
                        attack_vector="Code injection through dynamic execution of user-controlled data",
                        cwe_id="CWE-95",
                        confidence=confidence,
                        evidence=evidence.__dict__
                    ))
            
            # React Native specific security patterns
            rn_security_patterns = [
                r'AsyncStorage\.setItem\s*\([^)]*(?:password|token|key|secret|credential)',
                r'AsyncStorage\.multiSet\s*\([^)]*(?:password|token|key|secret)',
                r'@react-native-async-storage.*(?:password|token|key|secret)',
                r'SecureStore\.setItemAsync\s*\([^)]*["\'][^"\']*["\'].*["\'][^"\']*["\']',
                r'Keychain\.setInternetCredentials\s*\([^)]*',
                r'NativeModules\.[^.]+\.[^(]+\([^)]*(?:exec|eval|system)',
                r'bridge\.call\s*\([^)]*["\'](?:exec|eval|system)["\']',
                r'RCTBridge.*callNativeModule.*(?:exec|eval)',
                r'LinkingIOS\.openURL\s*\([^)]*\+',
                r'Linking\.openURL\s*\([^)]*\+.*(?:request|input|param)'
            ]
            
            for pattern in rn_security_patterns:
                matches = re.finditer(pattern, app_content, re.IGNORECASE)
                for match in matches:
                    context = self._get_code_context(app_content, match.start(), match.end())
                    
                    evidence = ConfidenceEvidence(
                        pattern_reliability=0.88,
                        match_quality=self._assess_rn_security_quality(match.group(), context),
                        context_relevance=0.85,
                        validation_sources=['rn_security_analysis', 'pattern_matching'],
                        cross_validation=1
                    )
                    
                    confidence = self.confidence_calculator.calculate_confidence(
                        'react_native_security', evidence
                    )
                    
                    vuln_type = self._classify_rn_vulnerability(match.group())
                    severity = self._assess_rn_vulnerability_severity(match.group(), context)
                    
                    findings.append(CrossPlatformFinding(
                        title=f"React Native Security Issue: {vuln_type}",
                        description=f"React Native security vulnerability detected: {match.group()}",
                        severity=severity,
                        vulnerability_type=VulnerabilityType.PLATFORM_USAGE.value,
                        affected_component=f"{location}/rn_security",
                        code_snippet=context,
                        recommendation=self._get_rn_security_recommendation(vuln_type),
                        attack_vector=self._get_rn_attack_vector(vuln_type),
                        cwe_id="CWE-200",
                        confidence=confidence,
                        evidence=evidence.__dict__
                    ))
            
            # Metro bundler configuration analysis
            metro_findings = self._analyze_metro_bundler_advanced(app_content, location)
            findings.extend(metro_findings)
            
            # Expo specific security analysis
            expo_findings = self._analyze_expo_security(app_content, location)
            findings.extend(expo_findings)
            
        except Exception as e:
            self.logger.error(f"Advanced JavaScript security analysis failed: {e}")
        
        return findings
    
    def _analyze_metro_bundler_advanced(self, content: str, location: str) -> List[CrossPlatformFinding]:
        """Advanced Metro bundler security configuration analysis."""
        findings = []
        
        try:
            # Metro configuration security patterns
            metro_patterns = [
                r'module\.exports\s*=\s*{[^}]*minify\s*:\s*false.*production',
                r'transformer\s*:\s*{[^}]*minifierPath\s*:\s*false',
                r'dev\s*:\s*true.*NODE_ENV.*production',
                r'enableHermes\s*:\s*false.*production',
                r'sourceMap\s*:\s*true.*production',
                r'bundleOutput.*\.js["\'](?![^}]*\.min\.)',
                r'resetCache\s*:\s*true.*production'
            ]
            
            for pattern in metro_patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    context = self._get_code_context(content, match.start(), match.end())
                    
                    evidence = ConfidenceEvidence(
                        pattern_reliability=0.82,
                        match_quality=self._assess_metro_config_quality(match.group(), context),
                        context_relevance=0.80,
                        validation_sources=['metro_config_analysis'],
                        cross_validation=1
                    )
                    
                    confidence = self.confidence_calculator.calculate_confidence(
                        'metro_configuration', evidence
                    )
                    
                    findings.append(CrossPlatformFinding(
                        title="Metro Bundler Security Configuration Issue",
                        description=f"Insecure Metro bundler configuration: {match.group()}",
                        severity=Severity.MEDIUM.value,
                        vulnerability_type=VulnerabilityType.CONFIGURATION.value,
                        affected_component=f"{location}/metro_config",
                        code_snippet=context,
                        recommendation="Configure Metro bundler for production with minification enabled and debug features disabled",
                        attack_vector="Information disclosure through debug configurations",
                        cwe_id="CWE-489",
                        confidence=confidence,
                        evidence=evidence.__dict__
                    ))
                    
        except Exception as e:
            self.logger.error(f"Metro bundler analysis failed: {e}")
        
        return findings
    
    def _analyze_expo_security(self, content: str, location: str) -> List[CrossPlatformFinding]:
        """Expo framework specific security analysis."""
        findings = []
        
        try:
            # Expo security patterns
            expo_patterns = [
                r'Expo\.Constants\.manifest\.debuggerHost',
                r'expo-constants.*debuggerHost',
                r'Expo\.Updates\.manifest\.debuggerHost',
                r'__DEV__.*Expo\.Constants',
                r'expo-permissions.*CAMERA.*MICROPHONE.*LOCATION',
                r'Expo\.Location\.getCurrentPositionAsync\s*\(\s*{[^}]*accuracy\s*:\s*Location\.Accuracy\.Highest',
                r'Expo\.Camera\..*recordAsync\s*\(\s*{[^}]*quality\s*:\s*["\']1080p["\']',
                r'Expo\.SecureStore\.setItemAsync\s*\([^)]*["\'][^"\']*["\'].*["\'][^"\']*["\']'
            ]
            
            for pattern in expo_patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    context = self._get_code_context(content, match.start(), match.end())
                    
                    evidence = ConfidenceEvidence(
                        pattern_reliability=0.75,
                        match_quality=self._assess_expo_security_quality(match.group(), context),
                        context_relevance=0.75,
                        validation_sources=['expo_security_analysis'],
                        cross_validation=1
                    )
                    
                    confidence = self.confidence_calculator.calculate_confidence(
                        'expo_security', evidence
                    )
                    
                    vuln_type = self._classify_expo_vulnerability(match.group())
                    severity = self._assess_expo_vulnerability_severity(match.group(), context)
                    
                    findings.append(CrossPlatformFinding(
                        title=f"Expo Security Issue: {vuln_type}",
                        description=f"Expo framework security issue detected: {match.group()}",
                        severity=severity,
                        vulnerability_type=VulnerabilityType.PLATFORM_USAGE.value,
                        affected_component=f"{location}/expo_security",
                        code_snippet=context,
                        recommendation=self._get_expo_security_recommendation(vuln_type),
                        attack_vector=self._get_expo_attack_vector(vuln_type),
                        cwe_id="CWE-200",
                        confidence=confidence,
                        evidence=evidence.__dict__
                    ))
                    
        except Exception as e:
            self.logger.error(f"Expo security analysis failed: {e}")
        
        return findings 
    
    def _analyze_native_bridge_deep_analysis(self, app_data: Dict, location: str) -> List[CrossPlatformFinding]:
        """Deep analysis of React Native bridge security."""
        findings = []
        
        try:
            app_content = self._extract_js_content_advanced(app_data)
            
            # RCTBridge security analysis
            bridge_findings = self._analyze_rct_bridge_security(app_content, location)
            findings.extend(bridge_findings)
            
            # TurboModules security analysis
            turbo_findings = self._analyze_turbo_modules_security(app_content, location)
            findings.extend(turbo_findings)
            
            # JSI (JavaScript Interface) security analysis
            jsi_findings = self._analyze_jsi_security(app_content, location)
            findings.extend(jsi_findings)
            
            # Fabric UI Manager security analysis
            fabric_findings = self._analyze_fabric_security(app_content, location)
            findings.extend(fabric_findings)
            
        except Exception as e:
            self.logger.error(f"Native bridge deep analysis failed: {e}")
        
        return findings
    
    def _analyze_rct_bridge_security(self, content: str, location: str) -> List[CrossPlatformFinding]:
        """Analyze RCTBridge security vulnerabilities."""
        findings = []
        
        try:
            # RCTBridge vulnerability patterns
            rct_patterns = [
                r'RCTBridge.*callNativeModule\s*:\s*[^,]*,\s*[^,]*,\s*\[[^\]]*(?:exec|eval|system)',
                r'bridge\.callNativeModule\s*\([^)]*["\'](?:exec|eval|system|shell)["\']',
                r'RCTModuleMethod.*invoke\s*:\s*[^,]*,\s*\[[^\]]*(?:user|input|param)',
                r'NativeModules\.[^.]+\.(?:exec|eval|system|shell)\s*\(',
                r'bridge\.eventDispatcher\.sendAppEventWithName\s*\([^)]*(?:exec|eval)',
                r'RCTBridge.*batchedBridge.*enqueueJSCall.*(?:exec|eval)',
                r'bridge\.moduleForClass\s*\([^)]*\)\.(?:exec|eval|system)',
                r'RCTBridge.*lazilyLoadedModuleForName.*(?:Shell|System|Exec)'
            ]
            
            for pattern in rct_patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    context = self._get_code_context(content, match.start(), match.end())
                    
                    evidence = ConfidenceEvidence(
                        pattern_reliability=0.92,
                        match_quality=self._assess_bridge_method_quality(match.group(), context),
                        context_relevance=0.88,
                        validation_sources=['rct_bridge_analysis', 'native_method_analysis'],
                        cross_validation=2
                    )
                    
                    confidence = self.confidence_calculator.calculate_confidence(
                        'rct_bridge_security', evidence
                    )
                    
                    severity = self._assess_bridge_vulnerability_severity(match.group(), context)
                    
                    findings.append(CrossPlatformFinding(
                        title="RCTBridge Security Vulnerability",
                        description=f"Dangerous RCTBridge method call: {match.group()}",
                        severity=severity,
                        vulnerability_type=VulnerabilityType.NATIVE_BRIDGE.value,
                        affected_component=f"{location}/rct_bridge",
                        code_snippet=context,
                        recommendation="Validate all bridge method calls and avoid exposing dangerous system functions",
                        attack_vector="Native code execution through bridge method calls",
                        cwe_id="CWE-749",
                        confidence=confidence,
                        evidence=evidence.__dict__
                    ))
                    
        except Exception as e:
            self.logger.error(f"RCTBridge security analysis failed: {e}")
        
        return findings
    
    def _analyze_turbo_modules_security(self, content: str, location: str) -> List[CrossPlatformFinding]:
        """Analyze TurboModules security vulnerabilities."""
        findings = []
        
        try:
            # TurboModules vulnerability patterns
            turbo_patterns = [
                r'TurboModuleRegistry\.get\s*\([^)]*\)\.(?:exec|eval|system|shell)',
                r'global\.__turboModuleProxy\.(?:exec|eval|system)',
                r'TurboModule.*invoke\s*\([^)]*(?:exec|eval|system)',
                r'global\.nativeFabricUIManager\.(?:exec|eval)',
                r'TurboModuleRegistry\.getEnforcing\s*\([^)]*\)\.(?:dangerous|unsafe)',
                r'NativeTurboModule.*\.(?:execShell|systemCall|evalJS)',
                r'turbo_module\s*::\s*invoke.*(?:exec|eval|system)'
            ]
            
            for pattern in turbo_patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    context = self._get_code_context(content, match.start(), match.end())
                    
                    evidence = ConfidenceEvidence(
                        pattern_reliability=0.90,
                        match_quality=self._assess_turbo_method_quality(match.group(), context),
                        context_relevance=0.85,
                        validation_sources=['turbo_modules_analysis'],
                        cross_validation=1
                    )
                    
                    confidence = self.confidence_calculator.calculate_confidence(
                        'turbo_modules_security', evidence
                    )
                    
                    findings.append(CrossPlatformFinding(
                        title="TurboModules Security Vulnerability",
                        description=f"Dangerous TurboModule method: {match.group()}",
                        severity=Severity.HIGH.value,
                        vulnerability_type=VulnerabilityType.NATIVE_BRIDGE.value,
                        affected_component=f"{location}/turbo_modules",
                        code_snippet=context,
                        recommendation="Review TurboModule implementations and restrict access to dangerous methods",
                        attack_vector="Code execution through TurboModule method calls",
                        cwe_id="CWE-749",
                        confidence=confidence,
                        evidence=evidence.__dict__
                    ))
                    
        except Exception as e:
            self.logger.error(f"TurboModules security analysis failed: {e}")
        
        return findings
    
    def _analyze_jsi_security(self, content: str, location: str) -> List[CrossPlatformFinding]:
        """Analyze JSI (JavaScript Interface) security."""
        findings = []
        
        try:
            # JSI vulnerability patterns
            jsi_patterns = [
                r'global\.(?:__fbBatchedBridge|__reactNativeBridge)\.(?:exec|eval)',
                r'__jsiModules\.(?:exec|eval|system)',
                r'jsi::Runtime.*eval\s*\(',
                r'jsi::Function.*call.*(?:exec|eval|system)',
                r'global\.__jsiObjectWrapper\.(?:exec|eval)',
                r'Runtime\.global\(\)\.getPropertyAsFunction.*(?:exec|eval)'
            ]
            
            for pattern in jsi_patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    context = self._get_code_context(content, match.start(), match.end())
                    
                    evidence = ConfidenceEvidence(
                        pattern_reliability=0.88,
                        match_quality=self._assess_jsi_method_quality(match.group(), context),
                        context_relevance=0.85,
                        validation_sources=['jsi_analysis'],
                        cross_validation=1
                    )
                    
                    confidence = self.confidence_calculator.calculate_confidence(
                        'jsi_security', evidence
                    )
                    
                    findings.append(CrossPlatformFinding(
                        title="JSI Security Vulnerability",
                        description=f"Dangerous JSI method call: {match.group()}",
                        severity=Severity.HIGH.value,
                        vulnerability_type=VulnerabilityType.NATIVE_BRIDGE.value,
                        affected_component=f"{location}/jsi",
                        code_snippet=context,
                        recommendation="Review JSI implementations and avoid exposing dangerous runtime methods",
                        attack_vector="Code execution through JSI runtime interface",
                        cwe_id="CWE-749",
                        confidence=confidence,
                        evidence=evidence.__dict__
                    ))
                    
        except Exception as e:
            self.logger.error(f"JSI security analysis failed: {e}")
        
        return findings
    
    def _analyze_fabric_security(self, content: str, location: str) -> List[CrossPlatformFinding]:
        """Analyze Fabric UI Manager security."""
        findings = []
        
        try:
            # Fabric vulnerability patterns
            fabric_patterns = [
                r'nativeFabricUIManager\.(?:exec|eval|system)',
                r'FabricUIManager.*dispatchCommand.*(?:exec|eval)',
                r'UIManager\.dispatchViewManagerCommand.*(?:exec|eval)',
                r'global\.nativeFabricUIManager\.measureInWindow.*(?:exec|eval)',
                r'FabricUIManager.*createNode.*(?:WebView|Script)',
                r'global\.RN\$Bridgeless.*(?:exec|eval)'
            ]
            
            for pattern in fabric_patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    context = self._get_code_context(content, match.start(), match.end())
                    
                    evidence = ConfidenceEvidence(
                        pattern_reliability=0.80,
                        match_quality=self._assess_fabric_method_quality(match.group(), context),
                        context_relevance=0.80,
                        validation_sources=['fabric_analysis'],
                        cross_validation=1
                    )
                    
                    confidence = self.confidence_calculator.calculate_confidence(
                        'fabric_security', evidence
                    )
                    
                    findings.append(CrossPlatformFinding(
                        title="Fabric UI Manager Security Issue",
                        description=f"Potentially dangerous Fabric method: {match.group()}",
                        severity=Severity.MEDIUM.value,
                        vulnerability_type=VulnerabilityType.NATIVE_BRIDGE.value,
                        affected_component=f"{location}/fabric",
                        code_snippet=context,
                        recommendation="Review Fabric UI Manager usage and validate all command dispatching",
                        attack_vector="UI manipulation through Fabric commands",
                        cwe_id="CWE-749",
                        confidence=confidence,
                        evidence=evidence.__dict__
                    ))
                    
        except Exception as e:
            self.logger.error(f"Fabric security analysis failed: {e}")
        
        return findings
    
    # Helper methods for assessment functions
    def _assess_dynamic_execution_quality(self, match: str, context: str) -> float:
        """Assess the quality of dynamic execution pattern matches."""
        quality = 0.5
        
        # Check for user input sources
        input_indicators = ['request', 'input', 'param', 'user', 'query', 'form']
        if any(indicator in context.lower() for indicator in input_indicators):
            quality += 0.3
            
        # Check for validation absence
        validation_indicators = ['sanitize', 'validate', 'escape', 'filter']
        if not any(indicator in context.lower() for indicator in validation_indicators):
            quality += 0.2
            
        return min(quality, 1.0)
    
    def _assess_rn_security_quality(self, match: str, context: str) -> float:
        """Assess React Native security pattern quality."""
        quality = 0.6
        
        # Check for sensitive data patterns
        if any(term in match.lower() for term in ['password', 'token', 'secret', 'credential']):
            quality += 0.2
            
        # Check for storage security
        if 'AsyncStorage' in match and any(term in match.lower() for term in ['password', 'token']):
            quality += 0.2
            
        return min(quality, 1.0)
    
    def _assess_metro_config_quality(self, match: str, context: str) -> float:
        """Assess Metro configuration security quality."""
        quality = 0.5
        
        # Check for production context
        if 'production' in context.lower():
            quality += 0.3
            
        # Check for debug features in production
        if any(term in match.lower() for term in ['debug', 'dev:', 'sourcemap']):
            quality += 0.2
            
        return min(quality, 1.0)
    
    def _assess_expo_security_quality(self, match: str, context: str) -> float:
        """Assess Expo security pattern quality."""
        quality = 0.5
        
        # Check for debug-related patterns
        if 'debugger' in match.lower() or '__DEV__' in match:
            quality += 0.3
            
        # Check for sensitive permissions
        if any(perm in match for perm in ['CAMERA', 'MICROPHONE', 'LOCATION']):
            quality += 0.2
            
        return min(quality, 1.0)
    
    def _assess_bridge_method_quality(self, match: str, context: str) -> float:
        """Assess bridge method call quality."""
        quality = 0.7
        
        # Check for dangerous methods
        if any(method in match.lower() for method in ['exec', 'eval', 'system', 'shell']):
            quality += 0.2
            
        # Check for input parameters
        if any(param in context.lower() for param in ['user', 'input', 'param']):
            quality += 0.1
            
        return min(quality, 1.0)
    
    def _assess_turbo_method_quality(self, match: str, context: str) -> float:
        """Assess TurboModule method quality."""
        return self._assess_bridge_method_quality(match, context)
    
    def _assess_jsi_method_quality(self, match: str, context: str) -> float:
        """Assess JSI method quality."""
        return self._assess_bridge_method_quality(match, context)
    
    def _assess_fabric_method_quality(self, match: str, context: str) -> float:
        """Assess Fabric method quality."""
        quality = 0.6
        
        # Check for command dispatching
        if 'dispatch' in match.lower():
            quality += 0.2
            
        # Check for potentially dangerous components
        if any(comp in match for comp in ['WebView', 'Script']):
            quality += 0.2
            
        return min(quality, 1.0)
    
    def _classify_rn_vulnerability(self, match: str) -> str:
        """Classify React Native vulnerability type."""
        if 'AsyncStorage' in match:
            return "Insecure Storage"
        elif 'bridge.call' in match or 'NativeModules' in match:
            return "Bridge Exposure"
        elif 'Linking.openURL' in match:
            return "URL Handling"
        else:
            return "Platform Usage"
    
    def _assess_rn_vulnerability_severity(self, match: str, context: str) -> str:
        """Assess React Native vulnerability severity."""
        if any(term in match.lower() for term in ['password', 'token', 'secret']):
            return Severity.HIGH.value
        elif any(term in match.lower() for term in ['exec', 'eval', 'system']):
            return Severity.CRITICAL.value
        else:
            return Severity.MEDIUM.value
    
    def _get_rn_security_recommendation(self, vuln_type: str) -> str:
        """Get recommendation for React Native vulnerability type."""
        recommendations = {
            "Insecure Storage": "Use react-native-keychain or Expo SecureStore for sensitive data",
            "Bridge Exposure": "Validate all bridge method calls and restrict access to dangerous functions",
            "URL Handling": "Validate all URLs before opening and use allowlist for external links",
            "Platform Usage": "Follow React Native security best practices and validate platform-specific code"
        }
        return recommendations.get(vuln_type, "Review and secure React Native implementation")
    
    def _get_rn_attack_vector(self, vuln_type: str) -> str:
        """Get attack vector for React Native vulnerability type."""
        vectors = {
            "Insecure Storage": "Local data extraction",
            "Bridge Exposure": "Native code execution",
            "URL Handling": "URL scheme hijacking",
            "Platform Usage": "Platform-specific exploitation"
        }
        return vectors.get(vuln_type, "React Native framework exploitation")
    
    def _get_rn_cwe_mapping(self, vuln_type: str) -> str:
        """Get CWE mapping for React Native vulnerability type."""
        mappings = {
            "Insecure Storage": "CWE-312",
            "Bridge Exposure": "CWE-749",
            "URL Handling": "CWE-939",
            "Platform Usage": "CWE-501"
        }
        return mappings.get(vuln_type, "CWE-200")
    
    def _classify_expo_vulnerability(self, match: str) -> str:
        """Classify Expo vulnerability type."""
        if 'debugger' in match.lower():
            return "Debug Information Exposure"
        elif any(perm in match for perm in ['CAMERA', 'MICROPHONE', 'LOCATION']):
            return "Excessive Permissions"
        else:
            return "Configuration Issue"
    
    def _assess_expo_vulnerability_severity(self, match: str, context: str) -> str:
        """Assess Expo vulnerability severity."""
        if 'debugger' in match.lower():
            return Severity.MEDIUM.value
        elif any(perm in match for perm in ['CAMERA', 'MICROPHONE', 'LOCATION']):
            return Severity.LOW.value
        else:
            return Severity.LOW.value
    
    def _get_expo_security_recommendation(self, vuln_type: str) -> str:
        """Get Expo security recommendation."""
        recommendations = {
            "Debug Information Exposure": "Disable debug features in production builds",
            "Excessive Permissions": "Request only necessary permissions and explain usage to users",
            "Configuration Issue": "Review Expo configuration for security best practices"
        }
        return recommendations.get(vuln_type, "Review Expo security configuration")
    
    def _get_expo_attack_vector(self, vuln_type: str) -> str:
        """Get Expo attack vector."""
        vectors = {
            "Debug Information Exposure": "Information disclosure",
            "Excessive Permissions": "Privacy violation",
            "Configuration Issue": "Configuration exploitation"
        }
        return vectors.get(vuln_type, "Expo framework exploitation")
    
    def _assess_bridge_vulnerability_severity(self, match: str, context: str) -> str:
        """Assess bridge vulnerability severity."""
        if any(method in match.lower() for method in ['exec', 'eval', 'system', 'shell']):
            return Severity.CRITICAL.value
        elif 'dangerous' in match.lower() or 'unsafe' in match.lower():
            return Severity.HIGH.value
        else:
            return Severity.MEDIUM.value
    
    def _analyze_framework_compatibility(self, app_data: Dict, location: str) -> List[CrossPlatformFinding]:
        """Analyze React Native framework version compatibility and security implications."""
        findings = []
        
        try:
            app_content = self._extract_js_content_advanced(app_data)
            
            # Version compatibility patterns
            version_patterns = [
                r'react-native@([0-9]+\.[0-9]+\.[0-9]+)',
                r'"react-native":\s*"([^"]+)"',
                r'ReactNative\s+([0-9.]+)',
                r'RN_VERSION\s*=\s*["\']([^"\']+)["\']'
            ]
            
            detected_versions = []
            for pattern in version_patterns:
                matches = re.finditer(pattern, app_content, re.IGNORECASE)
                for match in matches:
                    detected_versions.append(match.group(1))
            
            # Check for vulnerable versions
            vulnerable_versions = [
                "0.60.0", "0.60.1", "0.60.2", "0.60.3", "0.60.4", "0.60.5", "0.60.6",
                "0.61.0", "0.61.1", "0.61.2", "0.61.3", "0.61.4", "0.61.5",
                "0.62.0", "0.62.1", "0.62.2", "0.62.3",
                "0.63.0", "0.63.1", "0.63.2", "0.63.3", "0.63.4"
            ]
            
            for version in detected_versions:
                if version in vulnerable_versions:
                    evidence = ConfidenceEvidence(
                        pattern_reliability=0.95,
                        match_quality=0.9,
                        context_relevance=0.9,
                        validation_sources=['version_analysis', 'security_database'],
                        cross_validation=1
                    )
                    
                    confidence = self.confidence_calculator.calculate_confidence(
                        'framework_version', evidence
                    )
                    
                    findings.append(CrossPlatformFinding(
                        title="Vulnerable React Native Version",
                        description=f"Vulnerable React Native version detected: {version}",
                        severity=Severity.HIGH.value,
                        vulnerability_type=VulnerabilityType.VULNERABLE_COMPONENT.value,
                        affected_component=f"{location}/framework_version",
                        code_snippet=f"React Native version: {version}",
                        recommendation=f"Update React Native to the latest stable version (current: {version})",
                        attack_vector="Framework-specific vulnerabilities",
                        cwe_id="CWE-1035",
                        confidence=confidence,
                        evidence=evidence.__dict__
                    ))
            
            # Check for deprecated API usage
            deprecated_patterns = [
                r'NavigatorIOS',
                r'ListView',
                r'NetInfo\.isConnected',
                r'AsyncStorage\.setItem',  # Deprecated in favor of @react-native-async-storage
                r'Geolocation\.getCurrentPosition',
                r'CameraRoll',
                r'AppState\.currentState',
                r'Dimensions\.get\s*\(\s*["\']screen["\']',
                r'PushNotificationIOS',
                r'StatusBarIOS'
            ]
            
            for pattern in deprecated_patterns:
                matches = re.finditer(pattern, app_content, re.IGNORECASE)
                for match in matches:
                    context = self._get_code_context(app_content, match.start(), match.end())
                    
                    evidence = ConfidenceEvidence(
                        pattern_reliability=0.85,
                        match_quality=0.8,
                        context_relevance=0.75,
                        validation_sources=['deprecated_api_analysis'],
                        cross_validation=1
                    )
                    
                    confidence = self.confidence_calculator.calculate_confidence(
                        'deprecated_api', evidence
                    )
                    
                    findings.append(CrossPlatformFinding(
                        title="Deprecated API Usage",
                        description=f"Deprecated React Native API detected: {match.group()}",
                        severity=Severity.MEDIUM.value,
                        vulnerability_type=VulnerabilityType.CONFIGURATION.value,
                        affected_component=f"{location}/deprecated_api",
                        code_snippet=context,
                        recommendation=f"Replace deprecated API {match.group()} with modern alternative",
                        attack_vector="API deprecation security implications",
                        cwe_id="CWE-477",
                        confidence=confidence,
                        evidence=evidence.__dict__
                    ))
                    
        except Exception as e:
            self.logger.error(f"Framework compatibility analysis failed: {e}")
        
        return findings
    
    def _analyze_performance_security(self, app_data: Dict, location: str) -> List[CrossPlatformFinding]:
        """Analyze performance-related security issues in React Native apps."""
        findings = []
        
        try:
            app_content = self._extract_js_content_advanced(app_data)
            
            # Performance security patterns
            performance_patterns = [
                r'while\s*\(\s*true\s*\)',
                r'for\s*\(\s*;;\s*\)',
                r'setInterval\s*\([^)]*,\s*[01]\s*\)',  # Very short intervals
                r'setTimeout\s*\([^)]*,\s*0\s*\)',      # Zero timeout
                r'JSON\.stringify\s*\([^)]*\)\.\s*length\s*>\s*[0-9]{6,}',  # Large JSON
                r'Array\s*\(\s*[0-9]{6,}\s*\)',        # Large arrays
                r'new\s+Array\s*\(\s*[0-9]{6,}\s*\)',
                r'Math\.random\s*\(\s*\)\s*<\s*0\.0001',  # Inefficient random
                r'\.map\s*\([^)]*\)\.map\s*\([^)]*\)\.map',  # Chained maps
                r'while\s*\([^)]*Math\.random\s*\(\s*\)'   # Random loops
            ]
            
            for pattern in performance_patterns:
                matches = re.finditer(pattern, app_content, re.IGNORECASE)
                for match in matches:
                    context = self._get_code_context(app_content, match.start(), match.end())
                    
                    evidence = ConfidenceEvidence(
                        pattern_reliability=0.78,
                        match_quality=self._assess_performance_security_quality(match.group(), context),
                        context_relevance=0.75,
                        validation_sources=['performance_security_analysis'],
                        cross_validation=1
                    )
                    
                    confidence = self.confidence_calculator.calculate_confidence(
                        'performance_security', evidence
                    )
                    
                    severity = self._assess_performance_severity(match.group(), context)
                    
                    findings.append(CrossPlatformFinding(
                        title="Performance Security Issue",
                        description=f"Performance-related security issue: {match.group()}",
                        severity=severity,
                        vulnerability_type=VulnerabilityType.DENIAL_OF_SERVICE.value,
                        affected_component=f"{location}/performance",
                        code_snippet=context,
                        recommendation="Optimize performance-critical code to prevent DoS conditions",
                        attack_vector="Performance-based denial of service",
                        cwe_id="CWE-400",
                        confidence=confidence,
                        evidence=evidence.__dict__
                    ))
            
            # Memory leak patterns
            memory_leak_patterns = [
                r'setInterval\s*\([^)]*\)(?![^;]*clearInterval)',
                r'setTimeout\s*\([^)]*\)(?![^;]*clearTimeout)',
                r'addEventListener\s*\([^)]*\)(?![^;]*removeEventListener)',
                r'new\s+Worker\s*\([^)]*\)(?![^;]*terminate)',
                r'WebSocket\s*\([^)]*\)(?![^;]*close)',
                r'XMLHttpRequest\s*\(\s*\)(?![^;]*abort)'
            ]
            
            for pattern in memory_leak_patterns:
                matches = re.finditer(pattern, app_content, re.IGNORECASE)
                for match in matches:
                    context = self._get_code_context(app_content, match.start(), match.end())
                    
                    evidence = ConfidenceEvidence(
                        pattern_reliability=0.75,
                        match_quality=0.7,
                        context_relevance=0.7,
                        validation_sources=['memory_leak_analysis'],
                        cross_validation=1
                    )
                    
                    confidence = self.confidence_calculator.calculate_confidence(
                        'memory_leak', evidence
                    )
                    
                    findings.append(CrossPlatformFinding(
                        title="Potential Memory Leak",
                        description=f"Potential memory leak pattern: {match.group()}",
                        severity=Severity.MEDIUM.value,
                        vulnerability_type=VulnerabilityType.RESOURCE_MANAGEMENT.value,
                        affected_component=f"{location}/memory_leak",
                        code_snippet=context,
                        recommendation="Ensure proper cleanup of resources to prevent memory leaks",
                        attack_vector="Memory exhaustion through resource leaks",
                        cwe_id="CWE-401",
                        confidence=confidence,
                        evidence=evidence.__dict__
                    ))
                    
        except Exception as e:
            self.logger.error(f"Performance security analysis failed: {e}")
        
        return findings
    
    def _assess_performance_security_quality(self, match: str, context: str) -> float:
        """Assess the quality of performance security pattern matches."""
        quality = 0.5
        
        # Check for dangerous patterns
        if 'while(true)' in match or 'for(;;)' in match:
            quality += 0.3
        
        # Check for very short intervals
        if any(interval in match for interval in ['0', '1', '2']):
            quality += 0.2
            
        # Check for large allocations
        if any(size in match for size in ['100000', '1000000']):
            quality += 0.2
            
        return min(quality, 1.0)
    
    def _get_code_context(self, content: str, start: int, end: int, lines: int = 3) -> str:
        """Get code context around a match."""
        try:
            context_start = max(0, start - lines * 10)
            context_end = min(len(content), end + lines * 10)
            return content[context_start:context_end]
        except Exception:
            return content[start:end]  # Fallback to just the match
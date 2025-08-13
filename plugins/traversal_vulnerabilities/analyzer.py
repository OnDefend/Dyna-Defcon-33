"""
Traversal Vulnerabilities Analyzer

Core analysis engine for path traversal and directory traversal vulnerability detection.
Analyzes content providers, intent filters, file operations, and other traversal vectors.
"""

import re
import os
import logging
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List, Tuple, Union, Optional, Any
import uuid

from .data_structures import (
    TraversalVulnerability, ContentProviderAnalysis, IntentFilterAnalysis,
    FileOperationAnalysis, TraversalAnalysisConfig, TraversalType,
    SeverityLevel, RiskLevel, PayloadGenerationResult, SecurityControlAssessment,
    MAVSTraversalControls, CWETraversalCategories
)
from .confidence_calculator import TraversalConfidenceCalculator

# Import unified deduplication framework
from core.unified_deduplication_framework import (
    deduplicate_findings, 
    DeduplicationStrategy,
    create_deduplication_engine
)

logger = logging.getLogger(__name__)

class TraversalVulnerabilityAnalyzer:
    """
    Core analyzer for traversal vulnerability detection.
    
    Provides comprehensive analysis of path traversal vulnerabilities including:
    - Content provider security assessment
    - Intent filter analysis
    - File operation security analysis
    - Payload generation and testing
    - Security control assessment
    """
    
    def __init__(self, config: Optional[TraversalAnalysisConfig] = None):
        """Initialize the traversal vulnerability analyzer."""
        self.config = config or TraversalAnalysisConfig()
        self.confidence_calculator = TraversalConfidenceCalculator()
        
        # Initialize analysis patterns
        self.patterns = self._initialize_patterns()
        
        # Compiled regex patterns for performance
        self._compile_patterns()
        
        # Analysis results storage
        self.vulnerabilities = []
        self.content_providers = []
        self.intent_filters = []
        self.file_operations = []
        
        logger.info("Traversal vulnerability analyzer initialized")
    
    def _initialize_patterns(self) -> Dict[str, List[str]]:
        """Initialize vulnerability detection patterns."""
        return {
            'path_traversal_patterns': [
                r'\.\./',
                r'\.\.\\',
                r'%2e%2e%2f',
                r'%2e%2e%5c',
                r'..%2f',
                r'..%5c',
                r'%252e%252e%252f',
                r'%c0%ae%c0%ae%c0%af',
                r'%c1%9c%c1%9c%c1%af',
                r'\.\.\/+',
                r'\.\.\\+',
                r'\.\.%2f',
                r'\.\.%5c'
            ],
            'directory_traversal_patterns': [
                r'\/\.\.\/',
                r'\\\.\.\\'
                r'File\(\s*["\'].*\.\..*["\']\s*\)',
                r'FileInputStream\(\s*["\'].*\.\..*["\']\s*\)',
                r'FileOutputStream\(\s*["\'].*\.\..*["\']\s*\)',
                r'openFileInput\(\s*["\'].*\.\..*["\']\s*\)',
                r'openFileOutput\(\s*["\'].*\.\..*["\']\s*\)',
                r'getExternalFilesDir\(\s*["\'].*\.\..*["\']\s*\)'
            ],
            'file_inclusion_patterns': [
                r'include\s*\(\s*["\'].*\.\..*["\']\s*\)',
                r'require\s*\(\s*["\'].*\.\..*["\']\s*\)',
                r'import\s*["\'].*\.\..*["\']',
                r'loadUrl\(\s*["\'].*\.\..*["\']\s*\)',
                r'loadData\(\s*["\'].*\.\..*["\']\s*\)',
                r'evaluateJavascript\(\s*["\'].*\.\..*["\']\s*\)'
            ],
            'content_provider_patterns': [
                r'<provider[^>]*android:exported\s*=\s*["\']true["\'][^>]*>',
                r'<provider[^>]*android:grantUriPermissions\s*=\s*["\']true["\'][^>]*>',
                r'<path-permission[^>]*android:path\s*=\s*["\'][^"\']*\.\.[^"\']*["\'][^>]*>',
                r'query\(\s*[^,]*,\s*["\'][^"\']*\.\.[^"\']*["\']',
                r'openFile\(\s*[^,]*,\s*["\'][^"\']*\.\.[^"\']*["\']'
            ],
            'intent_filter_patterns': [
                r'<data[^>]*android:pathPattern\s*=\s*["\'][^"\']*\.\.[^"\']*["\'][^>]*>',
                r'<data[^>]*android:path\s*=\s*["\'][^"\']*\.\.[^"\']*["\'][^>]*>',
                r'<data[^>]*android:pathPrefix\s*=\s*["\'][^"\']*\.\.[^"\']*["\'][^>]*>',
                r'setData\(\s*Uri\.parse\(\s*["\'][^"\']*\.\.[^"\']*["\']',
                r'getStringExtra\(\s*["\'][^"\']*["\'].*\.\..*'
            ],
            'file_operation_patterns': [
                r'new\s+File\(\s*[^,)]*getIntent\(\)\.getStringExtra\([^)]*\)',
                r'new\s+File\(\s*[^,)]*getIntent\(\)\.getExtras\(\)\.getString\([^)]*\)',
                r'openFileInput\(\s*[^)]*getIntent\(\)\.getStringExtra\([^)]*\)',
                r'openFileOutput\(\s*[^)]*getIntent\(\)\.getStringExtra\([^)]*\)',
                r'createTempFile\(\s*[^,)]*getIntent\(\)\.getStringExtra\([^)]*\)',
                r'File\(\s*[^,)]*\+.*\.\..*\)'
            ],
            'uri_handling_patterns': [
                r'Uri\.parse\(\s*[^)]*\.\.[^)]*\)',
                r'Uri\.fromFile\(\s*[^)]*\.\.[^)]*\)',
                r'ContentResolver\.openInputStream\(\s*[^)]*\.\.[^)]*\)',
                r'ContentResolver\.openOutputStream\(\s*[^)]*\.\.[^)]*\)',
                r'getContentResolver\(\)\.query\(\s*[^,)]*\.\.[^,)]*'
            ],
            'webview_traversal_patterns': [
                r'loadUrl\(\s*["\']file:\/\/[^"\']*\.\.[^"\']*["\']',
                r'loadDataWithBaseURL\(\s*["\']file:\/\/[^"\']*\.\.[^"\']*["\']',
                r'WebView\.loadUrl\(\s*[^)]*\.\.[^)]*\)',
                r'WebView\.loadData\(\s*[^)]*\.\.[^)]*\)',
                r'addJavascriptInterface\(\s*[^,)]*,\s*["\'][^"\']*\.\.[^"\']*["\']'
            ]
        }
    
    def _compile_patterns(self):
        """Compile regex patterns for better performance."""
        self.compiled_patterns = {}
        
        for category, patterns in self.patterns.items():
            self.compiled_patterns[category] = []
            for pattern in patterns:
                try:
                    compiled = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
                    self.compiled_patterns[category].append(compiled)
                except re.error as e:
                    logger.warning(f"Failed to compile pattern {pattern}: {e}")
    
    def analyze_content(self, content: str, file_path: str = "") -> List[TraversalVulnerability]:
        """
        Analyze content for traversal vulnerabilities.
        
        Args:
            content: File content to analyze
            file_path: Path of the file being analyzed
            
        Returns:
            List of detected traversal vulnerabilities
        """
        vulnerabilities = []
        
        try:
            # Analyze different vulnerability types
            if self.config.enable_static_analysis:
                vulnerabilities.extend(self._analyze_static_patterns(content, file_path))
            
            if self.config.enable_content_provider_analysis:
                vulnerabilities.extend(self._analyze_content_provider_patterns(content, file_path))
            
            if self.config.enable_intent_filter_analysis:
                vulnerabilities.extend(self._analyze_intent_filter_patterns(content, file_path))
            
            if self.config.enable_file_operation_analysis:
                vulnerabilities.extend(self._analyze_file_operation_patterns(content, file_path))
            
            # Filter by confidence threshold
            if self.config.enable_false_positive_filtering:
                vulnerabilities = [v for v in vulnerabilities if v.confidence >= self.config.confidence_threshold]
            
            # Deduplicate vulnerabilities
            vulnerabilities = self._deduplicate_vulnerabilities(vulnerabilities)
            
            return vulnerabilities
            
        except Exception as e:
            logger.error(f"Error analyzing content for traversal vulnerabilities: {e}")
            return []
    
    def _analyze_static_patterns(self, content: str, file_path: str) -> List[TraversalVulnerability]:
        """Analyze static patterns for traversal vulnerabilities."""
        vulnerabilities = []
        
        for pattern_type, compiled_patterns in self.compiled_patterns.items():
            for pattern in compiled_patterns:
                matches = pattern.finditer(content)
                
                for match in matches:
                    vulnerability = self._create_vulnerability_from_match(
                        match, pattern_type, file_path, content
                    )
                    if vulnerability:
                        vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _analyze_content_provider_patterns(self, content: str, file_path: str) -> List[TraversalVulnerability]:
        """Analyze content provider specific patterns."""
        vulnerabilities = []
        
        if 'AndroidManifest.xml' in file_path:
            vulnerabilities.extend(self._analyze_manifest_providers(content, file_path))
        
        # Analyze Java/Kotlin code for content provider usage
        if file_path.endswith(('.java', '.kt')):
            vulnerabilities.extend(self._analyze_provider_code(content, file_path))
        
        return vulnerabilities
    
    def _analyze_intent_filter_patterns(self, content: str, file_path: str) -> List[TraversalVulnerability]:
        """Analyze intent filter patterns for traversal vulnerabilities."""
        vulnerabilities = []
        
        if 'AndroidManifest.xml' in file_path:
            vulnerabilities.extend(self._analyze_manifest_intent_filters(content, file_path))
        
        # Analyze Java/Kotlin code for intent handling
        if file_path.endswith(('.java', '.kt')):
            vulnerabilities.extend(self._analyze_intent_handling_code(content, file_path))
        
        return vulnerabilities
    
    def _analyze_file_operation_patterns(self, content: str, file_path: str) -> List[TraversalVulnerability]:
        """Analyze file operation patterns for traversal vulnerabilities."""
        vulnerabilities = []
        
        if not file_path.endswith(('.java', '.kt')):
            return vulnerabilities
        
        # Analyze file operations with user input
        for pattern in self.compiled_patterns.get('file_operation_patterns', []):
            matches = pattern.finditer(content)
            
            for match in matches:
                vulnerability = self._create_file_operation_vulnerability(
                    match, file_path, content
                )
                if vulnerability:
                    vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _analyze_manifest_providers(self, content: str, file_path: str) -> List[TraversalVulnerability]:
        """Analyze content providers in AndroidManifest.xml."""
        vulnerabilities = []
        
        try:
            root = ET.fromstring(content)
            
            # Find all provider elements
            providers = root.findall('.//provider')
            
            for provider in providers:
                provider_analysis = self._analyze_provider_element(provider, file_path)
                if provider_analysis and provider_analysis.vulnerabilities:
                    vulnerabilities.extend(provider_analysis.vulnerabilities)
        
        except ET.ParseError as e:
            logger.warning(f"Failed to parse AndroidManifest.xml: {e}")
        
        return vulnerabilities
    
    def _analyze_provider_element(self, provider: ET.Element, file_path: str) -> Optional[ContentProviderAnalysis]:
        """Analyze a single provider element."""
        try:
            provider_name = provider.get('android:name', '')
            authority = provider.get('android:authorities', '')
            exported = provider.get('android:exported', '').lower() == 'true'
            grant_uri_permissions = provider.get('android:grantUriPermissions', '').lower() == 'true'
            
            vulnerabilities = []
            
            # Check for exported provider without proper permissions
            if exported and not provider.get('android:permission'):
                vulnerability = TraversalVulnerability(
                    vulnerability_id=str(uuid.uuid4()),
                    title="Exported Content Provider Without Permission",
                    severity=SeverityLevel.HIGH.value,
                    confidence=self._calculate_provider_confidence(provider),
                    description=f"Content provider {provider_name} is exported without requiring permissions",
                    location=file_path,
                    evidence=ET.tostring(provider, encoding='unicode'),
                    traversal_type=TraversalType.CONTENT_PROVIDER.value,
                    cwe_id=CWETraversalCategories.AUTHORIZATION,
                    masvs_refs=[MAVSTraversalControls.PLATFORM_7]
                )
                vulnerabilities.append(vulnerability)
            
            # Check for grant URI permissions
            if grant_uri_permissions:
                vulnerability = TraversalVulnerability(
                    vulnerability_id=str(uuid.uuid4()),
                    title="Content Provider Grants URI Permissions",
                    severity=SeverityLevel.MEDIUM.value,
                    confidence=self._calculate_provider_confidence(provider),
                    description=f"Content provider {provider_name} grants URI permissions",
                    location=file_path,
                    evidence=ET.tostring(provider, encoding='unicode'),
                    traversal_type=TraversalType.CONTENT_PROVIDER.value,
                    cwe_id=CWETraversalCategories.ACCESS_CONTROL,
                    masvs_refs=[MAVSTraversalControls.PLATFORM_7]
                )
                vulnerabilities.append(vulnerability)
            
            return ContentProviderAnalysis(
                provider_name=provider_name,
                authority=authority,
                exported=exported,
                permissions=[provider.get('android:permission', '')] if provider.get('android:permission') else [],
                grant_uri_permissions=grant_uri_permissions,
                path_permissions=[],
                vulnerabilities=vulnerabilities,
                risk_level=self._assess_provider_risk(vulnerabilities)
            )
            
        except Exception as e:
            logger.error(f"Error analyzing provider element: {e}")
            return None
    
    def _create_vulnerability_from_match(self, match: re.Match, pattern_type: str, 
                                       file_path: str, content: str) -> Optional[TraversalVulnerability]:
        """Create a vulnerability from a regex match."""
        try:
            # Extract context around the match
            start = max(0, match.start() - 100)
            end = min(len(content), match.end() + 100)
            context = content[start:end]
            
            # Calculate confidence
            evidence = {
                'pattern_type': pattern_type,
                'match_quality': self._assess_match_quality(match, context),
                'file_location': file_path,
                'context_quality': self._assess_context_quality(context)
            }
            
            confidence = self.confidence_calculator.calculate_confidence(evidence)
            
            # Determine severity based on pattern type
            severity = self._determine_severity(pattern_type, context)
            
            # Create vulnerability
            vulnerability = TraversalVulnerability(
                vulnerability_id=str(uuid.uuid4()),
                title=self._get_vulnerability_title(pattern_type),
                severity=severity.value,
                confidence=confidence,
                description=self._get_vulnerability_description(pattern_type, match.group()),
                location=file_path,
                evidence=context,
                traversal_type=self._get_traversal_type(pattern_type),
                cwe_id=self._get_cwe_id(pattern_type),
                masvs_refs=self._get_masvs_refs(pattern_type),
                attack_vectors=self._get_attack_vectors(pattern_type),
                remediation=self._get_remediation(pattern_type)
            )
            
            return vulnerability
            
        except Exception as e:
            logger.error(f"Error creating vulnerability from match: {e}")
            return None
    
    def _calculate_provider_confidence(self, provider: ET.Element) -> float:
        """Calculate confidence for content provider vulnerability."""
        evidence = {
            'pattern_type': 'content_provider_patterns',
            'exported': provider.get('android:exported', '').lower() == 'true',
            'has_permission': bool(provider.get('android:permission')),
            'grant_uri_permissions': provider.get('android:grantUriPermissions', '').lower() == 'true'
        }
        
        return self.confidence_calculator.calculate_confidence(evidence)
    
    def _assess_match_quality(self, match: re.Match, context: str) -> float:
        """Assess the quality of a regex match."""
        match_text = match.group()
        
        # Higher quality for longer matches
        length_score = min(len(match_text) / 50.0, 1.0)
        
        # Check for common false positive indicators
        false_positive_indicators = ['test', 'example', 'demo', 'mock']
        fp_penalty = 0.0
        for indicator in false_positive_indicators:
            if indicator in context.lower():
                fp_penalty += 0.1
        
        quality = max(0.0, length_score - fp_penalty)
        return quality
    
    def _assess_context_quality(self, context: str) -> float:
        """Assess the quality of the context around a match."""
        # Check for security-related keywords
        security_keywords = ['validate', 'sanitize', 'check', 'verify', 'secure']
        security_score = 0.0
        
        for keyword in security_keywords:
            if keyword in context.lower():
                security_score += 0.1
        
        # Check for vulnerability indicators
        vuln_indicators = ['user', 'input', 'intent', 'external', 'untrusted']
        vuln_score = 0.0
        
        for indicator in vuln_indicators:
            if indicator in context.lower():
                vuln_score += 0.1
        
        return min(security_score + vuln_score, 1.0)
    
    def _determine_severity(self, pattern_type: str, context: str) -> SeverityLevel:
        """Determine severity level based on pattern type and context."""
        severity_mapping = {
            'path_traversal_patterns': SeverityLevel.HIGH,
            'directory_traversal_patterns': SeverityLevel.HIGH,
            'file_inclusion_patterns': SeverityLevel.CRITICAL,
            'content_provider_patterns': SeverityLevel.MEDIUM,
            'intent_filter_patterns': SeverityLevel.MEDIUM,
            'file_operation_patterns': SeverityLevel.HIGH,
            'uri_handling_patterns': SeverityLevel.MEDIUM,
            'webview_traversal_patterns': SeverityLevel.HIGH
        }
        
        base_severity = severity_mapping.get(pattern_type, SeverityLevel.MEDIUM)
        
        # Adjust severity based on context
        if 'external' in context.lower() or 'untrusted' in context.lower():
            # Increase severity for external/untrusted input
            if base_severity == SeverityLevel.MEDIUM:
                return SeverityLevel.HIGH
            elif base_severity == SeverityLevel.HIGH:
                return SeverityLevel.CRITICAL
        
        return base_severity
    
    def _get_vulnerability_title(self, pattern_type: str) -> str:
        """Get vulnerability title based on pattern type."""
        titles = {
            'path_traversal_patterns': 'Path Traversal Vulnerability',
            'directory_traversal_patterns': 'Directory Traversal Vulnerability',
            'file_inclusion_patterns': 'File Inclusion Vulnerability',
            'content_provider_patterns': 'Content Provider Security Issue',
            'intent_filter_patterns': 'Intent Filter Security Issue',
            'file_operation_patterns': 'Unsafe File Operation',
            'uri_handling_patterns': 'URI Handling Security Issue',
            'webview_traversal_patterns': 'WebView Traversal Vulnerability'
        }
        
        return titles.get(pattern_type, 'Traversal Vulnerability')
    
    def _get_vulnerability_description(self, pattern_type: str, match_text: str) -> str:
        """Get vulnerability description based on pattern type and match."""
        descriptions = {
            'path_traversal_patterns': f"Path traversal pattern detected: {match_text}",
            'directory_traversal_patterns': f"Directory traversal pattern detected: {match_text}",
            'file_inclusion_patterns': f"File inclusion vulnerability detected: {match_text}",
            'content_provider_patterns': f"Content provider security issue: {match_text}",
            'intent_filter_patterns': f"Intent filter security issue: {match_text}",
            'file_operation_patterns': f"Unsafe file operation detected: {match_text}",
            'uri_handling_patterns': f"URI handling security issue: {match_text}",
            'webview_traversal_patterns': f"WebView traversal vulnerability: {match_text}"
        }
        
        return descriptions.get(pattern_type, f"Traversal vulnerability detected: {match_text}")
    
    def _get_traversal_type(self, pattern_type: str) -> str:
        """Get traversal type based on pattern type."""
        type_mapping = {
            'path_traversal_patterns': TraversalType.PATH_TRAVERSAL.value,
            'directory_traversal_patterns': TraversalType.DIRECTORY_TRAVERSAL.value,
            'file_inclusion_patterns': TraversalType.FILE_INCLUSION.value,
            'content_provider_patterns': TraversalType.CONTENT_PROVIDER.value,
            'intent_filter_patterns': TraversalType.INTENT_BASED.value,
            'file_operation_patterns': TraversalType.PATH_TRAVERSAL.value,
            'uri_handling_patterns': TraversalType.URI_BASED.value,
            'webview_traversal_patterns': TraversalType.WEBVIEW_BASED.value
        }
        
        return type_mapping.get(pattern_type, TraversalType.PATH_TRAVERSAL.value)
    
    def _get_cwe_id(self, pattern_type: str) -> str:
        """Get CWE ID based on pattern type."""
        cwe_mapping = {
            'path_traversal_patterns': CWETraversalCategories.PATH_TRAVERSAL,
            'directory_traversal_patterns': CWETraversalCategories.DIRECTORY_TRAVERSAL,
            'file_inclusion_patterns': CWETraversalCategories.FILE_INCLUSION,
            'content_provider_patterns': CWETraversalCategories.ACCESS_CONTROL,
            'intent_filter_patterns': CWETraversalCategories.INPUT_VALIDATION,
            'file_operation_patterns': CWETraversalCategories.PATH_TRAVERSAL,
            'uri_handling_patterns': CWETraversalCategories.URI_HANDLING,
            'webview_traversal_patterns': CWETraversalCategories.PATH_TRAVERSAL
        }
        
        return cwe_mapping.get(pattern_type, CWETraversalCategories.PATH_TRAVERSAL)
    
    def _get_masvs_refs(self, pattern_type: str) -> List[str]:
        """Get MASVS references based on pattern type."""
        masvs_mapping = {
            'path_traversal_patterns': [MAVSTraversalControls.PLATFORM_1, MAVSTraversalControls.CODE_8],
            'directory_traversal_patterns': [MAVSTraversalControls.PLATFORM_1, MAVSTraversalControls.CODE_8],
            'file_inclusion_patterns': [MAVSTraversalControls.PLATFORM_1, MAVSTraversalControls.CODE_8],
            'content_provider_patterns': [MAVSTraversalControls.PLATFORM_7, MAVSTraversalControls.PLATFORM_2],
            'intent_filter_patterns': [MAVSTraversalControls.PLATFORM_9, MAVSTraversalControls.PLATFORM_1],
            'file_operation_patterns': [MAVSTraversalControls.PLATFORM_1, MAVSTraversalControls.CODE_8],
            'uri_handling_patterns': [MAVSTraversalControls.PLATFORM_9, MAVSTraversalControls.PLATFORM_1],
            'webview_traversal_patterns': [MAVSTraversalControls.PLATFORM_11, MAVSTraversalControls.PLATFORM_6]
        }
        
        return masvs_mapping.get(pattern_type, [MAVSTraversalControls.PLATFORM_1])
    
    def _get_attack_vectors(self, pattern_type: str) -> List[str]:
        """Get attack vectors based on pattern type."""
        vectors = {
            'path_traversal_patterns': ['../../../etc/passwd', '../../../etc/hosts', '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts'],
            'directory_traversal_patterns': ['Directory listing', 'Unauthorized file access', 'System file exposure'],
            'file_inclusion_patterns': ['Remote file inclusion', 'Local file inclusion', 'Code execution'],
            'content_provider_patterns': ['Unauthorized data access', 'Data manipulation', 'Privilege escalation'],
            'intent_filter_patterns': ['Intent injection', 'Data theft', 'Privilege escalation'],
            'file_operation_patterns': ['File overwrite', 'Directory traversal', 'Path manipulation'],
            'uri_handling_patterns': ['URI manipulation', 'Path traversal', 'Data access'],
            'webview_traversal_patterns': ['Local file access', 'Cross-origin attacks', 'Information disclosure']
        }
        
        return vectors.get(pattern_type, ['Path traversal', 'Unauthorized access'])
    
    def _get_remediation(self, pattern_type: str) -> str:
        """Get remediation advice based on pattern type."""
        remediations = {
            'path_traversal_patterns': 'Implement proper input validation and canonicalization. Use allowlists for permitted paths.',
            'directory_traversal_patterns': 'Validate and sanitize all file paths. Use secure file access methods.',
            'file_inclusion_patterns': 'Implement strict input validation. Use allowlists for permitted files.',
            'content_provider_patterns': 'Implement proper permissions and path validation for content providers.',
            'intent_filter_patterns': 'Validate intent data and implement proper path restrictions.',
            'file_operation_patterns': 'Implement secure file operations with proper validation.',
            'uri_handling_patterns': 'Validate and sanitize all URI inputs. Use secure URI handling methods.',
            'webview_traversal_patterns': 'Implement proper WebView security configuration and URL validation.'
        }
        
        return remediations.get(pattern_type, 'Implement proper input validation and security controls.')
    
    def _assess_provider_risk(self, vulnerabilities: List[TraversalVulnerability]) -> str:
        """Assess risk level for content provider based on vulnerabilities."""
        if not vulnerabilities:
            return RiskLevel.LOW.value
        
        high_count = sum(1 for v in vulnerabilities if v.severity == SeverityLevel.HIGH.value)
        critical_count = sum(1 for v in vulnerabilities if v.severity == SeverityLevel.CRITICAL.value)
        
        if critical_count > 0:
            return RiskLevel.CRITICAL.value
        elif high_count > 0:
            return RiskLevel.HIGH.value
        else:
            return RiskLevel.MEDIUM.value

    def _deduplicate_vulnerabilities(self, vulnerabilities: List) -> List:
        """Remove duplicate vulnerabilities using unified deduplication framework."""
        if not vulnerabilities:
            return vulnerabilities
        
        # Convert to dict format
        dict_findings = []
        for vuln in vulnerabilities:
            dict_finding = {
                'title': getattr(vuln, 'vulnerability_type', str(vuln)),
                'description': getattr(vuln, 'description', ''),
                'location': getattr(vuln, 'location', ''),
                'evidence': getattr(vuln, 'evidence', []),
                'original_object': vuln
            }
            dict_findings.append(dict_finding)
        
        try:
            result = deduplicate_findings(dict_findings, DeduplicationStrategy.INTELLIGENT)
            return [f['original_object'] for f in result.unique_findings if 'original_object' in f]
        except Exception:
            return self._deduplicate_vulnerabilities_fallback(vulnerabilities)

    def _deduplicate_vulnerabilities_fallback(self, vulnerabilities: List) -> List:
        """Fallback deduplication method (original logic)."""
        seen = set()
        unique_vulns = []
        
        for vuln in vulnerabilities:
            # Create signature for deduplication
            signature = (
                getattr(vuln, 'vulnerability_type', ''),
                getattr(vuln, 'location', ''),
                str(getattr(vuln, 'evidence', []))[:100]  # First 100 chars of evidence
            )
            
            if signature not in seen:
                seen.add(signature)
                unique_vulns.append(vuln)
        
        return unique_vulns

    def generate_payloads(self, vulnerability: TraversalVulnerability) -> PayloadGenerationResult:
        """Generate test payloads for a traversal vulnerability."""
        payloads = []
        payload_types = []
        effectiveness_scores = []
        
        if vulnerability.traversal_type == TraversalType.PATH_TRAVERSAL.value:
            payloads.extend(['../../../etc/passwd', '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts'])
            payload_types.extend(['unix_path_traversal', 'windows_path_traversal'])
            effectiveness_scores.extend([0.8, 0.7])
        
        elif vulnerability.traversal_type == TraversalType.DIRECTORY_TRAVERSAL.value:
            payloads.extend(['../../../../etc/passwd', '..\\..\\..\\..\\windows\\system32\\config\\sam'])
            payload_types.extend(['unix_directory_traversal', 'windows_directory_traversal'])
            effectiveness_scores.extend([0.9, 0.8])
        
        # Limit payloads based on configuration
        max_payloads = self.config.max_payloads_per_vulnerability
        if len(payloads) > max_payloads:
            payloads = payloads[:max_payloads]
            payload_types = payload_types[:max_payloads]
            effectiveness_scores = effectiveness_scores[:max_payloads]
        
        return PayloadGenerationResult(
            vulnerability_id=vulnerability.vulnerability_id,
            generated_payloads=payloads,
            payload_types=payload_types,
            effectiveness_scores=effectiveness_scores,
            bypass_techniques=['URL encoding', 'Double encoding', 'Unicode encoding'],
            detection_methods=['Static analysis', 'Dynamic testing', 'Fuzzing']
        ) 
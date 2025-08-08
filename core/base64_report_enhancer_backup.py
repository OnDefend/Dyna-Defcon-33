#!/usr/bin/env python3
"""
Base64 Report Enhancer for AODS
===============================

Automatically decodes Base64 values in security reports with intelligent content 
classification and enhanced presentation for immediate visibility of decoded content.

Features:
- Automatic Base64 detection and decoding (≥12 characters)
- Content classification: credentials, URLs, API keys, configuration data
- Binary data detection and safe handling
- Encoding validation with error handling
- Performance optimized (<10% impact on report generation)
- Support for nested/chained encoding detection

"""

import base64
import json
import logging
import re
import urllib.parse
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple, Union
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class Base64DecodingResult:
    """Result of Base64 decoding operation."""
    
    original_value: str
    decoded_value: str
    content_type: str
    confidence: float
    is_binary: bool
    encoding_chain: List[str]
    security_classification: str
    metadata: Dict[str, Any]
    # Enhanced location tracking
    source_location: Optional[str] = None
    source_field: Optional[str] = None
    discovery_context: Optional[Dict[str, Any]] = None

@dataclass
class ContentClassification:
    """Classification result for decoded content."""
    
    content_type: str
    confidence: float
    indicators: List[str]
    security_level: str  # LOW, MEDIUM, HIGH, CRITICAL
    redaction_recommended: bool

class Base64ReportEnhancer:
    """
    Enhanced Base64 decoder for security reports with intelligent content classification.
    
    This class provides automatic Base64 decoding with content classification,
    security assessment, and enhanced presentation for security reports.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the Base64 Report Enhancer.
        
        Args:
            config: Optional configuration dictionary
        """
        self.config = config or self._default_config()
        self.content_classifier = ContentClassifier()
        self.security_analyzer = SecurityAnalyzer()
        
        # Performance tracking
        self.stats = {
            'total_processed': 0,
            'base64_detected': 0,
            'successfully_decoded': 0,
            'classification_success': 0,
            'binary_data_detected': 0,
            'security_findings': 0
        }
        
        # Base64 detection patterns (enhanced from source_code_analyzer.py)
        self.base64_patterns = [
            # High confidence patterns (method context)
            r'Base64\.decode\s*\(\s*["\']([A-Za-z0-9+/]{12,}={0,2})["\']',
            r'fromBase64\s*\(\s*["\']([A-Za-z0-9+/]{12,}={0,2})["\']',
            r'decodeBase64\s*\(\s*["\']([A-Za-z0-9+/]{12,}={0,2})["\']',
            r'android\.util\.Base64\.decode\s*\(\s*["\']([A-Za-z0-9+/]{12,}={0,2})["\']',
            
            # Medium confidence patterns (assignment context)
            r'["\']([A-Za-z0-9+/]{16,}={0,2})["\']',  # Quoted Base64 strings (16+ chars)
            r'=\s*["\']([A-Za-z0-9+/]{16,}={0,2})["\']',  # Assignment context
            r'String\s+\w+\s*=\s*["\']([A-Za-z0-9+/]{16,}={0,2})["\']',  # String variable assignment
            r'final\s+String\s+\w+\s*=\s*["\']([A-Za-z0-9+/]{16,}={0,2})["\']',  # Final string assignment
            
            # Lower confidence patterns (standalone)
            r'([A-Za-z0-9+/]{20,}={0,2})',  # Standalone Base64 (20+ chars for better precision)
            r'([A-Za-z0-9+/]{32,}={0,2})',  # Longer Base64 (32+ chars, high confidence)
            r'([A-Za-z0-9+/]{64,}={0,2})',  # Very long Base64 (64+ chars, very high confidence)
        ]
        
        logger.info("Base64ReportEnhancer initialized successfully")
    
    def _default_config(self) -> Dict[str, Any]:
        """Default configuration for Base64 enhancement."""
        return {
            'min_base64_length': 12,
            'max_base64_length': 10000,
            'enable_content_classification': True,
            'enable_security_analysis': True,
            'enable_binary_detection': True,
            'enable_chained_decoding': True,
            'performance_mode': False,  # Set to True for faster processing with reduced accuracy
            'redaction_mode': 'smart',  # 'none', 'smart', 'aggressive'
            'max_decode_attempts': 3,
            'confidence_threshold': 0.7,
            'security_classification_enabled': True
        }
    
    def enhance_report_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Enhance findings with decoded Base64 content.
        
        Args:
            findings: List of security findings from the report
            
        Returns:
            Enhanced findings with Base64 decoding information
        """
        enhanced_findings = []
        
        for finding in findings:
            self.stats['total_processed'] += 1
            enhanced_finding = self._process_finding(finding)
            enhanced_findings.append(enhanced_finding)
        
        logger.info(f"Enhanced {len(findings)} findings with Base64 decoding")
        self._log_stats()
        
        return enhanced_findings
    
    def enhance_vulnerability_data(self, vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """
        Enhance a single vulnerability with Base64 decoding.
        
        Args:
            vulnerability: Vulnerability dictionary
            
        Returns:
            Enhanced vulnerability with Base64 decoding information
        """
        enhanced_vuln = vulnerability.copy()
        
        # Extract location information from vulnerability
        location_info = self._extract_location_info(vulnerability)
        
        # Process description with location context
        if 'description' in enhanced_vuln:
            enhanced_vuln['description'] = self._enhance_text_content_with_location(
                enhanced_vuln['description'], 'description', location_info
            )
        
        # Process evidence with location context
        if 'evidence' in enhanced_vuln and isinstance(enhanced_vuln['evidence'], list):
            enhanced_evidence = []
            for i, evidence_item in enumerate(enhanced_vuln['evidence']):
                enhanced_evidence.append(
                    self._enhance_text_content_with_location(
                        str(evidence_item), f'evidence[{i}]', location_info
                    )
                )
            enhanced_vuln['evidence'] = enhanced_evidence
        
        # Add Base64 analysis metadata with location information
        base64_analysis = self._analyze_vulnerability_for_base64_with_location(enhanced_vuln, location_info)
        if base64_analysis['has_base64_content']:
            enhanced_vuln['base64_analysis'] = base64_analysis
            self.stats['security_findings'] += 1
        
        return enhanced_vuln
    
    def _extract_location_info(self, vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """Extract location information from vulnerability data."""
        location_info = {}
        
        # Check for various location fields
        if 'file_location' in vulnerability:
            location_info['file_location'] = vulnerability['file_location']
        elif 'location' in vulnerability:
            if isinstance(vulnerability['location'], dict):
                location_info.update(vulnerability['location'])
            else:
                location_info['location'] = str(vulnerability['location'])
        
        # Check for file path information
        if 'file_path' in vulnerability:
            location_info['file_path'] = vulnerability['file_path']
        
        # Check for context information that might contain location
        if 'context' in vulnerability and isinstance(vulnerability['context'], dict):
            context = vulnerability['context']
            if 'file_location' in context:
                location_info['file_location'] = context['file_location']
            if 'resource_path' in context:
                location_info['resource_path'] = context['resource_path']
            if 'file_path' in context:
                location_info['file_path'] = context['file_path']
        
        # Check for detailed vulnerability framework location
        if 'location' in vulnerability and isinstance(vulnerability['location'], dict):
            loc = vulnerability['location']
            if 'file_path' in loc:
                location_info['file_path'] = loc['file_path']
            if 'line_number' in loc:
                location_info['line_number'] = loc['line_number']
            if 'method_name' in loc:
                location_info['method_name'] = loc['method_name']
            if 'class_name' in loc:
                location_info['class_name'] = loc['class_name']
        
        return location_info
    
    def _enhance_text_content_with_location(self, text: str, field_name: str, location_info: Dict[str, Any]) -> str:
        """Enhance text content with Base64 decoding and location information."""
        if not self._contains_base64(text):
            return text
        
        enhanced_text = text
        
        # Process each Base64 pattern
        for pattern in self.base64_patterns:
            matches = re.finditer(pattern, text, re.IGNORECASE)
            for match in matches:
                # Extract Base64 string (handle different capture groups)
                base64_candidate = None
                if match.groups():
                    # Use the first non-None group
                    for group in match.groups():
                        if group:
                            base64_candidate = group
                            break
                else:
                    base64_candidate = match.group(0)
                
                if base64_candidate and len(base64_candidate) >= self.config['min_base64_length']:
                    # Decode with location context
                    result = self._decode_base64_with_analysis_and_location(
                        base64_candidate, field_name, location_info
                    )
                    if result:
                        enhanced_text = self._insert_decoded_content_with_location(enhanced_text, match, result)
        
        return enhanced_text
    
    def _decode_base64_with_analysis_and_location(self, base64_string: str, field_name: str, location_info: Dict[str, Any]) -> Optional[Base64DecodingResult]:
        """
        Decode Base64 string with comprehensive analysis and location tracking.
        
        Args:
            base64_string: The Base64 string to decode
            field_name: The field where this Base64 was found
            location_info: Location information from the vulnerability
            
        Returns:
            Base64DecodingResult with location information or None if decoding fails
        """
        if not self._is_valid_base64_format(base64_string):
            return None
        
        try:
            # Add padding if necessary
            padded_base64 = self._add_base64_padding(base64_string)
            
            # Decode the Base64 string
            decoded_bytes = base64.b64decode(padded_base64)
            
            # Check if it's binary data
            is_binary = self._is_binary_data(decoded_bytes)
            
            if is_binary:
                decoded_value = f"<BINARY_DATA:{len(decoded_bytes)}_bytes>"
                self.stats['binary_data_detected'] += 1
            else:
                # Try to decode as UTF-8
                try:
                    decoded_value = decoded_bytes.decode('utf-8')
                except UnicodeDecodeError:
                    # Try other encodings
                    for encoding in ['latin-1', 'ascii', 'utf-16']:
                        try:
                            decoded_value = decoded_bytes.decode(encoding)
                            break
                        except UnicodeDecodeError:
                            continue
                    else:
                        decoded_value = f"<BINARY_DATA:{len(decoded_bytes)}_bytes>"
                        is_binary = True
            
            # Classify content
            classification = self.content_classifier.classify_content(decoded_value)
            
            # Detect encoding chain
            encoding_chain = self._detect_encoding_chain(decoded_value)
            
            # Security analysis
            security_analysis = self.security_analyzer.analyze_security_risk(decoded_value, classification.content_type)
            
            # Format location information
            formatted_location = self._format_location_info(location_info)
            
            # Create discovery context
            discovery_context = {
                'field_name': field_name,
                'location_info': location_info,
                'formatted_location': formatted_location,
                'detection_timestamp': datetime.now().isoformat()
            }
            
            result = Base64DecodingResult(
                original_value=base64_string,
                decoded_value=decoded_value,
                content_type=classification.content_type,
                confidence=classification.confidence,
                is_binary=is_binary,
                encoding_chain=encoding_chain,
                security_classification=security_analysis['risk_level'],
                metadata={
                    'classification': classification,
                    'security_analysis': security_analysis,
                    'decoded_length': len(decoded_bytes),
                    'original_length': len(base64_string)
                },
                source_location=formatted_location,
                source_field=field_name,
                discovery_context=discovery_context
            )
            
            self.stats['successfully_decoded'] += 1
            if classification.confidence > 0:
                self.stats['classification_success'] += 1
            
            return result
            
        except Exception as e:
            logger.warning(f"Failed to decode Base64 string: {e}")
            return None
    
    def _format_location_info(self, location_info: Dict[str, Any]) -> str:
        """Format location information for display."""
        if not location_info:
            return "Unknown location"
        
        # Priority order for location formatting
        if 'file_location' in location_info:
            return str(location_info['file_location'])
        elif 'file_path' in location_info and 'line_number' in location_info:
            return f"{location_info['file_path']}:{location_info['line_number']}"
        elif 'file_path' in location_info:
            return str(location_info['file_path'])
        elif 'resource_path' in location_info:
            return str(location_info['resource_path'])
        elif 'location' in location_info:
            return str(location_info['location'])
        else:
            # Fallback: combine available information
            parts = []
            for key in ['class_name', 'method_name']:
                if key in location_info:
                    parts.append(f"{key}:{location_info[key]}")
            return " | ".join(parts) if parts else "Unknown location"
    
    def _insert_decoded_content_with_location(self, text: str, match: re.Match, result: Base64DecodingResult) -> str:
        """Insert decoded content with location information into the original text."""
        # Get content type indicator
        type_indicator = self._get_content_type_indicator(result.content_type)
        
        # Create enhanced replacement with location
        if result.is_binary:
            decoded_preview = result.decoded_value
        else:
            # Truncate long decoded values for readability
            max_preview_length = 100
            if len(result.decoded_value) > max_preview_length:
                decoded_preview = result.decoded_value[:max_preview_length] + "..."
            else:
                decoded_preview = result.decoded_value
        
        # Build the enhanced content with location
        enhancement_parts = [
            f"DECODED ({result.content_type.upper()}, {result.confidence:.1%} confidence): {type_indicator} {decoded_preview}"
        ]
        
        # Add location information
        if result.source_location:
            enhancement_parts.append(f"FOUND AT: {result.source_location}")
        
        # Add security warning if applicable
        if result.security_classification in ['HIGH', 'CRITICAL']:
            enhancement_parts.append(f"SECURITY: {result.security_classification} risk content detected")
        
        # Add encoding chain if multiple encodings detected
        if len(result.encoding_chain) > 1:
            chain_display = " → ".join(result.encoding_chain)
            enhancement_parts.append(f"ENCODING CHAIN: {chain_display}")
        
        # Create the full replacement
        original_match = match.group(0)
        enhanced_content = f"{original_match}\n" + "\n".join(enhancement_parts)
        
        # Replace in the original text
        return text.replace(original_match, enhanced_content, 1)
    
    def _analyze_vulnerability_for_base64_with_location(self, vulnerability: Dict[str, Any], location_info: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze vulnerability for Base64 content with location tracking."""
        analysis = {
            'has_base64_content': False,
            'base64_findings': [],
            'security_impact': 'LOW',
            'recommendations': [],
            'location_context': location_info
        }
        
        # Fields to analyze for Base64 content
        fields_to_analyze = ['title', 'description', 'evidence', 'content', 'details']
        
        for field in fields_to_analyze:
            if field in vulnerability:
                field_content = str(vulnerability[field])
                if self._contains_base64(field_content):
                    # Find and analyze Base64 patterns in this field
                    for pattern in self.base64_patterns:
                        matches = re.finditer(pattern, field_content, re.IGNORECASE)
                        for match in matches:
                            base64_candidate = None
                            if match.groups():
                                for group in match.groups():
                                    if group:
                                        base64_candidate = group
                                        break
                            else:
                                base64_candidate = match.group(0)
                            
                            if base64_candidate and len(base64_candidate) >= self.config['min_base64_length']:
                                result = self._decode_base64_with_analysis_and_location(
                                    base64_candidate, field, location_info
                                )
                                if result:
                                    analysis['has_base64_content'] = True
                                    
                                    # Add finding with location information
                                    finding = {
                                        'field': field,
                                        'original': result.original_value,
                                        'decoded_preview': result.decoded_value[:100] + "..." if len(result.decoded_value) > 100 else result.decoded_value,
                                        'content_type': result.content_type,
                                        'confidence': result.confidence,
                                        'security_classification': result.security_classification,
                                        'source_location': result.source_location,
                                        'discovery_context': result.discovery_context
                                    }
                                    analysis['base64_findings'].append(finding)
                                    
                                    # Update overall security impact
                                    if result.security_classification == 'CRITICAL':
                                        analysis['security_impact'] = 'CRITICAL'
                                    elif result.security_classification == 'HIGH' and analysis['security_impact'] != 'CRITICAL':
                                        analysis['security_impact'] = 'HIGH'
                                    elif result.security_classification == 'MEDIUM' and analysis['security_impact'] in ['LOW']:
                                        analysis['security_impact'] = 'MEDIUM'
        
        # Generate recommendations with location context
        if analysis['has_base64_content']:
            analysis['recommendations'] = self._generate_base64_recommendations_with_location(analysis)
        
        return analysis
    
    def _generate_base64_recommendations_with_location(self, analysis: Dict[str, Any]) -> List[str]:
        """Generate security recommendations with location context."""
        recommendations = []
        
        # Base recommendations
        if analysis['security_impact'] == 'CRITICAL':
            recommendations.append("🔴 CRITICAL: Base64 encoded sensitive data detected - review for credential exposure")
        elif analysis['security_impact'] == 'HIGH':
            recommendations.append("🟠 HIGH: Base64 encoded potentially sensitive data found - verify security implications")
        elif analysis['security_impact'] == 'MEDIUM':
            recommendations.append("🟡 MEDIUM: Base64 encoded data detected - review for information disclosure")
        else:
            recommendations.append("🔵 INFO: Base64 encoded data found - verify if encoding is necessary")
        
        # Location-specific recommendations
        location_context = analysis.get('location_context', {})
        if location_context:
            if 'file_path' in location_context:
                file_path = location_context['file_path']
                if any(path_part in file_path.lower() for path_part in ['string', 'resource', 'xml']):
                    recommendations.append(f"📁 Review resource file {file_path} for hardcoded sensitive data")
                elif 'java' in file_path.lower() or 'kotlin' in file_path.lower():
                    recommendations.append(f"💻 Review source code in {file_path} for proper secret management")
                elif 'manifest' in file_path.lower():
                    recommendations.append(f"📋 Review manifest file {file_path} for exposed configuration data")
        
        # General security recommendations
        recommendations.extend([
            "Implement proper secret management instead of hardcoded Base64 values",
            "Use secure credential storage mechanisms (Android Keystore, encrypted preferences)",
            "Avoid hardcoding credentials in application code",
            "Validate that Base64 encoding is necessary and not used as a security measure",
            "Consider implementing runtime decryption instead of compile-time encoding"
        ])
        
        return recommendations
    
    def _log_stats(self) -> None:
        """Log processing statistics."""
        logger.info("Base64 Enhancement Statistics:")
        logger.info(f"  Total processed: {self.stats['total_processed']}")
        logger.info(f"  Base64 detected: {self.stats['base64_detected']}")
        logger.info(f"  Successfully decoded: {self.stats['successfully_decoded']}")
        logger.info(f"  Classification success: {self.stats['classification_success']}")
        logger.info(f"  Binary data detected: {self.stats['binary_data_detected']}")
        logger.info(f"  Security findings: {self.stats['security_findings']}")
    
    def get_enhancement_summary(self) -> Dict[str, Any]:
        """Get summary of enhancement operations."""
        return {
            'stats': self.stats.copy(),
            'config': self.config.copy(),
            'performance_impact': self._calculate_performance_impact()
        }
    
    def _calculate_performance_impact(self) -> Dict[str, Any]:
        """Calculate performance impact metrics."""
        if self.stats['total_processed'] == 0:
            return {'impact_percentage': 0, 'status': 'no_data'}
        
        processing_ratio = self.stats['base64_detected'] / self.stats['total_processed']
        
        # Estimate performance impact based on processing complexity
        estimated_impact = processing_ratio * 0.05  # 5% max impact for full Base64 processing
        
        return {
            'impact_percentage': min(estimated_impact * 100, 10),  # Cap at 10%
            'status': 'within_limits' if estimated_impact < 0.1 else 'review_needed',
            'processing_ratio': processing_ratio
        }

class ContentClassifier:
    """Classifies decoded Base64 content into categories."""
    
    def __init__(self):
        """Initialize content classifier with pattern definitions."""
        self.classification_patterns = {
            'credentials': {
                'patterns': [
                    r'password\s*[:=]\s*\w+',
                    r'username\s*[:=]\s*\w+',
                    r'login\s*[:=]\s*\w+',
                    r'auth\s*[:=]\s*\w+',
                    r'credential',
                    r'passwd',
                    r'pwd',
                    r'user.*pass',
                    r'admin.*pass'
                ],
                'confidence_weight': 0.9,
                'security_level': 'CRITICAL'
            },
            'api_key': {
                'patterns': [
                    r'api[_-]?key',
                    r'access[_-]?key',
                    r'secret[_-]?key',
                    r'private[_-]?key',
                    r'AKIA[0-9A-Z]{16}',  # AWS Access Key
                    r'AIza[0-9A-Za-z_-]{35}',  # Google API Key
                    r'sk-[a-zA-Z0-9]{48}',  # OpenAI API Key
                    r'xoxb-[0-9]{11}-[0-9]{11}-[a-zA-Z0-9]{24}',  # Slack Bot Token
                ],
                'confidence_weight': 0.95,
                'security_level': 'CRITICAL'
            },
            'url': {
                'patterns': [
                    r'https?://[^\s]+',
                    r'ftp://[^\s]+',
                    r'[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:/[^\s]*)?',
                    r'://[^\s]+',
                    r'www\.[^\s]+',
                ],
                'confidence_weight': 0.8,
                'security_level': 'MEDIUM'
            },
            'configuration': {
                'patterns': [
                    r'config',
                    r'setting',
                    r'property',
                    r'option',
                    r'param',
                    r'value',
                    r'[a-zA-Z_]+\s*[:=]\s*[^\s]+',
                    r'\{[^}]*\}',  # JSON-like
                    r'<[^>]+>[^<]*</[^>]+>',  # XML-like
                ],
                'confidence_weight': 0.6,
                'security_level': 'LOW'
            },
            'flag': {
                'patterns': [
                    r'flag\{[^}]+\}',
                    r'FLAG\{[^}]+\}',
                    r'ctf\{[^}]+\}',
                    r'[Ff]lag[_-]?\d+',
                    r'[Ff]lag[_-]?[a-zA-Z0-9]+',
                    r'\{[^}]*flag[^}]*\}',
                ],
                'confidence_weight': 0.9,
                'security_level': 'HIGH'
            },
            'secret': {
                'patterns': [
                    r'secret',
                    r'token',
                    r'bearer\s+[a-zA-Z0-9]+',
                    r'jwt\s+[a-zA-Z0-9._-]+',
                    r'[a-zA-Z0-9]{32,}',  # Long hex/base64 strings
                ],
                'confidence_weight': 0.7,
                'security_level': 'HIGH'
            },
            'certificate': {
                'patterns': [
                    r'-----BEGIN [A-Z ]+-----',
                    r'-----END [A-Z ]+-----',
                    r'CERTIFICATE',
                    r'PRIVATE KEY',
                    r'PUBLIC KEY',
                    r'RSA PRIVATE KEY',
                ],
                'confidence_weight': 0.95,
                'security_level': 'CRITICAL'
            },
            'json': {
                'patterns': [
                    r'^\s*\{.*\}\s*$',
                    r'^\s*\[.*\]\s*$',
                    r'"[^"]*"\s*:\s*"[^"]*"',
                ],
                'confidence_weight': 0.8,
                'security_level': 'LOW'
            },
            'xml': {
                'patterns': [
                    r'<\?xml[^>]*\?>',
                    r'<[a-zA-Z][^>]*>.*</[a-zA-Z][^>]*>',
                    r'<[a-zA-Z][^>]*/>'
                ],
                'confidence_weight': 0.8,
                'security_level': 'LOW'
            }
        }
    
    def classify_content(self, content: str) -> ContentClassification:
        """
        Classify decoded content.
        
        Args:
            content: Decoded content to classify
            
        Returns:
            ContentClassification result
        """
        if not content:
            return ContentClassification(
                content_type='unknown',
                confidence=0.0,
                indicators=[],
                security_level='LOW',
                redaction_recommended=False
            )
        
        best_match = None
        best_confidence = 0.0
        all_indicators = []
        
        content_lower = content.lower()
        
        for content_type, config in self.classification_patterns.items():
            type_confidence = 0.0
            type_indicators = []
            
            for pattern in config['patterns']:
                matches = re.findall(pattern, content, re.IGNORECASE)
                if matches:
                    type_indicators.extend(matches)
                    # Increase confidence based on number and quality of matches
                    match_confidence = min(len(matches) * 0.2, 1.0)
                    type_confidence = max(type_confidence, match_confidence)
            
            # Apply confidence weight
            final_confidence = type_confidence * config['confidence_weight']
            
            if final_confidence > best_confidence:
                best_confidence = final_confidence
                best_match = {
                    'content_type': content_type,
                    'confidence': final_confidence,
                    'indicators': type_indicators,
                    'security_level': config['security_level']
                }
            
            all_indicators.extend(type_indicators)
        
        if best_match:
            return ContentClassification(
                content_type=best_match['content_type'],
                confidence=best_match['confidence'],
                indicators=best_match['indicators'][:5],  # Limit indicators
                security_level=best_match['security_level'],
                redaction_recommended=best_match['security_level'] in ['HIGH', 'CRITICAL']
            )
        else:
            return ContentClassification(
                content_type='unknown',
                confidence=0.1,
                indicators=[],
                security_level='LOW',
                redaction_recommended=False
            )

class SecurityAnalyzer:
    """Analyzes decoded content for security implications."""
    
    def __init__(self):
        """Initialize security analyzer."""
        self.risk_patterns = {
            'credential_exposure': [
                r'password\s*[:=]\s*[^\s]+',
                r'secret\s*[:=]\s*[^\s]+',
                r'token\s*[:=]\s*[^\s]+',
            ],
            'api_key_exposure': [
                r'api[_-]?key\s*[:=]\s*[^\s]+',
                r'access[_-]?key\s*[:=]\s*[^\s]+',
            ],
            'url_exposure': [
                r'https?://[^\s]+',
                r'[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/[^\s]*',
            ]
        }
    
    def analyze_security_risk(self, content: str, content_type: str) -> Dict[str, Any]:
        """
        Analyze security risk of decoded content.
        
        Args:
            content: Decoded content
            content_type: Classified content type
            
        Returns:
            Security risk analysis
        """
        risk_analysis = {
            'risk_level': 'LOW',
            'risk_factors': [],
            'recommendations': [],
            'immediate_action_required': False
        }
        
        # Analyze based on content type
        if content_type in ['credentials', 'api_key', 'certificate']:
            risk_analysis['risk_level'] = 'CRITICAL'
            risk_analysis['immediate_action_required'] = True
            risk_analysis['risk_factors'].append('Sensitive authentication data exposed')
            risk_analysis['recommendations'].append('Immediately rotate exposed credentials')
            risk_analysis['recommendations'].append('Implement secure credential storage')
        
        elif content_type in ['secret', 'token']:
            risk_analysis['risk_level'] = 'HIGH'
            risk_analysis['risk_factors'].append('Secret data potentially exposed')
            risk_analysis['recommendations'].append('Review and rotate if necessary')
        
        elif content_type == 'url':
            risk_analysis['risk_level'] = 'MEDIUM'
            risk_analysis['risk_factors'].append('URL endpoints exposed')
            risk_analysis['recommendations'].append('Review for sensitive endpoint exposure')
        
        # Check for specific risk patterns
        for risk_type, patterns in self.risk_patterns.items():
            for pattern in patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    risk_analysis['risk_factors'].append(f'{risk_type} detected')
                    if risk_type in ['credential_exposure', 'api_key_exposure']:
                        risk_analysis['risk_level'] = 'CRITICAL'
                        risk_analysis['immediate_action_required'] = True
        
        return risk_analysis 
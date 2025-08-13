"""
Encoding Analyzer for AODS Framework.

This module provides comprehensive analysis of encoding vulnerabilities
in Android applications, specifically targeting patterns found in Android
security testing scenarios.

Features:
- Base64 used as encryption detection with entropy analysis
- ROT47/Caesar cipher detection and decoding
- Multi-layer encoding chain analysis
- XOR cipher detection in Flutter applications
- Comprehensive encoding security assessment

This analyzer specializes in identifying applications that use encoding
as a security mechanism, particularly those that mistake encoding for
encryption or use weak encoding-based obfuscation techniques.
"""

import base64
import hashlib
import json
import logging
import math
import os
import re
import time
from typing import Dict, List, Optional, Any, Tuple, Set
from pathlib import Path
from rich.text import Text
from rich.table import Table
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn

logger = logging.getLogger(__name__)

class EncodingAnalyzer:
    """
    Comprehensive encoding analyzer for Android applications.
    
    This analyzer identifies and analyzes encoding vulnerabilities in Android
    applications, with particular focus on cases where encoding is incorrectly
    used as a security mechanism or where weak encoding patterns expose
    sensitive information.
    """
    
    def __init__(self, apk_context=None):
        """
        Initialize the encoding analyzer.
        
        Args:
            apk_context: APK context object containing application metadata
        """
        self.apk_context = apk_context
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        self.console = Console()
        
        # Encoding patterns and detection rules
        self.encoding_patterns = {
            'base64': {
                'description': 'Base64 used as encryption detection',
                'patterns': [
                    r'[A-Za-z0-9+/]{20,}={0,2}',  # Base64 pattern
                    r'Base64\.encode\s*\(',
                    r'Base64\.decode\s*\(',
                    r'android\.util\.Base64',
                    r'java\.util\.Base64'
                ],
                'false_positive_indicators': [
                    'image', 'png', 'jpg', 'jpeg', 'gif', 'bitmap',
                    'icon', 'logo', 'picture', 'photo'
                ]
            },
            'rot47': {
                'description': 'ROT47/Caesar cipher detection',
                'patterns': [
                    r'[!-~]{10,}',  # ROT47 character range
                    r'charAt\s*\(\s*[^)]*\s*\)\s*[+\-]\s*\d+',
                    r'String\.valueOf\s*\(\s*\(char\)',
                    r'for\s*\([^)]*char[^)]*\)'
                ],
                'rotation_values': [13, 47, 25, 1, 2, 3, 4, 5]
            },
            'xor': {
                'description': 'XOR cipher detection',
                'patterns': [
                    r'\^\s*0x[0-9a-fA-F]+',
                    r'\^\s*\d+',
                    r'xor\s*\(',
                    r'XOR',
                    r'key\s*\^\s*',
                    r'data\s*\^\s*'
                ],
                'common_keys': ['MAD', 'KEY', 'XOR', '123', 'ABC', 'DEF']
            },
            'hex': {
                'description': 'Hexadecimal encoding detection',
                'patterns': [
                    r'0x[0-9a-fA-F]{4,}',
                    r'[0-9a-fA-F]{8,}',
                    r'Integer\.parseInt\s*\([^)]*,\s*16\)',
                    r'Long\.parseLong\s*\([^)]*,\s*16\)'
                ]
            },
            'multi_layer': {
                'description': 'Multi-layer encoding chains',
                'patterns': [
                    r'decode\s*\([^)]*decode\s*\(',
                    r'encode\s*\([^)]*encode\s*\(',
                    r'Base64[^;]*Base64',
                    r'decrypt\s*\([^)]*decrypt\s*\('
                ]
            }
        }
        
        # Analysis results
        self.encoding_findings = []
        self.decoded_content = []
        self.entropy_analysis = []
        self.security_implications = []
        
        # Statistics
        self.analysis_stats = {
            'patterns_found': 0,
            'successful_decodes': 0,
            'high_entropy_findings': 0,
            'security_issues': 0
        }
        
        self.logger.debug("Encoding Analyzer initialized")

    def analyze_encoding_vulnerabilities(self, deep_mode: bool = False) -> Tuple[str, Text]:
        """
        Comprehensive encoding vulnerability analysis.

        Args:
            deep_mode: Whether to perform deep analysis

        Returns:
            Tuple of (analysis_title, analysis_results)
        """
        self.logger.debug("Starting encoding vulnerability analysis")
        
        try:
            # Initialize progress tracking
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                console=self.console
            ) as progress:
                
                # Analysis phases
                pattern_task = progress.add_task("Analyzing encoding patterns", total=100)
                entropy_task = progress.add_task("Performing entropy analysis", total=100)
                decode_task = progress.add_task("Attempting decode operations", total=100)
                security_task = progress.add_task("Assessing security implications", total=100)
                
                # Phase 1: Pattern analysis
                progress.update(pattern_task, advance=20)
                self._analyze_encoding_patterns()
                progress.update(pattern_task, advance=60)
                
                # Phase 2: Entropy analysis
                progress.update(entropy_task, advance=25)
                self._perform_entropy_analysis()
                progress.update(entropy_task, advance=75)
                
                # Phase 3: Decode operations
                progress.update(decode_task, advance=30)
                self._attempt_decode_operations()
                progress.update(decode_task, advance=70)
                
                # Phase 4: Security assessment
                progress.update(security_task, advance=40)
                self._assess_security_implications()
                progress.update(security_task, advance=60)
                
                # Complete analysis
                progress.update(pattern_task, completed=100)
                progress.update(entropy_task, completed=100)
                progress.update(decode_task, completed=100)
                progress.update(security_task, completed=100)
            
            # Generate comprehensive report
            report = self._generate_encoding_report()
            
            self.logger.debug(f"Encoding analysis completed. Found {len(self.encoding_findings)} findings")
            
            return "Encoding Vulnerability Analysis", report
            
        except Exception as e:
            self.logger.error(f"Encoding analysis failed: {e}")
            return "Encoding Vulnerability Analysis", Text(f"Analysis failed: {str(e)}", style="red")

    def _analyze_encoding_patterns(self):
        """Analyze encoding patterns in the application."""
        self.logger.debug("Analyzing encoding patterns")
        
        try:
            if not self.apk_context:
                self.logger.warning("No APK context available for pattern analysis")
                return
            
            # Analyze source files
            source_files = getattr(self.apk_context, 'source_files', [])
            for file_path in source_files:
                self._analyze_file_for_encoding(file_path)
            
            # Analyze strings
            strings_data = getattr(self.apk_context, 'strings', [])
            self._analyze_strings_for_encoding(strings_data)
            
            # Analyze resources
            resources_data = getattr(self.apk_context, 'resources', {})
            self._analyze_resources_for_encoding(resources_data)
            
            self.analysis_stats['patterns_found'] = len(self.encoding_findings)

        except Exception as e:
            self.logger.error(f"Encoding pattern analysis failed: {e}")

    def _analyze_file_for_encoding(self, file_path: str):
        """Analyze individual file for encoding patterns."""
        try:
            if not os.path.exists(file_path):
                return
            
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Check each encoding pattern type
            for encoding_type, encoding_data in self.encoding_patterns.items():
                for pattern in encoding_data['patterns']:
                    matches = re.finditer(pattern, content, re.IGNORECASE)
                    
                    for match in matches:
                        # Skip false positives
                        if self._is_false_positive(match.group(), encoding_type):
                            continue

                        finding = {
                            'type': encoding_type,
                            'pattern': pattern,
                            'match': match.group(),
                            'file_path': file_path,
                            'line': content[:match.start()].count('\n') + 1,
                            'context': self._extract_context(content, match.start(), match.end()),
                            'confidence': self._calculate_confidence(match.group(), encoding_type),
                            'description': encoding_data['description']
                        }
                        
                        self.encoding_findings.append(finding)
                        
        except Exception as e:
            self.logger.error(f"File encoding analysis failed for {file_path}: {e}")

    def _analyze_strings_for_encoding(self, strings_data: List[str]):
        """Analyze strings for encoding patterns."""
        try:
            for string_value in strings_data:
                # Check for Base64 patterns
                if self._is_base64_string(string_value):
                    finding = {
                        'type': 'base64',
                        'match': string_value,
                        'source': 'strings',
                        'confidence': 0.8,
                        'description': 'Base64 encoded string detected',
                        'entropy': self._calculate_entropy(string_value)
                    }
                    self.encoding_findings.append(finding)
                
                # Check for ROT47/Caesar cipher
                if self._is_rot47_string(string_value):
                    finding = {
                        'type': 'rot47',
                        'match': string_value,
                        'source': 'strings',
                        'confidence': 0.6,
                        'description': 'ROT47/Caesar cipher detected',
                        'entropy': self._calculate_entropy(string_value)
                    }
                    self.encoding_findings.append(finding)
                
                # Check for XOR patterns
                if self._is_xor_string(string_value):
                    finding = {
                        'type': 'xor',
                        'match': string_value,
                        'source': 'strings',
                        'confidence': 0.7,
                        'description': 'XOR cipher pattern detected',
                        'entropy': self._calculate_entropy(string_value)
                    }
                    self.encoding_findings.append(finding)
                    
        except Exception as e:
            self.logger.error(f"String encoding analysis failed: {e}")

    def _analyze_resources_for_encoding(self, resources_data: Dict[str, Any]):
        """Analyze resources for encoding patterns."""
        try:
            for resource_type, resource_content in resources_data.items():
                if isinstance(resource_content, str):
                    # Check for encoded content in resources
                    if self._is_base64_string(resource_content):
                        finding = {
                            'type': 'base64',
                            'match': resource_content[:100] + '...' if len(resource_content) > 100 else resource_content,
                            'source': f'resource_{resource_type}',
                            'confidence': 0.7,
                            'description': 'Base64 encoded resource detected',
                            'entropy': self._calculate_entropy(resource_content)
                        }
                        self.encoding_findings.append(finding)
                        
        except Exception as e:
            self.logger.error(f"Resource encoding analysis failed: {e}")

    def _is_false_positive(self, match: str, encoding_type: str) -> bool:
        """Check if match is a false positive."""
        if encoding_type == 'base64':
            # Check for image/media content indicators
            false_positive_indicators = self.encoding_patterns['base64']['false_positive_indicators']
            match_lower = match.lower()
            return any(indicator in match_lower for indicator in false_positive_indicators)
        
        return False

    def _is_base64_string(self, text: str) -> bool:
        """Check if text is Base64 encoded."""
        try:
            # Basic length and character check
            if len(text) < 4 or len(text) % 4 != 0:
                return False
            
            # Character set check
            base64_pattern = r'^[A-Za-z0-9+/]*={0,2}$'
            if not re.match(base64_pattern, text):
                return False
            
            # Try to decode
            base64.b64decode(text)
            return True
            
        except:
            return False

    def _is_rot47_string(self, text: str) -> bool:
        """Check if text is ROT47 encoded."""
        try:
            # Check character range (printable ASCII)
            if not all(33 <= ord(c) <= 126 for c in text):
                return False
            
            # Check for common ROT47 patterns
            rot47_indicators = ['!', '"', '#', '$', '%', '&', "'", '(', ')', '*']
            indicator_count = sum(1 for char in text if char in rot47_indicators)
            
            return indicator_count > len(text) * 0.3  # 30% threshold
            
        except:
            return False

    def _is_xor_string(self, text: str) -> bool:
        """Check if text shows XOR cipher characteristics."""
        try:
            # Check for repeating patterns (XOR key reuse)
            if len(text) < 8:
                return False
            
            # Check entropy - XOR with short key shows patterns
            entropy = self._calculate_entropy(text)
            if entropy < 3.0:  # Low entropy suggests pattern
                return True
            
            # Check for non-printable characters
            non_printable = sum(1 for c in text if ord(c) < 32 or ord(c) > 126)
            return non_printable > len(text) * 0.2  # 20% threshold
            
        except:
            return False

    def _calculate_entropy(self, text: str) -> float:
        """Calculate entropy of text."""
        try:
            if not text:
                return 0.0
            
            # Count character frequencies
            char_counts = {}
            for char in text:
                char_counts[char] = char_counts.get(char, 0) + 1
            
            # Calculate entropy
            entropy = 0.0
            text_length = len(text)
            
            for count in char_counts.values():
                probability = count / text_length
                entropy -= probability * math.log2(probability)
            
            return entropy
            
        except:
            return 0.0

    def _calculate_confidence(self, match: str, encoding_type: str) -> float:
        """Calculate confidence score for encoding detection."""
        base_confidence = {
            'base64': 0.8,
            'rot47': 0.6,
            'xor': 0.7,
            'hex': 0.7,
            'multi_layer': 0.9
        }.get(encoding_type, 0.5)
        
        # Adjust based on match length
        length_factor = min(len(match) / 20, 1.0)  # Longer matches more confident
        
        # Adjust based on entropy
        entropy = self._calculate_entropy(match)
        entropy_factor = min(entropy / 4.0, 1.0)  # Higher entropy more confident
        
        return base_confidence * length_factor * entropy_factor

    def _extract_context(self, content: str, start: int, end: int, context_size: int = 80) -> str:
        """Extract context around a match."""
        try:
            context_start = max(0, start - context_size)
            context_end = min(len(content), end + context_size)
            return content[context_start:context_end].strip()
        except:
            return ""

    def _perform_entropy_analysis(self):
        """Perform entropy analysis on detected patterns."""
        self.logger.debug("Performing entropy analysis")
        
        try:
            for finding in self.encoding_findings:
                match = finding['match']
                entropy = self._calculate_entropy(match)
                
                analysis = {
                    'finding_id': id(finding),
                    'entropy': entropy,
                    'classification': self._classify_entropy(entropy),
                    'security_risk': self._assess_entropy_risk(entropy),
                    'recommendations': self._get_entropy_recommendations(entropy)
                }
                
                self.entropy_analysis.append(analysis)
                
                # Update statistics
                if entropy > 6.0:  # High entropy threshold
                    self.analysis_stats['high_entropy_findings'] += 1
                    
        except Exception as e:
            self.logger.error(f"Entropy analysis failed: {e}")

    def _classify_entropy(self, entropy: float) -> str:
        """Classify entropy level."""
        if entropy >= 7.0:
            return "Very High"
        elif entropy >= 5.0:
            return "High"
        elif entropy >= 3.0:
            return "Medium"
        elif entropy >= 1.0:
            return "Low"
        else:
            return "Very Low"

    def _assess_entropy_risk(self, entropy: float) -> str:
        """Assess security risk based on entropy."""
        if entropy < 2.0:
            return "HIGH - Weak encoding, easily breakable"
        elif entropy < 4.0:
            return "MEDIUM - Moderate encoding strength"
        elif entropy < 6.0:
            return "LOW - Good encoding strength"
        else:
            return "VERY LOW - Strong encoding"

    def _get_entropy_recommendations(self, entropy: float) -> List[str]:
        """Get recommendations based on entropy."""
        if entropy < 2.0:
            return [
                "Replace weak encoding with strong encryption",
                "Use cryptographically secure random keys",
                "Implement proper key management"
            ]
        elif entropy < 4.0:
            return [
                "Consider stronger encryption algorithms",
                "Increase key length and complexity",
                "Add additional security layers"
            ]
        else:
            return [
                "Encoding appears strong",
                "Verify proper key management",
                "Consider additional authentication"
            ]

    def _attempt_decode_operations(self):
        """Attempt to decode detected patterns."""
        self.logger.debug("Attempting decode operations")
        
        try:
            for finding in self.encoding_findings:
                encoding_type = finding['type']
                match = finding['match']
                
                decoded_result = None
                
                if encoding_type == 'base64':
                    decoded_result = self._decode_base64(match)
                elif encoding_type == 'rot47':
                    decoded_result = self._decode_rot47(match)
                elif encoding_type == 'xor':
                    decoded_result = self._decode_xor(match)
                elif encoding_type == 'hex':
                    decoded_result = self._decode_hex(match)
                
                if decoded_result:
                    decode_info = {
                        'finding_id': id(finding),
                        'original': match,
                        'decoded': decoded_result,
                        'encoding_type': encoding_type,
                        'success': True,
                        'confidence': finding.get('confidence', 0.5)
                    }
                    
                    # Check if decoded content reveals sensitive information
                    if self._is_sensitive_content(decoded_result):
                        decode_info['security_risk'] = 'HIGH'
                        decode_info['description'] = 'Encoded content contains sensitive information'
                        self.analysis_stats['security_issues'] += 1
                    
                    self.decoded_content.append(decode_info)
                    self.analysis_stats['successful_decodes'] += 1
                    
        except Exception as e:
            self.logger.error(f"Decode operations failed: {e}")

    def _decode_base64(self, text: str) -> Optional[str]:
        """Attempt to decode Base64 text."""
        try:
            decoded_bytes = base64.b64decode(text)
            return decoded_bytes.decode('utf-8', errors='ignore')
        except:
            return None

    def _decode_rot47(self, text: str) -> Optional[str]:
        """Attempt to decode ROT47 text."""
        try:
            # Try different rotation values
            for rotation in self.encoding_patterns['rot47']['rotation_values']:
                decoded = ""
                for char in text:
                    if 33 <= ord(char) <= 126:
                        decoded += chr(33 + (ord(char) - 33 + rotation) % 94)
                    else:
                        decoded += char
                
                # Check if result looks like readable text
                if self._is_readable_text(decoded):
                    return decoded
            
            return None
            
        except:
            return None

    def _decode_xor(self, text: str) -> Optional[str]:
        """Attempt to decode XOR cipher."""
        try:
            # Try common XOR keys
            for key in self.encoding_patterns['xor']['common_keys']:
                decoded = ""
                key_bytes = key.encode('utf-8')
                
                for i, char in enumerate(text):
                    key_char = key_bytes[i % len(key_bytes)]
                    decoded += chr(ord(char) ^ key_char)
                
                if self._is_readable_text(decoded):
                    return decoded
            
            return None
            
        except:
            return None

    def _decode_hex(self, text: str) -> Optional[str]:
        """Attempt to decode hexadecimal text."""
        try:
            # Remove 0x prefix if present
            hex_text = text.replace('0x', '')
            
            # Try to decode as hex
            decoded_bytes = bytes.fromhex(hex_text)
            return decoded_bytes.decode('utf-8', errors='ignore')
            
        except:
            return None

    def _is_readable_text(self, text: str) -> bool:
        """Check if text is readable."""
        try:
            # Check for common English words
            common_words = ['the', 'and', 'for', 'are', 'but', 'not', 'you', 'all', 'can', 'had', 'was', 'one', 'our', 'out', 'day', 'get', 'has', 'him', 'his', 'how', 'man', 'new', 'now', 'old', 'see', 'two', 'way', 'who', 'boy', 'did', 'its', 'let', 'put', 'say', 'she', 'too', 'use']
            
            text_lower = text.lower()
            word_count = sum(1 for word in common_words if word in text_lower)
            
            # Check printable character ratio
            printable_ratio = sum(1 for c in text if c.isprintable()) / len(text) if text else 0
            
            return word_count >= 2 and printable_ratio > 0.8
            
        except:
            return False

    def _is_sensitive_content(self, content: str) -> bool:
        """Check if content contains sensitive information."""
        try:
            sensitive_patterns = [
                r'password', r'passwd', r'pwd',
                r'secret', r'key', r'token',
                r'api[_-]?key', r'access[_-]?token',
                r'username', r'user[_-]?name',
                r'email', r'phone', r'ssn',
                r'credit[_-]?card', r'account',
                r'private[_-]?key', r'certificate'
            ]
            
            content_lower = content.lower()
            return any(re.search(pattern, content_lower) for pattern in sensitive_patterns)
            
        except:
            return False

    def _assess_security_implications(self):
        """Assess security implications of findings."""
        self.logger.debug("Assessing security implications")
        
        try:
            # Group findings by type
            findings_by_type = {}
            for finding in self.encoding_findings:
                encoding_type = finding['type']
                if encoding_type not in findings_by_type:
                    findings_by_type[encoding_type] = []
                findings_by_type[encoding_type].append(finding)
            
            # Assess each type
            for encoding_type, findings in findings_by_type.items():
                implication = {
                    'encoding_type': encoding_type,
                    'finding_count': len(findings),
                    'risk_level': self._assess_type_risk(encoding_type, findings),
                    'security_issues': self._identify_security_issues(encoding_type, findings),
                    'recommendations': self._get_security_recommendations(encoding_type),
                    'affected_files': list(set(f.get('file_path', 'unknown') for f in findings))
                }
                
                self.security_implications.append(implication)
                
        except Exception as e:
            self.logger.error(f"Security assessment failed: {e}")

    def _assess_type_risk(self, encoding_type: str, findings: List[Dict[str, Any]]) -> str:
        """Assess risk level for encoding type."""
        risk_levels = {
            'base64': 'HIGH',  # Often mistaken for encryption
            'rot47': 'MEDIUM',  # Weak cipher
            'xor': 'HIGH',  # Can be strong or weak
            'hex': 'LOW',  # Just representation
            'multi_layer': 'CRITICAL'  # Multiple layers suggest obfuscation
        }
        
        base_risk = risk_levels.get(encoding_type, 'MEDIUM')
        
        # Increase risk if many findings
        if len(findings) > 10:
            risk_mapping = {'LOW': 'MEDIUM', 'MEDIUM': 'HIGH', 'HIGH': 'CRITICAL'}
            base_risk = risk_mapping.get(base_risk, 'CRITICAL')
        
        return base_risk

    def _identify_security_issues(self, encoding_type: str, findings: List[Dict[str, Any]]) -> List[str]:
        """Identify security issues for encoding type."""
        issues_map = {
            'base64': [
                'Base64 is encoding, not encryption',
                'Sensitive data may be easily decoded',
                'No security protection provided',
                'Data exposure risk'
            ],
            'rot47': [
                'ROT47 is a weak cipher',
                'Easily breakable with frequency analysis',
                'No cryptographic security',
                'Trivial to reverse engineer'
            ],
            'xor': [
                'XOR cipher strength depends on key',
                'Short keys are easily broken',
                'Key reuse creates vulnerabilities',
                'No authentication provided'
            ],
            'hex': [
                'Hexadecimal is just representation',
                'No security protection',
                'Data easily readable',
                'May expose sensitive information'
            ],
            'multi_layer': [
                'Multiple encoding layers suggest obfuscation',
                'May hide malicious functionality',
                'Complicates security analysis',
                'Potential security through obscurity'
            ]
        }
        
        return issues_map.get(encoding_type, ['General encoding security concerns'])

    def _get_security_recommendations(self, encoding_type: str) -> List[str]:
        """Get security recommendations for encoding type."""
        recommendations_map = {
            'base64': [
                'Replace Base64 with proper encryption',
                'Use AES or similar strong encryption',
                'Implement proper key management',
                'Add authentication mechanisms'
            ],
            'rot47': [
                'Replace ROT47 with strong encryption',
                'Use cryptographically secure algorithms',
                'Implement proper key generation',
                'Add integrity protection'
            ],
            'xor': [
                'Use cryptographically secure keys',
                'Implement proper key management',
                'Add authentication and integrity',
                'Consider stronger algorithms'
            ],
            'hex': [
                'Encrypt sensitive data before encoding',
                'Use proper access controls',
                'Implement data classification',
                'Add logging and monitoring'
            ],
            'multi_layer': [
                'Simplify encoding architecture',
                'Use transparent security measures',
                'Implement proper documentation',
                'Add security code review'
            ]
        }
        
        return recommendations_map.get(encoding_type, ['Implement general security best practices'])

    def _generate_encoding_report(self) -> Text:
        """Generate comprehensive encoding analysis report."""
        report = Text()
        
        # Header
        report.append("🔐 Encoding Vulnerability Analysis Report\n", style="bold blue")
        report.append("=" * 50 + "\n\n", style="blue")
        
        # Summary statistics
        report.append("📊 Analysis Summary:\n", style="bold green")
        report.append(f"• Encoding patterns found: {len(self.encoding_findings)}\n", style="green")
        report.append(f"• Successful decodes: {self.analysis_stats['successful_decodes']}\n", style="green")
        report.append(f"• High entropy findings: {self.analysis_stats['high_entropy_findings']}\n", style="green")
        report.append(f"• Security issues: {self.analysis_stats['security_issues']}\n", style="red")
        report.append("\n")
        
        # Encoding findings
        if self.encoding_findings:
            report.append("🔍 Encoding Findings:\n", style="bold yellow")
            for i, finding in enumerate(self.encoding_findings[:10], 1):  # Top 10
                report.append(f"{i}. {finding['description']}\n", style="yellow")
                report.append(f"   Type: {finding['type']}\n", style="dim")
                report.append(f"   Confidence: {finding.get('confidence', 0.0):.2f}\n", style="dim")
                if 'file_path' in finding:
                    report.append(f"   File: {finding['file_path']}\n", style="dim")
                if 'line' in finding:
                    report.append(f"   Line: {finding['line']}\n", style="dim")
                report.append("\n")
        
        # Decoded content
        if self.decoded_content:
            report.append("🔓 Decoded Content:\n", style="bold cyan")
            for i, decode in enumerate(self.decoded_content[:5], 1):  # Top 5
                report.append(f"{i}. Type: {decode['encoding_type']}\n", style="cyan")
                report.append(f"   Original: {decode['original'][:50]}...\n", style="dim")
                report.append(f"   Decoded: {decode['decoded'][:50]}...\n", style="green")
                if 'security_risk' in decode:
                    report.append(f"   Security Risk: {decode['security_risk']}\n", style="red")
                report.append("\n")
        
        # Security implications
        if self.security_implications:
            report.append("⚠️ Security Implications:\n", style="bold red")
            for implication in self.security_implications:
                report.append(f"• {implication['encoding_type'].upper()}: {implication['risk_level']} Risk\n", style="red")
                report.append(f"  Findings: {implication['finding_count']}\n", style="dim")
                report.append(f"  Files: {len(implication['affected_files'])}\n", style="dim")
                report.append("\n")
        
        # Security recommendations
        report.append("🛡️ Security Recommendations:\n", style="bold green")
        if self.security_implications:
            all_recommendations = set()
            for implication in self.security_implications:
                all_recommendations.update(implication['recommendations'])
            
            for rec in sorted(all_recommendations):
                report.append(f"• {rec}\n", style="green")
        else:
            report.append("• No encoding vulnerabilities detected\n", style="green")
            report.append("• Continue monitoring for weak encoding patterns\n", style="green")
        
        return report

    def get_analysis_statistics(self) -> Dict[str, Any]:
        """Get comprehensive analysis statistics."""
        return {
            'total_findings': len(self.encoding_findings),
            'successful_decodes': self.analysis_stats['successful_decodes'],
            'high_entropy_findings': self.analysis_stats['high_entropy_findings'],
            'security_issues': self.analysis_stats['security_issues'],
            'encoding_types': list(set(f['type'] for f in self.encoding_findings)),
            'affected_files': len(set(f.get('file_path', 'unknown') for f in self.encoding_findings)),
            'analysis_quality': 'high' if len(self.encoding_findings) > 0 else 'medium'
        }

    def export_findings(self, output_file: str) -> bool:
        """Export findings to JSON file."""
        try:
            export_data = {
                'timestamp': time.time(),
                'analysis_type': 'encoding_vulnerability',
                'encoding_findings': self.encoding_findings,
                'decoded_content': self.decoded_content,
                'entropy_analysis': self.entropy_analysis,
                'security_implications': self.security_implications,
                'statistics': self.get_analysis_statistics()
            }
            
            with open(output_file, 'w') as f:
                json.dump(export_data, f, indent=2)
            
            self.logger.debug(f"Findings exported to: {output_file}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to export findings: {e}")
        return False
    
# Enhanced functions for plugin integration

def analyze_encoding_vulnerabilities_comprehensive(apk_context, deep_mode: bool = False) -> Tuple[str, Text]:
    """
    Comprehensive encoding vulnerability analysis function.
    
    Args:
        apk_context: APK context object
        deep_mode: Whether to perform deep analysis
        
    Returns:
        Tuple of (analysis_title, analysis_results)
    """
    analyzer = EncodingAnalyzer(apk_context)
    return analyzer.analyze_encoding_vulnerabilities(deep_mode)

def detect_encoding_patterns(apk_context) -> List[Dict[str, Any]]:
    """
    Detect encoding patterns in APK.
    
    Args:
        apk_context: APK context object
        
    Returns:
        List of encoding patterns
    """
    analyzer = EncodingAnalyzer(apk_context)
    analyzer._analyze_encoding_patterns()
    return analyzer.encoding_findings

def decode_encoded_content(apk_context) -> List[Dict[str, Any]]:
    """
    Decode encoded content found in APK.
    
    Args:
        apk_context: APK context object
        
    Returns:
        List of decoded content
    """
    analyzer = EncodingAnalyzer(apk_context)
    analyzer._analyze_encoding_patterns()
    analyzer._attempt_decode_operations()
    return analyzer.decoded_content

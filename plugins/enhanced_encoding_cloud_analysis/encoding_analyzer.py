"""
Advanced Encoding Analyzer Module

This module handles comprehensive encoding detection including Base64, ROT47, 
ciphers, multi-layer encoding chains, and Android-specific security patterns.
"""

import re
import base64
import binascii
import logging
from typing import List, Dict, Optional, Tuple, Set
from pathlib import Path

from .data_structures import (
    EncodingFinding, CipherFinding, EncodingChain, EncodingContext,
    EncodingType, CipherType, SeverityLevel, FileType, AnalysisPattern
)

logger = logging.getLogger(__name__)

class EncodingPatternLibrary:
    """Library of encoding detection patterns and algorithms."""
    
    def __init__(self):
        """Initialize encoding pattern library."""
        self._init_base64_patterns()
        self._init_rot_patterns()
        self._init_cipher_patterns()
        self._init_android_patterns()
    
    def _init_base64_patterns(self):
        """Initialize Base64 detection patterns."""
        # Standard Base64 patterns
        self.base64_patterns = [
            re.compile(r'[A-Za-z0-9+/]{20,}={0,2}'),  # Standard Base64
            re.compile(r'[A-Za-z0-9_-]{20,}={0,2}'),  # URL-safe Base64
            re.compile(r'(?:base64|b64)["\s]*[=:]["\s]*([A-Za-z0-9+/]{20,}={0,2})'),  # Labeled Base64
            re.compile(r'(?:encoded|encoding)["\s]*[=:]["\s]*([A-Za-z0-9+/]{20,}={0,2})'),  # Generic encoding
        ]
        
        # Android-specific Base64 patterns
        self.android_base64_patterns = [
            re.compile(r'Base64\.decode\(["\']([A-Za-z0-9+/]{20,}={0,2})["\']'),
            re.compile(r'Base64\.encode\(["\']([A-Za-z0-9+/]{20,}={0,2})["\']'),
            re.compile(r'android\.util\.Base64\.decode\(["\']([A-Za-z0-9+/]{20,}={0,2})["\']'),
        ]
    
    def _init_rot_patterns(self):
        """Initialize ROT cipher patterns."""
        self.rot_patterns = [
            re.compile(r'rot(?:13|47)["\s]*[=:]["\s]*([^\s"\']+)'),
            re.compile(r'(?:cipher|rotate)["\s]*[=:]["\s]*([^\s"\']+)'),
        ]
    
    def _init_cipher_patterns(self):
        """Initialize cipher detection patterns."""
        self.cipher_patterns = {
            CipherType.AES: [
                re.compile(r'AES[./]?(?:ECB|CBC|GCM|CTR)', re.IGNORECASE),
                re.compile(r'javax\.crypto\.Cipher\.getInstance\(["\']AES', re.IGNORECASE),
                re.compile(r'Cipher\.getInstance\(["\']AES/([^"\']+)["\']', re.IGNORECASE),
            ],
            CipherType.DES: [
                re.compile(r'DES[./]?(?:ECB|CBC)', re.IGNORECASE),
                re.compile(r'javax\.crypto\.Cipher\.getInstance\(["\']DES', re.IGNORECASE),
            ],
            CipherType.RSA: [
                re.compile(r'RSA[./]?(?:ECB|NONE)', re.IGNORECASE),
                re.compile(r'javax\.crypto\.Cipher\.getInstance\(["\']RSA', re.IGNORECASE),
                re.compile(r'KeyPairGenerator\.getInstance\(["\']RSA["\']', re.IGNORECASE),
            ],
            CipherType.RC4: [
                re.compile(r'RC4', re.IGNORECASE),
                re.compile(r'ARCFOUR', re.IGNORECASE),
            ],
            CipherType.BLOWFISH: [
                re.compile(r'Blowfish', re.IGNORECASE),
                re.compile(r'javax\.crypto\.Cipher\.getInstance\(["\']Blowfish', re.IGNORECASE),
            ]
        }
    
    def _init_android_patterns(self):
        """Initialize Android-specific security patterns."""
        self.android_security_patterns = [
            re.compile(r'firebase["\s]*[=:]["\s]*[A-Za-z0-9+/]{20,}={0,2}', re.IGNORECASE),
            re.compile(r'aws["\s]*[=:]["\s]*[A-Za-z0-9+/]{20,}={0,2}', re.IGNORECASE),
            re.compile(r's3["\s]*[=:]["\s]*[A-Za-z0-9+/]{20,}={0,2}', re.IGNORECASE),
            re.compile(r'api[_-]?key["\s]*[=:]["\s]*[A-Za-z0-9+/]{20,}={0,2}', re.IGNORECASE),
        ]

class EncodingDecoder:
    """Handles decoding of various encoding types."""
    
    @staticmethod
    def decode_base64(encoded_text: str) -> Tuple[bool, Optional[str]]:
        """
        Attempt to decode Base64 text.
        
        Returns:
            Tuple of (success, decoded_text)
        """
        try:
            # Add padding if needed
            padded = encoded_text + '=' * (4 - len(encoded_text) % 4)
            decoded_bytes = base64.b64decode(padded)
            decoded_text = decoded_bytes.decode('utf-8', errors='ignore')
            return True, decoded_text
        except Exception:
            try:
                # Try URL-safe Base64
                padded = encoded_text + '=' * (4 - len(encoded_text) % 4)
                decoded_bytes = base64.urlsafe_b64decode(padded)
                decoded_text = decoded_bytes.decode('utf-8', errors='ignore')
                return True, decoded_text
            except Exception:
                return False, None
    
    @staticmethod
    def decode_rot13(encoded_text: str) -> str:
        """Decode ROT13 text."""
        return ''.join(
            chr((ord(char) - 65 + 13) % 26 + 65) if 'A' <= char <= 'Z' else
            chr((ord(char) - 97 + 13) % 26 + 97) if 'a' <= char <= 'z' else
            char for char in encoded_text
        )
    
    @staticmethod
    def decode_rot47(encoded_text: str) -> str:
        """Decode ROT47 text."""
        return ''.join(
            chr((ord(char) - 33 + 47) % 94 + 33) if 33 <= ord(char) <= 126 else char
            for char in encoded_text
        )
    
    @staticmethod
    def decode_hex(encoded_text: str) -> Tuple[bool, Optional[str]]:
        """
        Attempt to decode hexadecimal text.
        
        Returns:
            Tuple of (success, decoded_text)
        """
        try:
            # Remove common hex prefixes
            clean_hex = encoded_text.replace('0x', '').replace('\\x', '')
            decoded_bytes = bytes.fromhex(clean_hex)
            decoded_text = decoded_bytes.decode('utf-8', errors='ignore')
            return True, decoded_text
        except Exception:
            return False, None
    
    @staticmethod
    def decode_url_encoding(encoded_text: str) -> str:
        """Decode URL-encoded text."""
        import urllib.parse
        return urllib.parse.unquote(encoded_text)

class AdvancedEncodingAnalyzer:
    """Advanced analyzer for encoding detection and security assessment."""
    
    def __init__(self):
        """Initialize the encoding analyzer."""
        self.pattern_library = EncodingPatternLibrary()
        self.decoder = EncodingDecoder()
        self.detected_encodings: Set[Tuple[str, str]] = set()  # Cache for deduplication
        
        # Analysis configuration
        self.min_base64_length = 20
        self.max_analysis_depth = 5
        self.confidence_threshold = 0.7
    
    def analyze_content(self, content: str, location: str, 
                       file_type: FileType = FileType.OTHER) -> List[EncodingFinding]:
        """
        Analyze content for encoding patterns and vulnerabilities.
        
        Args:
            content: Text content to analyze
            location: Location identifier for the content
            file_type: Type of file being analyzed
            
        Returns:
            List of encoding findings
        """
        findings = []
        
        if not content or not content.strip():
            return findings
        
        try:
            # Analyze different encoding types
            findings.extend(self._analyze_base64_patterns(content, location, file_type))
            findings.extend(self._analyze_rot_patterns(content, location, file_type))
            findings.extend(self._analyze_hex_patterns(content, location, file_type))
            findings.extend(self._analyze_android_patterns(content, location, file_type))
            
            # Detect multi-layer encoding chains
            encoding_chains = self._detect_encoding_chains(content, location, file_type)
            for chain in encoding_chains:
                findings.extend(self._create_findings_from_chain(chain, location, file_type))
            
        except Exception as e:
            logger.error(f"Error analyzing encoding content at {location}: {e}")
        
        return findings
    
    def _analyze_base64_patterns(self, content: str, location: str, 
                                file_type: FileType) -> List[EncodingFinding]:
        """Analyze content for Base64 patterns."""
        findings = []
        
        # Standard Base64 patterns
        for pattern in self.pattern_library.base64_patterns:
            for match in pattern.finditer(content):
                base64_text = match.group(0)
                
                # Skip if too short or already processed
                if len(base64_text) < self.min_base64_length:
                    continue
                
                cache_key = (base64_text, location)
                if cache_key in self.detected_encodings:
                    continue
                
                self.detected_encodings.add(cache_key)
                
                # Attempt to decode
                success, decoded = self.decoder.decode_base64(base64_text)
                
                if success and decoded and self._is_meaningful_content(decoded):
                    finding = self._create_encoding_finding(
                        encoding_type=EncodingType.BASE64,
                        encoded_content=base64_text,
                        decoded_content=decoded,
                        location=location,
                        file_type=file_type,
                        match_position=match.start(),
                        context_text=content[max(0, match.start()-50):match.end()+50]
                    )
                    
                    # Calculate confidence and severity
                    finding.confidence = self._calculate_base64_confidence(
                        base64_text, decoded, content, file_type
                    )
                    finding.severity = self._determine_encoding_severity(
                        finding, decoded, file_type
                    )
                    
                    findings.append(finding)
        
        # Android-specific Base64 patterns
        for pattern in self.pattern_library.android_base64_patterns:
            for match in pattern.finditer(content):
                base64_text = match.group(1) if match.groups() else match.group(0)
                
                cache_key = (base64_text, location)
                if cache_key in self.detected_encodings:
                    continue
                
                self.detected_encodings.add(cache_key)
                
                success, decoded = self.decoder.decode_base64(base64_text)
                
                if success and decoded:
                    finding = self._create_encoding_finding(
                        encoding_type=EncodingType.BASE64,
                        encoded_content=base64_text,
                        decoded_content=decoded,
                        location=location,
                        file_type=file_type,
                        match_position=match.start(),
                        context_text=content[max(0, match.start()-50):match.end()+50]
                    )
                    
                    # Android Base64 usage gets higher confidence
                    finding.confidence = min(1.0, self._calculate_base64_confidence(
                        base64_text, decoded, content, file_type
                    ) + 0.1)
                    
                    finding.severity = SeverityLevel.HIGH
                    finding.analysis_patterns.append(AnalysisPattern.ANDROID_SECURITY)
                    
                    findings.append(finding)
        
        return findings
    
    def _analyze_rot_patterns(self, content: str, location: str, 
                             file_type: FileType) -> List[EncodingFinding]:
        """Analyze content for ROT cipher patterns."""
        findings = []
        
        for pattern in self.pattern_library.rot_patterns:
            for match in pattern.finditer(content):
                rot_text = match.group(1) if match.groups() else match.group(0)
                
                cache_key = (rot_text, location)
                if cache_key in self.detected_encodings:
                    continue
                
                self.detected_encodings.add(cache_key)
                
                # Try ROT13 and ROT47
                rot13_decoded = self.decoder.decode_rot13(rot_text)
                rot47_decoded = self.decoder.decode_rot47(rot_text)
                
                # Determine which decoding is more meaningful
                if self._is_meaningful_content(rot13_decoded):
                    finding = self._create_encoding_finding(
                        encoding_type=EncodingType.ROT13,
                        encoded_content=rot_text,
                        decoded_content=rot13_decoded,
                        location=location,
                        file_type=file_type,
                        match_position=match.start(),
                        context_text=content[max(0, match.start()-50):match.end()+50]
                    )
                    findings.append(finding)
                
                elif self._is_meaningful_content(rot47_decoded):
                    finding = self._create_encoding_finding(
                        encoding_type=EncodingType.ROT47,
                        encoded_content=rot_text,
                        decoded_content=rot47_decoded,
                        location=location,
                        file_type=file_type,
                        match_position=match.start(),
                        context_text=content[max(0, match.start()-50):match.end()+50]
                    )
                    
                    # ROT47 encoding of Firebase URLs is a known pattern
                    if 'firebase' in rot47_decoded.lower():
                        finding.analysis_patterns.append(AnalysisPattern.FIREBASE_INTEGRATION)
                        finding.severity = SeverityLevel.HIGH
                    
                    findings.append(finding)
        
        return findings
    
    def _analyze_hex_patterns(self, content: str, location: str, 
                             file_type: FileType) -> List[EncodingFinding]:
        """Analyze content for hexadecimal patterns."""
        findings = []
        
        # Hex patterns
        hex_patterns = [
            re.compile(r'(?:0x|\\x)?([0-9a-fA-F]{20,})'),
            re.compile(r'hex["\s]*[=:]["\s]*([0-9a-fA-F]{20,})'),
        ]
        
        for pattern in hex_patterns:
            for match in pattern.finditer(content):
                hex_text = match.group(1) if match.groups() else match.group(0)
                
                cache_key = (hex_text, location)
                if cache_key in self.detected_encodings:
                    continue
                
                self.detected_encodings.add(cache_key)
                
                success, decoded = self.decoder.decode_hex(hex_text)
                
                if success and decoded and self._is_meaningful_content(decoded):
                    finding = self._create_encoding_finding(
                        encoding_type=EncodingType.HEX,
                        encoded_content=hex_text,
                        decoded_content=decoded,
                        location=location,
                        file_type=file_type,
                        match_position=match.start(),
                        context_text=content[max(0, match.start()-50):match.end()+50]
                    )
                    
                    finding.confidence = self._calculate_hex_confidence(
                        hex_text, decoded, content, file_type
                    )
                    
                    findings.append(finding)
        
        return findings
    
    def _analyze_android_patterns(self, content: str, location: str, 
                                 file_type: FileType) -> List[EncodingFinding]:
        """Analyze content for Android-specific security patterns."""
        findings = []
        
        for pattern in self.pattern_library.android_security_patterns:
            for match in pattern.finditer(content):
                encoded_text = match.group(0)
                
                # Extract the actual encoded value
                value_match = re.search(r'[A-Za-z0-9+/]{20,}={0,2}', encoded_text)
                if not value_match:
                    continue
                
                encoded_value = value_match.group(0)
                
                cache_key = (encoded_value, location)
                if cache_key in self.detected_encodings:
                    continue
                
                self.detected_encodings.add(cache_key)
                
                success, decoded = self.decoder.decode_base64(encoded_value)
                
                if success and decoded:
                    finding = self._create_encoding_finding(
                        encoding_type=EncodingType.BASE64,
                        encoded_content=encoded_value,
                        decoded_content=decoded,
                        location=location,
                        file_type=file_type,
                        match_position=match.start(),
                        context_text=content[max(0, match.start()-50):match.end()+50]
                    )
                    
                    # Set analysis pattern based on match content
                    if 'firebase' in encoded_text.lower():
                        finding.analysis_patterns.append(AnalysisPattern.FIREBASE_INTEGRATION)
                    elif 'aws' in encoded_text.lower() or 's3' in encoded_text.lower():
                        finding.analysis_patterns.append(AnalysisPattern.AWS_CREDENTIALS)
                    elif 'api' in encoded_text.lower():
                        finding.analysis_patterns.append(AnalysisPattern.CLOUD_ENDPOINTS)
                    
                    finding.analysis_patterns.append(AnalysisPattern.ANDROID_SECURITY)
                    finding.severity = SeverityLevel.HIGH
                    finding.confidence = 0.85
                    
                    findings.append(finding)
        
        return findings
    
    def _detect_encoding_chains(self, content: str, location: str, 
                               file_type: FileType) -> List[EncodingChain]:
        """Detect multi-layer encoding chains."""
        chains = []
        
        # Look for patterns that might indicate chained encoding
        potential_chains = re.findall(r'[A-Za-z0-9+/=]{40,}', content)
        
        for potential_chain in potential_chains:
            chain = self._analyze_encoding_chain(potential_chain, location, file_type)
            if chain and len(chain.encoding_layers) > 1:
                chains.append(chain)
        
        return chains
    
    def _analyze_encoding_chain(self, encoded_text: str, location: str, 
                               file_type: FileType) -> Optional[EncodingChain]:
        """Analyze a potential encoding chain."""
        try:
            current_text = encoded_text
            encoding_layers = []
            intermediate_steps = []
            
            for depth in range(self.max_analysis_depth):
                # Try Base64 decoding
                success, decoded = self.decoder.decode_base64(current_text)
                if success and decoded and decoded != current_text:
                    encoding_layers.append(EncodingType.BASE64)
                    intermediate_steps.append(current_text)
                    current_text = decoded
                    continue
                
                # Try hex decoding
                success, decoded = self.decoder.decode_hex(current_text)
                if success and decoded and decoded != current_text:
                    encoding_layers.append(EncodingType.HEX)
                    intermediate_steps.append(current_text)
                    current_text = decoded
                    continue
                
                # Try ROT47 decoding
                rot47_decoded = self.decoder.decode_rot47(current_text)
                if self._is_meaningful_content(rot47_decoded) and rot47_decoded != current_text:
                    encoding_layers.append(EncodingType.ROT47)
                    intermediate_steps.append(current_text)
                    current_text = rot47_decoded
                    continue
                
                # No more decoding possible
                break
            
            if len(encoding_layers) > 1:
                chain_id = f"chain_{hash(encoded_text) % 10000:04d}"
                
                return EncodingChain(
                    chain_id=chain_id,
                    encoding_layers=encoding_layers,
                    original_content=encoded_text,
                    intermediate_steps=intermediate_steps,
                    final_decoded_content=current_text,
                    complexity_score=len(encoding_layers) * 0.2,
                    detection_confidence=0.8,
                    locations=[location]
                )
            
        except Exception as e:
            logger.debug(f"Error analyzing encoding chain: {e}")
        
        return None
    
    def _create_encoding_finding(self, encoding_type: EncodingType, encoded_content: str,
                                decoded_content: str, location: str, file_type: FileType,
                                match_position: int, context_text: str) -> EncodingFinding:
        """Create an encoding finding with context."""
        finding_id = f"enc_{encoding_type.value}_{hash(encoded_content) % 10000:04d}"
        
        context = EncodingContext(
            file_path=location,
            file_type=file_type,
            line_number=context_text[:match_position].count('\n') + 1,
            surrounding_text=context_text
        )
        
        finding = EncodingFinding(
            finding_id=finding_id,
            encoding_type=encoding_type,
            encoded_content=encoded_content,
            decoded_content=decoded_content,
            location=location,
            context=context,
            description=f"Detected {encoding_type.value} encoding pattern",
            pattern_matched=encoded_content[:50] + "..." if len(encoded_content) > 50 else encoded_content
        )
        
        # Add security implications and recommendations
        finding.security_impact = self._assess_security_impact(finding, decoded_content)
        finding.recommendations = self._generate_encoding_recommendations(finding)
        finding.cwe = self._get_encoding_cwe(encoding_type)
        finding.masvs_control = self._get_encoding_masvs_control(encoding_type)
        
        return finding
    
    def _create_findings_from_chain(self, chain: EncodingChain, location: str, 
                                   file_type: FileType) -> List[EncodingFinding]:
        """Create findings from an encoding chain."""
        findings = []
        
        # Create a finding for the entire chain
        finding_id = f"chain_{chain.chain_id}"
        
        context = EncodingContext(
            file_path=location,
            file_type=file_type,
            surrounding_text=chain.original_content[:100]
        )
        
        finding = EncodingFinding(
            finding_id=finding_id,
            encoding_type=EncodingType.MULTI_LAYER,
            encoded_content=chain.original_content,
            decoded_content=chain.final_decoded_content,
            location=location,
            context=context,
            severity=SeverityLevel.HIGH,  # Multi-layer encoding is suspicious
            confidence=chain.detection_confidence,
            description=f"Multi-layer encoding chain detected: {' -> '.join(layer.value for layer in chain.encoding_layers)}",
            encoding_chain=chain.encoding_layers,
            analysis_patterns=[AnalysisPattern.ENCODING_CHAINS]
        )
        
        finding.security_impact = "Multi-layer encoding may indicate deliberate obfuscation of malicious or sensitive content"
        finding.recommendations = [
            "Review the purpose of multi-layer encoding",
            "Ensure encoded content does not contain sensitive information",
            "Consider using standard encryption instead of encoding for security"
        ]
        finding.cwe = "CWE-922"  # Insecure Storage of Sensitive Information
        finding.masvs_control = "MSTG-CRYPTO-01"
        
        findings.append(finding)
        
        return findings
    
    def _is_meaningful_content(self, text: str) -> bool:
        """Check if decoded text appears to be meaningful content."""
        if not text or len(text) < 3:
            return False
        
        # Check for common meaningful patterns
        meaningful_indicators = [
            'http', 'https', 'ftp', 'firebase', 'aws', 'api', 'key', 'token',
            'password', 'secret', 'config', 'database', 'server', 'client',
            'android', 'google', 'amazon', 'microsoft'
        ]
        
        text_lower = text.lower()
        return any(indicator in text_lower for indicator in meaningful_indicators)
    
    def _calculate_base64_confidence(self, base64_text: str, decoded: str, 
                                    content: str, file_type: FileType) -> float:
        """Calculate confidence score for Base64 detection."""
        confidence = 0.7  # Base confidence
        
        # Length factor
        if len(base64_text) > 50:
            confidence += 0.1
        if len(base64_text) > 100:
            confidence += 0.05
        
        # Decoded content quality
        if self._is_meaningful_content(decoded):
            confidence += 0.15
        
        # Context factors
        if 'base64' in content.lower() or 'encoded' in content.lower():
            confidence += 0.1
        
        # File type factors
        if file_type in [FileType.SOURCE_CODE, FileType.CONFIG_FILE]:
            confidence += 0.05
        
        return min(1.0, confidence)
    
    def _calculate_hex_confidence(self, hex_text: str, decoded: str, 
                                 content: str, file_type: FileType) -> float:
        """Calculate confidence score for hex detection."""
        confidence = 0.6  # Base confidence
        
        # Length and pattern factors
        if len(hex_text) > 40 and len(hex_text) % 2 == 0:
            confidence += 0.2
        
        if self._is_meaningful_content(decoded):
            confidence += 0.15
        
        return min(1.0, confidence)
    
    def _determine_encoding_severity(self, finding: EncodingFinding, 
                                   decoded_content: str, file_type: FileType) -> SeverityLevel:
        """Determine severity level for encoding finding."""
        # Check for sensitive information in decoded content
        sensitive_patterns = [
            'password', 'secret', 'key', 'token', 'credential', 'api_key',
            'private_key', 'access_token', 'auth', 'certificate'
        ]
        
        decoded_lower = decoded_content.lower()
        
        if any(pattern in decoded_lower for pattern in sensitive_patterns):
            return SeverityLevel.HIGH
        
        # Check for URLs or endpoints
        url_patterns = ['http', 'https', 'ftp', 'firebase', 'amazonaws']
        if any(pattern in decoded_lower for pattern in url_patterns):
            return SeverityLevel.MEDIUM
        
        # Multi-layer encoding is inherently suspicious
        if finding.encoding_type == EncodingType.MULTI_LAYER:
            return SeverityLevel.HIGH
        
        return SeverityLevel.LOW
    
    def _assess_security_impact(self, finding: EncodingFinding, decoded_content: str) -> str:
        """Assess security impact of the encoding finding."""
        if finding.encoding_type == EncodingType.MULTI_LAYER:
            return "Multi-layer encoding may indicate deliberate obfuscation of malicious or sensitive content"
        
        if any(pattern in decoded_content.lower() for pattern in ['password', 'secret', 'key']):
            return "Encoded content contains potential credentials or sensitive information"
        
        if any(pattern in decoded_content.lower() for pattern in ['http', 'api', 'endpoint']):
            return "Encoded content contains URLs or API endpoints that may expose service configurations"
        
        return "Encoded content should be reviewed for sensitive information"
    
    def _generate_encoding_recommendations(self, finding: EncodingFinding) -> List[str]:
        """Generate security recommendations for encoding finding."""
        recommendations = [
            "Review the decoded content for sensitive information",
            "Ensure encoding is not used as a security mechanism",
            "Consider using proper encryption for sensitive data"
        ]
        
        if finding.encoding_type == EncodingType.MULTI_LAYER:
            recommendations.extend([
                "Investigate the purpose of multi-layer encoding",
                "Verify that obfuscation is not hiding malicious content"
            ])
        
        if AnalysisPattern.ANDROID_SECURITY in finding.analysis_patterns:
            recommendations.extend([
                "Follow Android security best practices for data protection",
                "Use Android Keystore for sensitive key material"
            ])
        
        return recommendations
    
    def _get_encoding_cwe(self, encoding_type: EncodingType) -> Optional[str]:
        """Get CWE mapping for encoding type."""
        cwe_mapping = {
            EncodingType.BASE64: "CWE-922",
            EncodingType.ROT47: "CWE-922",
            EncodingType.ROT13: "CWE-922",
            EncodingType.HEX: "CWE-922",
            EncodingType.MULTI_LAYER: "CWE-656"
        }
        return cwe_mapping.get(encoding_type)
    
    def _get_encoding_masvs_control(self, encoding_type: EncodingType) -> Optional[str]:
        """Get MASVS control mapping for encoding type."""
        return "MSTG-CRYPTO-01"  # Cryptographic Key Management
    
    def get_analysis_statistics(self) -> Dict[str, int]:
        """Get statistics about encoding analysis."""
        return {
            'total_patterns_detected': len(self.detected_encodings),
            'unique_encodings': len(set(encoding[0] for encoding in self.detected_encodings)),
            'unique_locations': len(set(encoding[1] for encoding in self.detected_encodings))
        } 
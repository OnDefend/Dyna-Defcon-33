#!/usr/bin/env python3
"""
Cryptographic Utilities for AODS Shared Infrastructure

Consolidated cryptographic operations and security analysis utilities used across AODS plugins.
Provides standardized, secure, and efficient cryptographic capabilities.

Features:
- Secure hash generation and validation
- Cryptographic algorithm strength analysis
- Key generation and validation utilities
- Random number generation and entropy analysis
- Encoding/decoding operations (Base64, hex, etc.)
- Hash cracking and password analysis
- Cryptographic pattern detection
- Vulnerability assessment utilities
- Performance-optimized operations
- Security-focused implementations

This component provides standardized cryptographic capabilities for all
AODS plugins, ensuring consistent and secure cryptographic operations.
"""

import os
import re
import hashlib
import secrets
import base64
import binascii
import logging
import time
import itertools
import string
from typing import Dict, List, Optional, Any, Union, Set, Tuple, Pattern
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from collections import defaultdict
import math

# Optional imports for enhanced cryptographic operations
try:
    from cryptography.hazmat.primitives import hashes, kdf
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    from cryptography.fernet import Fernet
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False

logger = logging.getLogger(__name__)

class HashAlgorithmStrength(Enum):
    """Hash algorithm security strength levels."""
    BROKEN = "broken"
    WEAK = "weak"
    ACCEPTABLE = "acceptable"
    STRONG = "strong"
    RECOMMENDED = "recommended"

class EncryptionStrength(Enum):
    """Encryption algorithm strength levels."""
    BROKEN = "broken"
    WEAK = "weak"
    ACCEPTABLE = "acceptable"
    STRONG = "strong"
    RECOMMENDED = "recommended"

@dataclass
class HashAnalysisResult:
    """Result of hash algorithm analysis."""
    algorithm: str
    strength: HashAlgorithmStrength
    vulnerabilities: List[str]
    recommendations: List[str]
    estimated_attack_time: str
    is_collision_resistant: bool
    is_rainbow_table_resistant: bool

@dataclass
class CryptoPatternMatch:
    """Cryptographic pattern match result."""
    pattern_type: str
    algorithm: str
    location: str
    evidence: str
    strength: Union[HashAlgorithmStrength, EncryptionStrength]
    confidence: float

class CryptoSecurityAnalyzer:
    """Advanced cryptographic security analysis utilities."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self._initialize_algorithm_databases()
        self._initialize_patterns()
    
    def _initialize_algorithm_databases(self) -> None:
        """Initialize cryptographic algorithm security databases."""
        # Hash algorithm security assessment
        self.hash_strength_db = {
            'md5': {
                'strength': HashAlgorithmStrength.BROKEN,
                'vulnerabilities': ['collision_attacks', 'preimage_attacks', 'rainbow_tables'],
                'attack_time': 'seconds',
                'collision_resistant': False,
                'rainbow_table_resistant': False
            },
            'sha1': {
                'strength': HashAlgorithmStrength.WEAK,
                'vulnerabilities': ['collision_attacks', 'rainbow_tables'],
                'attack_time': 'hours_to_days',
                'collision_resistant': False,
                'rainbow_table_resistant': False
            },
            'sha256': {
                'strength': HashAlgorithmStrength.STRONG,
                'vulnerabilities': [],
                'attack_time': 'computationally_infeasible',
                'collision_resistant': True,
                'rainbow_table_resistant': True
            },
            'sha512': {
                'strength': HashAlgorithmStrength.RECOMMENDED,
                'vulnerabilities': [],
                'attack_time': 'computationally_infeasible',
                'collision_resistant': True,
                'rainbow_table_resistant': True
            },
            'sha3': {
                'strength': HashAlgorithmStrength.RECOMMENDED,
                'vulnerabilities': [],
                'attack_time': 'computationally_infeasible',
                'collision_resistant': True,
                'rainbow_table_resistant': True
            }
        }
        
        # Encryption algorithm security assessment
        self.encryption_strength_db = {
            'des': {
                'strength': EncryptionStrength.BROKEN,
                'vulnerabilities': ['small_key_space', 'brute_force'],
                'key_size': 56,
                'recommended_replacement': 'AES-256'
            },
            '3des': {
                'strength': EncryptionStrength.WEAK,
                'vulnerabilities': ['sweet32', 'small_block_size'],
                'key_size': 168,
                'recommended_replacement': 'AES-256'
            },
            'rc4': {
                'strength': EncryptionStrength.BROKEN,
                'vulnerabilities': ['biased_keystream', 'key_recovery'],
                'key_size': 128,
                'recommended_replacement': 'ChaCha20-Poly1305'
            },
            'aes': {
                'strength': EncryptionStrength.RECOMMENDED,
                'vulnerabilities': [],
                'key_size': 256,
                'recommended_replacement': None
            }
        }
    
    def _initialize_patterns(self) -> None:
        """Initialize cryptographic vulnerability patterns."""
        self.crypto_patterns = {
            'weak_hash': [
                re.compile(r'(?i)\bMD5\b', re.IGNORECASE),
                re.compile(r'(?i)\bSHA-?1\b', re.IGNORECASE),
                re.compile(r'(?i)MessageDigest\.getInstance\s*\(\s*["\']MD5["\']', re.IGNORECASE),
                re.compile(r'(?i)MessageDigest\.getInstance\s*\(\s*["\']SHA-?1["\']', re.IGNORECASE)
            ],
            'weak_encryption': [
                re.compile(r'(?i)\bDES\b(?!cendant|ign|k)', re.IGNORECASE),
                re.compile(r'(?i)\bRC4\b', re.IGNORECASE),
                re.compile(r'(?i)Cipher\.getInstance\s*\(\s*["\']DES["\']', re.IGNORECASE),
                re.compile(r'(?i)Cipher\.getInstance\s*\(\s*["\']RC4["\']', re.IGNORECASE)
            ],
            'hardcoded_secrets': [
                re.compile(r'(?i)(?:key|secret|password)\s*[:=]\s*["\'][A-Za-z0-9+/=]{16,}["\']', re.IGNORECASE),
                re.compile(r'(?i)SecretKeySpec\s*\([^)]*["\'][A-Za-z0-9+/=]{8,}["\']', re.IGNORECASE)
            ],
            'weak_random': [
                re.compile(r'(?i)Math\.random\(\)', re.IGNORECASE),
                re.compile(r'(?i)new\s+Random\s*\(\)', re.IGNORECASE),
                re.compile(r'(?i)Random\.setSeed\s*\(\s*[0-9]+\s*\)', re.IGNORECASE)
            ]
        }
    
    def analyze_hash_algorithm(self, algorithm: str) -> HashAnalysisResult:
        """
        Analyze hash algorithm security strength.
        
        Args:
            algorithm: Hash algorithm name
            
        Returns:
            HashAnalysisResult: Analysis results
        """
        algorithm_lower = algorithm.lower().replace('-', '').replace('_', '')
        
        # Normalize algorithm names
        algorithm_map = {
            'md5': 'md5',
            'sha1': 'sha1',
            'sha256': 'sha256',
            'sha512': 'sha512',
            'sha3': 'sha3',
            'sha3256': 'sha3',
            'sha3512': 'sha3'
        }
        
        normalized_algorithm = algorithm_map.get(algorithm_lower, algorithm_lower)
        
        if normalized_algorithm in self.hash_strength_db:
            info = self.hash_strength_db[normalized_algorithm]
            
            recommendations = []
            if info['strength'] in [HashAlgorithmStrength.BROKEN, HashAlgorithmStrength.WEAK]:
                recommendations.extend([
                    "Replace with SHA-256 or SHA-3",
                    "Use proper salt for password hashing",
                    "Consider bcrypt, scrypt, or Argon2 for passwords"
                ])
            
            return HashAnalysisResult(
                algorithm=algorithm,
                strength=info['strength'],
                vulnerabilities=info['vulnerabilities'],
                recommendations=recommendations,
                estimated_attack_time=info['attack_time'],
                is_collision_resistant=info['collision_resistant'],
                is_rainbow_table_resistant=info['rainbow_table_resistant']
            )
        
        # Unknown algorithm - assume weak
        return HashAnalysisResult(
            algorithm=algorithm,
            strength=HashAlgorithmStrength.WEAK,
            vulnerabilities=['unknown_security_properties'],
            recommendations=["Use well-known cryptographic algorithms like SHA-256"],
            estimated_attack_time='unknown',
            is_collision_resistant=False,
            is_rainbow_table_resistant=False
        )
    
    def detect_crypto_patterns(self, content: str, location: str = "") -> List[CryptoPatternMatch]:
        """
        Detect cryptographic vulnerability patterns in content.
        
        Args:
            content: Content to analyze
            location: Location identifier for context
            
        Returns:
            List[CryptoPatternMatch]: Detected patterns
        """
        matches = []
        
        for pattern_type, patterns in self.crypto_patterns.items():
            for pattern in patterns:
                for match in pattern.finditer(content):
                    # Extract algorithm from match
                    algorithm = self._extract_algorithm_from_match(match, pattern_type)
                    
                    # Determine strength based on pattern type
                    if pattern_type in ['weak_hash']:
                        strength = self.analyze_hash_algorithm(algorithm).strength
                    elif pattern_type in ['weak_encryption']:
                        strength = self._analyze_encryption_strength(algorithm)
                    else:
                        strength = HashAlgorithmStrength.WEAK
                    
                    # Calculate confidence based on pattern specificity
                    confidence = self._calculate_pattern_confidence(match, pattern_type)
                    
                    matches.append(CryptoPatternMatch(
                        pattern_type=pattern_type,
                        algorithm=algorithm,
                        location=location,
                        evidence=match.group(0),
                        strength=strength,
                        confidence=confidence
                    ))
        
        return matches
    
    def _extract_algorithm_from_match(self, match: re.Match, pattern_type: str) -> str:
        """Extract algorithm name from regex match."""
        text = match.group(0).lower()
        
        # Common algorithm extraction patterns
        if 'md5' in text:
            return 'MD5'
        elif 'sha1' in text or 'sha-1' in text:
            return 'SHA-1'
        elif 'sha256' in text or 'sha-256' in text:
            return 'SHA-256'
        elif 'sha512' in text or 'sha-512' in text:
            return 'SHA-512'
        elif 'des' in text and 'aes' not in text:
            return 'DES'
        elif 'rc4' in text:
            return 'RC4'
        elif 'aes' in text:
            return 'AES'
        
        return 'unknown'
    
    def _analyze_encryption_strength(self, algorithm: str) -> EncryptionStrength:
        """Analyze encryption algorithm strength."""
        algorithm_lower = algorithm.lower()
        
        if algorithm_lower in self.encryption_strength_db:
            return self.encryption_strength_db[algorithm_lower]['strength']
        
        return EncryptionStrength.WEAK
    
    def _calculate_pattern_confidence(self, match: re.Match, pattern_type: str) -> float:
        """Calculate confidence score for pattern match."""
        base_confidence = {
            'weak_hash': 0.9,
            'weak_encryption': 0.9,
            'hardcoded_secrets': 0.8,
            'weak_random': 0.85
        }.get(pattern_type, 0.7)
        
        # Adjust confidence based on context
        match_text = match.group(0)
        
        # Higher confidence for specific API calls
        if 'getInstance' in match_text or 'MessageDigest' in match_text:
            base_confidence += 0.05
        
        # Lower confidence for comments
        if match.string[max(0, match.start()-10):match.start()].strip().startswith('//'):
            base_confidence -= 0.2
        
        return min(1.0, max(0.1, base_confidence))

class HashingUtils:
    """Enhanced hashing and fingerprinting utilities."""
    
    @staticmethod
    def calculate_content_hash(content: str, algorithm: str = 'sha256') -> str:
        """
        Calculate hash of content with multiple algorithm support.
        
        Args:
            content: Content to hash
            algorithm: Hash algorithm to use
            
        Returns:
            str: Hex digest of hash
        """
        if not content:
            return ""
        
        try:
            hash_obj = hashlib.new(algorithm)
            hash_obj.update(content.encode('utf-8'))
            return hash_obj.hexdigest()
        except ValueError:
            # Fallback to SHA-256 for unknown algorithms
            hash_obj = hashlib.sha256()
            hash_obj.update(content.encode('utf-8'))
            return hash_obj.hexdigest()
    
    @staticmethod
    def calculate_file_hash(file_path: str, algorithm: str = 'sha256', 
                          chunk_size: int = 8192) -> Optional[str]:
        """
        Calculate hash of file contents efficiently.
        
        Args:
            file_path: Path to file
            algorithm: Hash algorithm to use
            chunk_size: Size of chunks to read
            
        Returns:
            Optional[str]: Hex digest of hash or None if error
        """
        try:
            hash_obj = hashlib.new(algorithm)
            with open(file_path, 'rb') as f:
                while chunk := f.read(chunk_size):
                    hash_obj.update(chunk)
            return hash_obj.hexdigest()
        except Exception as e:
            logger.debug(f"Failed to calculate hash for {file_path}: {e}")
            return None
    
    @staticmethod
    def create_finding_fingerprint(finding_data: Dict[str, Any]) -> str:
        """
        Create unique fingerprint for a security finding.
        
        Args:
            finding_data: Finding data to fingerprint
            
        Returns:
            str: Unique fingerprint string
        """
        key_fields = ['title', 'file_path', 'line_number', 'pattern', 'evidence']
        fingerprint_parts = []
        
        for field in key_fields:
            if field in finding_data and finding_data[field]:
                fingerprint_parts.append(str(finding_data[field]))
        
        fingerprint_content = '|'.join(fingerprint_parts)
        return HashingUtils.calculate_content_hash(fingerprint_content, 'md5')[:12]
    
    @staticmethod
    def calculate_entropy(data: bytes) -> float:
        """
        Calculate Shannon entropy of data.
        
        Args:
            data: Binary data to analyze
            
        Returns:
            float: Entropy value (0-8 bits)
        """
        if not data:
            return 0.0
        
        # Count byte frequencies
        byte_counts = defaultdict(int)
        for byte in data:
            byte_counts[byte] += 1
        
        # Calculate entropy
        entropy = 0.0
        data_length = len(data)
        
        for count in byte_counts.values():
            if count > 0:
                probability = count / data_length
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    @staticmethod
    def is_high_entropy(data: bytes, threshold: float = 6.0) -> bool:
        """
        Check if data has high entropy (likely encrypted/random).
        
        Args:
            data: Binary data to check
            threshold: Entropy threshold (default: 6.0)
            
        Returns:
            bool: True if high entropy
        """
        return HashingUtils.calculate_entropy(data) >= threshold

class SecureRandomGenerator:
    """Secure random number generation utilities."""
    
    @staticmethod
    def generate_secure_bytes(length: int) -> bytes:
        """
        Generate cryptographically secure random bytes.
        
        Args:
            length: Number of bytes to generate
            
        Returns:
            bytes: Secure random bytes
        """
        return secrets.token_bytes(length)
    
    @staticmethod
    def generate_secure_string(length: int, alphabet: str = None) -> str:
        """
        Generate cryptographically secure random string.
        
        Args:
            length: Length of string to generate
            alphabet: Character set to use (default: alphanumeric)
            
        Returns:
            str: Secure random string
        """
        if alphabet is None:
            alphabet = string.ascii_letters + string.digits
        
        return ''.join(secrets.choice(alphabet) for _ in range(length))
    
    @staticmethod
    def generate_secure_hex(length: int) -> str:
        """
        Generate cryptographically secure random hex string.
        
        Args:
            length: Length of hex string to generate
            
        Returns:
            str: Secure random hex string
        """
        return secrets.token_hex(length // 2)

class EncodingUtils:
    """Enhanced encoding and decoding utilities."""
    
    @staticmethod
    def safe_base64_encode(data: Union[str, bytes]) -> str:
        """
        Safely encode data to Base64.
        
        Args:
            data: Data to encode
            
        Returns:
            str: Base64 encoded string
        """
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        return base64.b64encode(data).decode('ascii')
    
    @staticmethod
    def safe_base64_decode(encoded_data: str) -> Optional[bytes]:
        """
        Safely decode Base64 data.
        
        Args:
            encoded_data: Base64 encoded string
            
        Returns:
            Optional[bytes]: Decoded data or None if invalid
        """
        try:
            return base64.b64decode(encoded_data, validate=True)
        except Exception as e:
            logger.debug(f"Base64 decode failed: {e}")
            return None
    
    @staticmethod
    def safe_hex_encode(data: Union[str, bytes]) -> str:
        """
        Safely encode data to hexadecimal.
        
        Args:
            data: Data to encode
            
        Returns:
            str: Hex encoded string
        """
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        return data.hex()
    
    @staticmethod
    def safe_hex_decode(hex_data: str) -> Optional[bytes]:
        """
        Safely decode hexadecimal data.
        
        Args:
            hex_data: Hex encoded string
            
        Returns:
            Optional[bytes]: Decoded data or None if invalid
        """
        try:
            return bytes.fromhex(hex_data)
        except ValueError as e:
            logger.debug(f"Hex decode failed: {e}")
            return None
    
    @staticmethod
    def detect_encoding(data: bytes) -> Dict[str, Any]:
        """
        Detect encoding of binary data.
        
        Args:
            data: Binary data to analyze
            
        Returns:
            Dict[str, Any]: Encoding detection results
        """
        results = {
            'is_base64': False,
            'is_hex': False,
            'is_ascii': False,
            'is_utf8': False,
            'entropy': HashingUtils.calculate_entropy(data),
            'likely_encoded': False
        }
        
        try:
            # Check if data is valid ASCII
            data.decode('ascii')
            results['is_ascii'] = True
        except UnicodeDecodeError:
            pass
        
        try:
            # Check if data is valid UTF-8
            data.decode('utf-8')
            results['is_utf8'] = True
        except UnicodeDecodeError:
            pass
        
        # Check if data looks like Base64
        if results['is_ascii']:
            text = data.decode('ascii')
            if re.match(r'^[A-Za-z0-9+/]*={0,2}$', text) and len(text) % 4 == 0:
                results['is_base64'] = True
        
        # Check if data looks like hex
        if results['is_ascii']:
            text = data.decode('ascii')
            if re.match(r'^[0-9a-fA-F]*$', text) and len(text) % 2 == 0:
                results['is_hex'] = True
        
        # High entropy suggests encoding/encryption
        results['likely_encoded'] = results['entropy'] > 6.0
        
        return results

class PasswordHashAnalyzer:
    """Password hash analysis and cracking utilities."""
    
    def __init__(self):
        self.common_passwords = [
            'password', '123456', 'admin', 'root', 'test', 'guest',
            'password123', 'admin123', '12345678', 'qwerty',
            'letmein', 'welcome', 'monkey', 'dragon', 'secret'
        ]
    
    def analyze_password_hash(self, hash_value: str, context: str = "") -> Dict[str, Any]:
        """
        Analyze password hash security and attempt cracking.
        
        Args:
            hash_value: Hash value to analyze
            context: Context information for analysis
            
        Returns:
            Dict[str, Any]: Analysis results
        """
        results = {
            'hash_value': hash_value,
            'hash_type': self._detect_hash_type(hash_value),
            'is_salted': self._appears_salted(hash_value, context),
            'estimated_strength': 'unknown',
            'cracked_password': None,
            'vulnerability_assessment': []
        }
        
        # Attempt to crack the hash
        if results['hash_type'] != 'unknown':
            results['cracked_password'] = self._attempt_crack(hash_value, results['hash_type'])
        
        # Assess vulnerability
        vulnerabilities = []
        if results['hash_type'] in ['md5', 'sha1']:
            vulnerabilities.append('weak_hash_algorithm')
        
        if not results['is_salted']:
            vulnerabilities.append('no_salt_detected')
        
        if results['cracked_password']:
            vulnerabilities.append('weak_password')
        
        results['vulnerability_assessment'] = vulnerabilities
        results['estimated_strength'] = self._estimate_hash_strength(results)
        
        return results
    
    def _detect_hash_type(self, hash_value: str) -> str:
        """Detect hash algorithm type based on format."""
        hash_value = hash_value.strip()
        
        # Common hash length patterns
        if len(hash_value) == 32 and re.match(r'^[a-fA-F0-9]+$', hash_value):
            return 'md5'
        elif len(hash_value) == 40 and re.match(r'^[a-fA-F0-9]+$', hash_value):
            return 'sha1'
        elif len(hash_value) == 64 and re.match(r'^[a-fA-F0-9]+$', hash_value):
            return 'sha256'
        elif len(hash_value) == 128 and re.match(r'^[a-fA-F0-9]+$', hash_value):
            return 'sha512'
        elif hash_value.startswith('$2a$') or hash_value.startswith('$2b$'):
            return 'bcrypt'
        elif hash_value.startswith('$argon2'):
            return 'argon2'
        
        return 'unknown'
    
    def _appears_salted(self, hash_value: str, context: str) -> bool:
        """Check if hash appears to use salt."""
        # bcrypt and argon2 include salt
        if self._detect_hash_type(hash_value) in ['bcrypt', 'argon2']:
            return True
        
        # Look for salt indicators in context
        salt_indicators = ['salt', 'nonce', 'random', 'unique']
        context_lower = context.lower()
        
        return any(indicator in context_lower for indicator in salt_indicators)
    
    def _attempt_crack(self, hash_value: str, hash_type: str) -> Optional[str]:
        """Attempt to crack hash using common passwords."""
        if hash_type not in ['md5', 'sha1', 'sha256']:
            return None
        
        hash_functions = {
            'md5': hashlib.md5,
            'sha1': hashlib.sha1,
            'sha256': hashlib.sha256
        }
        
        hash_func = hash_functions[hash_type]
        
        # Try common passwords
        for password in self.common_passwords:
            test_hash = hash_func(password.encode()).hexdigest()
            if test_hash.lower() == hash_value.lower():
                return password
        
        # Try common variations
        for base_password in self.common_passwords[:5]:  # Limit for performance
            for variation in self._generate_password_variations(base_password):
                test_hash = hash_func(variation.encode()).hexdigest()
                if test_hash.lower() == hash_value.lower():
                    return variation
        
        return None
    
    def _generate_password_variations(self, base_password: str) -> List[str]:
        """Generate common password variations."""
        variations = []
        
        # Case variations
        variations.extend([
            base_password.upper(),
            base_password.lower(),
            base_password.capitalize()
        ])
        
        # Numeric suffixes
        for i in range(10):
            variations.append(base_password + str(i))
        
        # Common suffixes
        for suffix in ['123', '!', '1']:
            variations.append(base_password + suffix)
        
        return variations
    
    def _estimate_hash_strength(self, analysis_results: Dict[str, Any]) -> str:
        """Estimate overall hash strength."""
        vulnerabilities = analysis_results['vulnerability_assessment']
        
        if 'weak_password' in vulnerabilities:
            return 'very_weak'
        elif 'weak_hash_algorithm' in vulnerabilities:
            return 'weak'
        elif 'no_salt_detected' in vulnerabilities:
            return 'moderate'
        else:
            return 'strong'

# Global instances for easy access
crypto_analyzer = CryptoSecurityAnalyzer()
password_analyzer = PasswordHashAnalyzer()

# Convenience functions
def analyze_crypto_content(content: str, location: str = "") -> List[CryptoPatternMatch]:
    """Analyze content for cryptographic vulnerabilities."""
    return crypto_analyzer.detect_crypto_patterns(content, location)

def calculate_content_hash(content: str, algorithm: str = 'sha256') -> str:
    """Calculate hash of content."""
    return HashingUtils.calculate_content_hash(content, algorithm)

def calculate_file_hash(file_path: str, algorithm: str = 'sha256') -> Optional[str]:
    """Calculate hash of file."""
    return HashingUtils.calculate_file_hash(file_path, algorithm)

def generate_secure_key(length: int = 32) -> str:
    """Generate secure cryptographic key."""
    return SecureRandomGenerator.generate_secure_hex(length)

def analyze_password_hash(hash_value: str, context: str = "") -> Dict[str, Any]:
    """Analyze password hash security."""
    return password_analyzer.analyze_password_hash(hash_value, context) 
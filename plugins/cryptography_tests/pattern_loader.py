#!/usr/bin/env python3

"""
Pattern Loader for Cryptography Tests

This module provides pattern loading and compilation functionality for 
cryptographic vulnerability detection.
"""

import re
import logging
from typing import Dict, List, Any, Optional
from pathlib import Path

logger = logging.getLogger(__name__)

class PatternLoader:
    """Pattern loader for cryptographic vulnerability detection."""
    
    def __init__(self):
        self.compiled_patterns = {}
    
    def load_patterns(self) -> Dict[str, Any]:
        """Load and compile cryptographic patterns."""
        patterns = {
            'md5_usage': {
                'name': 'MD5 Hash Usage',
                'pattern': r'MessageDigest\.getInstance\s*\(\s*[\"\']\s*MD5\s*[\"\']\s*\)',
                'compiled_regex': re.compile(r'MessageDigest\.getInstance\s*\(\s*[\"\']\s*MD5\s*[\"\']\s*\)', re.IGNORECASE),
                'severity': 'HIGH',
                'cwe': ['CWE-327'],
                'recommendations': ['Use SHA-256 instead of MD5']
            },
            'sha1_usage': {
                'name': 'SHA-1 Hash Usage',
                'pattern': r'MessageDigest\.getInstance\s*\(\s*[\"\']\s*SHA-?1\s*[\"\']\s*\)',
                'compiled_regex': re.compile(r'MessageDigest\.getInstance\s*\(\s*[\"\']\s*SHA-?1\s*[\"\']\s*\)', re.IGNORECASE),
                'severity': 'MEDIUM',
                'cwe': ['CWE-327'],
                'recommendations': ['Use SHA-256 instead of SHA-1']
            },
            'des_usage': {
                'name': 'DES Cipher Usage',
                'pattern': r'Cipher\.getInstance\s*\(\s*[\"\']\s*DES',
                'compiled_regex': re.compile(r'Cipher\.getInstance\s*\(\s*[\"\']\s*DES', re.IGNORECASE),
                'severity': 'CRITICAL',
                'cwe': ['CWE-327'],
                'recommendations': ['Use AES instead of DES']
            },
            'ecb_mode': {
                'name': 'ECB Mode Usage',
                'pattern': r'Cipher\.getInstance\s*\(\s*[\"\']\s*[^\"\']*ECB[^\"\']*\s*[\"\']\s*\)',
                'compiled_regex': re.compile(r'Cipher\.getInstance\s*\(\s*[\"\']\s*[^\"\']*ECB[^\"\']*\s*[\"\']\s*\)', re.IGNORECASE),
                'severity': 'HIGH',
                'cwe': ['CWE-327'],
                'recommendations': ['Use CBC, GCM, or other secure modes instead of ECB']
            },
            'hardcoded_key': {
                'name': 'Hardcoded Cryptographic Key',
                'pattern': r'SecretKeySpec\s*\(\s*[\"\']\s*[^\"\']{16,}\s*[\"\']\s*\)',
                'compiled_regex': re.compile(r'SecretKeySpec\s*\(\s*[\"\']\s*[^\"\']{16,}\s*[\"\']\s*\)', re.IGNORECASE),
                'severity': 'CRITICAL',
                'cwe': ['CWE-798'],
                'recommendations': ['Generate keys at runtime, use secure key storage']
            }
        }
        
        return patterns
    
    def compile_pattern(self, pattern_string: str) -> re.Pattern:
        """Compile a pattern string into a regex pattern."""
        try:
            return re.compile(pattern_string, re.IGNORECASE | re.MULTILINE)
        except re.error as e:
            logger.error(f"Failed to compile pattern: {pattern_string}, error: {e}")
            return None
    
    def validate_patterns(self, patterns: Dict[str, Any]) -> bool:
        """Validate that all patterns compile correctly."""
        for pattern_name, pattern_info in patterns.items():
            try:
                if 'pattern' in pattern_info:
                    re.compile(pattern_info['pattern'])
                    logger.debug(f"Pattern {pattern_name} validated successfully")
            except re.error as e:
                logger.error(f"Pattern {pattern_name} validation failed: {e}")
                return False
        
        return True 
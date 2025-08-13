#!/usr/bin/env python3
"""
Shared Data Transformation Utilities

Consolidated data parsing, validation, and transformation utilities used across AODS plugins.
Provides efficient, reusable, and standardized data processing capabilities.

Features:
- Pattern compilation and regex caching for performance
- XML, JSON, YAML parsing with error handling
- Data validation and sanitization utilities
- Content analysis and extraction helpers
- Binary data decoding and encoding utilities
- Performance-optimized transformations
"""

import re
import json
import yaml
import base64
import binascii
import hashlib
import logging
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Any, Union, Pattern, Set, Tuple
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)

@dataclass
class CompiledPattern:
    """Container for compiled regex patterns with metadata."""
    pattern: Pattern[str]
    category: str
    description: str
    flags: int = 0

class PatternCompiler:
    """Efficient pattern compilation and caching system."""
    
    def __init__(self):
        self._compiled_patterns: Dict[str, CompiledPattern] = {}
        self._pattern_cache: Dict[str, Pattern[str]] = {}
    
    def compile_patterns(self, pattern_definitions: Dict[str, Dict[str, Any]]) -> Dict[str, List[CompiledPattern]]:
        """
        Compile multiple pattern definitions with caching.
        
        Args:
            pattern_definitions: Dict of pattern categories and their definitions
            
        Returns:
            Dict[str, List[CompiledPattern]]: Compiled patterns by category
        """
        compiled_by_category = defaultdict(list)
        
        for category, pattern_info in pattern_definitions.items():
            patterns = pattern_info.get('patterns', [])
            description = pattern_info.get('description', f'{category} patterns')
            flags = pattern_info.get('flags', re.IGNORECASE | re.MULTILINE)
            
            for pattern_str in patterns:
                compiled_pattern = self._compile_single_pattern(
                    pattern_str, category, description, flags
                )
                if compiled_pattern:
                    compiled_by_category[category].append(compiled_pattern)
        
        return dict(compiled_by_category)
    
    def _compile_single_pattern(self, pattern_str: str, category: str, 
                              description: str, flags: int) -> Optional[CompiledPattern]:
        """Compile a single pattern with caching."""
        cache_key = f"{pattern_str}:{flags}"
        
        if cache_key in self._pattern_cache:
            pattern = self._pattern_cache[cache_key]
        else:
            try:
                pattern = re.compile(pattern_str, flags)
                self._pattern_cache[cache_key] = pattern
            except re.error as e:
                logger.warning(f"Failed to compile pattern '{pattern_str}': {e}")
                return None
        
        return CompiledPattern(
            pattern=pattern,
            category=category,
            description=description,
            flags=flags
        )
    
    def get_compiled_pattern(self, pattern_str: str, flags: int = re.IGNORECASE) -> Optional[Pattern[str]]:
        """Get a single compiled pattern with caching."""
        cache_key = f"{pattern_str}:{flags}"
        
        if cache_key not in self._pattern_cache:
            try:
                self._pattern_cache[cache_key] = re.compile(pattern_str, flags)
            except re.error as e:
                logger.warning(f"Failed to compile pattern '{pattern_str}': {e}")
                return None
        
        return self._pattern_cache[cache_key]

class ContentParser:
    """Universal content parsing utilities for various formats."""
    
    @staticmethod
    def parse_json_safe(content: str) -> Optional[Dict[str, Any]]:
        """
        Safely parse JSON content with error handling.
        
        Args:
            content: JSON string to parse
            
        Returns:
            Optional[Dict[str, Any]]: Parsed JSON or None if parsing failed
        """
        if not content or not content.strip():
            return None
        
        try:
            return json.loads(content)
        except json.JSONDecodeError as e:
            logger.debug(f"JSON parsing failed: {e}")
            
            # Try to fix common JSON issues
            try:
                # Remove trailing commas
                fixed_content = re.sub(r',\s*}', '}', content)
                fixed_content = re.sub(r',\s*]', ']', fixed_content)
                return json.loads(fixed_content)
            except json.JSONDecodeError:
                return None
    
    @staticmethod
    def parse_yaml_safe(content: str) -> Optional[Dict[str, Any]]:
        """
        Safely parse YAML content with error handling.
        
        Args:
            content: YAML string to parse
            
        Returns:
            Optional[Dict[str, Any]]: Parsed YAML or None if parsing failed
        """
        if not content or not content.strip():
            return None
        
        try:
            return yaml.safe_load(content)
        except yaml.YAMLError as e:
            logger.debug(f"YAML parsing failed: {e}")
            return None
    
    @staticmethod
    def parse_xml_safe(content: str) -> Optional[ET.Element]:
        """
        Safely parse XML content with error handling.
        
        Args:
            content: XML string to parse
            
        Returns:
            Optional[ET.Element]: Parsed XML root element or None if parsing failed
        """
        if not content or not content.strip():
            return None
        
        try:
            return ET.fromstring(content)
        except ET.ParseError as e:
            logger.debug(f"XML parsing failed: {e}")
            
            # Try to fix common XML issues
            try:
                # Remove invalid control characters
                fixed_content = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '', content)
                return ET.fromstring(fixed_content)
            except ET.ParseError:
                return None
    
    @staticmethod
    def parse_properties(content: str) -> Dict[str, str]:
        """
        Parse properties file format (key=value lines).
        
        Args:
            content: Properties file content
            
        Returns:
            Dict[str, str]: Parsed key-value pairs
        """
        properties = {}
        
        for line in content.split('\n'):
            line = line.strip()
            if not line or line.startswith('#') or line.startswith('!'):
                continue
            
            # Handle different separators
            for separator in ['=', ':', ' ']:
                if separator in line:
                    key, value = line.split(separator, 1)
                    properties[key.strip()] = value.strip()
                    break
        
        return properties
    
    @staticmethod
    def extract_key_value_pairs(content: str, patterns: List[str]) -> Dict[str, List[str]]:
        """
        Extract key-value pairs using regex patterns.
        
        Args:
            content: Content to search
            patterns: List of regex patterns with named groups 'key' and 'value'
            
        Returns:
            Dict[str, List[str]]: Extracted key-value pairs grouped by pattern
        """
        extracted = defaultdict(list)
        
        for i, pattern_str in enumerate(patterns):
            try:
                pattern = re.compile(pattern_str, re.IGNORECASE | re.MULTILINE)
                for match in pattern.finditer(content):
                    if 'key' in match.groupdict() and 'value' in match.groupdict():
                        key = match.group('key').strip()
                        value = match.group('value').strip()
                        extracted[f"pattern_{i}"].append(f"{key}={value}")
            except re.error as e:
                logger.warning(f"Invalid regex pattern: {pattern_str}: {e}")
        
        return dict(extracted)

class DataValidator:
    """Data validation and sanitization utilities."""
    
    @staticmethod
    def validate_file_size(file_path: str, max_size_mb: int = 50) -> bool:
        """
        Validate file size is within acceptable limits.
        
        Args:
            file_path: Path to file to check
            max_size_mb: Maximum allowed size in MB
            
        Returns:
            bool: True if file size is acceptable
        """
        try:
            file_size = Path(file_path).stat().st_size
            max_size_bytes = max_size_mb * 1024 * 1024
            return file_size <= max_size_bytes
        except Exception:
            return False
    
    @staticmethod
    def sanitize_string(text: str, max_length: int = 1000, preserve_newlines: bool = False) -> str:
        """
        Sanitize string for safe processing and display.
        
        Args:
            text: Text to sanitize
            max_length: Maximum allowed length
            preserve_newlines: Whether to preserve newline characters
            
        Returns:
            str: Sanitized text
        """
        if not text:
            return ""
        
        # Remove or replace control characters
        if preserve_newlines:
            # Keep newlines but remove other control chars
            sanitized = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '', text)
        else:
            # Remove all control characters including newlines
            sanitized = re.sub(r'[\x00-\x1F\x7F]', ' ', text)
        
        # Normalize whitespace
        sanitized = re.sub(r'\s+', ' ', sanitized).strip()
        
        # Truncate if too long
        if len(sanitized) > max_length:
            sanitized = sanitized[:max_length-3] + "..."
        
        return sanitized
    
    @staticmethod
    def validate_encoding_patterns(content: str, expected_patterns: List[str]) -> Dict[str, bool]:
        """
        Validate that content contains expected encoding patterns.
        
        Args:
            content: Content to validate
            expected_patterns: List of regex patterns that should be present
            
        Returns:
            Dict[str, bool]: Validation results for each pattern
        """
        results = {}
        
        for pattern_str in expected_patterns:
            try:
                pattern = re.compile(pattern_str, re.IGNORECASE)
                results[pattern_str] = bool(pattern.search(content))
            except re.error:
                results[pattern_str] = False
        
        return results
    
    @staticmethod
    def detect_suspicious_patterns(content: str) -> List[str]:
        """
        Detect potentially suspicious patterns in content.
        
        Args:
            content: Content to analyze
            
        Returns:
            List[str]: List of detected suspicious patterns
        """
        suspicious_patterns = [
            r'eval\s*\(',
            r'exec\s*\(',
            r'system\s*\(',
            r'shell_exec\s*\(',
            r'base64_decode\s*\(',
            r'[A-Za-z0-9+/]{50,}={0,2}',  # Base64-like strings
            r'\\x[0-9a-fA-F]{2}',  # Hex escape sequences
            r'%[0-9a-fA-F]{2}',  # URL encoding
        ]
        
        detected = []
        for pattern_str in suspicious_patterns:
            try:
                pattern = re.compile(pattern_str)
                if pattern.search(content):
                    detected.append(pattern_str)
            except re.error:
                continue
        
        return detected

class EncodingUtils:
    """Encoding and decoding utilities for various formats."""
    
    @staticmethod
    def decode_base64_safe(content: str) -> Optional[str]:
        """
        Safely decode base64 content.
        
        Args:
            content: Base64 encoded string
            
        Returns:
            Optional[str]: Decoded content or None if decoding failed
        """
        try:
            # Clean the input
            content = content.strip().replace(' ', '').replace('\n', '')
            
            # Add padding if missing
            missing_padding = len(content) % 4
            if missing_padding:
                content += '=' * (4 - missing_padding)
            
            decoded_bytes = base64.b64decode(content)
            return decoded_bytes.decode('utf-8', errors='ignore')
        
        except Exception as e:
            logger.debug(f"Base64 decoding failed: {e}")
            return None
    
    @staticmethod
    def decode_hex_safe(content: str) -> Optional[str]:
        """
        Safely decode hexadecimal content.
        
        Args:
            content: Hex encoded string
            
        Returns:
            Optional[str]: Decoded content or None if decoding failed
        """
        try:
            # Clean the input
            content = content.strip().replace(' ', '').replace('0x', '')
            
            decoded_bytes = bytes.fromhex(content)
            return decoded_bytes.decode('utf-8', errors='ignore')
        
        except Exception as e:
            logger.debug(f"Hex decoding failed: {e}")
            return None
    
    @staticmethod
    def detect_encoding_type(content: str) -> str:
        """
        Detect the likely encoding type of content.
        
        Args:
            content: Content to analyze
            
        Returns:
            str: Detected encoding type
        """
        content = content.strip()
        
        # Base64 detection
        if re.match(r'^[A-Za-z0-9+/]*={0,2}$', content) and len(content) % 4 == 0:
            return "base64"
        
        # Hex detection
        if re.match(r'^(0x)?[0-9a-fA-F]+$', content):
            return "hex"
        
        # URL encoding detection
        if '%' in content and re.search(r'%[0-9a-fA-F]{2}', content):
            return "url_encoded"
        
        # JWT detection
        if content.count('.') == 2:
            parts = content.split('.')
            if all(re.match(r'^[A-Za-z0-9_-]+$', part) for part in parts):
                return "jwt"
        
        return "plain_text"
    
    @staticmethod
    def calculate_entropy(content: str) -> float:
        """
        Calculate Shannon entropy of content.
        
        Args:
            content: Content to analyze
            
        Returns:
            float: Entropy value (0.0 to 8.0)
        """
        if not content:
            return 0.0
        
        # Count character frequencies
        char_counts = defaultdict(int)
        for char in content:
            char_counts[char] += 1
        
        # Calculate entropy
        length = len(content)
        entropy = 0.0
        
        for count in char_counts.values():
            probability = count / length
            entropy -= probability * (probability.bit_length() - 1)
        
        return entropy

class ContentAnalyzer:
    """Advanced content analysis utilities."""
    
    @staticmethod
    def extract_urls(content: str) -> List[str]:
        """
        Extract URLs from content using comprehensive patterns.
        
        Args:
            content: Content to search
            
        Returns:
            List[str]: List of extracted URLs
        """
        url_patterns = [
            r'https?://[^\s<>"{}|\\^`\[\]]+',
            r'ftp://[^\s<>"{}|\\^`\[\]]+',
            r'www\.[^\s<>"{}|\\^`\[\]]+',
        ]
        
        urls = []
        for pattern_str in url_patterns:
            pattern = re.compile(pattern_str, re.IGNORECASE)
            matches = pattern.findall(content)
            urls.extend(matches)
        
        return list(set(urls))  # Remove duplicates
    
    @staticmethod
    def extract_ip_addresses(content: str) -> List[str]:
        """
        Extract IP addresses from content.
        
        Args:
            content: Content to search
            
        Returns:
            List[str]: List of extracted IP addresses
        """
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        pattern = re.compile(ip_pattern)
        
        ips = pattern.findall(content)
        
        # Validate IP addresses
        valid_ips = []
        for ip in ips:
            parts = ip.split('.')
            if all(0 <= int(part) <= 255 for part in parts):
                valid_ips.append(ip)
        
        return list(set(valid_ips))
    
    @staticmethod
    def extract_email_addresses(content: str) -> List[str]:
        """
        Extract email addresses from content.
        
        Args:
            content: Content to search
            
        Returns:
            List[str]: List of extracted email addresses
        """
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        pattern = re.compile(email_pattern)
        
        emails = pattern.findall(content)
        return list(set(emails))
    
    @staticmethod
    def extract_hash_values(content: str) -> Dict[str, List[str]]:
        """
        Extract various hash values from content.
        
        Args:
            content: Content to search
            
        Returns:
            Dict[str, List[str]]: Hash values grouped by type
        """
        hash_patterns = {
            'md5': r'\b[a-fA-F0-9]{32}\b',
            'sha1': r'\b[a-fA-F0-9]{40}\b',
            'sha256': r'\b[a-fA-F0-9]{64}\b',
            'sha512': r'\b[a-fA-F0-9]{128}\b'
        }
        
        extracted_hashes = {}
        for hash_type, pattern_str in hash_patterns.items():
            pattern = re.compile(pattern_str)
            matches = pattern.findall(content)
            if matches:
                extracted_hashes[hash_type] = list(set(matches))
        
        return extracted_hashes
    
    @staticmethod
    def analyze_text_statistics(content: str) -> Dict[str, Any]:
        """
        Analyze text statistics for content characterization.
        
        Args:
            content: Content to analyze
            
        Returns:
            Dict[str, Any]: Text statistics
        """
        if not content:
            return {}
        
        lines = content.split('\n')
        words = content.split()
        
        # Character analysis
        char_counts = defaultdict(int)
        for char in content:
            char_counts[char] += 1
        
        # Calculate statistics
        stats = {
            'total_characters': len(content),
            'total_lines': len(lines),
            'total_words': len(words),
            'avg_line_length': sum(len(line) for line in lines) / len(lines) if lines else 0,
            'avg_word_length': sum(len(word) for word in words) / len(words) if words else 0,
            'unique_characters': len(char_counts),
            'entropy': EncodingUtils.calculate_entropy(content),
            'printable_ratio': sum(1 for c in content if c.isprintable()) / len(content) if content else 0,
            'alpha_ratio': sum(1 for c in content if c.isalpha()) / len(content) if content else 0,
            'digit_ratio': sum(1 for c in content if c.isdigit()) / len(content) if content else 0,
        }
        
        return stats

# Export main classes for easy import
__all__ = [
    'CompiledPattern',
    'PatternCompiler',
    'ContentParser',
    'DataValidator',
    'EncodingUtils', 
    'ContentAnalyzer'
] 
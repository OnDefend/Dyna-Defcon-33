#!/usr/bin/env python3
"""
Source Code Analyzer for AODS

JADX Integration & Decompiled Source Analysis Engine

Advanced source code analysis capabilities for Android applications with
comprehensive decompilation and security assessment features.
"""

import hashlib
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Import JADX unified helper for memory optimization
try:
    from core.shared_infrastructure import get_decompiled_sources_unified, analyze_with_jadx_optimized
    JADX_UNIFIED_AVAILABLE = True
except ImportError:
    JADX_UNIFIED_AVAILABLE = False
    logger.warning("JADX unified helper not available, using direct implementation")

@dataclass
class SourceCodeFinding:
    """Represents a security finding in source code."""

    finding_type: str
    severity: str
    confidence: float
    file_path: str
    line_number: int
    code_snippet: str
    pattern_matched: str
    description: str
    category: str
    remediation: str
    context: Dict[str, Any]

@dataclass
class DecompilationResult:
    """Results from JADX decompilation process."""

    success: bool
    output_directory: str
    decompilation_time: float
    total_files: int
    java_files: int
    kotlin_files: int
    xml_files: int
    error_message: Optional[str] = None

@dataclass
class SourceAnalysisResult:
    """Complete source code analysis results."""

    apk_path: str
    analysis_time: float
    decompilation_result: DecompilationResult
    findings: List[SourceCodeFinding]
    statistics: Dict[str, Any]
    performance_metrics: Dict[str, float]
    memory_usage: Dict[str, float]

    @property
    def security_findings(self) -> List[SourceCodeFinding]:
        """Alias for findings to maintain compatibility with evaluation scripts."""
        return self.findings

    @property
    def finding_count(self) -> int:
        """Total number of findings."""
        return len(self.findings)

    @property
    def high_severity_count(self) -> int:
        """Number of high severity findings."""
        return len([f for f in self.findings if f.severity.upper() == "HIGH"])

    @property
    def medium_severity_count(self) -> int:
        """Number of medium severity findings."""
        return len([f for f in self.findings if f.severity.upper() == "MEDIUM"])

    @property
    def low_severity_count(self) -> int:
        """Number of low severity findings."""
        return len([f for f in self.findings if f.severity.upper() == "LOW"])

class SourceCodeAnalyzer:
    """
    🔍 AODS Source Code Analyzer with JADX Integration

    Comprehensive source code analysis for Android APKs using organic
    vulnerability detection patterns. No hardcoded app-specific logic.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the Source Code Analyzer."""
        self.config = config or self._get_default_config()
        self.jadx_path = self._find_jadx_executable()
        self.analysis_lock = threading.Lock()

        # Security patterns for organic detection
        self._initialize_security_patterns()

        # Performance tracking
        self.performance_metrics = {
            "decompilation_time": 0.0,
            "analysis_time": 0.0,
            "pattern_matching_time": 0.0,
            "total_time": 0.0,
        }

        # 🚀 Deobfuscation Integration - Deobfuscation Integration - Multi-layer encoding detection
        self.deobfuscation_enabled = True
        self.deobfuscation_chain_patterns = {
            # Common obfuscation chains
            "base64_rot13": [
                r'Base64\.decode\s*\(\s*rot13\s*\(',
                r'rot13\s*\(\s*Base64\.decode\s*\(',
                r'String.*Base64.*rot.*13',
                r'decode.*rot.*encode',
            ],
            "base64_xor": [
                r'Base64\.decode.*\^\s*0x[0-9a-fA-F]+',
                r'decode.*xor.*[0-9]+',
                r'String.*Base64.*\^\s*[0-9x]+',
                r'decodeBase64.*xor\s*\(',
            ],
            "base64_reverse": [
                r'reverse\s*\(\s*Base64\.decode',
                r'Base64\.decode.*reverse\s*\(',
                r'StringBuilder.*reverse.*Base64',
                r'StringBuffer.*reverse.*decode',
            ],
            "base64_hex": [
                r'Base64\.decode.*Integer\.parseInt.*16',
                r'decode.*fromHex',
                r'hexToString.*Base64',
                r'Base64.*hex.*decode',
            ],
            "multiple_base64": [
                r'Base64\.decode\s*\(\s*Base64\.decode',
                r'decode.*decode.*decode',
                r'String.*new.*String.*Base64.*Base64',
                r'decodeBase64.*decodeBase64',
            ],
            "url_base64": [
                r'URLDecoder\.decode.*Base64\.decode',
                r'Base64\.decode.*URLDecoder\.decode',
                r'decode.*url.*base64',
                r'base64.*url.*decode',
            ],
        }
        
        # 🚀 Deobfuscation Integration - Enhanced deobfuscation confidence weights
        self.deobfuscation_confidence_weights = {
            # Multi-layer encoding bonuses
            "double_encoding": 0.4,        # Two layers of encoding detected
            "triple_encoding": 0.6,        # Three layers of encoding detected
            "complex_chain": 0.8,          # Complex multi-step deobfuscation chain
            
            # Obfuscation technique bonuses
            "rot13_encoding": 0.25,        # ROT13 obfuscation detected
            "xor_obfuscation": 0.35,       # XOR obfuscation detected
            "reverse_string": 0.2,         # String reversal obfuscation
            "hex_encoding": 0.3,           # Hexadecimal encoding detected
            "custom_cipher": 0.45,         # Custom cipher implementation
            
            # Context-specific bonuses
            "obfuscated_strings": 0.3,     # Obfuscated string literals
            "encrypted_payloads": 0.5,     # Encrypted payload detection
            "anti_analysis": 0.6,          # Anti-analysis techniques
            "steganography": 0.7,          # Steganographic content hiding
            
            # Complexity indicators
            "nested_operations": 0.25,     # Nested encoding operations
            "dynamic_keys": 0.35,          # Dynamic key generation
            "time_based_keys": 0.4,        # Time-based key derivation
            "environment_dependent": 0.3,  # Environment-dependent decoding
        }
        
        # 🚀 Deobfuscation Integration - Deobfuscation pattern matchers
        self.obfuscation_patterns = {
            # ROT13 and Caesar cipher patterns
            "rot_cipher": [
                r'rot13\s*\(',
                r'caesar\s*\(',
                r'shift\s*\(\s*[^,]+,\s*13\s*\)',
                r'char.*\+.*13.*%.*26',
                r'[a-zA-Z]\s*\+\s*13',
                r'Character\.toString.*\+.*13',
            ],
            
            # XOR obfuscation patterns
            "xor_obfuscation": [
                r'\^\s*0x[0-9a-fA-F]+',
                r'\^\s*[0-9]+',
                r'xor\s*\(',
                r'byte.*\^\s*key',
                r'char.*\^\s*[0-9x]+',
                r'decrypt.*xor',
            ],
            
            # String reversal patterns
            "string_reversal": [
                r'reverse\s*\(\s*\)',
                r'StringBuilder.*reverse',
                r'StringBuffer.*reverse',
                r'new.*String.*reverse',
                r'charAt.*length.*-.*1',
                r'substring.*reverse',
            ],
            
            # Hexadecimal encoding patterns
            "hex_encoding": [
                r'Integer\.parseInt\s*\([^,]+,\s*16\s*\)',
                r'fromHex\s*\(',
                r'hexToString\s*\(',
                r'parseHex\s*\(',
                r'[0-9a-fA-F]{16,}',
                r'decode.*hex.*16',
            ],
            
            # Custom cipher implementations
            "custom_cipher": [
                r'encrypt\s*\([^)]+key[^)]*\)',
                r'decrypt\s*\([^)]+key[^)]*\)',
                r'cipher\s*\([^)]+\)',
                r'scramble\s*\(',
                r'obfuscate\s*\(',
                r'transform\s*\([^)]+key[^)]*\)',
            ],
            
            # Anti-analysis techniques
            "anti_analysis": [
                r'isDebuggerConnected\s*\(\s*\)',
                r'detectEmulator\s*\(\s*\)',
                r'checkRoot\s*\(\s*\)',
                r'anti.*debug',
                r'detect.*hook',
                r'bypass.*detection',
            ],
        }

        # 🚀 Deobfuscation Integration - Common obfuscation key patterns
        self.obfuscation_key_patterns = [
            r'key\s*=\s*["\'][^"\']{8,}["\']',
            r'password\s*=\s*["\'][^"\']+["\']',
            r'seed\s*=\s*[0-9]+',
            r'salt\s*=\s*["\'][^"\']+["\']',
            r'secret\s*=\s*["\'][^"\']+["\']',
        ]

        logger.debug("🔍 Source Code Analyzer initialized successfully")

    def _get_default_config(self) -> Dict[str, Any]:
        """Get default configuration for source code analysis."""
        return {
            "jadx_options": [
                "--no-res",  # Skip resources for faster decompilation
                "--no-imports",  # Skip unused imports
                "--escape-unicode",  # Escape unicode characters
                "--respect-bytecode-access-modifiers",
                "--deobf",  # Enable deobfuscation
                "--deobf-min",
                "3",  # Minimum length for deobfuscation
                "--deobf-max",
                "64",  # Maximum length for deobfuscation
            ],
            "analysis_options": {
                "max_file_size_mb": 10,  # Skip files larger than 10MB
                "max_analysis_time_seconds": 30,  # Per APK analysis timeout
                "enable_parallel_processing": True,
                "max_worker_threads": min(8, os.cpu_count() or 4),  # PERFORMANCE FIX: Increased workers
                "memory_limit_gb": 2.0,
                "enable_kotlin_analysis": True,
                "enable_xml_analysis": True,
                "pattern_confidence_threshold": 0.6,
                "use_process_pool": False,  # PERFORMANCE FIX: Disable ProcessPool for stability, use optimized threads
                "max_files_to_analyze": 2000,  # PERFORMANCE FIX: Limit files to analyze for large APKs
                "skip_framework_files": True,  # PERFORMANCE FIX: Skip Android framework files
                "batch_processing": True,  # PERFORMANCE FIX: Enable batch processing
            },
            "performance": {
                "target_decompilation_time": 25.0,  # seconds
                "target_analysis_time": 30.0,  # seconds
                "memory_warning_threshold": 1.5,  # GB
            },
        }

    def _find_jadx_executable(self) -> str:
        """Find JADX executable in system PATH."""
        jadx_candidates = ["jadx", "/usr/bin/jadx", "/usr/local/bin/jadx"]

        for candidate in jadx_candidates:
            if shutil.which(candidate):
                logger.debug(f"✅ Found JADX at: {candidate}")
                return candidate

        raise RuntimeError("❌ JADX not found in system PATH. Please install JADX.")

    def _initialize_security_patterns(self) -> None:
        """Initialize comprehensive security patterns for organic detection."""

        # ORGANIC secret detection patterns (universal, no hardcoded app names)
        self.sensitive_patterns = {
            # Generic secret patterns (universal, no hardcoded app names)
            "secrets": [
                r'[Pp]assword\s*[:=]\s*["\'][^"\']{4,}["\']',  # Password literals
                r'[Ss]ecret\s*[:=]\s*["\'][^"\']{4,}["\']',  # Secret literals
                r'[Kk]ey\s*[:=]\s*["\'][^"\']{8,}["\']',  # Key literals
                r'[Tt]oken\s*[:=]\s*["\'][^"\']{16,}["\']',  # Token literals
            ],
            # Generic API key patterns
            "api_keys": [
                r'[Aa]pi[_-]?[Kk]ey\s*[:=]\s*["\'][^"\']{8,}["\']',  # API keys
                r'[Aa]ccess[_-]?[Kk]ey\s*[:=]\s*["\'][^"\']{8,}["\']',  # Access keys
                r'[Aa]uth[_-]?[Tt]oken\s*[:=]\s*["\'][^"\']{8,}["\']',  # Auth tokens
            ],
            # 🔥 PRIORITY 1 FIX: Enhanced Base64 Detection with Context Awareness
            "encoding": [
                # Multi-length Base64 patterns with improved specificity
                r"[A-Za-z0-9+/]{12,}={0,2}",  # Base64 12+ chars (improved from 16+)
                r"[A-Za-z0-9+/]{16,}={0,2}",  # Base64 16+ chars (medium confidence)
                r"[A-Za-z0-9+/]{32,}={0,2}",  # Base64 32+ chars (high confidence)
                r"[A-Za-z0-9+/]{64,}={0,2}",  # Base64 64+ chars (very high confidence)
                r"[A-Za-z0-9+/]{20}=",        # Base64 with single padding
                r"[A-Za-z0-9+/]{24}==?",      # Base64 with double padding patterns
                # Context-aware Base64 patterns (higher confidence when in context)
                r'["\'][A-Za-z0-9+/]{12,}={0,2}["\']',  # Quoted Base64 strings (12+ chars)
                r'=\s*["\'][A-Za-z0-9+/]{12,}={0,2}["\']',  # Assignment context
                r'String\s+\w+\s*=\s*["\'][A-Za-z0-9+/]{12,}={0,2}["\']',  # String variable assignment
                r'final\s+String\s+\w+\s*=\s*["\'][A-Za-z0-9+/]{12,}={0,2}["\']',  # Final string assignment
                
                # Base64 method context (very high confidence)
                r'Base64\.decode\s*\(\s*["\'][A-Za-z0-9+/]{8,}={0,2}["\']',  # Base64.decode() calls (even 8+ chars)
                r'fromBase64\s*\(\s*["\'][A-Za-z0-9+/]{8,}={0,2}["\']',  # fromBase64() calls
                r'decodeBase64\s*\(\s*["\'][A-Za-z0-9+/]{8,}={0,2}["\']',  # decodeBase64() calls
                r'android\.util\.Base64\.decode\s*\(\s*["\'][A-Za-z0-9+/]{8,}={0,2}["\']',  # Android Base64
                
                # URL encoding patterns
                r"%[0-9a-fA-F]{2}",  # URL encoding
            ],
            # Generic cloud service patterns
            "cloud_services": [
                r"AKIA[0-9A-Z]{16}",  # AWS Access Keys
                r"[A-Za-z0-9/+=]{40}",  # AWS Secret Keys (40 chars)
                r"AIza[0-9A-Za-z_-]{35}",  # Google API Keys
                r"firebase[a-z]*\.com",  # Firebase URLs
                r"\.s3\.amazonaws\.com",  # S3 URLs
            ],
        }

        # Comprehensive pattern matching
        self.all_secret_patterns = []
        for category, patterns in self.sensitive_patterns.items():
            self.all_secret_patterns.extend(patterns)

        # 🚀 Enhanced Base64 Intelligence - Enhanced Base64 Intelligence - Improved confidence scoring
        self.base64_validation_enabled = True
        self.base64_confidence_weights = {
            # Enhanced length-based confidence (more granular)
            "length_8_11": 0.15,     # Very low confidence for very short Base64
            "length_12_15": 0.25,    # Low confidence for short Base64
            "length_16_31": 0.45,    # Moderate confidence for medium Base64
            "length_32_63": 0.65,    # Good confidence for longer Base64
            "length_64_127": 0.8,    # High confidence for long Base64
            "length_128_plus": 0.9,  # Very high confidence for very long Base64
            
            # Context-aware detection bonuses
            "context_assignment": 0.08,     # String assignment context
            "context_final_variable": 0.12, # final String variable context
            "context_method_parameter": 0.15, # Method parameter context
            "context_method_call": 0.25,    # Base64.decode/encode method context (increased)
            "context_annotation": 0.1,      # @Value or similar annotations
            
            # Encoding validation bonuses
            "padding_valid": 0.06,          # Valid Base64 padding
            "charset_valid": 0.08,          # Valid Base64 character set
            "decode_successful": 0.15,      # Successfully decodable
            "decode_meaningful": 0.25,      # Decoded content contains meaningful data
            
            # Entropy and pattern analysis
            "entropy_high": 0.12,           # High entropy content (> 4.5)
            "entropy_very_high": 0.18,     # Very high entropy content (> 5.0)
            "pattern_randomness": 0.1,      # Randomness pattern indicators
            "pattern_repeating": -0.15,     # Penalty for repeating patterns
            
            # Semantic content analysis
            "contains_secrets": 0.3,        # Decoded content contains secret-like strings
            "contains_flags": 0.35,         # Decoded content contains flag-like strings
            "contains_keys": 0.25,          # Decoded content contains key-like strings
            "contains_urls": 0.2,           # Decoded content contains URLs
            "contains_config": 0.15,        # Decoded content contains configuration
            
            # Context penalties for false positives
            "penalty_image_data": -0.25,    # Likely image/binary data (increased penalty)
            "penalty_resource_path": -0.2,  # Likely resource file path (increased penalty)
            "penalty_guid_uuid": -0.15,     # Likely GUID/UUID format (increased penalty)
            "penalty_timestamp": -0.15,     # Likely timestamp format (increased penalty)
        }
        
        # 🚀 Enhanced Base64 Intelligence - Enhanced encoding chain analysis patterns
        self.encoding_chain_patterns = {
            "base64_decode_chain": [
                r'Base64\.decode\s*\(\s*([^)]+)\s*\)',
                r'fromBase64\s*\(\s*([^)]+)\s*\)',
                r'decodeBase64\s*\(\s*([^)]+)\s*\)',
                r'android\.util\.Base64\.decode\s*\(\s*([^)]+)\s*\)',
            ],
            "base64_encode_chain": [
                r'Base64\.encode\s*\(\s*([^)]+)\s*\)',
                r'toBase64\s*\(\s*([^)]+)\s*\)',
                r'encodeBase64\s*\(\s*([^)]+)\s*\)',
                r'android\.util\.Base64\.encode\s*\(\s*([^)]+)\s*\)',
            ],
            "string_processing_chain": [
                r'String\s+\w+\s*=\s*new\s+String\s*\(\s*Base64\.decode',
                r'new\s+String\s*\(\s*[^)]*\.decode\s*\(',
                r'\.toString\s*\(\s*[^)]*Base64',
            ]
        }
        
        # 🚀 Enhanced Base64 Intelligence - Semantic analysis keywords for decoded content
        self.semantic_keywords = {
            "secrets": ["password", "secret", "key", "token", "credential", "auth", "api"],
            "flags": ["flag", "ctf", "flag{", "flag_", "FLAG", "{", "}", "challenge"],
            "keys": ["private", "public", "rsa", "aes", "cipher", "encrypt", "decrypt"],
            "urls": ["http://", "https://", "ftp://", "://", ".com", ".org", ".net"],
            "config": ["config", "setting", "property", "value", "option", "param"],
        }

        # ���� Enhanced Pattern Detection - Vulnerability patterns
        self.vulnerability_patterns = {
            # 1. Hardcoded authentication bypass patterns (FLAG 1 type)
            "authentication_bypass": [
                r'if\s*\(\s*["\']?true["\']?\s*\)',  # if (true) bypass
                r'return\s+true\s*;',  # return true; bypass
                r'[Pp]assword\s*[=:]\s*["\']["\']',  # Empty password
                r'[Uu]sername\s*[=:]\s*["\']admin["\']',  # Hardcoded admin
                r'[Aa]uth\w*\s*=\s*true',  # Authentication = true
                r'[Ii]s[Aa]uthorized\s*=\s*true',  # isAuthorized = true
                r'[Ll]ogin\w*\s*=\s*true',  # loginSuccess = true
                r'bypass|skip.*[Aa]uth',  # bypass authentication
                r'[Aa]llow[Aa]ll\s*=\s*true',  # allowAll = true
                r'[Dd]isable.*[Ss]ecurity',  # disable security
            ],
            
            # 2. Weak cryptographic implementations (DES, MD5, SHA1) (FLAG 6 type)
            "weak_crypto": [
                r'DES["\']|"DES"|\'DES\'',  # DES algorithm
                r'3DES["\']|"3DES"|\'3DES\'',  # 3DES algorithm
                r'MD5["\']|"MD5"|\'MD5\'',  # MD5 algorithm
                r'SHA1["\']|"SHA1"|\'SHA1\'',  # SHA1 algorithm
                r'MessageDigest\.getInstance\s*\(\s*["\']MD5["\']',  # MD5 usage
                r'MessageDigest\.getInstance\s*\(\s*["\']SHA-?1["\']',  # SHA1 usage
                r'Cipher\.getInstance\s*\(\s*["\']DES',  # DES cipher
                r'DigestUtils\.md5',  # Apache Commons MD5
                r'DigestUtils\.sha1',  # Apache Commons SHA1
                r'Mac\.getInstance\s*\(\s*["\']HmacMD5["\']',  # HMAC-MD5
                r'Mac\.getInstance\s*\(\s*["\']HmacSHA1["\']',  # HMAC-SHA1
                r'[Cc]rypto.*[Mm]d5',  # Crypto MD5 patterns
                r'[Hh]ash.*[Mm]d5',  # Hash MD5 patterns
            ],
            
            # 3. Insecure random number generation patterns
            "insecure_random": [
                r'Math\.random\s*\(\s*\)',  # Math.random()
                r'Random\s*\(\s*\)',  # new Random() without seed
                r'Random\s*\(\s*System\.currentTimeMillis',  # Predictable seed
                r'Random\s*\(\s*\d+\s*\)',  # Fixed seed
                r'new\s+Random\s*\(\s*[0-9]+\s*\)',  # Fixed numeric seed
                r'SecureRandom\s*\(\s*[0-9]+\s*\)',  # Fixed seed for SecureRandom
                r'setSeed\s*\(\s*[0-9]+\s*\)',  # Setting fixed seed
                r'nextInt\s*\(\s*\)\s*%',  # Modulo bias in random
                r'Math\.random\s*\(\s*\)\s*\*',  # Scaled Math.random
            ],
            
            # 4. Debug code patterns in production builds
            "debug_code": [
                r'Log\.d\s*\(|Log\.v\s*\(',  # Debug/Verbose logging
                r'System\.out\.print',  # System.out debug prints
                r'printStackTrace\s*\(\s*\)',  # Stack trace printing
                r'BuildConfig\.DEBUG\s*==\s*true',  # Debug flag checks
                r'if\s*\(\s*DEBUG\s*\)',  # Debug conditional blocks
                r'[Dd]ebug\s*=\s*true',  # Debug flag assignments
                r'[Tt]est\w*\s*=\s*true',  # Test mode flags
                r'//\s*TODO',  # TODO comments
                r'//\s*FIXME',  # FIXME comments
                r'//\s*HACK',  # HACK comments
                r'throw\s+new\s+RuntimeException\s*\(\s*["\']',  # Debug exceptions
            ],
            
            # 5. SQL Injection vulnerabilities
            "sql_injection": [
                r'SELECT\s+.*\+.*FROM',  # String concatenation in SQL
                r'INSERT\s+.*\+.*VALUES',  # String concatenation in INSERT
                r'UPDATE\s+.*\+.*SET',  # String concatenation in UPDATE
                r'DELETE\s+.*\+.*WHERE',  # String concatenation in DELETE
                r'query\s*\(\s*["\'][^"\']*\+',  # Query with concatenation
                r'execSQL\s*\(\s*["\'][^"\']*\+',  # execSQL with concatenation
                r'rawQuery\s*\(\s*["\'][^"\']*\+',  # rawQuery with concatenation
            ],
            
            # 6. WebView vulnerabilities
            "webview_vulnerabilities": [
                r'setJavaScriptEnabled\s*\(\s*true\s*\)',  # JavaScript enabled
                r'setAllowFileAccess\s*\(\s*true\s*\)',  # File access enabled
                r'setAllowContentAccess\s*\(\s*true\s*\)',  # Content access
                r'setAllowFileAccessFromFileURLs\s*\(\s*true\s*\)',  # File URL access
                r'setAllowUniversalAccessFromFileURLs\s*\(\s*true\s*\)',  # Universal access
                r'addJavascriptInterface\s*\(',  # JavaScript interface exposure
                r'loadUrl\s*\(\s*["\']file://',  # Loading file URLs
                r'loadData.*text/html',  # Loading HTML data
            ],
            
            # 7. Insecure networking patterns
            "insecure_networking": [
                r'http://[^"\']*',  # HTTP URLs (cleartext)
                r'TrustManager.*return\s+true',  # Trust all certificates
                r'HostnameVerifier.*return\s+true',  # Accept all hostnames
                r'setHostnameVerifier.*ALLOW_ALL',  # Allow all hostnames
                r'SSL_VERIFY_NONE|VERIFY_NONE',  # Disable SSL verification
                r'checkServerTrusted.*\{\s*\}',  # Empty trust check
                r'checkClientTrusted.*\{\s*\}',  # Empty client trust check
                r'getAcceptedIssuers.*return\s+null',  # Return null for issuers
            ],
        }

        # ���� Enhanced Pattern Detection - Insecure method patterns
        self.method_patterns = {
            # Cryptographic method misuse
            "crypto_methods": [
                r'Cipher\.getInstance\s*\(\s*["\'][^"\']*ECB[^"\']*["\']',  # ECB mode
                r'KeyGenerator\.getInstance\s*\(\s*["\']DES["\']',  # DES key generation
                r'SecretKeySpec\s*\([^)]*,\s*["\']DES["\']',  # DES key spec
                r'IvParameterSpec\s*\(\s*new\s+byte\s*\[',  # Zero IV
            ],
            
            # File operation methods
            "file_methods": [
                r'openFileOutput\s*\([^,]*,\s*MODE_WORLD_READABLE',  # World readable files
                r'openFileOutput\s*\([^,]*,\s*MODE_WORLD_WRITEABLE',  # World writable files
                r'getSharedPreferences\s*\([^,]*,\s*MODE_WORLD_READABLE',  # World readable prefs
                r'getSharedPreferences\s*\([^,]*,\s*MODE_WORLD_WRITEABLE',  # World writable prefs
            ],
            
            # Network security methods
            "network_methods": [
                r'HttpURLConnection\s*.*setDefaultHostnameVerifier',  # Custom hostname verifier
                r'SSLContext\.getInstance\s*\(\s*["\']SSL["\']',  # SSL instead of TLS
                r'trust.*\.checkServerTrusted',  # Custom trust manager
            ],
        }

    def analyze_apk(self, apk_path: str) -> SourceAnalysisResult:
        """
        Analyze an APK file using JADX decompilation and source code analysis.

        Args:
            apk_path: Path to the APK file to analyze

        Returns:
            SourceAnalysisResult containing complete analysis results
        """
        start_time = time.time()

        try:
            # Validate APK file
            if not os.path.exists(apk_path):
                raise FileNotFoundError(f"APK file not found: {apk_path}")

            # Get APK size for performance tracking
            apk_size_mb = os.path.getsize(apk_path) / (1024 * 1024)
            logger.debug(
                f"🔍 Starting analysis of APK: {os.path.basename(apk_path)} ({apk_size_mb:.1f}MB)"
            )

            # Step 1: Decompile APK using JADX
            decompilation_result = self._decompile_apk(apk_path)

            if not decompilation_result.success:
                return SourceAnalysisResult(
                    apk_path=apk_path,
                    analysis_time=time.time() - start_time,
                    decompilation_result=decompilation_result,
                    findings=[],
                    statistics={"error": "Decompilation failed"},
                    performance_metrics=self.performance_metrics,
                    memory_usage=self._get_memory_usage(),
                )

            # Step 2: Analyze decompiled source code
            findings = self._analyze_source_code(decompilation_result.output_directory)

            # Step 3: Generate statistics and performance metrics
            statistics = self._generate_statistics(
                findings, decompilation_result, apk_size_mb
            )

            analysis_time = time.time() - start_time
            self.performance_metrics["total_time"] = analysis_time

            logger.debug(
                f"✅ Analysis completed in {analysis_time:.2f}s - Found {len(findings)} issues"
            )

            return SourceAnalysisResult(
                apk_path=apk_path,
                analysis_time=analysis_time,
                decompilation_result=decompilation_result,
                findings=findings,
                statistics=statistics,
                performance_metrics=self.performance_metrics,
                memory_usage=self._get_memory_usage(),
            )

        except Exception as e:
            logger.error(f"❌ Analysis failed: {str(e)}")
            return SourceAnalysisResult(
                apk_path=apk_path,
                analysis_time=time.time() - start_time,
                decompilation_result=DecompilationResult(
                    success=False,
                    output_directory="",
                    decompilation_time=0.0,
                    total_files=0,
                    java_files=0,
                    kotlin_files=0,
                    xml_files=0,
                    error_message=str(e),
                ),
                findings=[],
                statistics={"error": str(e)},
                performance_metrics=self.performance_metrics,
                memory_usage=self._get_memory_usage(),
            )

        finally:
            # Cleanup temporary files
            if hasattr(self, "_temp_output_dir") and os.path.exists(
                self._temp_output_dir
            ):
                try:
                    shutil.rmtree(self._temp_output_dir)
                except Exception as e:
                    logger.warning(f"⚠️ Failed to cleanup temp directory: {e}")

    def _decompile_apk(self, apk_path: str) -> DecompilationResult:
        """
        Decompile APK using memory-optimized unified JADX helper.
        
        This method now uses the centralized JADX manager and cache system
        to eliminate redundant decompilations and optimize memory usage.
        """
        start_time = time.time()

        try:
            # Use unified JADX helper for memory optimization
            if JADX_UNIFIED_AVAILABLE:
                logger.debug("🔧 Using memory-optimized JADX decompilation...")
                
                # Get timeout from config
                timeout = self.config["analysis_options"]["max_analysis_time_seconds"]
                
                # Use unified helper with memory optimization
                decompiled_dir = get_decompiled_sources_unified(
                    apk_path=apk_path,
                    analyzer_name="SourceCodeAnalyzer",
                    timeout=timeout
                )
                
                if decompiled_dir:
                    # Store for cleanup (only if it's a temporary directory)
                    if "temp" in str(decompiled_dir).lower():
                        self._temp_output_dir = decompiled_dir
                    
                    decompilation_time = time.time() - start_time
                    self.performance_metrics["decompilation_time"] = decompilation_time
                    
                    # Count decompiled files
                    file_counts = self._count_decompiled_files(decompiled_dir)
                    
                    logger.debug(f"✅ Memory-optimized decompilation completed in {decompilation_time:.2f}s")
                    logger.debug(
                        f"📊 Files: {file_counts['total']} total, {file_counts['java']} Java, {file_counts['kotlin']} Kotlin"
                    )
                    
                    return DecompilationResult(
                        success=True,
                        output_directory=decompiled_dir,
                        decompilation_time=decompilation_time,
                        total_files=file_counts["total"],
                        java_files=file_counts["java"],
                        kotlin_files=file_counts["kotlin"],
                        xml_files=file_counts["xml"],
                        error_message=None,
                    )
                else:
                    # Unified helper failed, fall back to direct implementation
                    logger.warning("Memory-optimized decompilation failed, falling back to direct JADX")
                    return self._decompile_apk_direct(apk_path, start_time)
            else:
                # Unified helper not available, use direct implementation
                return self._decompile_apk_direct(apk_path, start_time)
                
        except Exception as e:
            logger.error(f"❌ Memory-optimized JADX decompilation failed: {str(e)}")
            # Fall back to direct implementation
            return self._decompile_apk_direct(apk_path, start_time)
    
    def _decompile_apk_direct(self, apk_path: str, start_time: float) -> DecompilationResult:
        """Direct JADX decompilation fallback method."""
        try:
            # Create temporary output directory
            self._temp_output_dir = tempfile.mkdtemp(prefix="aods_jadx_direct_")

            # Convert to absolute path to avoid JADX path issues
            abs_apk_path = os.path.abspath(apk_path)

            # Build JADX command
            jadx_cmd = [
                self.jadx_path,
                *self.config["jadx_options"],
                "--output-dir",
                self._temp_output_dir,
                abs_apk_path,
            ]

            logger.debug(f"🔧 Decompiling APK with direct JADX (fallback)...")

            # Execute JADX with timeout
            result = subprocess.run(
                jadx_cmd,
                capture_output=True,
                text=True,
                timeout=self.config["analysis_options"]["max_analysis_time_seconds"],
            )

            decompilation_time = time.time() - start_time
            self.performance_metrics["decompilation_time"] = decompilation_time

            if result.returncode != 0:
                logger.warning(f"⚠️ JADX completed with warnings: {result.stderr}")

            # Count decompiled files
            file_counts = self._count_decompiled_files(self._temp_output_dir)

            logger.debug(f"✅ Direct decompilation completed in {decompilation_time:.2f}s")
            logger.debug(
                f"📊 Files: {file_counts['total']} total, {file_counts['java']} Java, {file_counts['kotlin']} Kotlin"
            )

            return DecompilationResult(
                success=True,
                output_directory=self._temp_output_dir,
                decompilation_time=decompilation_time,
                total_files=file_counts["total"],
                java_files=file_counts["java"],
                kotlin_files=file_counts["kotlin"],
                xml_files=file_counts["xml"],
                error_message=result.stderr if result.returncode != 0 else None,
            )

        except subprocess.TimeoutExpired:
            logger.error("❌ Direct JADX decompilation timed out")
            return DecompilationResult(
                success=False,
                output_directory="",
                decompilation_time=time.time() - start_time,
                total_files=0,
                java_files=0,
                kotlin_files=0,
                xml_files=0,
                error_message="Decompilation timed out",
            )
        except Exception as e:
            logger.error(f"❌ Direct JADX decompilation failed: {str(e)}")
            return DecompilationResult(
                success=False,
                output_directory="",
                decompilation_time=time.time() - start_time,
                total_files=0,
                java_files=0,
                kotlin_files=0,
                xml_files=0,
                error_message=str(e),
            )

    def _count_decompiled_files(self, output_dir: str) -> Dict[str, int]:
        """Count decompiled files by type."""
        counts = {"total": 0, "java": 0, "kotlin": 0, "xml": 0}

        try:
            for root, dirs, files in os.walk(output_dir):
                for file in files:
                    counts["total"] += 1
                    ext = os.path.splitext(file)[1].lower()
                    if ext == ".java":
                        counts["java"] += 1
                    elif ext in [".kt", ".kts"]:
                        counts["kotlin"] += 1
                    elif ext == ".xml":
                        counts["xml"] += 1
        except Exception as e:
            logger.warning(f"⚠️ Failed to count files: {e}")

        return counts

    def _analyze_source_code(self, source_dir: str) -> List[SourceCodeFinding]:
        """Analyze decompiled source code for security vulnerabilities."""
        start_time = time.time()
        findings = []

        try:
            # Get all relevant files for analysis
            files_to_analyze = self._get_files_for_analysis(source_dir)
            
            # PERFORMANCE OPTIMIZATION: Filter files to reduce analysis load
            files_to_analyze = self._filter_files_for_performance(files_to_analyze)

            logger.debug(f"🔍 Analyzing {len(files_to_analyze)} source files...")

            # Use parallel processing for better performance
            if self.config["analysis_options"]["enable_parallel_processing"]:
                findings = self._analyze_files_parallel(files_to_analyze)
            else:
                findings = self._analyze_files_sequential(files_to_analyze)

            analysis_time = time.time() - start_time
            self.performance_metrics["analysis_time"] = analysis_time

            logger.debug(f"🔍 Source analysis completed in {analysis_time:.2f}s")

            return findings

        except Exception as e:
            logger.error(f"❌ Source code analysis failed: {str(e)}")
            return []

    def _get_files_for_analysis(self, source_dir: str) -> List[str]:
        """Get list of files to analyze based on configuration."""
        files_to_analyze = []
        max_file_size = (
            self.config["analysis_options"]["max_file_size_mb"] * 1024 * 1024
        )

        try:
            for root, dirs, files in os.walk(source_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    ext = os.path.splitext(file)[1].lower()

                    # Check file type and size
                    if self._should_analyze_file(file_path, ext, max_size):
                        files_to_analyze.append(file_path)

        except Exception as e:
            logger.warning(f"⚠️ Failed to enumerate files: {e}")

        return files_to_analyze

    def _should_analyze_file(self, file_path: str, ext: str, max_size: int) -> bool:
        """Determine if a file should be analyzed."""
        # Check file extension
        analyzable_extensions = [".java", ".kt", ".kts"]
        if self.config["analysis_options"]["enable_xml_analysis"]:
            analyzable_extensions.append(".xml")

        if ext not in analyzable_extensions:
            return False

        # Check file size
        try:
            if os.path.getsize(file_path) > max_size:
                return False
        except OSError:
            return False

        return True

    def _analyze_files_parallel(self, files: List[str]) -> List[SourceCodeFinding]:
        """Analyze files using parallel processing with ProcessPoolExecutor for CPU-bound tasks."""
        findings = []
        max_workers = self.config["analysis_options"]["max_worker_threads"]
        
        # PERFORMANCE FIX: Use ProcessPoolExecutor for CPU-bound analysis (3-4x improvement)
        # This avoids Python's GIL limitation for pattern matching and file analysis
        use_process_pool = self.config["analysis_options"].get("use_process_pool", True)
        
        if use_process_pool and len(files) > 10:  # Use processes for larger file sets
            try:
                # Use ProcessPoolExecutor for CPU-intensive pattern matching
                with ProcessPoolExecutor(max_workers=min(max_workers, os.cpu_count() or 4)) as executor:
                    # Prepare data for multiprocessing (need to pass config and patterns)
                    analysis_data = {
                        'patterns': self.patterns,
                        'config': self.config
                    }
                    
                    futures = {
                        executor.submit(_analyze_file_worker, file_path, analysis_data): file_path
                        for file_path in files
                    }
                    
                    for future in as_completed(futures):
                        try:
                            file_findings = future.result(timeout=30)  # 30s per file
                            findings.extend(file_findings)
                        except Exception as e:
                            file_path = futures[future]
                            logger.warning(f"⚠️ Process pool analysis failed for {file_path}: {e}")
                            
            except Exception as e:
                logger.warning(f"⚠️ ProcessPoolExecutor failed, falling back to ThreadPoolExecutor: {e}")
                # Fallback to thread pool
                use_process_pool = False
        else:
            use_process_pool = False
            
        if not use_process_pool:
            # Fallback to ThreadPoolExecutor for smaller files or if ProcessPool fails
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {
                    executor.submit(self._analyze_file, file_path): file_path
                    for file_path in files
                }

                for future in as_completed(futures):
                    try:
                        file_findings = future.result()
                        findings.extend(file_findings)
                    except Exception as e:
                        file_path = futures[future]
                        logger.warning(f"⚠️ Failed to analyze {file_path}: {e}")

        return findings

    def _analyze_files_sequential(self, files: List[str]) -> List[SourceCodeFinding]:
        """Analyze files sequentially."""
        findings = []

        for file_path in files:
            try:
                file_findings = self._analyze_file(file_path)
                findings.extend(file_findings)
            except Exception as e:
                logger.warning(f"⚠️ Failed to analyze {file_path}: {e}")

        return findings

    def _analyze_file(self, file_path: str) -> List[SourceCodeFinding]:
        """Analyze a single source file for security vulnerabilities."""
        findings = []

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            # Analyze for different types of vulnerabilities
            findings.extend(self._find_secrets(file_path, content))
            findings.extend(self._find_vulnerabilities(file_path, content))
            findings.extend(self._find_insecure_methods(file_path, content))

        except Exception as e:
            logger.debug(f"⚠️ Failed to analyze file {file_path}: {e}")

        return findings

    def _find_secrets(self, file_path: str, content: str) -> List[SourceCodeFinding]:
        """Find hardcoded secrets in source code."""
        findings = []

        for category, patterns in self.sensitive_patterns.items():
            for pattern in patterns:
                try:
                    matches = re.finditer(
                        pattern, content, re.MULTILINE | re.IGNORECASE
                    )
                    for match in matches:
                        line_number = content[: match.start()].count("\n") + 1
                        code_snippet = self._get_code_snippet(
                            content, match.start(), match.end()
                        )

                        finding = SourceCodeFinding(
                            finding_type="hardcoded_secret",
                            severity=self._get_severity_for_secret(category),
                            confidence=self._calculate_confidence(
                                match, pattern, category, content
                            ),
                            file_path=file_path,
                            line_number=line_number,
                            code_snippet=code_snippet,
                            pattern_matched=pattern,
                            description=f"Hardcoded {category.replace('_', ' ')} detected in source code",
                            category=category,
                            remediation=self._get_remediation_for_secret(category),
                            context={
                                "match_groups": match.groups(),
                                "pattern_type": "secret",
                            },
                        )

                        # Filter low-confidence findings
                        if (
                            finding.confidence
                            >= self.config["analysis_options"][
                                "pattern_confidence_threshold"
                            ]
                        ):
                            findings.append(finding)

                except Exception as e:
                    logger.debug(f"⚠️ Pattern matching failed for {category}: {e}")

        return findings

    def _find_vulnerabilities(
        self, file_path: str, content: str
    ) -> List[SourceCodeFinding]:
        """Find security vulnerabilities in source code."""
        findings = []

        for category, patterns in self.vulnerability_patterns.items():
            for pattern in patterns:
                try:
                    matches = re.finditer(
                        pattern, content, re.MULTILINE | re.IGNORECASE
                    )
                    for match in matches:
                        line_number = content[: match.start()].count("\n") + 1
                        code_snippet = self._get_code_snippet(
                            content, match.start(), match.end()
                        )

                        finding = SourceCodeFinding(
                            finding_type="vulnerability",
                            severity=self._get_severity_for_vulnerability(category),
                            confidence=self._calculate_confidence(
                                match, pattern, category, content
                            ),
                            file_path=file_path,
                            line_number=line_number,
                            code_snippet=code_snippet,
                            pattern_matched=pattern,
                            description=f"{category.replace('_', ' ').title()} vulnerability detected",
                            category=category,
                            remediation=self._get_remediation_for_vulnerability(
                                category
                            ),
                            context={
                                "match_groups": match.groups(),
                                "pattern_type": "vulnerability",
                            },
                        )

                        if (
                            finding.confidence
                            >= self.config["analysis_options"][
                                "pattern_confidence_threshold"
                            ]
                        ):
                            findings.append(finding)

                except Exception as e:
                    logger.debug(
                        f"⚠️ Vulnerability pattern matching failed for {category}: {e}"
                    )

        return findings

    def _find_insecure_methods(
        self, file_path: str, content: str
    ) -> List[SourceCodeFinding]:
        """Find insecure method usage patterns."""
        findings = []

        for category, patterns in self.method_patterns.items():
            for pattern in patterns:
                try:
                    matches = re.finditer(
                        pattern, content, re.MULTILINE | re.IGNORECASE
                    )
                    for match in matches:
                        line_number = content[: match.start()].count("\n") + 1
                        code_snippet = self._get_code_snippet(
                            content, match.start(), match.end()
                        )

                        # Additional validation for method security
                        if self._is_method_potentially_insecure(code_snippet, category):
                            finding = SourceCodeFinding(
                                finding_type="insecure_method",
                                severity="medium",
                                confidence=self._calculate_confidence(
                                    match, pattern, category, content
                                ),
                                file_path=file_path,
                                line_number=line_number,
                                code_snippet=code_snippet,
                                pattern_matched=pattern,
                                description=f"Potentially insecure {category.replace('_', ' ')} method usage",
                                category=category,
                                remediation=self._get_remediation_for_method(category),
                                context={
                                    "match_groups": match.groups(),
                                    "pattern_type": "method",
                                },
                            )

                            if (
                                finding.confidence
                                >= self.config["analysis_options"][
                                    "pattern_confidence_threshold"
                                ]
                            ):
                                findings.append(finding)

                except Exception as e:
                    logger.debug(
                        f"⚠️ Method pattern matching failed for {category}: {e}"
                    )

        return findings

    def _get_code_snippet(
        self, content: str, start: int, end: int, context_lines: int = 2
    ) -> str:
        """Extract code snippet with context around the match."""
        lines = content.split("\n")
        match_start_line = content[:start].count("\n")
        match_end_line = content[:end].count("\n")

        snippet_start = max(0, match_start_line - context_lines)
        snippet_end = min(len(lines), match_end_line + context_lines + 1)

        snippet_lines = []
        for i in range(snippet_start, snippet_end):
            if i < len(lines):
                prefix = ">>> " if match_start_line <= i <= match_end_line else "    "
                snippet_lines.append(f"{prefix}{lines[i]}")

        return "\n".join(snippet_lines)

    def _get_severity_for_secret(self, category: str) -> str:
        """Get severity level for different secret types."""
        severity_map = {
            "api_keys": "high",
            "aws_credentials": "critical",
            "database_credentials": "high",
            "urls_endpoints": "medium",
            "cryptographic_keys": "critical",
            "tokens": "high",
        }
        return severity_map.get(category, "medium")

    def _get_severity_for_vulnerability(self, category: str) -> str:
        """Get severity level for different vulnerability types."""
        severity_map = {
            "weak_crypto": "high",
            "hardcoded_crypto_keys": "critical",
            "insecure_random": "medium",
            "sql_injection": "critical",
            "webview_vulnerabilities": "high",
            "insecure_networking": "high",
        }
        return severity_map.get(category, "medium")

    def _calculate_confidence(
        self, match: re.Match, pattern: str, category: str, file_content: str = None
    ) -> float:
        """🔥 PRIORITY 1 FIX: Enhanced confidence calculation with Base64 analysis."""
        base_confidence = 0.7

        # Adjust confidence based on pattern specificity
        if len(pattern) > 50:  # Complex patterns are more specific
            base_confidence += 0.2

        # Adjust based on match length and characteristics
        matched_text = match.group(0)
        if len(matched_text) > 20:  # Longer matches are more likely to be real
            base_confidence += 0.1

        # Category-specific adjustments
        if category in ["aws_credentials", "cryptographic_keys"]:
            base_confidence += 0.1  # These patterns are highly specific

        # 🔥 PRIORITY 1 FIX: Enhanced Base64 confidence scoring with deobfuscation
        if category == "encoding" and self.base64_validation_enabled:
            return self._calculate_base64_confidence(matched_text, pattern, file_content)

        return min(1.0, base_confidence)

    def _calculate_base64_confidence(self, matched_text: str, pattern: str, file_content: str = None) -> float:
        """🚀 Enhanced Base64 Intelligence with Deobfuscation Integration."""
        import base64
        import math
        import re

        confidence = 0.3  # Lower base confidence, enhanced by comprehensive analysis

        # Extract potential Base64 string from match
        base64_candidate = self._extract_base64_string(matched_text)

        if not base64_candidate or len(base64_candidate) < 8:
            return 0.05  # Very low confidence for very short strings

        # 1. Enhanced length-based confidence scoring
        length = len(base64_candidate)
        if length >= 128:
            confidence += self.base64_confidence_weights["length_128_plus"]
        elif length >= 64:
            confidence += self.base64_confidence_weights["length_64_127"]
        elif length >= 32:
            confidence += self.base64_confidence_weights["length_32_63"]
        elif length >= 16:
            confidence += self.base64_confidence_weights["length_16_31"]
        elif length >= 12:
            confidence += self.base64_confidence_weights["length_12_15"]
        elif length >= 8:
            confidence += self.base64_confidence_weights["length_8_11"]

        # 2. Enhanced context-aware detection
        context_analysis = self._analyze_base64_context(matched_text, pattern)
        for context_type, bonus in context_analysis.items():
            if context_type in self.base64_confidence_weights:
                confidence += self.base64_confidence_weights[context_type]

        # 3. Enhanced encoding validation
        encoding_analysis = self._analyze_base64_encoding(base64_candidate)
        for encoding_aspect, value in encoding_analysis.items():
            if encoding_aspect in self.base64_confidence_weights and value:
                confidence += self.base64_confidence_weights[encoding_aspect]

        # 4. Enhanced entropy and pattern analysis
        entropy_score = self._calculate_entropy(base64_candidate)
        if entropy_score > 5.0:
            confidence += self.base64_confidence_weights["entropy_very_high"]
        elif entropy_score > 4.5:
            confidence += self.base64_confidence_weights["entropy_high"]

        # Pattern randomness analysis
        if self._has_randomness_patterns(base64_candidate):
            confidence += self.base64_confidence_weights["pattern_randomness"]
        
        # Penalty for repeating patterns
        if self._has_repeating_patterns(base64_candidate):
            confidence += self.base64_confidence_weights["pattern_repeating"]

        # 5. Enhanced semantic content analysis
        semantic_analysis = self._analyze_decoded_content(base64_candidate)
        for semantic_type, value in semantic_analysis.items():
            if semantic_type in self.base64_confidence_weights and value:
                confidence += self.base64_confidence_weights[semantic_type]

        # 6. False positive penalties
        false_positive_analysis = self._analyze_false_positive_indicators(base64_candidate)
        for penalty_type, value in false_positive_analysis.items():
            if penalty_type in self.base64_confidence_weights and value:
                confidence += self.base64_confidence_weights[penalty_type]

        # 7. Encoding chain analysis
        if self._is_part_of_encoding_chain(matched_text):
            confidence += 0.2  # Bonus for being part of encoding/decoding chain

        # 🚀 Deobfuscation Integration - Deobfuscation Integration - Enhanced multi-layer analysis
        if self.deobfuscation_enabled and file_content:
            # Analyze deobfuscation chains
            deobfuscation_analysis = self._analyze_deobfuscation_chains(file_content, matched_text)
            confidence += deobfuscation_analysis.get("confidence_bonus", 0.0)
            
            # Attempt deobfuscation if chain detected
            if deobfuscation_analysis.get("chain_detected", False):
                deobfuscation_result = self._attempt_deobfuscation(base64_candidate, deobfuscation_analysis)
                confidence += deobfuscation_result.get("confidence_bonus", 0.0)
                
                # Key analysis for obfuscation
                context_window = self._get_context_window(file_content, matched_text, window_size=10)
                key_analysis = self._detect_obfuscation_keys(file_content, context_window)
                confidence += key_analysis.get("confidence_bonus", 0.0)

        return max(0.0, min(1.0, confidence))

    def _analyze_base64_context(self, matched_text: str, pattern: str) -> dict:
        """Analyze the context in which Base64 string appears."""
        context = {}
        
        # Extract the Base64 string for context analysis
        base64_string = self._extract_base64_string(matched_text)
        if not base64_string:
            return context
        
        # Check for different context types with more robust patterns
        if re.search(r'final\s+String\s+\w+\s*=.*' + re.escape(base64_string), matched_text):
            context["context_final_variable"] = True
        elif re.search(r'String\s+\w+\s*=.*' + re.escape(base64_string), matched_text):
            context["context_assignment"] = True
        
        # Enhanced method call context detection
        if any(method in matched_text for method in ["Base64.decode", "Base64.encode", "fromBase64", "decodeBase64", "encodeBase64"]):
            context["context_method_call"] = True
        
        # Enhanced method parameter context detection - look for the Base64 string inside method parentheses
        method_param_patterns = [
            r'\w+\s*\(\s*[^)]*' + re.escape(base64_string) + r'[^)]*\)',  # methodName(..."base64"...)
            r'Base64\.\w+\s*\(\s*[^)]*' + re.escape(base64_string),  # Base64.method(...base64...)
            r'android\.util\.Base64\.\w+\s*\(\s*[^)]*' + re.escape(base64_string),  # android.util.Base64.method(...)
        ]
        if any(re.search(pattern, matched_text) for pattern in method_param_patterns):
            context["context_method_parameter"] = True
            
        # Enhanced annotation context detection
        annotation_patterns = [
            r'@\w+\s*\(\s*[^)]*' + re.escape(base64_string),  # @Annotation(...base64...)
            r'@Value\s*\(\s*[^)]*' + re.escape(base64_string),  # @Value(...base64...)
        ]
        if any(re.search(pattern, matched_text) for pattern in annotation_patterns):
            context["context_annotation"] = True
            
        return context

    def _analyze_base64_encoding(self, base64_candidate: str) -> dict:
        """Analyze Base64 encoding characteristics."""
        analysis = {}
        
        # Padding validation
        analysis["padding_valid"] = self._is_valid_base64_padding(base64_candidate)
        
        # Character set validation  
        analysis["charset_valid"] = bool(re.match(r'^[A-Za-z0-9+/]*={0,2}$', base64_candidate))
        
        # Decode validation
        try:
            decoded_bytes = base64.b64decode(base64_candidate, validate=True)
            analysis["decode_successful"] = True
            
            # Check if decoded content is meaningful (printable)
            try:
                decoded_str = decoded_bytes.decode('utf-8', errors='strict')
                analysis["decode_meaningful"] = len(decoded_str.strip()) > 0 and decoded_str.isprintable()
            except:
                analysis["decode_meaningful"] = False
                
        except:
            analysis["decode_successful"] = False
            analysis["decode_meaningful"] = False
            
        return analysis

    def _has_randomness_patterns(self, base64_string: str) -> bool:
        """Check if Base64 string has randomness patterns."""
        # Check for good character distribution
        char_counts = {}
        for char in base64_string:
            char_counts[char] = char_counts.get(char, 0) + 1
        
        # Good randomness if no character appears more than 25% of the time
        max_frequency = max(char_counts.values()) / len(base64_string)
        return max_frequency < 0.25

    def _has_repeating_patterns(self, base64_string: str) -> bool:
        """Check for repeating patterns that indicate low entropy."""
        # Check for repeating substrings
        for length in range(2, min(8, len(base64_string) // 3)):
            for i in range(len(base64_string) - length * 2):
                substring = base64_string[i:i+length]
                if base64_string.count(substring) >= 3:
                    return True
        return False

    def _analyze_decoded_content(self, base64_candidate: str) -> dict:
        """Analyze decoded content for semantic meaning."""
        analysis = {}
        
        try:
            decoded_bytes = base64.b64decode(base64_candidate, validate=True)
            decoded_str = decoded_bytes.decode('utf-8', errors='ignore').lower()
            
            # Check for various semantic categories
            for category, keywords in self.semantic_keywords.items():
                contains_category = any(keyword in decoded_str for keyword in keywords)
                analysis[f"contains_{category}"] = contains_category
                
        except:
            # If decoding fails, all semantic analysis is False
            for category in self.semantic_keywords.keys():
                analysis[f"contains_{category}"] = False
                
        return analysis

    def _analyze_false_positive_indicators(self, base64_candidate: str) -> dict:
        """Analyze indicators that suggest false positive Base64 detections."""
        analysis = {}
        
        try:
            decoded_bytes = base64.b64decode(base64_candidate, validate=True)
            
            # Check for image/binary data (high proportion of non-printable bytes)
            if len(decoded_bytes) > 0:
                non_printable_ratio = sum(1 for b in decoded_bytes if b < 32 or b > 126) / len(decoded_bytes)
                analysis["penalty_image_data"] = non_printable_ratio > 0.3
            else:
                analysis["penalty_image_data"] = False
            
            # Try to decode as string for further analysis
            try:
                decoded_str = decoded_bytes.decode('utf-8', errors='strict')
                
                # Check for resource path patterns - enhanced detection
                path_patterns = [
                    r'res/', r'assets/', r'drawable/', r'layout/', r'values/', r'raw/',
                    r'\.xml$', r'\.png$', r'\.jpg$', r'\.gif$', r'\.json$',
                    r'/android_asset/', r'file://', r'content://'
                ]
                analysis["penalty_resource_path"] = any(re.search(pattern, decoded_str, re.IGNORECASE) for pattern in path_patterns)
                
                # Check for GUID/UUID patterns - enhanced detection
                guid_patterns = [
                    r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',  # Standard UUID
                    r'[0-9a-fA-F]{32}',  # 32-hex string (GUID without dashes)
                    r'\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}'  # UUID with braces
                ]
                analysis["penalty_guid_uuid"] = any(re.search(pattern, decoded_str) for pattern in guid_patterns)
                
                # Check for timestamp patterns - enhanced detection
                timestamp_patterns = [
                    r'^\d{10}$',  # Unix timestamp (10 digits)
                    r'^\d{13}$',  # Unix timestamp in milliseconds (13 digits)
                    r'\d{4}-\d{2}-\d{2}',  # ISO date format
                    r'\d{2}/\d{2}/\d{4}',  # US date format
                    r'\d{4}\d{2}\d{2}',  # Compact date format
                    r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}'  # ISO datetime
                ]
                analysis["penalty_timestamp"] = any(re.search(pattern, decoded_str) for pattern in timestamp_patterns)
                
            except UnicodeDecodeError:
                # If string decoding fails, assume binary data (penalty for image data already set)
                analysis["penalty_resource_path"] = False
                analysis["penalty_guid_uuid"] = False  
                analysis["penalty_timestamp"] = False
                
        except Exception:
            # If Base64 decoding fails, no penalties can be applied
            analysis["penalty_image_data"] = False
            analysis["penalty_resource_path"] = False
            analysis["penalty_guid_uuid"] = False
            analysis["penalty_timestamp"] = False
            
        return analysis

    def _is_part_of_encoding_chain(self, matched_text: str) -> bool:
        """Check if Base64 string is part of an encoding/decoding chain."""
        # Check against encoding chain patterns
        for chain_type, patterns in self.encoding_chain_patterns.items():
            for pattern in patterns:
                if re.search(pattern, matched_text, re.IGNORECASE):
                    return True
        return False

    def _extract_base64_string(self, matched_text: str) -> str:
        """Extract the actual Base64 string from the matched pattern."""
        import re

        # Try to find the Base64 string with various approaches
        
        # 1. Direct Base64 pattern extraction (highest priority)
        base64_patterns = [
            r'[A-Za-z0-9+/]{16,}={0,2}',  # Standard Base64
            r'[A-Za-z0-9+/]{8,}={0,2}',   # Shorter Base64 (fallback)
        ]
        
        for pattern in base64_patterns:
            matches = re.findall(pattern, matched_text)
            if matches:
                # Return the longest match (most likely to be the actual Base64)
                return max(matches, key=len)
        
        # 2. Clean the matched text and extract Base64-like content
        cleaned = matched_text
        
        # Remove common prefixes and suffixes
        cleaning_patterns = [
            (r'^[^"\']*["\']', ''),  # Remove everything before first quote
            (r'["\'][^"\']*$', ''),  # Remove everything after last quote
            (r'^.*?=\s*["\']?', ''),  # Remove assignment operators
            (r'^.*?\(\s*["\']?', ''),  # Remove method calls
            (r'["\']?\s*[,\)].*$', ''),  # Remove trailing commas, parentheses
            (r'["\']', ''),  # Remove all quotes
        ]
        
        for pattern, replacement in cleaning_patterns:
            cleaned = re.sub(pattern, replacement, cleaned)
        
        # Final cleanup - just get the Base64-like string
        cleaned = cleaned.strip()
        
        # Validate that we have a reasonable Base64-like string
        if len(cleaned) >= 8 and re.match(r'^[A-Za-z0-9+/]*={0,2}$', cleaned):
            return cleaned
        
        # 3. Fallback - return the longest alphanumeric+/+ sequence
        fallback_match = re.search(r'[A-Za-z0-9+/]{8,}', matched_text)
        if fallback_match:
            return fallback_match.group(0)
        
        # 4. Last resort - return cleaned text
        return cleaned

    def _is_valid_base64_padding(self, base64_string: str) -> bool:
        """Check if Base64 string has valid padding."""
        if not base64_string:
            return False

        # Valid Base64 lengths are multiples of 4
        if len(base64_string) % 4 == 0:
            return True

        # Check padding patterns
        if len(base64_string) % 4 == 2 and base64_string.endswith("=="):
            return True
        if len(base64_string) % 4 == 3 and base64_string.endswith("="):
            return True

        return False

    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not text:
            return 0.0

        import math
        from collections import Counter

        # Calculate character frequencies
        char_counts = Counter(text)
        text_length = len(text)

        # Calculate Shannon entropy
        entropy = 0.0
        for count in char_counts.values():
            probability = count / text_length
            if probability > 0:
                entropy -= probability * math.log2(probability)

        return entropy

    def _is_valid_base64(self, base64_string: str) -> bool:
        """Check if string is valid Base64 encoding."""
        import base64
        import re

        # Check character set
        if not re.match(r"^[A-Za-z0-9+/]*={0,2}$", base64_string):
            return False

        # Check length (must be multiple of 4 with proper padding)
        if len(base64_string) % 4 != 0:
            return False

        try:
            # Attempt to decode
            decoded = base64.b64decode(base64_string, validate=True)
            # Re-encode and compare (roundtrip test)
            reencoded = base64.b64encode(decoded).decode("ascii")
            return reencoded == base64_string
        except:
            return False

    def _is_method_potentially_insecure(self, code_snippet: str, category: str) -> bool:
        """Additional validation for method security."""
        # This is a simplified check - could be enhanced with more sophisticated analysis
        insecure_keywords = {
            "encryption_methods": ["DES", "MD5", "SHA1", "ECB"],
            "network_methods": ["http://", "TrustAll", "verify.*return true"],
            "storage_methods": ["MODE_WORLD_READABLE", "MODE_WORLD_WRITABLE"],
        }

        keywords = insecure_keywords.get(category, [])
        for keyword in keywords:
            if re.search(keyword, code_snippet, re.IGNORECASE):
                return True

        return False

    def _get_remediation_for_secret(self, category: str) -> str:
        """Get remediation advice for different secret types."""
        remediation_map = {
            "api_keys": "Store API keys in secure configuration or environment variables",
            "aws_credentials": "Use IAM roles or AWS Secrets Manager instead of hardcoded credentials",
            "database_credentials": "Store database credentials securely using Android Keystore",
            "urls_endpoints": "Move URLs to configuration files or remote configuration",
            "cryptographic_keys": "Generate keys dynamically or store in Android Keystore",
            "tokens": "Store tokens securely and implement token refresh mechanisms",
            "secrets": "Remove hardcoded sensitive data from source code",
            "flags": "Remove hardcoded flags and sensitive identifiers from source code",
            "encoding": "🔥 Base64 encoded data detected - ensure sensitive data is properly encrypted before encoding, not just obfuscated",
            "cloud_services": "Store cloud service credentials securely using proper credential management",
        }
        return remediation_map.get(
            category, "Remove hardcoded sensitive data from source code"
        )

    def _get_remediation_for_vulnerability(self, category: str) -> str:
        """Get remediation advice for different vulnerability types."""
        remediation_map = {
            "weak_crypto": "Use strong cryptographic algorithms (AES-256, SHA-256, etc.)",
            "hardcoded_crypto_keys": "Generate cryptographic keys dynamically or use secure key storage",
            "insecure_random": "Use SecureRandom for cryptographic operations",
            "sql_injection": "Use parameterized queries or prepared statements",
            "webview_vulnerabilities": "Disable unnecessary WebView features and validate all inputs",
            "insecure_networking": "Implement proper SSL/TLS certificate validation",
        }
        return remediation_map.get(category, "Follow secure coding best practices")

    def _get_remediation_for_method(self, category: str) -> str:
        """Get remediation advice for different method types."""
        remediation_map = {
            "encryption_methods": "Review encryption implementation for security best practices",
            "network_methods": "Ensure secure network communication with proper certificate validation",
            "storage_methods": "Use secure storage mechanisms and proper file permissions",
        }
        return remediation_map.get(
            category, "Review method implementation for security best practices"
        )

    def _generate_statistics(
        self,
        findings: List[SourceCodeFinding],
        decompilation_result: DecompilationResult,
        apk_size_mb: float,
    ) -> Dict[str, Any]:
        """Generate comprehensive analysis statistics."""

        # Count findings by type and severity
        findings_by_type = {}
        findings_by_severity = {}
        findings_by_category = {}

        for finding in findings:
            findings_by_type[finding.finding_type] = (
                findings_by_type.get(finding.finding_type, 0) + 1
            )
            findings_by_severity[finding.severity] = (
                findings_by_severity.get(finding.severity, 0) + 1
            )
            findings_by_category[finding.category] = (
                findings_by_category.get(finding.category, 0) + 1
            )

        # Calculate average confidence
        avg_confidence = (
            sum(f.confidence for f in findings) / len(findings) if findings else 0.0
        )

        return {
            "total_findings": len(findings),
            "findings_by_type": findings_by_type,
            "findings_by_severity": findings_by_severity,
            "findings_by_category": findings_by_category,
            "average_confidence": round(avg_confidence, 3),
            "apk_size_mb": round(apk_size_mb, 2),
            "decompilation_stats": {
                "total_files": decompilation_result.total_files,
                "java_files": decompilation_result.java_files,
                "kotlin_files": decompilation_result.kotlin_files,
                "xml_files": decompilation_result.xml_files,
                "decompilation_time": round(decompilation_result.decompilation_time, 2),
            },
            "performance_analysis": {
                "meets_decompilation_target": decompilation_result.decompilation_time
                < self.config["performance"]["target_decompilation_time"],
                "meets_analysis_target": self.performance_metrics.get("total_time", 0)
                < self.config["performance"]["target_analysis_time"],
                "performance_ratio": round(
                    self.performance_metrics.get("total_time", 0)
                    / self.config["performance"]["target_analysis_time"],
                    2,
                ),
            },
        }

    def _get_memory_usage(self) -> Dict[str, float]:
        """Get current memory usage statistics."""
        try:
            import psutil

            process = psutil.Process()
            memory_info = process.memory_info()

            return {
                "rss_mb": round(memory_info.rss / (1024 * 1024), 2),
                "vms_mb": round(memory_info.vms / (1024 * 1024), 2),
                "percent": round(process.memory_percent(), 2),
            }
        except ImportError:
            return {"error": "psutil not available for memory monitoring"}
        except Exception as e:
            return {"error": f"Memory monitoring failed: {str(e)}"}

    def export_results(self, result: SourceAnalysisResult, output_file: str) -> bool:
        """Export analysis results to JSON file."""
        try:
            # Convert dataclass to dictionary for JSON serialization
            result_dict = asdict(result)

            with open(output_file, "w", encoding="utf-8") as f:
                json.dump(result_dict, f, indent=2, ensure_ascii=False)

            logger.debug(f"✅ Results exported to: {output_file}")
            return True

        except Exception as e:
            logger.error(f"❌ Failed to export results: {str(e)}")
            return False

    # 🚀 Deobfuscation Integration - Deobfuscation Integration - Core analysis methods
    def _analyze_deobfuscation_chains(self, file_content: str, matched_text: str) -> dict:
        """Analyze potential deobfuscation chains and multi-layer encoding."""
        analysis = {
            "chain_detected": False,
            "chain_type": None,
            "chain_complexity": 0,
            "encoding_layers": [],
            "confidence_bonus": 0.0,
            "deobfuscation_patterns": [],
        }
        
        # Check for multi-layer encoding chains
        for chain_type, patterns in self.deobfuscation_chain_patterns.items():
            for pattern in patterns:
                if re.search(pattern, matched_text, re.IGNORECASE):
                    analysis["chain_detected"] = True
                    analysis["chain_type"] = chain_type
                    analysis["deobfuscation_patterns"].append(pattern)
                    
                    # Calculate complexity based on chain type
                    complexity_map = {
                        "base64_rot13": 2,
                        "base64_xor": 2, 
                        "base64_reverse": 2,
                        "base64_hex": 2,
                        "multiple_base64": 3,
                        "url_base64": 2,
                    }
                    analysis["chain_complexity"] = max(
                        analysis["chain_complexity"], 
                        complexity_map.get(chain_type, 1)
                    )
        
        # Analyze broader context for additional obfuscation layers
        context_window = self._get_context_window(file_content, matched_text, window_size=5)
        
        # Check for obfuscation patterns in context
        for obf_type, patterns in self.obfuscation_patterns.items():
            for pattern in patterns:
                if re.search(pattern, context_window, re.IGNORECASE):
                    analysis["encoding_layers"].append(obf_type)
                    analysis["deobfuscation_patterns"].append(f"context_{pattern}")
        
        # Calculate confidence bonus based on complexity
        if analysis["chain_detected"]:
            if analysis["chain_complexity"] >= 3:
                analysis["confidence_bonus"] += self.deobfuscation_confidence_weights["triple_encoding"]
            elif analysis["chain_complexity"] >= 2:
                analysis["confidence_bonus"] += self.deobfuscation_confidence_weights["double_encoding"]
            
            # Add technique-specific bonuses
            for layer in analysis["encoding_layers"]:
                if layer in ["rot_cipher"]:
                    analysis["confidence_bonus"] += self.deobfuscation_confidence_weights["rot13_encoding"]
                elif layer in ["xor_obfuscation"]:
                    analysis["confidence_bonus"] += self.deobfuscation_confidence_weights["xor_obfuscation"]
                elif layer in ["string_reversal"]:
                    analysis["confidence_bonus"] += self.deobfuscation_confidence_weights["reverse_string"]
                elif layer in ["hex_encoding"]:
                    analysis["confidence_bonus"] += self.deobfuscation_confidence_weights["hex_encoding"]
                elif layer in ["custom_cipher"]:
                    analysis["confidence_bonus"] += self.deobfuscation_confidence_weights["custom_cipher"]
                elif layer in ["anti_analysis"]:
                    analysis["confidence_bonus"] += self.deobfuscation_confidence_weights["anti_analysis"]
        
        # Complex chain bonus
        if len(analysis["encoding_layers"]) >= 2:
            analysis["confidence_bonus"] += self.deobfuscation_confidence_weights["complex_chain"]
        
        return analysis

    def _get_context_window(self, file_content: str, matched_text: str, window_size: int = 5) -> str:
        """Get a context window around the matched text for broader analysis."""
        try:
            lines = file_content.split('\n')
            
            # Find the line containing the matched text
            target_line = -1
            for i, line in enumerate(lines):
                if matched_text in line:
                    target_line = i
                    break
            
            if target_line == -1:
                return matched_text  # Fallback if not found
            
            # Get context window
            start_line = max(0, target_line - window_size)
            end_line = min(len(lines), target_line + window_size + 1)
            
            return '\n'.join(lines[start_line:end_line])
        except:
            return matched_text  # Fallback on any error

    def _attempt_deobfuscation(self, encoded_string: str, chain_analysis: dict) -> dict:
        """Attempt to deobfuscate encoded strings using detected patterns."""
        deobfuscation_result = {
            "success": False,
            "decoded_content": None,
            "deobfuscation_steps": [],
            "confidence_bonus": 0.0,
            "meaningful_content": False,
        }
        
        if not chain_analysis["chain_detected"]:
            return deobfuscation_result
        
        current_content = encoded_string
        steps = []
        
        try:
            # Attempt multi-layer deobfuscation based on detected patterns
            chain_type = chain_analysis["chain_type"]
            
            if "base64" in chain_type.lower():
                # Try Base64 decoding first
                try:
                    import base64
                    decoded = base64.b64decode(current_content).decode('utf-8', errors='ignore')
                    current_content = decoded
                    steps.append(f"Base64 decode: {len(encoded_string)} -> {len(decoded)} chars")
                    deobfuscation_result["success"] = True
                except:
                    pass
            
            if "rot13" in chain_type.lower() or "rot_cipher" in chain_analysis["encoding_layers"]:
                # Apply ROT13 decoding
                try:
                    import codecs
                    decoded = codecs.decode(current_content, 'rot13')
                    current_content = decoded
                    steps.append(f"ROT13 decode: {len(current_content)} chars")
                    deobfuscation_result["success"] = True
                except:
                    pass
            
            if "reverse" in chain_type.lower() or "string_reversal" in chain_analysis["encoding_layers"]:
                # Apply string reversal
                try:
                    decoded = current_content[::-1]
                    current_content = decoded
                    steps.append(f"String reverse: {len(current_content)} chars")
                    deobfuscation_result["success"] = True
                except:
                    pass
            
            if "hex" in chain_type.lower() or "hex_encoding" in chain_analysis["encoding_layers"]:
                # Apply hex decoding
                try:
                    import codecs
                    decoded = codecs.decode(current_content, 'hex').decode('utf-8', errors='ignore')
                    current_content = decoded
                    steps.append(f"Hex decode: {len(current_content)} chars")
                    deobfuscation_result["success"] = True
                except:
                    pass
            
            # Analyze decoded content for meaningful data
            if deobfuscation_result["success"] and current_content != encoded_string:
                deobfuscation_result["decoded_content"] = current_content
                deobfuscation_result["deobfuscation_steps"] = steps
                
                # Check if decoded content contains meaningful data
                meaningful_indicators = [
                    "flag", "password", "key", "secret", "token", "credential",
                    "http://", "https://", "ftp://", "api", "endpoint",
                    "{", "}", "[", "]", "=", ":", "\"", "'",
                ]
                
                content_lower = current_content.lower()
                meaningful_count = sum(1 for indicator in meaningful_indicators 
                                     if indicator in content_lower)
                
                if meaningful_count >= 2 or len(current_content) > 20:
                    deobfuscation_result["meaningful_content"] = True
                    deobfuscation_result["confidence_bonus"] += self.deobfuscation_confidence_weights["encrypted_payloads"]
                
                # Additional semantic analysis on decoded content
                semantic_analysis = self._analyze_decoded_content(current_content)
                if semantic_analysis.get("contains_secrets", False):
                    deobfuscation_result["confidence_bonus"] += 0.3
                if semantic_analysis.get("contains_flags", False):
                    deobfuscation_result["confidence_bonus"] += 0.4
        
        except Exception as e:
            # Log error but don't fail the analysis
            deobfuscation_result["deobfuscation_steps"].append(f"Error during deobfuscation: {str(e)}")
        
        return deobfuscation_result

    def _detect_obfuscation_keys(self, file_content: str, context_window: str) -> dict:
        """Detect potential obfuscation keys and parameters."""
        key_analysis = {
            "keys_detected": [],
            "key_types": [],
            "confidence_bonus": 0.0,
            "dynamic_key_generation": False,
            "environment_dependent": False,
        }
        
        # Search for hardcoded keys
        for pattern in self.obfuscation_key_patterns:
            matches = re.finditer(pattern, context_window, re.IGNORECASE)
            for match in matches:
                key_analysis["keys_detected"].append(match.group(0))
                
                # Determine key type
                if "key" in match.group(0).lower():
                    key_analysis["key_types"].append("encryption_key")
                elif "password" in match.group(0).lower():
                    key_analysis["key_types"].append("password")
                elif "salt" in match.group(0).lower():
                    key_analysis["key_types"].append("salt")
                elif "secret" in match.group(0).lower():
                    key_analysis["key_types"].append("secret")
        
        # Check for dynamic key generation patterns
        dynamic_patterns = [
            r'System\.currentTimeMillis\s*\(\s*\)',
            r'UUID\.randomUUID\s*\(\s*\)',
            r'Random\s*\(\s*\)\.next',
            r'SecureRandom\s*\(\s*\)',
            r'Math\.random\s*\(\s*\)',
            r'getSystemProperty\s*\(',
        ]
        
        for pattern in dynamic_patterns:
            if re.search(pattern, context_window, re.IGNORECASE):
                key_analysis["dynamic_key_generation"] = True
                key_analysis["confidence_bonus"] += self.deobfuscation_confidence_weights["dynamic_keys"]
                break
        
        # Check for environment-dependent keys
        env_patterns = [
            r'getProperty\s*\(',
            r'getenv\s*\(',
            r'BuildConfig\.',
            r'getString\s*\(R\.string\.',
            r'getResources\s*\(\s*\)',
        ]
        
        for pattern in env_patterns:
            if re.search(pattern, context_window, re.IGNORECASE):
                key_analysis["environment_dependent"] = True
                key_analysis["confidence_bonus"] += self.deobfuscation_confidence_weights["environment_dependent"]
                break
        
        return key_analysis

    def _filter_files_for_performance(self, files: List[str]) -> List[str]:
        """
        PERFORMANCE OPTIMIZATION: Filter files to reduce analysis time for large APKs.
        Prioritizes application files over framework files and limits total file count.
        """
        if not files:
            return files
            
        config = self.config["analysis_options"]
        max_files = config.get("max_files_to_analyze", 2000)
        skip_framework = config.get("skip_framework_files", True)
        
        # Filter out framework files if enabled
        if skip_framework:
            filtered_files = []
            framework_patterns = [
                '/android/', '/androidx/', '/com/google/', '/com/android/',
                '/java/', '/javax/', '/org/apache/', '/org/json/',
                '/kotlin/', '/kotlinx/', '/retrofit/', '/okhttp/',
                '/com/squareup/', '/io/reactivex/', '/rx/'
            ]
            
            for file_path in files:
                is_framework = any(pattern in file_path.lower() for pattern in framework_patterns)
                if not is_framework:
                    filtered_files.append(file_path)
                elif len(filtered_files) < max_files // 10:  # Keep some framework files for analysis
                    filtered_files.append(file_path)
            
            files = filtered_files
            logger.info(f"🎯 PERFORMANCE: Filtered framework files, analyzing {len(files)} application files")
        
        # Limit total file count for performance
        if len(files) > max_files:
            # Prioritize important file types
            priority_files = []
            regular_files = []
            
            for file_path in files:
                file_lower = file_path.lower()
                if any(pattern in file_lower for pattern in ['activity', 'service', 'receiver', 'provider', 'fragment', 'main', 'auth', 'login', 'security', 'crypto', 'key']):
                    priority_files.append(file_path)
                else:
                    regular_files.append(file_path)
            
            # Take priority files + remaining quota from regular files
            remaining_quota = max_files - len(priority_files)
            selected_files = priority_files + regular_files[:remaining_quota]
            
            logger.info(f"🎯 PERFORMANCE: Limited analysis to {len(selected_files)} priority files (from {len(files)} total)")
            return selected_files
        
        return files

def main():
    """
    🧪 AODS Source Code Analyzer - Standalone Testing

    This function demonstrates the source code analyzer capabilities
    for testing and validation purposes.
    """
    import argparse

    parser = argparse.ArgumentParser(description="AODS Source Code Analyzer")
    parser.add_argument("apk_path", help="Path to APK file to analyze")
    parser.add_argument("--output", "-o", help="Output JSON file for results")
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Enable verbose logging"
    )

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Initialize analyzer
    analyzer = SourceCodeAnalyzer()

    # Analyze APK
    print(f"🔍 Starting AODS Source Code Analysis...")
    print(f"📱 APK: {args.apk_path}")

    result = analyzer.analyze_apk(args.apk_path)

    # Display results
    print(f"\n📊 Analysis Results:")
    print(f"   ⏱️  Analysis Time: {result.analysis_time:.2f}s")
    print(f"   🔍 Total Findings: {len(result.findings)}")
    print(
        f"   📁 Files Analyzed: {result.decompilation_result.java_files + result.decompilation_result.kotlin_files}"
    )
    print(f"   💾 Memory Usage: {result.memory_usage.get('rss_mb', 'N/A')}MB")

    if result.findings:
        print(f"\n🔴 Security Findings:")
        for i, finding in enumerate(result.findings[:5], 1):  # Show top 5
            print(f"   {i}. {finding.description} ({finding.severity})")

        if len(result.findings) > 5:
            print(f"   ... and {len(result.findings) - 5} more findings")

    # Export results if requested
    if args.output:
        if analyzer.export_results(result, args.output):
            print(f"✅ Results exported to: {args.output}")

    print(f"\n🎯 AODS Source Code Analysis Complete!")

if __name__ == "__main__":
    main()

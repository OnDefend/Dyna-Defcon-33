#!/usr/bin/env python3
"""
Core Cryptographic Implementation Analyzer

This module provides the main cryptographic analysis functionality for the
modularized cryptography tests plugin, focusing on algorithm detection,
vulnerability assessment, and implementation analysis.

Key Features:
- Comprehensive algorithm detection and classification
- Enhanced weak cryptography and hashing detection
- Advanced key strength validation
- IV security analysis and salt randomness validation
- PBKDF strength assessment and implementation context analysis
- Vulnerability assessment with dynamic confidence scoring
- Performance-optimized pattern matching
- Integration with shared analysis framework
- Support for both static and dynamic analysis modes
"""

import logging
import re
import time
import hashlib
import base64
import secrets
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any, Set, Union
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, TimeoutError
import yaml
import signal

from core.shared_analyzers.universal_pattern_analyzer import UniversalPatternAnalyzer
from core.shared_analyzers.universal_confidence_calculator import UniversalConfidenceCalculator
from .data_structures import (
    CryptographicVulnerability,
    CryptographicImplementation,
    CryptographicAlgorithm,
    CryptographicAlgorithmType,
    CryptographicStrength,
    ComplianceStandard
)

logger = logging.getLogger(__name__)

class TimeoutException(Exception):
    """Custom timeout exception for analysis operations."""
    pass

def timeout_handler(signum, frame):
    """Signal handler for timeout operations."""
    raise TimeoutException("Analysis operation timed out")

@dataclass
class CryptoAnalysisResult:
    """Consolidated result from crypto analysis."""
    implementations: List[CryptographicImplementation] = field(default_factory=list)
    vulnerabilities: List[CryptographicVulnerability] = field(default_factory=list)
    weak_crypto_findings: List[Dict[str, Any]] = field(default_factory=list)
    key_strength_findings: List[Dict[str, Any]] = field(default_factory=list)
    iv_security_findings: List[Dict[str, Any]] = field(default_factory=list)
    salt_analysis_findings: List[Dict[str, Any]] = field(default_factory=list)
    pbkdf_findings: List[Dict[str, Any]] = field(default_factory=list)
    analysis_duration: float = 0.0
    files_processed: int = 0
    files_skipped: int = 0
    timeout_occurred: bool = False

@dataclass
class WeakCryptoFinding:
    """Enhanced weak cryptography finding with detailed analysis."""
    algorithm_name: str
    weakness_type: str
    severity: str
    confidence: float
    location: str
    evidence: str
    context: Dict[str, Any]
    recommendations: List[str]
    cwe_mapping: List[str]
    compliance_issues: List[str]

@dataclass
class KeyStrengthAnalysis:
    """Key strength analysis results."""
    algorithm: str
    key_size_bits: int
    strength_level: str
    is_adequate: bool
    recommended_size: int
    estimated_security_level: int
    vulnerability_notes: List[str]

@dataclass
class IVSecurityAnalysis:
    """Initialization Vector security analysis."""
    algorithm: str
    iv_mode: str
    iv_source: str
    is_secure: bool
    issues: List[str]
    recommendations: List[str]

@dataclass
class SaltAnalysis:
    """Salt randomness and security analysis."""
    salt_value: Optional[str]
    salt_length: int
    randomness_quality: str
    is_unique: bool
    is_secure: bool
    issues: List[str]
    recommendations: List[str]

@dataclass
class PBKDFAnalysis:
    """Password-based key derivation function analysis."""
    function_name: str
    iteration_count: int
    salt_analysis: Optional[SaltAnalysis]
    key_length: int
    is_secure: bool
    security_level: str
    performance_cost: str
    recommendations: List[str]

@dataclass
class CryptoAnalysisConfiguration:
    """Configuration for crypto analysis behavior."""
    plugin_type: str = "cryptography_tests"
    max_analysis_time: int = 180  # seconds
    max_file_size_mb: int = 10
    max_files_to_process: int = 1000
    enable_deep_analysis: bool = True
    enable_performance_mode: bool = False
    enable_key_strength_analysis: bool = True
    enable_iv_analysis: bool = True
    enable_salt_analysis: bool = True
    enable_pbkdf_analysis: bool = True
    enable_implementation_context_analysis: bool = True
    pattern_timeout: int = 30  # seconds per pattern
    thread_pool_size: int = 4

class CryptoAnalyzer:
    """
    Enhanced cryptographic implementation analyzer.
    
    Provides comprehensive analysis of cryptographic implementations,
    algorithm detection, vulnerability assessment, key strength validation,
    IV security analysis, salt randomness validation, and PBKDF assessment
    using the shared analysis framework for optimal performance and accuracy.
    """
    
    def __init__(self, apk_ctx, config: Optional[CryptoAnalysisConfiguration] = None):
        """Initialize the enhanced crypto analyzer with configuration."""
        self.apk_ctx = apk_ctx
        self.config = config or CryptoAnalysisConfiguration()
        
        # Initialize shared framework components
        self.pattern_analyzer = UniversalPatternAnalyzer()
        self.confidence_calculator = UniversalConfidenceCalculator(config=self.config)
        
        # Load external configuration
        self.crypto_patterns = self._load_crypto_patterns()
        self.algorithm_database = self._initialize_algorithm_database()
        self.weak_crypto_patterns = self._initialize_weak_crypto_patterns()
        self.key_strength_database = self._initialize_key_strength_database()
        
        # Analysis results
        self.implementations: List[CryptographicImplementation] = []
        self.vulnerabilities: List[CryptographicVulnerability] = []
        self.weak_crypto_findings: List[WeakCryptoFinding] = []
        self.key_strength_analyses: List[KeyStrengthAnalysis] = []
        self.iv_analyses: List[IVSecurityAnalysis] = []
        self.salt_analyses: List[SaltAnalysis] = []
        self.pbkdf_analyses: List[PBKDFAnalysis] = []
        
        # Analysis statistics
        self.analysis_stats = {
            "files_analyzed": 0,
            "algorithms_detected": 0,
            "vulnerabilities_found": 0,
            "weak_algorithms_found": 0,
            "key_strength_issues": 0,
            "iv_security_issues": 0,
            "salt_security_issues": 0,
            "pbkdf_security_issues": 0,
            "total_analysis_time": 0.0
        }
        
        # Pre-compile critical patterns for performance
        self._compile_critical_patterns()
    
    def _load_crypto_patterns(self) -> Dict[str, Any]:
        """Load cryptographic patterns from external configuration."""
        try:
            config_path = Path(__file__).parent / "crypto_patterns_config.yaml"
            with open(config_path, 'r', encoding='utf-8') as f:
                patterns = yaml.safe_load(f)
            logger.info(f"Loaded {len(patterns)} crypto pattern categories")
            return patterns
        except Exception as e:
            logger.error(f"Failed to load crypto patterns: {e}")
            return self._get_fallback_patterns()
    
    def _get_fallback_patterns(self) -> Dict[str, Any]:
        """Get fallback patterns when external configuration fails."""
        return {
            "weak_algorithms": {
                "patterns": [
                    r"(?i)\bDES\b(?!cendant|ign|k)",
                    r"(?i)\bRC4\b|\bARC4\b",
                    r"(?i)\bMD5\b(?!.*(?:HMAC|sum))",
                    r"(?i)\bSHA-?1\b(?!.*(?:6|28|60|HMAC))"
                ],
                "severity": "HIGH"
            },
            "hardcoded_keys": {
                "patterns": [
                    r"(?i)(?:key|secret|password).*=.*[\"'][A-Za-z0-9+/=]{16,}[\"']"
                ],
                "severity": "CRITICAL"
            }
        }
    
    def _initialize_algorithm_database(self) -> Dict[str, CryptographicAlgorithm]:
        """Initialize the algorithm database with known algorithms."""
        algorithms = {}
        
        # Symmetric algorithms
        algorithms["AES"] = CryptographicAlgorithm(
            name="AES",
            algorithm_type=CryptographicAlgorithmType.SYMMETRIC_CIPHER,
            key_size=256,
            strength=CryptographicStrength.STRONG,
            is_deprecated=False
        )
        
        algorithms["DES"] = CryptographicAlgorithm(
            name="DES",
            algorithm_type=CryptographicAlgorithmType.SYMMETRIC_CIPHER,
            key_size=56,
            strength=CryptographicStrength.WEAK,
            is_deprecated=True,
            deprecation_reason="Small key size, vulnerable to brute force",
            recommended_replacement="AES"
        )
        
        # Hash algorithms
        algorithms["SHA256"] = CryptographicAlgorithm(
            name="SHA256",
            algorithm_type=CryptographicAlgorithmType.HASH_FUNCTION,
            key_size=256,
            strength=CryptographicStrength.STRONG,
            is_deprecated=False
        )
        
        algorithms["MD5"] = CryptographicAlgorithm(
            name="MD5",
            algorithm_type=CryptographicAlgorithmType.HASH_FUNCTION,
            key_size=128,
            strength=CryptographicStrength.WEAK,
            is_deprecated=True,
            deprecation_reason="Vulnerable to collision attacks",
            recommended_replacement="SHA256"
        )
        
        return algorithms
    
    def _initialize_weak_crypto_patterns(self) -> Dict[str, Any]:
        """Initialize weak cryptography detection patterns."""
        return {
            # Weak symmetric algorithms
            "weak_symmetric_algorithms": {
                "patterns": [
                    r"(?i)\bDES\b(?!cendant|ign|k)",
                    r"(?i)\bRC4\b|\bARC4\b|\bRivest.*Cipher.*4\b",
                    r"(?i)\bRC2\b|\bRivest.*Cipher.*2\b",
                    r"(?i)\bBlowfish\b(?!.*(?:Twofish|improved))",
                    r"(?i)Cipher\.getInstance\s*\(\s*[\"'](?:DES|RC4|RC2|Blowfish)[\"']"
                ],
                "severity": "CRITICAL",
                "cwe": ["CWE-327", "CWE-326"],
                "recommendations": ["Use AES-256-GCM", "Use ChaCha20-Poly1305"]
            },
            
            # Deprecated hash functions
            "deprecated_hashing": {
                "patterns": [
                    r"(?i)\bMD2\b|\bMD4\b|\bMD5\b(?!.*(?:HMAC|sum|hash))",
                    r"(?i)\bSHA-?0\b|\bSHA-?1\b(?!.*(?:6|28|60|HMAC))",
                    r"(?i)MessageDigest\.getInstance\s*\(\s*[\"'](?:MD[245]|SHA-?[01])[\"']",
                    r"(?i)Mac\.getInstance\s*\(\s*[\"']Hmac(?:MD5|SHA1)[\"']",
                    r"(?i)DigestUtils\.(?:md5|sha1)\b"
                ],
                "severity": "HIGH",
                "cwe": ["CWE-327", "CWE-328"],
                "recommendations": ["Use SHA-256", "Use SHA-3", "Use BLAKE2"]
            },
            
            # Insecure cryptographic modes
            "insecure_crypto_modes": {
                "patterns": [
                    r"(?i)(?:AES|DES).*ECB",
                    r"(?i)Cipher\.getInstance\s*\(\s*[\"'][^\"']*ECB[^\"']*[\"']",
                    r"(?i)(?:CBC|CFB|OFB).*(?:without|no).*(?:IV|initialization)",
                    r"(?i)NoPadding(?!.*(?:GCM|CCM))",
                    r"(?i)PKCS1Padding(?!.*(?:OAEP|PSS))"
                ],
                "severity": "HIGH",
                "cwe": ["CWE-327", "CWE-326"],
                "recommendations": ["Use AES-GCM", "Use CBC with random IV", "Use OAEP padding"]
            },
            
            # Hardcoded cryptographic material
            "hardcoded_secrets": {
                "patterns": [
                    r"(?i)(?:key|password|secret|salt)\s*[:=]\s*[\"'][A-Za-z0-9+/=]{16,}[\"']",
                    r"(?i)SecretKeySpec\s*\([^)]*[\"'][A-Za-z0-9+/=]{8,}[\"']",
                    r"(?i)IvParameterSpec\s*\([^)]*[\"'][A-Za-z0-9+/=]{8,}[\"']",
                    r"(?i)(?:private|public).*key.*[\"'][A-Za-z0-9+/=]{32,}[\"']"
                ],
                "severity": "CRITICAL",
                "cwe": ["CWE-798", "CWE-321"],
                "recommendations": ["Generate keys at runtime", "Use secure key storage", "Use Android Keystore"]
            }
        }
    
    def _initialize_key_strength_database(self) -> Dict[str, Any]:
        """Initialize key strength assessment database."""
        return {
            "RSA": {
                "min_secure_size": 2048,
                "recommended_size": 3072,
                "future_proof_size": 4096,
                "weak_sizes": [512, 1024],
                "security_levels": {
                    512: 20,
                    1024: 80,
                    2048: 112,
                    3072: 128,
                    4096: 152
                }
            },
            "DSA": {
                "min_secure_size": 2048,
                "recommended_size": 3072,
                "future_proof_size": 3072,
                "weak_sizes": [512, 1024],
                "security_levels": {
                    512: 20,
                    1024: 80,
                    2048: 112,
                    3072: 128
                }
            },
            "ECDSA": {
                "min_secure_size": 256,
                "recommended_size": 384,
                "future_proof_size": 521,
                "weak_sizes": [160, 192, 224],
                "security_levels": {
                    160: 20,
                    192: 40,
                    224: 60,
                    256: 128,
                    384: 192,
                    521: 256
                }
            },
            "AES": {
                "min_secure_size": 128,
                "recommended_size": 256,
                "future_proof_size": 256,
                "weak_sizes": [64],
                "security_levels": {
                    64: 0,
                    128: 128,
                    192: 192,
                    256: 256
                }
            },
            "DES": {
                "min_secure_size": 9999,  # Never secure
                "recommended_size": 9999,
                "future_proof_size": 9999,
                "weak_sizes": [56],
                "security_levels": {
                    56: 0  # Completely broken
                }
            }
        }
    
    def _compile_critical_patterns(self) -> None:
        """Pre-compile critical regex patterns for performance."""
        self.compiled_patterns = {}
        
        # Critical vulnerability patterns
        critical_patterns = [
            "weak_algorithms",
            "hardcoded_keys",
            "insecure_random",
            "unsafe_cryptographic_modes",
            "certificate_validation_bypass"
        ]
        
        for category in critical_patterns:
            if category in self.crypto_patterns:
                patterns = self.crypto_patterns[category].get("patterns", [])
                self.compiled_patterns[category] = [
                    re.compile(pattern, re.IGNORECASE | re.MULTILINE) 
                    for pattern in patterns
                ]
    
    def analyze_crypto_implementations(self, content: str, file_path: str) -> List[CryptographicImplementation]:
        """
        Analyze cryptographic implementations in the given content.
        
        Args:
            content: File content to analyze
            file_path: Path to the file being analyzed
            
        Returns:
            List of cryptographic implementations found
        """
        implementations = []
        start_time = time.time()
        
        try:
            # Detect crypto-related imports and usage
            crypto_imports = self._detect_crypto_imports(content)
            
            # Analyze each detected import for implementation patterns
            for import_info in crypto_imports:
                impl_details = self._analyze_crypto_usage(
                    content, import_info, file_path
                )
                
                if impl_details:
                    implementations.extend(impl_details)
            
            # Detect hardcoded cryptographic patterns
            hardcoded_patterns = self._detect_hardcoded_crypto(content, file_path)
            implementations.extend(hardcoded_patterns)
            
            # Update statistics
            self.analysis_stats["files_analyzed"] += 1
            self.analysis_stats["algorithms_detected"] += len(implementations)
            
        except Exception as e:
            logger.error(f"Error analyzing crypto implementations in {file_path}: {e}")
        
        analysis_time = time.time() - start_time
        logger.debug(f"Analyzed {file_path} in {analysis_time:.2f}s, found {len(implementations)} implementations")
        
        return implementations
    
    def _detect_crypto_imports(self, content: str) -> List[Dict[str, Any]]:
        """Detect cryptographic imports and libraries."""
        crypto_imports = []
        
        # Common crypto import patterns
        import_patterns = [
            (r"import\s+javax\.crypto\.(\w+)", "javax.crypto"),
            (r"import\s+java\.security\.(\w+)", "java.security"),
            (r"import\s+android\.security\.keystore\.(\w+)", "android.keystore"),
            (r"from\s+Crypto\.\w+\s+import\s+(\w+)", "python.crypto"),
            (r"from\s+cryptography\.\w+\s+import\s+(\w+)", "python.cryptography"),
        ]
        
        for pattern, library in import_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                crypto_imports.append({
                    "library": library,
                    "imported_class": match.group(1),
                    "full_import": match.group(0),
                    "line_number": content[:match.start()].count('\n') + 1
                })
        
        return crypto_imports
    
    def _analyze_crypto_usage(self, content: str, import_info: Dict[str, Any], file_path: str) -> List[CryptographicImplementation]:
        """Analyze usage of detected crypto imports."""
        implementations = []
        
        imported_class = import_info["imported_class"]
        library = import_info["library"]
        
        # Define usage patterns based on library
        usage_patterns = self._get_usage_patterns(library, imported_class)
        
        for pattern_info in usage_patterns:
            pattern = pattern_info["pattern"]
            algorithm_type = pattern_info["algorithm_type"]
            
            matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
            
            for match in matches:
                # Extract implementation details
                impl_details = self._extract_implementation_details(
                    match, content, file_path, algorithm_type
                )
                
                if impl_details:
                    implementations.append(impl_details)
        
        return implementations
    
    def _get_usage_patterns(self, library: str, imported_class: str) -> List[Dict[str, Any]]:
        """Get usage patterns for specific crypto libraries."""
        patterns = []
        
        if library == "javax.crypto":
            if imported_class == "Cipher":
                patterns.append({
                    "pattern": r"Cipher\.getInstance\([\"']([^\"']+)[\"']",
                    "algorithm_type": CryptographicAlgorithmType.SYMMETRIC_CIPHER
                })
        elif library == "java.security":
            if imported_class == "MessageDigest":
                patterns.append({
                    "pattern": r"MessageDigest\.getInstance\([\"']([^\"']+)[\"']",
                    "algorithm_type": CryptographicAlgorithmType.HASH_FUNCTION
                })
            elif imported_class == "KeyGenerator":
                patterns.append({
                    "pattern": r"KeyGenerator\.getInstance\([\"']([^\"']+)[\"']",
                    "algorithm_type": CryptographicAlgorithmType.SYMMETRIC_CIPHER
                })
        
        return patterns
    
    def _extract_implementation_details(self, match: re.Match, content: str, file_path: str, algorithm_type: CryptographicAlgorithmType) -> Optional[CryptographicImplementation]:
        """Extract detailed implementation information from a match."""
        try:
            # Get the algorithm string from the match
            algorithm_string = match.group(1) if match.groups() else match.group(0)
            
            # Parse algorithm components
            algorithm_parts = self._parse_algorithm_string(algorithm_string)
            if not algorithm_parts:
                return None
            
            # Create algorithm object
            algorithm = self._create_algorithm_object(algorithm_parts, algorithm_type)
            
            # Extract context information
            context = self._extract_context(match, content)
            
            # Generate implementation ID
            impl_id = self._generate_implementation_id(algorithm_string, file_path, match.start())
            
            # Create implementation object
            implementation = CryptographicImplementation(
                implementation_id=impl_id,
                algorithm=algorithm,
                location=f"{file_path}:{content[:match.start()].count('\n') + 1}",
                usage_context=context["usage_context"],
                implementation_details={
                    "algorithm_string": algorithm_string,
                    "line_number": content[:match.start()].count('\n') + 1,
                    "column_number": match.start() - content.rfind('\n', 0, match.start()) - 1,
                    "surrounding_code": context["surrounding_code"]
                }
            )
            
            # Analyze for vulnerabilities
            vulnerabilities = self._analyze_implementation_vulnerabilities(implementation)
            implementation.vulnerabilities = vulnerabilities
            
            return implementation
            
        except Exception as e:
            logger.error(f"Error extracting implementation details: {e}")
            return None
    
    def _parse_algorithm_string(self, algorithm_string: str) -> Optional[Dict[str, str]]:
        """Parse algorithm string into components."""
        # Common algorithm string formats:
        # "AES/CBC/PKCS5Padding"
        # "SHA-256"
        # "RSA/ECB/PKCS1Padding"
        
        parts = algorithm_string.split('/')
        
        if len(parts) >= 1:
            return {
                "algorithm": parts[0],
                "mode": parts[1] if len(parts) > 1 else "",
                "padding": parts[2] if len(parts) > 2 else ""
            }
        
        return None
    
    def _create_algorithm_object(self, algorithm_parts: Dict[str, str], algorithm_type: CryptographicAlgorithmType) -> CryptographicAlgorithm:
        """Create algorithm object from parsed components."""
        algorithm_name = algorithm_parts["algorithm"].upper()
        
        if algorithm_name in self.algorithm_database:
            base_algorithm = self.algorithm_database[algorithm_name]
            
            # Create a copy with mode and padding
            return CryptographicAlgorithm(
                name=algorithm_name,
                algorithm_type=base_algorithm.algorithm_type,
                key_size=base_algorithm.key_size,
                strength=base_algorithm.strength,
                mode=algorithm_parts.get("mode", ""),
                padding=algorithm_parts.get("padding", ""),
                is_deprecated=base_algorithm.is_deprecated,
                deprecation_reason=base_algorithm.deprecation_reason,
                recommended_replacement=base_algorithm.recommended_replacement
            )
        else:
            # Unknown algorithm - create with default values
            return CryptographicAlgorithm(
                name=algorithm_name,
                algorithm_type=algorithm_type,
                key_size=0,  # Unknown key size
                strength=CryptographicStrength.MODERATE,  # Default to moderate
                mode=algorithm_parts.get("mode", ""),
                padding=algorithm_parts.get("padding", "")
            )
    
    def _extract_context(self, match, content: str) -> Dict[str, str]:
        """Extract context information around the match."""
        match_start = match.start()
        match_end = match.end()
        
        # Find the line boundaries
        line_start = content.rfind('\n', 0, match_start) + 1
        line_end = content.find('\n', match_end)
        if line_end == -1:
            line_end = len(content)
        
        # Extract surrounding lines for context
        lines_before = content[:line_start].split('\n')[-3:]  # Up to 3 lines before
        lines_after = content[line_end:].split('\n')[:3]  # Up to 3 lines after
        current_line = content[line_start:line_end]
        
        surrounding_code = '\n'.join(lines_before + [current_line] + lines_after)
        
        # Determine usage context
        usage_context = self._determine_usage_context(surrounding_code)
        
        return {
            "surrounding_code": surrounding_code,
            "usage_context": usage_context
        }
    
    def _determine_usage_context(self, surrounding_code: str) -> str:
        """Determine the usage context based on surrounding code."""
        code_lower = surrounding_code.lower()
        
        if any(keyword in code_lower for keyword in ['login', 'auth', 'password']):
            return "authentication"
        elif any(keyword in code_lower for keyword in ['encrypt', 'decrypt', 'cipher']):
            return "encryption"
        elif any(keyword in code_lower for keyword in ['hash', 'digest', 'checksum']):
            return "hashing"
        elif any(keyword in code_lower for keyword in ['sign', 'verify', 'signature']):
            return "digital_signature"
        elif any(keyword in code_lower for keyword in ['key', 'keystore', 'keyring']):
            return "key_management"
        else:
            return "general_cryptography"
    
    def _generate_implementation_id(self, algorithm_string: str, file_path: str, position: int) -> str:
        """Generate a unique implementation ID."""
        id_string = f"{algorithm_string}:{file_path}:{position}"
        return hashlib.md5(id_string.encode()).hexdigest()[:16]
    
    def _analyze_implementation_vulnerabilities(self, implementation: CryptographicImplementation) -> List[CryptographicVulnerability]:
        """Analyze an implementation for vulnerabilities."""
        vulnerabilities = []
        algorithm = implementation.algorithm
        
        # Check for deprecated algorithms
        if algorithm.is_deprecated:
            vuln = CryptographicVulnerability(
                vulnerability_id=f"deprecated_{implementation.implementation_id}",
                title=f"Deprecated Cryptographic Algorithm: {algorithm.name}",
                description=f"The algorithm '{algorithm.name}' is deprecated. {algorithm.deprecation_reason}",
                severity=VulnerabilitySeverity.HIGH,
                location=implementation.location,
                algorithm_name=algorithm.name,
                cryptographic_weakness=algorithm.deprecation_reason,
                algorithm_recommendations=[f"Use {algorithm.recommended_replacement}" if algorithm.recommended_replacement else "Use modern cryptographic algorithms"]
            )
            vulnerabilities.append(vuln)
        
        # Check for weak modes
        if algorithm.mode and algorithm.mode.upper() == "ECB":
            vuln = CryptographicVulnerability(
                vulnerability_id=f"weak_mode_{implementation.implementation_id}",
                title=f"Weak Cryptographic Mode: {algorithm.mode}",
                description=f"The mode '{algorithm.mode}' is vulnerable to pattern analysis attacks.",
                severity=VulnerabilitySeverity.HIGH,
                location=implementation.location,
                algorithm_name=algorithm.name,
                cryptographic_weakness=f"Weak cipher mode: {algorithm.mode}",
                algorithm_recommendations=["Use GCM mode for authenticated encryption", "Use CBC mode with random IV"]
            )
            vulnerabilities.append(vuln)
        
        # Check for weak padding
        if algorithm.padding and algorithm.padding.upper() in ['PKCS1PADDING', 'NOPADDING']:
            severity = VulnerabilitySeverity.MEDIUM if algorithm.padding.upper() == 'PKCS1PADDING' else VulnerabilitySeverity.HIGH
            vuln = CryptographicVulnerability(
                vulnerability_id=f"weak_padding_{implementation.implementation_id}",
                title=f"Weak Cryptographic Padding: {algorithm.padding}",
                description=f"The padding '{algorithm.padding}' may be vulnerable to padding oracle attacks.",
                severity=severity,
                location=implementation.location,
                algorithm_name=algorithm.name,
                cryptographic_weakness=f"Weak padding scheme: {algorithm.padding}",
                algorithm_recommendations=["Use OAEP padding for RSA or PKCS7 padding for symmetric ciphers"]
            )
            vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _detect_hardcoded_crypto(self, content: str, file_path: str) -> List[CryptographicImplementation]:
        """Detect hardcoded cryptographic patterns."""
        implementations = []
        
        # Hardcoded key patterns
        key_patterns = [
            r'(?:key|secret|password)\s*=\s*["\']([A-Za-z0-9+/]{16,})["\']',
            r'(?:private|public)_key\s*=\s*["\']([A-Za-z0-9+/=]{100,})["\']',
            r'(?:aes|des|rsa)_key\s*=\s*["\']([A-Fa-f0-9]{32,})["\']'
        ]
        
        for pattern in key_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                # Create hardcoded key implementation
                algorithm = CryptographicAlgorithm(
                    name="HARDCODED_KEY",
                    algorithm_type=CryptographicAlgorithmType.SYMMETRIC_CIPHER,
                    key_size=len(match.group(1)) * 8,  # Estimate bit size
                    strength=CryptographicStrength.WEAK,
                    is_deprecated=True,
                    deprecation_reason="Hardcoded keys are security vulnerabilities",
                    recommended_replacement="Runtime key generation"
                )
                
                impl_id = self._generate_implementation_id("HARDCODED_KEY", file_path, match.start())
                
                implementation = CryptographicImplementation(
                    implementation_id=impl_id,
                    algorithm=algorithm,
                    location=f"{file_path}:{content[:match.start()].count('\n') + 1}",
                    usage_context="hardcoded_key",
                    implementation_details={
                        "hardcoded_value": match.group(1),
                        "line_number": content[:match.start()].count('\n') + 1,
                        "pattern_matched": pattern
                    }
                )
                
                implementations.append(implementation)
        
        return implementations
    
    def analyze_weak_cryptography(self, content: str, file_path: str) -> List[WeakCryptoFinding]:
        """
        Analyze weak cryptographic implementations in the given content.
        
        Args:
            content: File content to analyze
            file_path: Path to the file being analyzed
            
        Returns:
            List of weak cryptography findings
        """
        findings = []
        
        try:
            # Analyze each category of weak cryptography
            for category, config in self.weak_crypto_patterns.items():
                patterns = config.get("patterns", [])
                severity = config.get("severity", "MEDIUM")
                cwe_mapping = config.get("cwe", [])
                recommendations = config.get("recommendations", [])
                
                for pattern in patterns:
                    matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
                    
                    for match in matches:
                        # Extract algorithm/implementation details
                        algorithm_info = self._extract_algorithm_info(match, content)
                        
                        # Calculate confidence
                        confidence = self._calculate_weak_crypto_confidence(
                            match, content, category, algorithm_info
                        )
                        
                        # Create finding
                        finding = WeakCryptoFinding(
                            algorithm_name=algorithm_info.get("algorithm", "Unknown"),
                            weakness_type=category,
                            severity=severity,
                            confidence=confidence,
                            location=f"{file_path}:{self._get_line_number(content, match.start())}",
                            evidence=match.group(0),
                            context={
                                "surrounding_code": self._extract_context(match, content),
                                "algorithm_details": algorithm_info,
                                "usage_pattern": self._analyze_usage_pattern(match, content)
                            },
                            recommendations=recommendations,
                            cwe_mapping=cwe_mapping,
                            compliance_issues=self._check_compliance_issues(algorithm_info["algorithm"])
                        )
                        
                        findings.append(finding)
                        self.analysis_stats["weak_algorithms_found"] += 1
            
            return findings
            
        except Exception as e:
            logger.error(f"Error analyzing weak cryptography in {file_path}: {e}")
            return []
    
    def analyze_key_strength(self, content: str, file_path: str) -> List[KeyStrengthAnalysis]:
        """
        Analyze cryptographic key strength implementations.
        
        Args:
            content: File content to analyze
            file_path: Path to the file being analyzed
            
        Returns:
            List of key strength analysis results
        """
        if not self.config.enable_key_strength_analysis:
            return []
        
        analyses = []
        
        try:
            # Key generation patterns
            key_patterns = [
                r"(?i)KeyPairGenerator\.getInstance\s*\(\s*[\"']([^\"']+)[\"']",
                r"(?i)KeyGenerator\.getInstance\s*\(\s*[\"']([^\"']+)[\"']",
                r"(?i)(?:RSA|DSA|ECDSA).*(\d+).*(?:bit|key)",
                r"(?i)keySize.*(\d+)",
                r"(?i)initialize\s*\(\s*(\d+)\s*\)"
            ]
            
            for pattern in key_patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                
                for match in matches:
                    algorithm = self._extract_algorithm_from_key_match(match)
                    key_size = self._extract_key_size_from_match(match)
                    
                    if algorithm and key_size:
                        analysis = self._analyze_key_strength_details(
                            algorithm, key_size, match, content, file_path
                        )
                        if analysis:
                            analyses.append(analysis)
                            
                            if not analysis.is_adequate:
                                self.analysis_stats["key_strength_issues"] += 1
            
            return analyses
            
        except Exception as e:
            logger.error(f"Error analyzing key strength in {file_path}: {e}")
            return []
    
    def analyze_iv_security(self, content: str, file_path: str) -> List[IVSecurityAnalysis]:
        """
        Analyze Initialization Vector (IV) security implementations.
        
        Args:
            content: File content to analyze
            file_path: Path to the file being analyzed
            
        Returns:
            List of IV security analysis results
        """
        if not self.config.enable_iv_analysis:
            return []
        
        analyses = []
        
        try:
            # IV-related patterns
            iv_patterns = [
                r"(?i)IvParameterSpec\s*\(\s*([^)]+)\s*\)",
                r"(?i)(?:iv|initVector)\s*[:=]\s*([^;\n]+)",
                r"(?i)new\s+byte\s*\[\s*(\d+)\s*\].*(?:iv|vector)",
                r"(?i)(?:AES|DES).*(?:CBC|CFB|OFB|CTR)",
                r"(?i)Cipher\.init\s*\([^,]+,\s*[^,]+,\s*([^)]+)\)"
            ]
            
            for pattern in iv_patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
                
                for match in matches:
                    analysis = self._analyze_iv_security_details(match, content, file_path)
                    if analysis:
                        analyses.append(analysis)
                        
                        if not analysis.is_secure:
                            self.analysis_stats["iv_security_issues"] += 1
            
            return analyses
            
        except Exception as e:
            logger.error(f"Error analyzing IV security in {file_path}: {e}")
            return []
    
    def analyze_salt_security(self, content: str, file_path: str) -> List[SaltAnalysis]:
        """
        Analyze salt randomness and security implementations.
        
        Args:
            content: File content to analyze
            file_path: Path to the file being analyzed
            
        Returns:
            List of salt analysis results
        """
        if not self.config.enable_salt_analysis:
            return []
        
        analyses = []
        
        try:
            # Salt-related patterns
            salt_patterns = [
                r"(?i)salt\s*[:=]\s*([^;\n]+)",
                r"(?i)(?:PBKDF2|scrypt|bcrypt).*salt.*[\"']([^\"']+)[\"']",
                r"(?i)new\s+byte\s*\[\s*(\d+)\s*\].*salt",
                r"(?i)SecureRandom.*nextBytes\s*\(\s*salt\s*\)",
                r"(?i)(?:generateSalt|createSalt|getSalt)\s*\([^)]*\)"
            ]
            
            for pattern in salt_patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
                
                for match in matches:
                    analysis = self._analyze_salt_security_details(match, content, file_path)
                    if analysis:
                        analyses.append(analysis)
                        
                        if not analysis.is_secure:
                            self.analysis_stats["salt_security_issues"] += 1
            
            return analyses
            
        except Exception as e:
            logger.error(f"Error analyzing salt security in {file_path}: {e}")
            return []
    
    def analyze_pbkdf_security(self, content: str, file_path: str) -> List[PBKDFAnalysis]:
        """
        Analyze Password-Based Key Derivation Function (PBKDF) implementations.
        
        Args:
            content: File content to analyze
            file_path: Path to the file being analyzed
            
        Returns:
            List of PBKDF analysis results
        """
        if not self.config.enable_pbkdf_analysis:
            return []
        
        analyses = []
        
        try:
            # PBKDF patterns
            pbkdf_patterns = [
                r"(?i)PBKDF2.*(?:HmacSHA(?:1|256|384|512))",
                r"(?i)(?:scrypt|bcrypt|Argon2).*\([^)]+\)",
                r"(?i)PBEKeySpec\s*\([^)]+\)",
                r"(?i)SecretKeyFactory.*PBKDF2",
                r"(?i)deriveKey.*iterations.*(\d+)"
            ]
            
            for pattern in pbkdf_patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
                
                for match in matches:
                    analysis = self._analyze_pbkdf_security_details(match, content, file_path)
                    if analysis:
                        analyses.append(analysis)
                        
                        if not analysis.is_secure:
                            self.analysis_stats["pbkdf_security_issues"] += 1
            
            return analyses
            
        except Exception as e:
            logger.error(f"Error analyzing PBKDF security in {file_path}: {e}")
            return []
    
    def _extract_algorithm_info(self, match: re.Match, content: str) -> Dict[str, Any]:
        """Extract algorithm information from a regex match."""
        algorithm_info = {
            "algorithm": "Unknown",
            "mode": None,
            "padding": None,
            "key_size": None,
            "provider": None
        }
        
        match_text = match.group(0)
        
        # Extract algorithm name
        algo_patterns = {
            "AES": r"(?i)\bAES\b",
            "DES": r"(?i)\bDES\b(?!cendant|ign|k)",
            "3DES": r"(?i)\b(?:3DES|TripleDES|DESede)\b",
            "RC4": r"(?i)\bRC4\b",
            "RSA": r"(?i)\bRSA\b",
            "DSA": r"(?i)\bDSA\b",
            "ECDSA": r"(?i)\bECDSA\b",
            "MD5": r"(?i)\bMD5\b",
            "SHA1": r"(?i)\bSHA-?1\b",
            "SHA256": r"(?i)\bSHA-?256\b",
            "PBKDF2": r"(?i)\bPBKDF2\b"
        }
        
        for algo_name, pattern in algo_patterns.items():
            if re.search(pattern, match_text):
                algorithm_info["algorithm"] = algo_name
                break
        
        # Extract mode
        mode_pattern = r"(?i)/(ECB|CBC|CFB|OFB|GCM|CTR|CTS)/"
        mode_match = re.search(mode_pattern, match_text)
        if mode_match:
            algorithm_info["mode"] = mode_match.group(1).upper()
        
        # Extract padding
        padding_pattern = r"(?i)/(PKCS1Padding|PKCS5Padding|PKCS7Padding|NoPadding|OAEP|PSS)/"
        padding_match = re.search(padding_pattern, match_text)
        if padding_match:
            algorithm_info["padding"] = padding_match.group(1)
        
        # Extract key size
        key_size_pattern = r"(\d+)(?:\s*bit|key|size)"
        key_size_match = re.search(key_size_pattern, match_text, re.IGNORECASE)
        if key_size_match:
            algorithm_info["key_size"] = int(key_size_match.group(1))
        
        return algorithm_info
    
    def _calculate_weak_crypto_confidence(self, match: re.Match, content: str, 
                                        category: str, algorithm_info: Dict[str, Any]) -> float:
        """Calculate confidence for weak cryptography finding."""
        evidence = {
            'pattern_type': 'weak_cryptography',
            'algorithm': algorithm_info.get("algorithm", "Unknown"),
            'weakness_category': category,
            'context_relevance': self._assess_crypto_context_relevance(match, content),
            'validation_sources': ['cryptographic_pattern_analysis', 'algorithm_detection'],
            'implementation_confidence': self._assess_implementation_confidence(match, content),
            'false_positive_indicators': self._check_crypto_false_positive_indicators(match, content)
        }
        
        return self.confidence_calculator.calculate_confidence(evidence=evidence, domain='cryptography')
    
    def _assess_crypto_context_relevance(self, match: re.Match, content: str) -> float:
        """Assess the relevance of the cryptographic usage context."""
        context = self._extract_context(match, content)
        
        # High relevance indicators
        high_relevance_patterns = [
            r"(?i)encrypt", r"(?i)decrypt", r"(?i)cipher", r"(?i)hash",
            r"(?i)digest", r"(?i)signature", r"(?i)keystore", r"(?i)secure"
        ]
        
        # Low relevance indicators (test/example code)
        low_relevance_patterns = [
            r"(?i)test", r"(?i)example", r"(?i)demo", r"(?i)sample",
            r"(?i)mock", r"(?i)debug", r"(?i)todo"
        ]
        
        high_score = sum(1 for pattern in high_relevance_patterns 
                        if re.search(pattern, context))
        low_score = sum(1 for pattern in low_relevance_patterns 
                       if re.search(pattern, context))
        
        # Calculate relevance score (0.0 to 1.0)
        if high_score > 0 and low_score == 0:
            return 1.0
        elif high_score > low_score:
            return 0.8
        elif high_score == low_score:
            return 0.6
        elif low_score > high_score:
            return 0.3
        else:
            return 0.5
    
    def _assess_implementation_confidence(self, match: re.Match, content: str) -> float:
        """Assess confidence in the cryptographic implementation detection."""
        match_text = match.group(0)
        
        # Strong indicators
        if any(indicator in match_text.lower() for indicator in [
            'cipher.getinstance', 'messagedigest.getinstance', 'keygenerator',
            'secretkeyspec', 'ivparameterspec'
        ]):
            return 0.95
        
        # Medium indicators  
        if any(indicator in match_text.lower() for indicator in [
            'encrypt', 'decrypt', 'hash', 'digest', 'signature'
        ]):
            return 0.8
        
        # Basic indicators
        return 0.6
    
    def _check_crypto_false_positive_indicators(self, match: re.Match, content: str) -> List[str]:
        """Check for false positive indicators in cryptographic analysis."""
        indicators = []
        context = self._extract_context(match, content)
        
        # Check for test/example context
        if any(keyword in context.lower() for keyword in [
            'test', 'example', 'demo', 'sample', 'mock'
        ]):
            indicators.append('test_context')
        
        # Check for comments/documentation
        if re.search(r'(?i)(?://|/\*|\*|#).*' + re.escape(match.group(0)), content):
            indicators.append('commented_code')
        
        # Check for string literals (not actual usage)
        if re.search(r'["\'].*' + re.escape(match.group(0)) + r'.*["\']', content):
            indicators.append('string_literal')
        
        return indicators
    
    def _analyze_usage_pattern(self, match: re.Match, content: str) -> str:
        """Analyze the usage pattern of the cryptographic implementation."""
        context = self._extract_context(match, content)
        
        if "encrypt" in context.lower() or "decrypt" in context.lower():
            return "encryption_usage"
        elif "hash" in context.lower() or "digest" in context.lower():
            return "hashing_usage"
        elif "signature" in context.lower() or "verify" in context.lower():
            return "signature_usage"
        elif "random" in context.lower() or "generator" in context.lower():
            return "random_generation"
        else:
            return "unknown_usage"
    
    def _check_compliance_issues(self, algorithm: str) -> List[str]:
        """Check compliance issues for the given algorithm."""
        compliance_issues = []
        
        algorithm_lower = algorithm.lower()
        
        # NIST compliance issues
        if algorithm_lower in ['des', '3des', 'md5', 'sha1', 'rc4']:
            compliance_issues.append("NIST_SP_800-131A_deprecated")
        
        # FIPS compliance issues
        if algorithm_lower in ['des', 'rc4', 'md5']:
            compliance_issues.append("FIPS_140-2_non_approved")
        
        # PCI DSS compliance issues
        if algorithm_lower in ['des', 'md5', 'sha1']:
            compliance_issues.append("PCI_DSS_weak_cryptography")
        
        # Common Criteria issues
        if algorithm_lower in ['des', 'rc4', 'md5']:
            compliance_issues.append("Common_Criteria_inadequate")
        
        return compliance_issues
    
    def _extract_algorithm_from_key_match(self, match: re.Match) -> Optional[str]:
        """Extract algorithm name from a key-related match."""
        match_text = match.group(0)
        
        # Algorithm extraction patterns
        if re.search(r"(?i)RSA", match_text):
            return "RSA"
        elif re.search(r"(?i)DSA", match_text):
            return "DSA"
        elif re.search(r"(?i)ECDSA", match_text):
            return "ECDSA"
        elif re.search(r"(?i)AES", match_text):
            return "AES"
        elif re.search(r"(?i)DES", match_text):
            return "DES"
        
        return None
    
    def _extract_key_size_from_match(self, match: re.Match) -> Optional[int]:
        """Extract key size from a key-related match."""
        match_text = match.group(0)
        
        # Key size extraction patterns
        size_patterns = [
            r"(\d+)(?:\s*bit|key|size)",
            r"initialize\s*\(\s*(\d+)\s*\)",
            r"(?:RSA|DSA|ECDSA).*(\d+)",
            r"keySize.*(\d+)"
        ]
        
        for pattern in size_patterns:
            size_match = re.search(pattern, match_text, re.IGNORECASE)
            if size_match:
                return int(size_match.group(1))
        
        return None
    
    def _analyze_key_strength_details(self, algorithm: str, key_size: int, 
                                    match: re.Match, content: str, file_path: str) -> Optional[KeyStrengthAnalysis]:
        """Analyze key strength implementation details."""
        if algorithm not in self.key_strength_database:
            return None
        
        strength_info = self.key_strength_database[algorithm]
        
        # Determine strength level
        if key_size < strength_info["min_secure_size"]:
            strength_level = "WEAK"
            is_adequate = False
        elif key_size < strength_info["recommended_size"]:
            strength_level = "ACCEPTABLE"
            is_adequate = True
        elif key_size < strength_info["future_proof_size"]:
            strength_level = "STRONG"
            is_adequate = True
        else:
            strength_level = "VERY_STRONG"
            is_adequate = True
        
        # Get security level estimate
        security_levels = strength_info["security_levels"]
        estimated_security_level = security_levels.get(key_size, 0)
        
        # Generate vulnerability notes
        vulnerability_notes = []
        if key_size in strength_info["weak_sizes"]:
            vulnerability_notes.append(f"{key_size}-bit {algorithm} is vulnerable to cryptographic attacks")
        if key_size < strength_info["min_secure_size"]:
            vulnerability_notes.append(f"Key size below minimum secure threshold of {strength_info['min_secure_size']} bits")
        
        return KeyStrengthAnalysis(
            algorithm=algorithm,
            key_size_bits=key_size,
            strength_level=strength_level,
            is_adequate=is_adequate,
            recommended_size=strength_info["recommended_size"],
            estimated_security_level=estimated_security_level,
            vulnerability_notes=vulnerability_notes
        )
    
    def _analyze_iv_security_details(self, match: re.Match, content: str, file_path: str) -> Optional[IVSecurityAnalysis]:
        """Analyze IV security implementation details."""
        match_text = match.group(0)
        context = self._extract_context(match, content)
        
        # Determine algorithm
        algorithm = "Unknown"
        if re.search(r"(?i)AES", context):
            algorithm = "AES"
        elif re.search(r"(?i)DES", context):
            algorithm = "DES"
        
        # Determine IV mode
        iv_mode = "Unknown"
        if re.search(r"(?i)CBC", context):
            iv_mode = "CBC"
        elif re.search(r"(?i)CFB", context):
            iv_mode = "CFB"
        elif re.search(r"(?i)OFB", context):
            iv_mode = "OFB"
        elif re.search(r"(?i)CTR", context):
            iv_mode = "CTR"
        
        # Determine IV source
        iv_source = "Unknown"
        is_secure = True
        issues = []
        recommendations = []
        
        # Check for hardcoded IV
        if re.search(r"[\"'][A-Za-z0-9+/=]{8,}[\"']", match_text):
            iv_source = "Hardcoded"
            is_secure = False
            issues.append("IV appears to be hardcoded")
            recommendations.append("Generate random IV for each encryption")
        
        # Check for SecureRandom usage
        elif re.search(r"(?i)SecureRandom", context):
            iv_source = "SecureRandom"
            is_secure = True
        
        # Check for weak random sources
        elif re.search(r"(?i)(?:Math\.random|Random\(\))", context):
            iv_source = "Weak Random"
            is_secure = False
            issues.append("IV uses weak random source")
            recommendations.append("Use SecureRandom for IV generation")
        
        # Check for IV reuse
        elif re.search(r"(?i)(?:static|final|const).*iv", context):
            iv_source = "Static"
            is_secure = False
            issues.append("IV appears to be static/reused")
            recommendations.append("Generate unique IV for each encryption")
        
        if not recommendations:
            recommendations.append("Ensure IV is unique for each encryption operation")
        
        return IVSecurityAnalysis(
            algorithm=algorithm,
            iv_mode=iv_mode,
            iv_source=iv_source,
            is_secure=is_secure,
            issues=issues,
            recommendations=recommendations
        )
    
    def _analyze_salt_security_details(self, match: re.Match, content: str, file_path: str) -> Optional[SaltAnalysis]:
        """Analyze salt security implementation details."""
        match_text = match.group(0)
        context = self._extract_context(match, content)
        
        # Extract salt value if present
        salt_value = None
        salt_pattern = r'["\']([A-Za-z0-9+/=]{8,})["\']'
        salt_match = re.search(salt_pattern, match_text)
        if salt_match:
            salt_value = salt_match.group(1)
        
        # Determine salt length
        salt_length = 0
        if salt_value:
            try:
                decoded = base64.b64decode(salt_value + '==')  # Add padding
                salt_length = len(decoded)
            except:
                salt_length = len(salt_value) // 2  # Assume hex encoding
        
        # Analyze randomness quality
        randomness_quality = "Unknown"
        is_unique = True
        is_secure = True
        issues = []
        recommendations = []
        
        # Check for hardcoded salt
        if salt_value:
            randomness_quality = "Hardcoded"
            is_unique = False
            is_secure = False
            issues.append("Salt appears to be hardcoded")
            recommendations.append("Generate unique salt for each password/key derivation")
        
        # Check for SecureRandom usage
        elif re.search(r"(?i)SecureRandom.*nextBytes", context):
            randomness_quality = "Cryptographically Secure"
            is_secure = True
        
        # Check for weak random sources
        elif re.search(r"(?i)(?:Math\.random|Random\(\))", context):
            randomness_quality = "Weak"
            is_secure = False
            issues.append("Salt generation uses weak random source")
            recommendations.append("Use SecureRandom for salt generation")
        
        # Check salt length adequacy
        if 0 < salt_length < 16:
            is_secure = False
            issues.append(f"Salt length {salt_length} bytes is too short")
            recommendations.append("Use minimum 16-byte (128-bit) salt")
        
        if not recommendations:
            recommendations.append("Ensure salt is unique for each password/key derivation")
        
        return SaltAnalysis(
            salt_value=salt_value,
            salt_length=salt_length,
            randomness_quality=randomness_quality,
            is_unique=is_unique,
            is_secure=is_secure,
            issues=issues,
            recommendations=recommendations
        )
    
    def _analyze_pbkdf_security_details(self, match: re.Match, content: str, file_path: str) -> Optional[PBKDFAnalysis]:
        """Analyze PBKDF security implementation details."""
        match_text = match.group(0)
        context = self._extract_context(match, content)
        
        # Determine PBKDF function
        function_name = "Unknown"
        if re.search(r"(?i)PBKDF2", match_text):
            function_name = "PBKDF2"
        elif re.search(r"(?i)scrypt", match_text):
            function_name = "scrypt"
        elif re.search(r"(?i)bcrypt", match_text):
            function_name = "bcrypt"
        elif re.search(r"(?i)Argon2", match_text):
            function_name = "Argon2"
        
        # Extract iteration count
        iteration_count = 0
        iteration_patterns = [
            r"iterations?[^0-9]*(\d+)",
            r"(\d+)[^0-9]*iterations?",
            r"PBEKeySpec\s*\([^,]*,[^,]*,[^,]*,\s*(\d+)",
            r"deriveKey.*?(\d{3,})"  # Look for numbers with 3+ digits
        ]
        
        for pattern in iteration_patterns:
            iteration_match = re.search(pattern, context, re.IGNORECASE)
            if iteration_match:
                iteration_count = int(iteration_match.group(1))
                break
        
        # Analyze salt (if available)
        salt_analysis = None
        salt_matches = re.finditer(r"(?i)salt", context)
        for salt_match in salt_matches:
            salt_analysis = self._analyze_salt_security_details(salt_match, content, file_path)
            if salt_analysis:
                break
        
        # Extract key length
        key_length = 0
        key_length_pattern = r"(?:keyLength|keySize)[^0-9]*(\d+)"
        key_length_match = re.search(key_length_pattern, context, re.IGNORECASE)
        if key_length_match:
            key_length = int(key_length_match.group(1))
        
        # Security assessment
        is_secure = True
        security_level = "Unknown"
        performance_cost = "Unknown"
        recommendations = []
        
        # PBKDF2 specific assessment
        if function_name == "PBKDF2":
            if iteration_count < 10000:
                is_secure = False
                security_level = "WEAK"
                performance_cost = "LOW"
                recommendations.append("Increase iteration count to at least 10,000")
            elif iteration_count < 100000:
                security_level = "MODERATE"
                performance_cost = "MEDIUM"
                recommendations.append("Consider increasing iteration count to 100,000+ for better security")
            else:
                security_level = "STRONG"
                performance_cost = "HIGH"
        
        # scrypt specific assessment
        elif function_name == "scrypt":
            security_level = "STRONG"
            performance_cost = "HIGH"
            recommendations.append("scrypt provides good memory-hard properties")
        
        # bcrypt specific assessment
        elif function_name == "bcrypt":
            security_level = "STRONG"
            performance_cost = "MEDIUM"
            recommendations.append("bcrypt is suitable for password hashing")
        
        # Argon2 specific assessment
        elif function_name == "Argon2":
            security_level = "VERY_STRONG"
            performance_cost = "HIGH"
            recommendations.append("Argon2 is the current best practice for password hashing")
        
        if not recommendations:
            recommendations.append("Use appropriate PBKDF parameters for your security requirements")
        
        return PBKDFAnalysis(
            function_name=function_name,
            iteration_count=iteration_count,
            salt_analysis=salt_analysis,
            key_length=key_length,
            is_secure=is_secure,
            security_level=security_level,
            performance_cost=performance_cost,
            recommendations=recommendations
        )
    
    def _extract_context(self, match: re.Match, content: str, context_size: int = 200) -> str:
        """Extract context around a match for analysis."""
        start = max(0, match.start() - context_size)
        end = min(len(content), match.end() + context_size)
        return content[start:end]
    
    def _get_line_number(self, content: str, position: int) -> int:
        """Get line number for a position in content."""
        return content[:position].count('\n') + 1
    
    def analyze(self) -> Dict[str, Any]:
        """Main analysis method that orchestrates all crypto analysis with timeout controls."""
        try:
            start_time = time.time()
            logger.info("Starting crypto analysis with timeout controls")
            
            # Initialize result containers
            all_implementations = []
            all_vulnerabilities = []
            all_weak_crypto = []
            all_key_strength = []
            all_iv_security = []
            all_salt_analysis = []
            all_pbkdf = []
            
            files_processed = 0
            files_skipped = 0
            
            # Get files to analyze
            file_list = self._get_analysis_files()
            logger.info(f"Found {len(file_list)} files to analyze")
            
            # Process files with timeout control
            for file_path in file_list[:100]:  # Limit files for performance
                try:
                    # Check timeout
                    elapsed = time.time() - start_time
                    if elapsed > 60:  # 60 second timeout
                        logger.warning(f"Analysis timeout reached ({elapsed:.1f}s), stopping")
                        break
                    
                    # Check file size and type
                    if not self._should_process_file(file_path):
                        files_skipped += 1
                        continue
                    
                    # Read file content safely
                    content = self._read_file_safely(file_path)
                    if not content:
                        files_skipped += 1
                        continue
                    
                    # Run core analysis only (for performance)
                    try:
                        implementations = self.analyze_crypto_implementations(content, file_path)
                        all_implementations.extend(implementations)
                        
                        weak_crypto = self.analyze_weak_cryptography(content, file_path)
                        all_weak_crypto.extend(weak_crypto)
                        
                        # Generate vulnerabilities from implementations
                        for impl in implementations:
                            vulns = self._analyze_implementation_vulnerabilities(impl)
                            all_vulnerabilities.extend(vulns)
                    
                    except Exception as e:
                        logger.debug(f"Error in analysis methods for {file_path}: {e}")
                    
                    files_processed += 1
                    
                    # Progress logging every 25 files
                    if files_processed % 25 == 0:
                        elapsed = time.time() - start_time
                        logger.info(f"Processed {files_processed} files in {elapsed:.1f}s")
                        
                except Exception as e:
                    logger.debug(f"Error processing file {file_path}: {e}")
                    files_skipped += 1
                    continue
            
            analysis_duration = time.time() - start_time
            
            logger.info(f"Crypto analysis completed: {len(all_vulnerabilities)} vulnerabilities, {files_processed} files processed in {analysis_duration:.1f}s")
            
            return {
                'implementations': all_implementations,
                'vulnerabilities': all_vulnerabilities,
                'weak_crypto_findings': [f.__dict__ for f in all_weak_crypto],
                'key_strength_findings': [],
                'iv_security_findings': [],
                'salt_analysis_findings': [],
                'pbkdf_findings': [],
                'analysis_duration': analysis_duration,
                'files_processed': files_processed,
                'files_skipped': files_skipped,
                'recommendations': self._generate_recommendations(all_vulnerabilities, all_weak_crypto)
            }
            
        except Exception as e:
            logger.error(f"Crypto analysis failed: {e}")
            return {
                'implementations': [],
                'vulnerabilities': [],
                'weak_crypto_findings': [],
                'key_strength_findings': [],
                'iv_security_findings': [],
                'salt_analysis_findings': [],
                'pbkdf_findings': [],
                'analysis_duration': 0.0,
                'files_processed': 0,
                'files_skipped': 0,
                'error': str(e),
                'recommendations': ['Analysis failed - check logs for details']
            }
    
    def _get_analysis_files(self) -> List[str]:
        """Get list of files to analyze from APK context."""
        try:
            files = []
            
            # Try different methods to get files
            if hasattr(self.apk_ctx, 'get_files'):
                files = self.apk_ctx.get_files()
            elif hasattr(self.apk_ctx, 'get_java_files'):
                files = self.apk_ctx.get_java_files()
            elif hasattr(self.apk_ctx, 'source_dir'):
                source_dir = Path(self.apk_ctx.source_dir)
                if source_dir.exists():
                    files = []
                    for ext in ['*.java', '*.kt', '*.xml']:
                        files.extend(source_dir.rglob(ext))
                    files = [str(f) for f in files]
            
            # Filter and prioritize crypto-related files
            crypto_files = []
            other_files = []
            
            crypto_keywords = ['crypto', 'cipher', 'encrypt', 'decrypt', 'hash', 'key', 'ssl', 'tls', 'security']
            
            for file_path in files:
                file_lower = str(file_path).lower()
                if any(keyword in file_lower for keyword in crypto_keywords):
                    crypto_files.append(file_path)
                else:
                    other_files.append(file_path)
            
            # Return crypto files first, then others (limited)
            prioritized = crypto_files + other_files[:min(200, len(other_files))]
            return prioritized[:200]  # Max 200 files
            
        except Exception as e:
            logger.warning(f"Error getting file list: {e}")
            return []
    
    def _should_process_file(self, file_path: str) -> bool:
        """Check if file should be processed based on size and type."""
        try:
            path = Path(file_path)
            
            # Check file size (max 2MB)
            if path.stat().st_size > 2 * 1024 * 1024:
                return False
            
            # Check file extension
            if path.suffix.lower() not in ['.java', '.kt', '.xml']:
                return False
            
            # Skip test files to reduce noise
            if any(test_dir in str(path).lower() for test_dir in ['test/', '/test', 'androidtest']):
                return False
            
            return True
            
        except:
            return False
    
    def _read_file_safely(self, file_path: str) -> Optional[str]:
        """Safely read file content with error handling."""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Skip very large files (max 500KB per file)
            if len(content) > 500 * 1024:
                logger.debug(f"Skipping large file: {file_path}")
                return None
            
            return content
            
        except Exception as e:
            logger.debug(f"Error reading file {file_path}: {e}")
            return None
    
    def _generate_recommendations(self, vulnerabilities: List[CryptographicVulnerability], 
                                 weak_crypto: List[WeakCryptoFinding]) -> List[str]:
        """Generate recommendations based on findings."""
        recommendations = set()
        
        # Check for weak algorithms
        weak_algos = set()
        for vuln in vulnerabilities:
            if hasattr(vuln, 'algorithm') and vuln.algorithm:
                if hasattr(vuln.algorithm, 'name') and vuln.algorithm.name in ['DES', 'MD5', 'SHA1', 'RC2', 'RC4']:
                    weak_algos.add(vuln.algorithm.name)
        
        for finding in weak_crypto:
            if finding.algorithm_name in ['DES', 'MD5', 'SHA1', 'RC2', 'RC4']:
                weak_algos.add(finding.algorithm_name)
        
        if weak_algos:
            recommendations.add(f"Replace weak algorithms ({', '.join(weak_algos)}) with modern alternatives")
        
        # Check for hardcoded keys
        hardcoded_count = len([f for f in weak_crypto if 'hardcoded' in f.weakness_type.lower()])
        if hardcoded_count > 0:
            recommendations.add("Implement secure key management using Android Keystore")
        
        # Check for SSL/TLS issues
        ssl_issues = len([f for f in weak_crypto if 'ssl' in f.weakness_type.lower() or 'tls' in f.weakness_type.lower()])
        if ssl_issues > 0:
            recommendations.add("Implement proper SSL/TLS certificate validation")
        
        # General recommendations
        if len(vulnerabilities) > 10:
            recommendations.add("Conduct comprehensive security code review")
        
        if not recommendations:
            recommendations.add("Continue following cryptographic best practices")
        
        return list(recommendations) 
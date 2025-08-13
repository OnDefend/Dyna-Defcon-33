"""
Enhanced Secret Detection Module

Specialized analyzer for secret detection, hash security analysis, and cryptographic
implementation assessment. Provides comprehensive analysis of:
- Hash collision vulnerability analysis
- Rainbow table attack susceptibility assessment  
- Hash algorithm strength evaluation
- Salting mechanism effectiveness validation
- Password hashing best practices compliance
"""

import logging
import re
import hashlib
import base64
import secrets
import time
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field
from pathlib import Path

from core.shared_infrastructure.dependency_injection import AnalysisContext
from .data_structures import SecretFinding, SecretType, StorageVulnerabilitySeverity
from .confidence_calculator import StorageConfidenceCalculator

@dataclass
class HashSecurityAnalysis:
    """Hash security analysis results."""
    algorithm: str
    hash_value: Optional[str]
    is_vulnerable_to_collisions: bool
    is_vulnerable_to_rainbow_tables: bool
    strength_level: str
    estimated_attack_time: str
    vulnerability_details: List[str]
    recommendations: List[str]

@dataclass
class SaltingMechanismAnalysis:
    """Salting mechanism effectiveness analysis."""
    has_salt: bool
    salt_source: str
    salt_length: int
    salt_randomness: str
    is_unique_per_hash: bool
    is_effective: bool
    issues: List[str]
    recommendations: List[str]

@dataclass
class PasswordHashingAnalysis:
    """Password hashing best practices analysis."""
    hashing_function: str
    is_slow_hash: bool
    has_work_factor: bool
    work_factor_value: Optional[int]
    is_memory_hard: bool
    is_secure: bool
    compliance_level: str
    best_practice_score: float
    recommendations: List[str]

class SecretDetector:
    """Enhanced secret detection analyzer with comprehensive hash security analysis."""
    
    def __init__(self, context: AnalysisContext, confidence_calculator: StorageConfidenceCalculator, logger: logging.Logger):
        self.context = context
        self.confidence_calculator = confidence_calculator
        self.logger = logger
        
        # Initialize hash security patterns and databases
        self.hash_algorithms_db = self._initialize_hash_algorithms_database()
        self.vulnerable_hash_patterns = self._initialize_vulnerable_hash_patterns()
        self.password_hashing_patterns = self._initialize_password_hashing_patterns()
        self.salt_detection_patterns = self._initialize_salt_detection_patterns()
        
        # Analysis statistics
        self.analysis_stats = {
            "secrets_found": 0,
            "hash_vulnerabilities_found": 0,
            "weak_salting_found": 0,
            "insecure_password_hashing_found": 0,
            "files_analyzed": 0,
            "analysis_duration": 0.0
        }
        
        logger.info("Enhanced SecretDetector initialized with hash security analysis")
    
    def analyze(self, apk_ctx) -> List[SecretFinding]:
        """Analyze and detect secrets with enhanced hash security analysis."""
        start_time = time.time()
        findings = []
        
        try:
            self.logger.info(f"Starting enhanced secret detection for {apk_ctx.package_name}")
            
            # Get analysis targets (files to analyze)
            analysis_targets = self._get_analysis_targets(apk_ctx)
            
            for target in analysis_targets:
                try:
                    # Analyze each target for different types of security issues
                    target_findings = []
                    
                    # Traditional secret detection
                    target_findings.extend(self._detect_traditional_secrets(target))
                    
                    # Enhanced hash security analysis
                    target_findings.extend(self._analyze_hash_security(target))
                    
                    # Password hashing security analysis
                    target_findings.extend(self._analyze_password_hashing_security(target))
                    
                    # Salting mechanism analysis
                    target_findings.extend(self._analyze_salting_mechanisms(target))
                    
                    findings.extend(target_findings)
                    self.analysis_stats["files_analyzed"] += 1
                    
                except Exception as e:
                    self.logger.warning(f"Secret detection failed for {target.get('file_path', 'unknown')}: {e}")
            
            # Update analysis statistics
            self.analysis_stats["secrets_found"] = len(findings)
            self.analysis_stats["analysis_duration"] = time.time() - start_time
            
            self.logger.info(f"Enhanced secret detection completed: {len(findings)} findings in {self.analysis_stats['analysis_duration']:.2f}s")
            
            return findings
            
        except Exception as e:
            self.logger.error(f"Enhanced secret detection analysis failed: {e}")
            return []
    
    def _initialize_hash_algorithms_database(self) -> Dict[str, Dict[str, Any]]:
        """Initialize comprehensive hash algorithms security database."""
        return {
            # Cryptographically broken hashes
            "MD2": {
                "strength": "broken",
                "collision_resistant": False,
                "rainbow_table_vulnerable": True,
                "estimated_attack_time": "seconds",
                "security_level": 0,
                "year_broken": 2004,
                "vulnerabilities": ["Collision attacks", "Preimage attacks", "Rainbow table attacks"]
            },
            "MD4": {
                "strength": "broken", 
                "collision_resistant": False,
                "rainbow_table_vulnerable": True,
                "estimated_attack_time": "seconds",
                "security_level": 0,
                "year_broken": 1995,
                "vulnerabilities": ["Collision attacks", "Preimage attacks", "Rainbow table attacks"]
            },
            "MD5": {
                "strength": "broken",
                "collision_resistant": False,
                "rainbow_table_vulnerable": True,
                "estimated_attack_time": "seconds to minutes",
                "security_level": 0,
                "year_broken": 2004,
                "vulnerabilities": ["Collision attacks", "Chosen-prefix attacks", "Rainbow table attacks"]
            },
            
            # Weak hashes
            "SHA0": {
                "strength": "weak",
                "collision_resistant": False,
                "rainbow_table_vulnerable": True,
                "estimated_attack_time": "hours",
                "security_level": 20,
                "year_broken": 1998,
                "vulnerabilities": ["Collision attacks", "Rainbow table attacks"]
            },
            "SHA1": {
                "strength": "weak",
                "collision_resistant": False,
                "rainbow_table_vulnerable": True,
                "estimated_attack_time": "hours to days",
                "security_level": 20,
                "year_broken": 2017,
                "vulnerabilities": ["Collision attacks (SHAttered)", "Rainbow table attacks"]
            },
            
            # Secure hashes
            "SHA224": {
                "strength": "secure",
                "collision_resistant": True,
                "rainbow_table_vulnerable": False,
                "estimated_attack_time": "2^112 operations",
                "security_level": 112,
                "vulnerabilities": []
            },
            "SHA256": {
                "strength": "secure",
                "collision_resistant": True,
                "rainbow_table_vulnerable": False,
                "estimated_attack_time": "2^128 operations",
                "security_level": 128,
                "vulnerabilities": []
            },
            "SHA384": {
                "strength": "secure",
                "collision_resistant": True,
                "rainbow_table_vulnerable": False,
                "estimated_attack_time": "2^192 operations", 
                "security_level": 192,
                "vulnerabilities": []
            },
            "SHA512": {
                "strength": "secure",
                "collision_resistant": True,
                "rainbow_table_vulnerable": False,
                "estimated_attack_time": "2^256 operations",
                "security_level": 256,
                "vulnerabilities": []
            },
            
            # SHA-3 family
            "SHA3-224": {
                "strength": "secure",
                "collision_resistant": True,
                "rainbow_table_vulnerable": False,
                "estimated_attack_time": "2^112 operations",
                "security_level": 112,
                "vulnerabilities": []
            },
            "SHA3-256": {
                "strength": "secure",
                "collision_resistant": True,
                "rainbow_table_vulnerable": False,
                "estimated_attack_time": "2^128 operations",
                "security_level": 128,
                "vulnerabilities": []
            },
            "SHA3-384": {
                "strength": "secure",
                "collision_resistant": True,
                "rainbow_table_vulnerable": False,
                "estimated_attack_time": "2^192 operations",
                "security_level": 192,
                "vulnerabilities": []
            },
            "SHA3-512": {
                "strength": "secure",
                "collision_resistant": True,
                "rainbow_table_vulnerable": False,
                "estimated_attack_time": "2^256 operations",
                "security_level": 256,
                "vulnerabilities": []
            },
            
            # Modern hashes
            "BLAKE2b": {
                "strength": "secure",
                "collision_resistant": True,
                "rainbow_table_vulnerable": False,
                "estimated_attack_time": "2^256 operations",
                "security_level": 256,
                "vulnerabilities": []
            },
            "BLAKE2s": {
                "strength": "secure",
                "collision_resistant": True,
                "rainbow_table_vulnerable": False,
                "estimated_attack_time": "2^128 operations",
                "security_level": 128,
                "vulnerabilities": []
            }
        }
    
    def _initialize_vulnerable_hash_patterns(self) -> Dict[str, List[str]]:
        """Initialize patterns for detecting vulnerable hash usage."""
        return {
            "md5_usage": [
                r"(?i)MessageDigest\.getInstance\s*\(\s*['\"]MD5['\"]\s*\)",
                r"(?i)\.md5\(\)",
                r"(?i)Hashing\.md5\(\)",
                r"(?i)DigestUtils\.md5",
                r"(?i)md5\s*\(",
                r"(?i)MD5\.digest",
                r"(?i)CryptoJS\.MD5",
                r"(?i)hashlib\.md5"
            ],
            "sha1_usage": [
                r"(?i)MessageDigest\.getInstance\s*\(\s*['\"]SHA-?1['\"]\s*\)",
                r"(?i)\.sha1\(\)",
                r"(?i)Hashing\.sha1\(\)",
                r"(?i)DigestUtils\.sha1",
                r"(?i)sha1\s*\(",
                r"(?i)SHA1\.digest",
                r"(?i)CryptoJS\.SHA1",
                r"(?i)hashlib\.sha1"
            ],
            "weak_hash_general": [
                r"(?i)MessageDigest\.getInstance\s*\(\s*['\"](?:MD[245]|SHA-?[01])['\"]\s*\)",
                r"(?i)Mac\.getInstance\s*\(\s*['\"]Hmac(?:MD5|SHA1)['\"]\s*\)",
                r"(?i)(?:md[245]|sha[01]).*hash",
                r"(?i)hash.*(?:md[245]|sha[01])"
            ]
        }
    
    def _initialize_password_hashing_patterns(self) -> Dict[str, Dict[str, Any]]:
        """Initialize password hashing security patterns."""
        return {
            # Modern secure password hashing
            "argon2": {
                "patterns": [
                    r"(?i)Argon2(?:i|d|id)?",
                    r"(?i)argon2.*hash",
                    r"(?i)hash.*argon2"
                ],
                "is_secure": True,
                "is_slow": True,
                "is_memory_hard": True,
                "min_work_factor": 1,
                "recommended_work_factor": 3
            },
            "scrypt": {
                "patterns": [
                    r"(?i)scrypt",
                    r"(?i)SCrypt\.generate",
                    r"(?i)scrypt.*hash"
                ],
                "is_secure": True,
                "is_slow": True,
                "is_memory_hard": True,
                "min_work_factor": 16384,
                "recommended_work_factor": 32768
            },
            "bcrypt": {
                "patterns": [
                    r"(?i)bcrypt",
                    r"(?i)BCrypt\.hashpw",
                    r"(?i)bcrypt.*hash"
                ],
                "is_secure": True,
                "is_slow": True,
                "is_memory_hard": False,
                "min_work_factor": 10,
                "recommended_work_factor": 12
            },
            "pbkdf2": {
                "patterns": [
                    r"(?i)PBKDF2",
                    r"(?i)PBEKeySpec",
                    r"(?i)pbkdf2.*hash"
                ],
                "is_secure": True,
                "is_slow": True,
                "is_memory_hard": False,
                "min_work_factor": 10000,
                "recommended_work_factor": 100000
            },
            
            # Insecure password hashing
            "plain_md5": {
                "patterns": [
                    r"(?i)password.*md5",
                    r"(?i)md5.*password",
                    r"(?i)MD5\(.*password"
                ],
                "is_secure": False,
                "vulnerabilities": ["Fast computation", "Rainbow table attacks", "Collision attacks"]
            },
            "plain_sha1": {
                "patterns": [
                    r"(?i)password.*sha1?",
                    r"(?i)sha1?.*password",
                    r"(?i)SHA1\(.*password"
                ],
                "is_secure": False,
                "vulnerabilities": ["Fast computation", "Rainbow table attacks", "Collision attacks"]
            },
            "plain_sha256": {
                "patterns": [
                    r"(?i)password.*sha256",
                    r"(?i)sha256.*password",
                    r"(?i)SHA256\(.*password"
                ],
                "is_secure": False,
                "vulnerabilities": ["Fast computation", "Rainbow table attacks"]
            }
        }
    
    def _initialize_salt_detection_patterns(self) -> Dict[str, List[str]]:
        """Initialize salt detection patterns."""
        return {
            "salt_generation": [
                r"(?i)salt\s*=\s*new\s+byte",
                r"(?i)SecureRandom.*nextBytes\s*\(\s*salt",
                r"(?i)generateSalt\s*\(",
                r"(?i)createSalt\s*\(",
                r"(?i)Random.*nextBytes.*salt"
            ],
            "hardcoded_salt": [
                r"(?i)salt\s*=\s*['\"][A-Za-z0-9+/=]{8,}['\"]",
                r"(?i)SALT\s*=\s*['\"][A-Za-z0-9+/=]{8,}['\"]",
                r"(?i)private.*salt.*['\"][A-Za-z0-9+/=]{8,}['\"]",
                r"(?i)static.*salt.*['\"][A-Za-z0-9+/=]{8,}['\"]"
            ],
            "no_salt_usage": [
                r"(?i)hash\s*\(\s*password\s*\)",
                r"(?i)digest\s*\(\s*password\s*\)",
                r"(?i)MessageDigest.*digest\s*\(\s*[^,)]*\s*\)",
                r"(?i)(?:md5|sha1|sha256)\s*\(\s*password\s*\)"
            ]
        }
    
    def _get_analysis_targets(self, apk_ctx) -> List[Dict[str, Any]]:
        """Get files and content to analyze for secret detection."""
        targets = []
        
        try:
            # Analyze manifest
            if hasattr(apk_ctx, 'manifest_xml') and apk_ctx.manifest_xml:
                targets.append({
                    'type': 'manifest',
                    'content': apk_ctx.manifest_xml,
                    'file_path': 'AndroidManifest.xml'
                })
            
            # Analyze source code
            if hasattr(apk_ctx, 'jadx_output_dir') and apk_ctx.jadx_output_dir:
                source_files = list(Path(apk_ctx.jadx_output_dir).rglob('*.java'))[:50]  # Limit for performance
                for file_path in source_files:
                    try:
                        content = file_path.read_text(encoding='utf-8', errors='ignore')
                        targets.append({
                            'type': 'source',
                            'content': content,
                            'file_path': str(file_path)
                        })
                    except Exception as e:
                        self.logger.debug(f"Failed to read source file {file_path}: {e}")
            
            # Analyze configuration files
            if hasattr(apk_ctx, 'resources_dir') and apk_ctx.resources_dir:
                config_patterns = ['*.xml', '*.properties', '*.json', '*.yml', '*.yaml']
                for pattern in config_patterns:
                    config_files = list(Path(apk_ctx.resources_dir).rglob(pattern))[:20]
                    for file_path in config_files:
                        try:
                            content = file_path.read_text(encoding='utf-8', errors='ignore')
                            targets.append({
                                'type': 'config',
                                'content': content,
                                'file_path': str(file_path)
                            })
                        except Exception as e:
                            self.logger.debug(f"Failed to read config file {file_path}: {e}")
        
        except Exception as e:
            self.logger.warning(f"Failed to get analysis targets: {e}")
        
        return targets
    
    def _detect_traditional_secrets(self, target: Dict[str, Any]) -> List[SecretFinding]:
        """Detect traditional secrets (API keys, passwords, tokens, etc.)."""
        findings = []
        content = target['content']
        file_path = target['file_path']
        
        # Traditional secret patterns from the storage patterns config
        secret_patterns = {
            SecretType.API_KEY: [
                r'[Aa][Pp][Ii]_?[Kk][Ee][Yy].*["\']([A-Za-z0-9]{20,})["\']',
                r'AIza[0-9A-Za-z\\-_]{35}',  # Google API Key
                r'sk_live_[0-9a-zA-Z]{24}',  # Stripe Secret Key
            ],
            SecretType.PASSWORD: [
                r'[Pp][Aa][Ss][Ss][Ww][Oo][Rr][Dd].*["\']([^"\']{8,})["\']',
                r'password\s*=\s*["\']([^"\']{8,})["\']',
            ],
            SecretType.TOKEN: [
                r'[Tt][Oo][Kk][Ee][Nn].*["\']([A-Za-z0-9+/=]{20,})["\']',
                r'[Bb][Ee][Aa][Rr][Ee][Rr]\s+([A-Za-z0-9+/=]{20,})',
            ],
            SecretType.PRIVATE_KEY: [
                r'-----BEGIN PRIVATE KEY-----',
                r'-----BEGIN RSA PRIVATE KEY-----',
            ],
            SecretType.ENCRYPTION_KEY: [
                r'[Ee][Nn][Cc][Rr][Yy][Pp][Tt][Ii][Oo][Nn]_?[Kk][Ee][Yy].*["\']([A-Za-z0-9+/=]{16,})["\']',
            ]
        }
        
        for secret_type, patterns in secret_patterns.items():
            for pattern in patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
                for match in matches:
                    finding = self._create_secret_finding(
                        secret_type, match, content, file_path, pattern
                    )
                    findings.append(finding)
        
        return findings
    
    def _analyze_hash_security(self, target: Dict[str, Any]) -> List[SecretFinding]:
        """Analyze hash security including collision and rainbow table vulnerabilities."""
        findings = []
        content = target['content']
        file_path = target['file_path']
        
        for hash_type, patterns in self.vulnerable_hash_patterns.items():
            for pattern in patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
                for match in matches:
                    # Extract algorithm name
                    algorithm = self._extract_hash_algorithm(match, content)
                    
                    if algorithm and algorithm in self.hash_algorithms_db:
                        hash_analysis = self._analyze_hash_algorithm_security(algorithm, match, content)
                        
                        if hash_analysis.is_vulnerable_to_collisions or hash_analysis.is_vulnerable_to_rainbow_tables:
                            finding = self._create_hash_vulnerability_finding(
                                hash_analysis, match, content, file_path, pattern
                            )
                            findings.append(finding)
                            self.analysis_stats["hash_vulnerabilities_found"] += 1
        
        return findings
    
    def _analyze_password_hashing_security(self, target: Dict[str, Any]) -> List[SecretFinding]:
        """Analyze password hashing security and best practices compliance."""
        findings = []
        content = target['content']
        file_path = target['file_path']
        
        for hash_type, hash_info in self.password_hashing_patterns.items():
            patterns = hash_info["patterns"]
            is_secure = hash_info.get("is_secure", False)
            
            for pattern in patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
                for match in matches:
                    password_analysis = self._analyze_password_hashing_implementation(
                        hash_type, hash_info, match, content
                    )
                    
                    if not password_analysis.is_secure:
                        finding = self._create_password_hashing_finding(
                            password_analysis, match, content, file_path, pattern
                        )
                        findings.append(finding)
                        self.analysis_stats["insecure_password_hashing_found"] += 1
        
        return findings
    
    def _analyze_salting_mechanisms(self, target: Dict[str, Any]) -> List[SecretFinding]:
        """Analyze salting mechanism effectiveness."""
        findings = []
        content = target['content']
        file_path = target['file_path']
        
        # Check for salting issues
        for mechanism_type, patterns in self.salt_detection_patterns.items():
            for pattern in patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
                for match in matches:
                    salt_analysis = self._analyze_salt_mechanism(mechanism_type, match, content)
                    
                    if not salt_analysis.is_effective:
                        finding = self._create_salting_vulnerability_finding(
                            salt_analysis, match, content, file_path, pattern
                        )
                        findings.append(finding)
                        self.analysis_stats["weak_salting_found"] += 1
        
        return findings

    def _extract_hash_algorithm(self, match: re.Match, content: str) -> Optional[str]:
        """Extract hash algorithm name from a match."""
        match_text = match.group(0).upper()
        
        # Algorithm extraction patterns
        if "MD5" in match_text:
            return "MD5"
        elif "MD4" in match_text:
            return "MD4"
        elif "MD2" in match_text:
            return "MD2"
        elif "SHA-1" in match_text or "SHA1" in match_text:
            return "SHA1"
        elif "SHA-0" in match_text or "SHA0" in match_text:
            return "SHA0"
        elif "SHA-224" in match_text or "SHA224" in match_text:
            return "SHA224"
        elif "SHA-256" in match_text or "SHA256" in match_text:
            return "SHA256"
        elif "SHA-384" in match_text or "SHA384" in match_text:
            return "SHA384"
        elif "SHA-512" in match_text or "SHA512" in match_text:
            return "SHA512"
        elif "SHA3-224" in match_text:
            return "SHA3-224"
        elif "SHA3-256" in match_text:
            return "SHA3-256"
        elif "SHA3-384" in match_text:
            return "SHA3-384"
        elif "SHA3-512" in match_text:
            return "SHA3-512"
        elif "BLAKE2B" in match_text:
            return "BLAKE2b"
        elif "BLAKE2S" in match_text:
            return "BLAKE2s"
        
        return None
    
    def _analyze_hash_algorithm_security(self, algorithm: str, match: re.Match, content: str) -> HashSecurityAnalysis:
        """Analyze the security of a specific hash algorithm."""
        algo_info = self.hash_algorithms_db[algorithm]
        
        # Extract hash value if present
        hash_value = None
        context = self._extract_context(match, content)
        hash_pattern = r'["\']([a-fA-F0-9]{32,128})["\']'
        hash_match = re.search(hash_pattern, context)
        if hash_match:
            hash_value = hash_match.group(1)
        
        # Build analysis result
        analysis = HashSecurityAnalysis(
            algorithm=algorithm,
            hash_value=hash_value,
            is_vulnerable_to_collisions=not algo_info["collision_resistant"],
            is_vulnerable_to_rainbow_tables=algo_info["rainbow_table_vulnerable"],
            strength_level=algo_info["strength"],
            estimated_attack_time=algo_info["estimated_attack_time"],
            vulnerability_details=algo_info["vulnerabilities"].copy(),
            recommendations=self._get_hash_security_recommendations(algorithm, algo_info)
        )
        
        return analysis
    
    def _get_hash_security_recommendations(self, algorithm: str, algo_info: Dict[str, Any]) -> List[str]:
        """Get security recommendations for a hash algorithm."""
        recommendations = []
        
        if algo_info["strength"] == "broken":
            recommendations.append(f"Immediately replace {algorithm} with a secure hash function")
            recommendations.append("Use SHA-256 or SHA-3 family for new implementations")
            recommendations.append("Consider SHA-512 for high-security applications")
        elif algo_info["strength"] == "weak":
            recommendations.append(f"Migrate away from {algorithm} as soon as possible")
            recommendations.append("Use SHA-256 minimum for new implementations")
            recommendations.append("Plan migration timeline for existing uses")
        
        # Add specific recommendations based on vulnerabilities
        if "Collision attacks" in algo_info["vulnerabilities"]:
            recommendations.append("Vulnerable to collision attacks - avoid for digital signatures")
        if "Rainbow table attacks" in algo_info["vulnerabilities"]:
            recommendations.append("Use proper salting to prevent rainbow table attacks")
        
        if not recommendations:
            recommendations.append("Algorithm is secure for current use")
        
        return recommendations
    
    def _create_hash_vulnerability_finding(self, hash_analysis: HashSecurityAnalysis, 
                                         match: re.Match, content: str, file_path: str, pattern: str) -> SecretFinding:
        """Create a finding for hash vulnerabilities."""
        # Determine severity based on vulnerability type
        if hash_analysis.strength_level == "broken":
            severity = StorageVulnerabilitySeverity.CRITICAL
        elif hash_analysis.strength_level == "weak":
            severity = StorageVulnerabilitySeverity.HIGH
        else:
            severity = StorageVulnerabilitySeverity.MEDIUM
        
        # Calculate confidence
        evidence = {
            'pattern_type': 'hash_vulnerability',
            'algorithm': hash_analysis.algorithm,
            'strength_level': hash_analysis.strength_level,
            'vulnerability_details': hash_analysis.vulnerability_details,
            'context_relevance': 'security_critical',
            'validation_sources': ['hash_algorithm_analysis', 'cryptographic_research']
        }
        
        confidence = self.confidence_calculator.calculate_confidence(evidence=evidence, domain='cryptography')
        
        return SecretFinding(
            id=f"hash_vuln_{hash_analysis.algorithm}_{hash(match.group(0))}",
            secret_type=SecretType.ENCRYPTION_KEY,  # Closest match for hash vulnerabilities
            pattern_name=f"Vulnerable Hash Algorithm ({hash_analysis.algorithm})",
            evidence=match.group(0),
            location=file_path,
            file_path=file_path,
            severity=severity,
            confidence=confidence,
            description=f"Vulnerable hash algorithm {hash_analysis.algorithm} detected",
            remediation="; ".join(hash_analysis.recommendations),
            context={
                "algorithm": hash_analysis.algorithm,
                "strength_level": hash_analysis.strength_level,
                "vulnerabilities": hash_analysis.vulnerability_details,
                "estimated_attack_time": hash_analysis.estimated_attack_time,
                "line_number": self._get_line_number(content, match.start())
            }
        )
    
    def _analyze_password_hashing_implementation(self, hash_type: str, hash_info: Dict[str, Any], 
                                               match: re.Match, content: str) -> PasswordHashingAnalysis:
        """Analyze password hashing implementation details."""
        context = self._extract_context(match, content)
        
        # Extract work factor if present
        work_factor = None
        if hash_type in ["pbkdf2", "bcrypt", "scrypt", "argon2"]:
            # Look for iteration count, cost factor, or work factor
            work_factor_patterns = [
                r"(?:iterations?|cost|work.*factor)[^0-9]*(\d+)",
                r"(\d+)[^0-9]*(?:iterations?|cost|rounds?)",
                r"(?:N|rounds?|cost)\s*[:=]\s*(\d+)"
            ]
            
            for pattern in work_factor_patterns:
                work_match = re.search(pattern, context, re.IGNORECASE)
                if work_match:
                    work_factor = int(work_match.group(1))
                    break
        
        # Determine security
        is_secure = hash_info.get("is_secure", False)
        compliance_level = "Unknown"
        best_practice_score = 0.0
        recommendations = []
        
        if hash_type in ["argon2", "scrypt", "bcrypt", "pbkdf2"]:
            # Secure password hashing functions
            min_work = hash_info.get("min_work_factor", 1)
            recommended_work = hash_info.get("recommended_work_factor", min_work)
            
            if work_factor:
                if work_factor >= recommended_work:
                    compliance_level = "Excellent"
                    best_practice_score = 1.0
                elif work_factor >= min_work:
                    compliance_level = "Good"
                    best_practice_score = 0.8
                else:
                    compliance_level = "Inadequate"
                    best_practice_score = 0.3
                    is_secure = False
                    recommendations.append(f"Increase work factor to minimum {min_work}")
            else:
                compliance_level = "Unknown"
                best_practice_score = 0.6
                recommendations.append("Unable to determine work factor - verify configuration")
        else:
            # Insecure password hashing
            compliance_level = "Non-compliant"
            best_practice_score = 0.0
            is_secure = False
            vulnerabilities = hash_info.get("vulnerabilities", [])
            recommendations.extend([f"Vulnerability: {vuln}" for vuln in vulnerabilities])
            recommendations.append("Use Argon2, scrypt, bcrypt, or PBKDF2 for password hashing")
        
        return PasswordHashingAnalysis(
            hashing_function=hash_type,
            is_slow_hash=hash_info.get("is_slow", False),
            has_work_factor=work_factor is not None,
            work_factor_value=work_factor,
            is_memory_hard=hash_info.get("is_memory_hard", False),
            is_secure=is_secure,
            compliance_level=compliance_level,
            best_practice_score=best_practice_score,
            recommendations=recommendations
        )
    
    def _create_password_hashing_finding(self, password_analysis: PasswordHashingAnalysis,
                                       match: re.Match, content: str, file_path: str, pattern: str) -> SecretFinding:
        """Create a finding for password hashing vulnerabilities."""
        # Determine severity based on compliance level
        if password_analysis.compliance_level == "Non-compliant":
            severity = StorageVulnerabilitySeverity.CRITICAL
        elif password_analysis.compliance_level == "Inadequate":
            severity = StorageVulnerabilitySeverity.HIGH
        elif password_analysis.compliance_level == "Unknown":
            severity = StorageVulnerabilitySeverity.MEDIUM
        else:
            severity = StorageVulnerabilitySeverity.LOW
        
        # Calculate confidence
        evidence = {
            'pattern_type': 'password_hashing_vulnerability',
            'hashing_function': password_analysis.hashing_function,
            'compliance_level': password_analysis.compliance_level,
            'best_practice_score': password_analysis.best_practice_score,
            'context_relevance': 'security_critical',
            'validation_sources': ['password_hashing_analysis', 'best_practices_compliance']
        }
        
        confidence = self.confidence_calculator.calculate_confidence(evidence=evidence, domain='cryptography')
        
        return SecretFinding(
            id=f"pwd_hash_{password_analysis.hashing_function}_{hash(match.group(0))}",
            secret_type=SecretType.PASSWORD,
            pattern_name=f"Password Hashing ({password_analysis.hashing_function})",
            evidence=match.group(0),
            location=file_path,
            file_path=file_path,
            severity=severity,
            confidence=confidence,
            description=f"Password hashing using {password_analysis.hashing_function}",
            remediation="; ".join(password_analysis.recommendations),
            context={
                "hashing_function": password_analysis.hashing_function,
                "compliance_level": password_analysis.compliance_level,
                "is_secure": password_analysis.is_secure,
                "work_factor": password_analysis.work_factor_value,
                "best_practice_score": password_analysis.best_practice_score,
                "line_number": self._get_line_number(content, match.start())
            }
        )
    
    def _analyze_salt_mechanism(self, mechanism_type: str, match: re.Match, content: str) -> SaltingMechanismAnalysis:
        """Analyze salting mechanism implementation."""
        context = self._extract_context(match, content)
        
        # Initialize analysis
        has_salt = mechanism_type != "no_salt_usage"
        salt_source = "Unknown"
        salt_length = 0
        salt_randomness = "Unknown"
        is_unique_per_hash = True
        is_effective = True
        issues = []
        recommendations = []
        
        if mechanism_type == "salt_generation":
            # Proper salt generation detected
            salt_source = "Generated"
            
            # Check salt length
            length_pattern = r"new\s+byte\s*\[\s*(\d+)\s*\]"
            length_match = re.search(length_pattern, context)
            if length_match:
                salt_length = int(length_match.group(1))
                if salt_length < 16:
                    issues.append(f"Salt length {salt_length} bytes is too short")
                    recommendations.append("Use minimum 16-byte salt")
                    is_effective = False
            
            # Check randomness source
            if "SecureRandom" in context:
                salt_randomness = "Cryptographically Secure"
            elif "Random" in context:
                salt_randomness = "Pseudorandom"
                issues.append("Using weak random source for salt generation")
                recommendations.append("Use SecureRandom for salt generation")
                is_effective = False
            
        elif mechanism_type == "hardcoded_salt":
            # Hardcoded salt detected
            salt_source = "Hardcoded"
            is_unique_per_hash = False
            is_effective = False
            salt_randomness = "None (Hardcoded)"
            
            # Extract salt value and length
            salt_pattern = r'["\']([A-Za-z0-9+/=]{8,})["\']'
            salt_match = re.search(salt_pattern, match.group(0))
            if salt_match:
                salt_value = salt_match.group(1)
                try:
                    decoded = base64.b64decode(salt_value + '==')
                    salt_length = len(decoded)
                except:
                    salt_length = len(salt_value) // 2  # Assume hex
            
            issues.append("Hardcoded salt defeats purpose of salting")
            recommendations.append("Generate unique salt for each password")
            
        elif mechanism_type == "no_salt_usage":
            # No salt detected
            has_salt = False
            is_effective = False
            issues.append("No salt used with password hashing")
            recommendations.append("Always use unique salt for password hashing")
            recommendations.append("Protects against rainbow table attacks")
        
        return SaltingMechanismAnalysis(
            has_salt=has_salt,
            salt_source=salt_source,
            salt_length=salt_length,
            salt_randomness=salt_randomness,
            is_unique_per_hash=is_unique_per_hash,
            is_effective=is_effective,
            issues=issues,
            recommendations=recommendations
        )
    
    def _create_salting_vulnerability_finding(self, salt_analysis: SaltingMechanismAnalysis,
                                            match: re.Match, content: str, file_path: str, pattern: str) -> SecretFinding:
        """Create a finding for salting mechanism vulnerabilities."""
        # Determine severity based on effectiveness
        if not salt_analysis.has_salt:
            severity = StorageVulnerabilitySeverity.HIGH
        elif not salt_analysis.is_unique_per_hash:
            severity = StorageVulnerabilitySeverity.HIGH
        elif salt_analysis.salt_length < 16:
            severity = StorageVulnerabilitySeverity.MEDIUM
        elif salt_analysis.salt_randomness == "Pseudorandom":
            severity = StorageVulnerabilitySeverity.MEDIUM
        else:
            severity = StorageVulnerabilitySeverity.LOW
        
        # Calculate confidence
        evidence = {
            'pattern_type': 'salting_vulnerability',
            'has_salt': salt_analysis.has_salt,
            'salt_source': salt_analysis.salt_source,
            'is_effective': salt_analysis.is_effective,
            'context_relevance': 'security_critical',
            'validation_sources': ['salting_mechanism_analysis', 'best_practices_compliance']
        }
        
        confidence = self.confidence_calculator.calculate_confidence(evidence=evidence, domain='cryptography')
        
        return SecretFinding(
            id=f"salt_vuln_{salt_analysis.salt_source}_{hash(match.group(0))}",
            secret_type=SecretType.PASSWORD,
            pattern_name=f"Salting Mechanism ({salt_analysis.salt_source})",
            evidence=match.group(0),
            location=file_path,
            file_path=file_path,
            severity=severity,
            confidence=confidence,
            description=f"Salting mechanism issue: {'; '.join(salt_analysis.issues)}",
            remediation="; ".join(salt_analysis.recommendations),
            context={
                "has_salt": salt_analysis.has_salt,
                "salt_source": salt_analysis.salt_source,
                "salt_length": salt_analysis.salt_length,
                "salt_randomness": salt_analysis.salt_randomness,
                "is_effective": salt_analysis.is_effective,
                "line_number": self._get_line_number(content, match.start())
            }
        )
    
    def _create_secret_finding(self, secret_type: SecretType, match: re.Match, 
                             content: str, file_path: str, pattern: str) -> SecretFinding:
        """Create a traditional secret finding."""
        # Determine severity based on secret type
        severity_map = {
            SecretType.PRIVATE_KEY: StorageVulnerabilitySeverity.CRITICAL,
            SecretType.ENCRYPTION_KEY: StorageVulnerabilitySeverity.CRITICAL,
            SecretType.PASSWORD: StorageVulnerabilitySeverity.HIGH,
            SecretType.DATABASE_CREDENTIAL: StorageVulnerabilitySeverity.HIGH,
            SecretType.API_KEY: StorageVulnerabilitySeverity.MEDIUM,
            SecretType.TOKEN: StorageVulnerabilitySeverity.MEDIUM,
        }
        
        severity = severity_map.get(secret_type, StorageVulnerabilitySeverity.MEDIUM)
        
        # Calculate confidence
        evidence = {
            'pattern_type': 'secret_detection',
            'secret_type': secret_type.value,
            'context_relevance': 'security_critical',
            'validation_sources': ['secret_pattern_analysis'],
            'pattern_strength': 'high'
        }
        
        confidence = self.confidence_calculator.calculate_confidence(evidence=evidence, domain='storage')
        
        return SecretFinding(
            id=f"secret_{secret_type.value}_{hash(match.group(0))}",
            secret_type=secret_type,
            pattern_name=f"{secret_type.value.replace('_', ' ').title()} Detection",
            evidence=match.group(0),
            location=file_path,
            file_path=file_path,
            severity=severity,
            confidence=confidence,
            description=f"Detected {secret_type.value.replace('_', ' ')} in source code",
            remediation="Move secrets to secure storage (Android Keystore, encrypted preferences)",
            context={
                "secret_type": secret_type.value,
                "line_number": self._get_line_number(content, match.start())
            }
        )
    
    def _extract_context(self, match: re.Match, content: str, context_size: int = 150) -> str:
        """Extract context around a match for analysis."""
        start = max(0, match.start() - context_size)
        end = min(len(content), match.end() + context_size)
        return content[start:end]
    
    def _get_line_number(self, content: str, position: int) -> int:
        """Get line number for a position in content."""
        return content[:position].count('\n') + 1 
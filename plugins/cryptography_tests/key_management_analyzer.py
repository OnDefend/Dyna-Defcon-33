#!/usr/bin/env python3

"""
Enhanced Key Management Analyzer for Cryptography Tests

This module provides comprehensive analysis of cryptographic key management practices,
including advanced key generation, storage, rotation, lifecycle management, HSM integration,
and biometric protection analysis.

Features:
- Hardware Security Module (HSM) integration analysis
- Android Keystore security validation
- Key rotation mechanism assessment  
- Key escrow and backup security analysis
- Key lifecycle management validation
- Biometric key protection analysis
- Key derivation function security
- Key strength and entropy validation
"""

import re
import logging
import base64
from typing import Dict, List, Any, Optional, Tuple, Set
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)

@dataclass
class KeyManagementFinding:
    """Key management security finding."""
    finding_id: str
    title: str
    description: str
    severity: str
    location: str
    evidence: str
    recommendations: List[str]
    cwe_mapping: List[str]

@dataclass
class HSMIntegrationAssessment:
    """HSM integration security assessment."""
    hsm_detected: bool = False
    hsm_libraries: List[str] = None
    hsm_configurations: List[str] = None
    security_level: str = "UNKNOWN"
    vulnerabilities: List[str] = None
    
    def __post_init__(self):
        if self.hsm_libraries is None:
            self.hsm_libraries = []
        if self.hsm_configurations is None:
            self.hsm_configurations = []
        if self.vulnerabilities is None:
            self.vulnerabilities = []

@dataclass
class AndroidKeystoreAssessment:
    """Android Keystore security assessment."""
    keystore_usage: bool = False
    hardware_backed: bool = False
    strongbox_usage: bool = False
    attestation_enabled: bool = False
    user_authentication_required: bool = False
    biometric_protection: bool = False
    security_vulnerabilities: List[str] = None
    
    def __post_init__(self):
        if self.security_vulnerabilities is None:
            self.security_vulnerabilities = []

@dataclass
class KeyRotationAssessment:
    """Key rotation mechanism assessment."""
    rotation_detected: bool = False
    rotation_mechanisms: List[str] = None
    rotation_frequency: str = "UNKNOWN"
    automated_rotation: bool = False
    rotation_vulnerabilities: List[str] = None
    
    def __post_init__(self):
        if self.rotation_mechanisms is None:
            self.rotation_mechanisms = []
        if self.rotation_vulnerabilities is None:
            self.rotation_vulnerabilities = []

class KeyManagementAnalyzer:
    """Enhanced analyzer for cryptographic key management practices."""
    
    def __init__(self, context=None):
        self.context = context
        self.findings = []
        self.key_generation_patterns = self._initialize_key_generation_patterns()
        self.hardcoded_key_patterns = self._initialize_hardcoded_key_patterns()
        self.key_storage_patterns = self._initialize_key_storage_patterns()
        
        # Enhanced patterns for advanced analysis
        self.hsm_patterns = self._initialize_hsm_patterns()
        self.android_keystore_patterns = self._initialize_android_keystore_patterns()
        self.key_rotation_patterns = self._initialize_key_rotation_patterns()
        self.biometric_patterns = self._initialize_biometric_patterns()
        self.key_lifecycle_patterns = self._initialize_key_lifecycle_patterns()
    
    def _initialize_key_generation_patterns(self) -> List[str]:
        """Initialize patterns for key generation analysis."""
        return [
            r"KeyStore\.getInstance\([\"']AndroidKeyStore[\"']\)",
            r"KeyPairGenerator\.getInstance\([\"']RSA[\"']\)",
            r"KeyPairGenerator\.getInstance\([\"']EC[\"']\)",
            r"KeyGenerator\.getInstance\([\"']AES[\"']\)",
            r"SecretKeyFactory\.getInstance\([\"']PBKDF2[\"']\)",
            r"SecureRandom\.getInstance\([\"']SHA1PRNG[\"']\)",
            # Enhanced patterns
            r"KeyPairGenerator\.getInstance\([\"']Ed25519[\"']\)",
            r"KeyGenerator\.getInstance\([\"']ChaCha20[\"']\)",
            r"KeyAgreement\.getInstance\([\"']ECDH[\"']\)",
            r"Cipher\.getInstance\([\"']AES/GCM/NoPadding[\"']\)"
        ]
    
    def _initialize_hardcoded_key_patterns(self) -> List[str]:
        """Initialize patterns for hardcoded key detection."""
        return [
            r"[\"'][A-Za-z0-9+/]{32,}={0,2}[\"']",  # Base64 encoded keys
            r"[\"'][A-Fa-f0-9]{32,}[\"']",  # Hex encoded keys
            r"[\"']MII[A-Za-z0-9+/]{100,}[\"']",  # PEM format keys
            r"-----BEGIN.*KEY-----",
            r"-----END.*KEY-----"
        ]
    
    def _initialize_key_storage_patterns(self) -> List[str]:
        """Initialize patterns for key storage analysis."""
        return [
            r"SharedPreferences.*\.putString\([\"'][^\"']*[kK]ey[^\"']*[\"']",
            r"getSharedPreferences\([\"'][^\"']*[kK]ey[^\"']*[\"']",
            r"\.store\([^)]*[kK]ey[^)]*\)",
            r"\.load\([^)]*[kK]ey[^)]*\)",
            r"FileOutputStream.*[kK]ey",
            r"FileInputStream.*[kK]ey"
        ]
    
    def _initialize_hsm_patterns(self) -> List[str]:
        """Initialize patterns for HSM integration detection."""
        return [
            r"PKCS11Provider",
            r"SunPKCS11",
            r"HSMKeyStore",
            r"SafeNetHSM",
            r"ThalesHSM",
            r"LunaProvider",
            r"CaviumProvider",
            r"pkcs11\.library",
            r"HSM_.*_CONFIG",
            r"Hardware.*Security.*Module",
            r"\.p11",
            r"CKM_.*_GENERATE",
            r"C_.*Key.*",
            r"HSMClient",
            r"SafeNet.*KeySecure"
        ]
    
    def _initialize_android_keystore_patterns(self) -> List[str]:
        """Initialize patterns for Android Keystore analysis."""
        return [
            r"setKeyStoreAlias\(",
            r"setRequireUserAuthentication\(true\)",
            r"setUserAuthenticationRequired\(true\)",
            r"setRandomizedEncryptionRequired\(true\)",
            r"setIsStrongBoxBacked\(true\)",
            r"setAttestationChallenge\(",
            r"setInvalidatedByBiometricEnrollment\(",
            r"KeyProtection\.Builder\(",
            r"KeyGenParameterSpec\.Builder\(",
            r"setUserAuthenticationValidityDurationSeconds\(",
            r"setUserPresenceRequired\(true\)",
            r"setTrustedUserPresenceRequired\(true\)",
            r"setUnlockedDeviceRequired\(true\)",
            r"AndroidKeyStore.*hardware",
            r"StrongBox.*attestation",
            r"BiometricPrompt.*CryptoObject"
        ]
    
    def _initialize_key_rotation_patterns(self) -> List[str]:
        """Initialize patterns for key rotation mechanism detection."""
        return [
            r"rotateKey\(",
            r"keyRotation",
            r"KeyRotationScheduler",
            r"PeriodicWorkRequest.*[kK]ey.*[rR]otat",
            r"AlarmManager.*[kK]ey.*[rR]otat",
            r"CronJob.*[kK]ey",
            r"Timer.*[kK]ey.*[rR]otat",
            r"KeyVersioning",
            r"OldKeyRetention",
            r"KeyMigration",
            r"updateKeys\(",
            r"migrateKeys\(",
            r"deprecateKey\(",
            r"KeyLifecycleManager",
            r"KeyExpiration.*Policy"
        ]
    
    def _initialize_biometric_patterns(self) -> List[str]:
        """Initialize patterns for biometric protection analysis."""
        return [
            r"BiometricPrompt",
            r"FingerprintManager",
            r"BiometricManager",
            r"BIOMETRIC_SUCCESS",
            r"setUserAuthenticationRequired\(true\)",
            r"setUserAuthenticationValidityDurationSeconds\(0\)",
            r"CryptoObject\(",
            r"BiometricAuthentication",
            r"FaceManager",
            r"IrisManager", 
            r"USE_FINGERPRINT",
            r"USE_BIOMETRIC",
            r"BIOMETRIC_WEAK",
            r"BIOMETRIC_STRONG",
            r"setInvalidatedByBiometricEnrollment\(true\)"
        ]
    
    def _initialize_key_lifecycle_patterns(self) -> List[str]:
        """Initialize patterns for key lifecycle management."""
        return [
            r"KeyLifecycle",
            r"KeyExpiry",
            r"KeyGeneration.*Timestamp",
            r"KeyValidityPeriod",
            r"KeyRetentionPolicy",
            r"KeyArchival",
            r"KeyDestruction",
            r"SecureKeyDeletion",
            r"KeyEscrow",
            r"KeyRecovery",
            r"KeyBackup",
            r"MasterKeyDerivation",
            r"KeyVersionControl",
            r"KeyAuditLog",
            r"KeyUsageTracking"
        ]

    # Enhanced analysis methods

    def analyze_hsm_integration(self, content: str, file_path: str) -> HSMIntegrationAssessment:
        """Analyze Hardware Security Module integration."""
        assessment = HSMIntegrationAssessment()
        
        try:
            # Detect HSM usage
            for pattern in self.hsm_patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    assessment.hsm_detected = True
                    context = self._extract_context(match, content, 100)
                    
                    # Identify HSM library/provider
                    if any(lib in pattern.lower() for lib in ['pkcs11', 'safenet', 'thales', 'luna', 'cavium']):
                        assessment.hsm_libraries.append(match.group())
                    
                    # Extract configuration details
                    if 'config' in pattern.lower() or 'library' in pattern.lower():
                        assessment.hsm_configurations.append(context)
            
            # Assess security level
            if assessment.hsm_detected:
                if any('strongbox' in lib.lower() or 'fips' in lib.lower() for lib in assessment.hsm_libraries):
                    assessment.security_level = "HIGH"
                elif assessment.hsm_libraries:
                    assessment.security_level = "MEDIUM"
                else:
                    assessment.security_level = "LOW"
                    assessment.vulnerabilities.append("HSM usage detected but security level unclear")
            
        except Exception as e:
            logger.error(f"Error analyzing HSM integration: {e}")
            assessment.vulnerabilities.append(f"Analysis error: {e}")
        
        return assessment
    
    def analyze_android_keystore_security(self, content: str, file_path: str) -> AndroidKeystoreAssessment:
        """Analyze Android Keystore security configuration."""
        assessment = AndroidKeystoreAssessment()
        
        try:
            for pattern in self.android_keystore_patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    assessment.keystore_usage = True
                    match_text = match.group().lower()
                    
                    # Check for hardware backing
                    if 'strongbox' in match_text:
                        assessment.strongbox_usage = True
                        assessment.hardware_backed = True
                    elif 'hardware' in match_text:
                        assessment.hardware_backed = True
                    
                    # Check for attestation
                    if 'attestation' in match_text:
                        assessment.attestation_enabled = True
                    
                    # Check for user authentication requirements
                    if 'userauthentication' in match_text or 'biometric' in match_text:
                        assessment.user_authentication_required = True
                        if 'biometric' in match_text:
                            assessment.biometric_protection = True
            
            # Assess security vulnerabilities
            if assessment.keystore_usage:
                if not assessment.hardware_backed:
                    assessment.security_vulnerabilities.append("Software-only keystore usage (not hardware-backed)")
                if not assessment.user_authentication_required:
                    assessment.security_vulnerabilities.append("No user authentication required for key access")
                if not assessment.attestation_enabled:
                    assessment.security_vulnerabilities.append("Key attestation not enabled")
                    
        except Exception as e:
            logger.error(f"Error analyzing Android Keystore: {e}")
            assessment.security_vulnerabilities.append(f"Analysis error: {e}")
        
        return assessment
    
    def analyze_key_rotation_mechanisms(self, content: str, file_path: str) -> KeyRotationAssessment:
        """Analyze key rotation mechanisms."""
        assessment = KeyRotationAssessment()
        
        try:
            for pattern in self.key_rotation_patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    assessment.rotation_detected = True
                    context = self._extract_context(match, content, 150)
                    assessment.rotation_mechanisms.append(match.group())
                    
                    # Analyze rotation frequency and automation
                    if any(word in context.lower() for word in ['periodic', 'scheduled', 'automatic']):
                        assessment.automated_rotation = True
                    
                    # Extract frequency indicators
                    frequency_patterns = [
                        r'(\d+)\s*(day|week|month|year)s?',
                        r'(daily|weekly|monthly|yearly)',
                        r'(\d+)\s*(hour|minute)s?'
                    ]
                    for freq_pattern in frequency_patterns:
                        freq_match = re.search(freq_pattern, context, re.IGNORECASE)
                        if freq_match:
                            assessment.rotation_frequency = freq_match.group()
                            break
            
            # Assess rotation security
            if assessment.rotation_detected:
                if not assessment.automated_rotation:
                    assessment.rotation_vulnerabilities.append("Manual key rotation detected (should be automated)")
                if assessment.rotation_frequency == "UNKNOWN":
                    assessment.rotation_vulnerabilities.append("Key rotation frequency not specified")
                    
        except Exception as e:
            logger.error(f"Error analyzing key rotation: {e}")
            assessment.rotation_vulnerabilities.append(f"Analysis error: {e}")
        
        return assessment
    
    def analyze_biometric_key_protection(self, content: str, file_path: str) -> List[KeyManagementFinding]:
        """Analyze biometric key protection implementation."""
        findings = []
        
        try:
            biometric_usage = False
            strong_biometric = False
            proper_crypto_integration = False
            
            for pattern in self.biometric_patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    biometric_usage = True
                    context = self._extract_context(match, content, 200)
                    
                    # Check for strong biometric authentication
                    if 'biometric_strong' in match.group().lower():
                        strong_biometric = True
                    
                    # Check for proper crypto integration
                    if 'cryptoobject' in match.group().lower():
                        proper_crypto_integration = True
            
            # Generate findings based on analysis
            if biometric_usage:
                if not strong_biometric:
                    findings.append(KeyManagementFinding(
                        finding_id="WEAK_BIOMETRIC_AUTH",
                        title="Weak Biometric Authentication",
                        description="Application uses biometric authentication but may allow weak biometric methods",
                        severity="MEDIUM",
                        location=file_path,
                        evidence="Biometric usage detected without BIOMETRIC_STRONG requirement",
                        recommendations=[
                            "Use BIOMETRIC_STRONG authentication class",
                            "Implement proper fallback authentication",
                            "Validate biometric enrollment status"
                        ],
                        cwe_mapping=["CWE-287", "CWE-308"]
                    ))
                
                if not proper_crypto_integration:
                    findings.append(KeyManagementFinding(
                        finding_id="IMPROPER_BIOMETRIC_CRYPTO",
                        title="Improper Biometric-Crypto Integration",
                        description="Biometric authentication not properly integrated with cryptographic operations",
                        severity="HIGH",
                        location=file_path,
                        evidence="Biometric usage without CryptoObject integration",
                        recommendations=[
                            "Use BiometricPrompt.CryptoObject for key operations",
                            "Bind keys to biometric authentication",
                            "Implement proper key invalidation on biometric changes"
                        ],
                        cwe_mapping=["CWE-287", "CWE-320"]
                    ))
                    
        except Exception as e:
            logger.error(f"Error analyzing biometric protection: {e}")
        
        return findings
    
    def analyze_key_lifecycle_management(self, content: str, file_path: str) -> List[KeyManagementFinding]:
        """Analyze key lifecycle management practices."""
        findings = []
        
        try:
            lifecycle_features = {
                'expiry': False,
                'rotation': False,
                'archival': False,
                'destruction': False,
                'backup': False,
                'audit': False
            }
            
            for pattern in self.key_lifecycle_patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    match_text = match.group().lower()
                    
                    # Categorize lifecycle features
                    if any(keyword in match_text for keyword in ['expiry', 'validity', 'retention']):
                        lifecycle_features['expiry'] = True
                    elif any(keyword in match_text for keyword in ['rotation', 'migrate']):
                        lifecycle_features['rotation'] = True
                    elif any(keyword in match_text for keyword in ['archival', 'backup']):
                        lifecycle_features['archival'] = True
                        lifecycle_features['backup'] = True
                    elif any(keyword in match_text for keyword in ['destruction', 'deletion']):
                        lifecycle_features['destruction'] = True
                    elif any(keyword in match_text for keyword in ['audit', 'tracking']):
                        lifecycle_features['audit'] = True
            
            # Generate findings for missing lifecycle features
            missing_features = [feature for feature, implemented in lifecycle_features.items() if not implemented]
            
            if missing_features:
                findings.append(KeyManagementFinding(
                    finding_id="INCOMPLETE_KEY_LIFECYCLE",
                    title="Incomplete Key Lifecycle Management",
                    description=f"Key lifecycle management missing: {', '.join(missing_features)}",
                    severity="MEDIUM",
                    location=file_path,
                    evidence=f"Missing lifecycle features: {missing_features}",
                    recommendations=[
                        "Implement comprehensive key lifecycle management",
                        "Define key expiration and rotation policies",
                        "Implement secure key destruction procedures",
                        "Add key usage auditing and tracking"
                    ],
                    cwe_mapping=["CWE-320", "CWE-522"]
                ))
                
        except Exception as e:
            logger.error(f"Error analyzing key lifecycle: {e}")
        
        return findings

    # Original methods (updated signatures to maintain compatibility)
    
    def analyze_key_generation(self, content: str, file_path: str) -> List[KeyManagementFinding]:
        """Analyze key generation practices."""
        findings = []
        
        for pattern in self.key_generation_patterns:
            matches = re.finditer(pattern, content)
            for match in matches:
                finding = self._analyze_key_generation_match(match, content, file_path)
                if finding:
                    findings.append(finding)
        
        return findings
    
    def analyze_hardcoded_keys(self, content: str, file_path: str) -> List[KeyManagementFinding]:
        """Analyze for hardcoded cryptographic keys."""
        findings = []
        
        for pattern in self.hardcoded_key_patterns:
            matches = re.finditer(pattern, content)
            for match in matches:
                if self._is_hardcoded_key(match, content):
                    finding = self._create_hardcoded_key_finding(match, content, file_path)
                    findings.append(finding)
        
        return findings
    
    def analyze_key_storage(self, content: str, file_path: str) -> List[KeyManagementFinding]:
        """Analyze key storage practices."""
        findings = []
        
        for pattern in self.key_storage_patterns:
            matches = re.finditer(pattern, content)
            for match in matches:
                finding = self._analyze_key_storage_match(match, content, file_path)
                if finding:
                    findings.append(finding)
        
        return findings
    
    def _analyze_key_generation_match(self, match: re.Match, content: str, file_path: str) -> Optional[KeyManagementFinding]:
        """Analyze a key generation match."""
        context = self._extract_context(match, content)
        
        # Basic analysis for secure key generation
        if "SecureRandom" not in context and "getInstance" in match.group():
            return KeyManagementFinding(
                finding_id="WEAK_KEY_GENERATION",
                title="Potentially Weak Key Generation",
                description="Key generation may not use cryptographically secure random number generator",
                severity="HIGH",
                location=file_path,
                evidence=match.group(),
                recommendations=["Use SecureRandom for key generation", "Verify randomness source"],
                cwe_mapping=["CWE-330", "CWE-338"]
            )
        
        return None
    
    def _is_hardcoded_key(self, match: re.Match, context: str) -> bool:
        """Check if a match represents a hardcoded key."""
        key_candidate = match.group().strip('"\'')
        
        # Basic heuristics for hardcoded keys
        if len(key_candidate) < 16:  # Too short to be a meaningful key
            return False
        
        # Check for base64 patterns
        if re.match(r'^[A-Za-z0-9+/]+=*$', key_candidate) and len(key_candidate) >= 32:
            return True
        
        # Check for hex patterns
        if re.match(r'^[A-Fa-f0-9]+$', key_candidate) and len(key_candidate) >= 32:
            return True
        
        # Check for PEM format
        if key_candidate.startswith('MII') or 'BEGIN' in key_candidate:
            return True
        
        return False
    
    def _create_hardcoded_key_finding(self, match: re.Match, content: str, file_path: str) -> KeyManagementFinding:
        """Create a finding for hardcoded key."""
        return KeyManagementFinding(
            finding_id="HARDCODED_KEY",
            title="Hardcoded Cryptographic Key",
            description="Cryptographic key appears to be hardcoded in the application",
            severity="CRITICAL",
            location=file_path,
            evidence=match.group()[:50] + "..." if len(match.group()) > 50 else match.group(),
            recommendations=[
                "Remove hardcoded keys from source code",
                "Use secure key storage mechanisms",
                "Implement proper key management"
            ],
            cwe_mapping=["CWE-798", "CWE-321"]
        )
    
    def _analyze_key_storage_match(self, match: re.Match, content: str, file_path: str) -> Optional[KeyManagementFinding]:
        """Analyze a key storage match."""
        context = self._extract_context(match, content)
        
        # Check for insecure storage
        if "SharedPreferences" in match.group() and "MODE_PRIVATE" not in context:
            return KeyManagementFinding(
                finding_id="INSECURE_KEY_STORAGE",
                title="Insecure Key Storage",
                description="Cryptographic keys may be stored insecurely",
                severity="HIGH",
                location=file_path,
                evidence=match.group(),
                recommendations=[
                    "Use Android Keystore for key storage",
                    "Encrypt keys before storage",
                    "Use appropriate file permissions"
                ],
                cwe_mapping=["CWE-312", "CWE-922"]
            )
        
        return None
    
    def _extract_context(self, match: re.Match, content: str, context_size: int = 200) -> str:
        """Extract context around a match."""
        start = max(0, match.start() - context_size // 2)
        end = min(len(content), match.end() + context_size // 2)
        return content[start:end]
    
    def analyze_key_management(self, content: str, file_path: str) -> List[KeyManagementFinding]:
        """Comprehensive key management analysis."""
        findings = []
        
        # Original analyses
        findings.extend(self.analyze_key_generation(content, file_path))
        findings.extend(self.analyze_hardcoded_keys(content, file_path))
        findings.extend(self.analyze_key_storage(content, file_path))
        
        # Enhanced analyses
        findings.extend(self.analyze_biometric_key_protection(content, file_path))
        findings.extend(self.analyze_key_lifecycle_management(content, file_path))
        
        # Store assessments for reporting
        self.hsm_assessment = self.analyze_hsm_integration(content, file_path)
        self.keystore_assessment = self.analyze_android_keystore_security(content, file_path)
        self.rotation_assessment = self.analyze_key_rotation_mechanisms(content, file_path)
        
        return findings
    
    def get_secure_key_generation_patterns(self) -> List[str]:
        """Get patterns for secure key generation."""
        return [
            r"KeyPairGenerator\.getInstance\([\"']EC[\"']\)",
            r"KeyGenerator\.getInstance\([\"']AES[\"']\)",
            r"SecretKeyFactory\.getInstance\([\"']PBKDF2WithHmacSHA256[\"']\)",
            r"SecureRandom\.getInstanceStrong\(\)"
        ]
    
    def validate_key_strength(self, algorithm: str, key_size: int) -> Dict[str, Any]:
        """Validate cryptographic key strength."""
        validation = {
            "algorithm": algorithm,
            "key_size": key_size,
            "is_secure": False,
            "recommendations": []
        }
        
        # Algorithm-specific validation
        if algorithm.upper() == "RSA":
            validation["is_secure"] = key_size >= 2048
            if key_size < 2048:
                validation["recommendations"].append("Use at least 2048-bit RSA keys")
        elif algorithm.upper() == "AES":
            validation["is_secure"] = key_size >= 128
            if key_size < 128:
                validation["recommendations"].append("Use at least 128-bit AES keys")
        elif algorithm.upper() in ["EC", "ECDSA", "ECDH"]:
            validation["is_secure"] = key_size >= 256
            if key_size < 256:
                validation["recommendations"].append("Use at least 256-bit elliptic curve keys")
        
        return validation 
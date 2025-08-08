#!/usr/bin/env python3
"""
Runtime Vulnerability Detector

Advanced vulnerability detection engine that analyzes runtime hook data
to identify security issues during actual application execution.

Author: AODS Team
Date: January 2025
"""

import logging
import re
import json
import time
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
import yaml

try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False

# Import enhanced detector capabilities
try:
    from .enhanced_runtime_detector import (
        EnhancedRuntimeVulnerabilityDetector, 
        EnhancedVulnerability, 
        EnhancedVulnerabilityType
    )
    ENHANCED_DETECTOR_AVAILABLE = True
except ImportError:
    logging.warning("Enhanced runtime detector not available")
    ENHANCED_DETECTOR_AVAILABLE = False


class VulnerabilityType(Enum):
    """Types of runtime vulnerabilities."""
    WEAK_CRYPTOGRAPHY = "WEAK_CRYPTOGRAPHY"
    INSECURE_NETWORK = "INSECURE_NETWORK"
    INSECURE_STORAGE = "INSECURE_STORAGE"
    AUTHENTICATION_BYPASS = "AUTHENTICATION_BYPASS"
    DATA_LEAKAGE = "DATA_LEAKAGE"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    CODE_INJECTION = "CODE_INJECTION"
    BEHAVIORAL_ANOMALY = "BEHAVIORAL_ANOMALY"


class Severity(Enum):
    """Vulnerability severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class RuntimeVulnerability:
    """Runtime vulnerability detection result."""
    vulnerability_type: VulnerabilityType
    title: str
    description: str
    severity: Severity
    confidence: float
    cwe_id: str
    masvs_control: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    runtime_context: Dict[str, Any] = field(default_factory=dict)
    call_stack: List[str] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)
    affected_apis: List[str] = field(default_factory=list)
    remediation: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            'vulnerability_type': self.vulnerability_type.value,
            'title': self.title,
            'description': self.description,
            'severity': self.severity.value,
            'confidence': self.confidence,
            'cwe_id': self.cwe_id,
            'masvs_control': self.masvs_control,
            'evidence': self.evidence,
            'runtime_context': self.runtime_context,
            'call_stack': self.call_stack,
            'timestamp': self.timestamp,
            'affected_apis': self.affected_apis,
            'remediation': self.remediation,
            'source': 'runtime_dynamic_analysis'
        }


@dataclass
class VulnerabilityPattern:
    """Pattern for detecting vulnerabilities."""
    pattern_id: str
    name: str
    description: str
    vulnerability_type: VulnerabilityType
    severity: Severity
    cwe_id: str
    masvs_control: str
    pattern_regex: str
    detection_logic: str
    confidence_base: float
    remediation: str
    examples: List[str] = field(default_factory=list)


class RuntimeVulnerabilityDetector:
    """
    Advanced vulnerability detection engine for runtime analysis.
    
    This engine analyzes runtime hook data to identify security vulnerabilities
    during actual application execution with high accuracy and low false positives.
    """
    
    def __init__(self, patterns_dir: Optional[Path] = None):
        """
        Initialize the runtime vulnerability detector.
        
        Args:
            patterns_dir: Directory containing vulnerability patterns (optional)
        """
        self.logger = logging.getLogger(f"{__name__}.RuntimeVulnerabilityDetector")
        
        # Vulnerability detection state
        self.vulnerabilities = []
        self.patterns = {}
        self.detection_stats = {
            'total_events_analyzed': 0,
            'vulnerabilities_detected': 0,
            'false_positive_rate': 0.0,
            'detection_accuracy': 0.0
        }
        
        # Pattern directories
        self.patterns_dir = patterns_dir or Path(__file__).parent.parent / "patterns"
        
        # Runtime analysis context
        self.runtime_context = {
            'start_time': time.time(),
            'analyzed_apis': set(),
            'detection_timeline': [],
            'behavioral_patterns': {}
        }
        
        # Load vulnerability patterns
        self._load_vulnerability_patterns()
        
        # Initialize behavioral analysis
        self._initialize_behavioral_analysis()
        
        # Initialize enhanced detector for advanced capabilities
        self.enhanced_detector = None
        if ENHANCED_DETECTOR_AVAILABLE:
            try:
                self.enhanced_detector = EnhancedRuntimeVulnerabilityDetector()
                self.logger.info("✅ Enhanced runtime detector initialized")
            except Exception as e:
                self.logger.warning(f"⚠️ Failed to initialize enhanced detector: {e}")
        
        self.logger.info(f"🚀 RuntimeVulnerabilityDetector initialized with {len(self.patterns)} patterns")
    
    def analyze_hook_data(self, hook_data: Dict[str, Any]) -> List[RuntimeVulnerability]:
        """
        Analyze runtime hook data for vulnerabilities.
        
        Args:
            hook_data: Data from runtime hooks
            
        Returns:
            List of detected vulnerabilities
        """
        detected_vulnerabilities = []
        
        try:
            self.detection_stats['total_events_analyzed'] += 1
            
            # Extract event type and data
            event_type = hook_data.get('type', '')
            timestamp = hook_data.get('timestamp', time.time())
            
            self.logger.debug(f"🔍 Analyzing hook data: {event_type}")
            
            # Analyze based on event type
            if event_type == 'crypto_vulnerability':
                vulnerabilities = self.detect_crypto_weaknesses([hook_data])
                detected_vulnerabilities.extend(vulnerabilities)
            
            elif event_type == 'network_communication':
                vulnerabilities = self.detect_network_issues([hook_data])
                detected_vulnerabilities.extend(vulnerabilities)
            
            elif event_type in ['file_access', 'shared_preferences', 'database_access']:
                vulnerabilities = self.detect_storage_issues([hook_data])
                detected_vulnerabilities.extend(vulnerabilities)
            
            elif event_type == 'network_security':
                vulnerabilities = self.detect_authentication_issues([hook_data])
                detected_vulnerabilities.extend(vulnerabilities)
            
            elif event_type == 'insecure_logging_vulnerability':
                vulnerabilities = self.detect_logging_issues([hook_data])
                detected_vulnerabilities.extend(vulnerabilities)
            
            elif event_type == 'shared_preferences_vulnerability':
                vulnerabilities = self.detect_shared_preferences_issues([hook_data])
                detected_vulnerabilities.extend(vulnerabilities)
            
            elif event_type == 'keyboard_cache_vulnerability':
                vulnerabilities = self.detect_keyboard_cache_issues([hook_data])
                detected_vulnerabilities.extend(vulnerabilities)
            
            elif event_type == 'certificate_pinning_vulnerability':
                vulnerabilities = self.detect_certificate_pinning_issues([hook_data])
                detected_vulnerabilities.extend(vulnerabilities)
            
            # Behavioral analysis (cross-event patterns)
            self._update_behavioral_analysis(hook_data)
            behavioral_vulnerabilities = self._detect_behavioral_anomalies()
            detected_vulnerabilities.extend(behavioral_vulnerabilities)
            
            # Update detection statistics
            self.detection_stats['vulnerabilities_detected'] += len(detected_vulnerabilities)
            
            # Store vulnerabilities
            self.vulnerabilities.extend(detected_vulnerabilities)
            
            # Update timeline
            self.runtime_context['detection_timeline'].append({
                'timestamp': timestamp,
                'event_type': event_type,
                'vulnerabilities_found': len(detected_vulnerabilities)
            })
            
            if detected_vulnerabilities:
                self.logger.warning(f"🚨 Detected {len(detected_vulnerabilities)} vulnerabilities from {event_type} event")
            
            # Use enhanced detector for advanced analysis if available
            if self.enhanced_detector and isinstance(hook_data, list):
                try:
                    enhanced_vulns = self.enhanced_detector.analyze_all_enhanced_findings(hook_data)
                    # Convert enhanced vulnerabilities to runtime vulnerabilities
                    for enhanced_vuln in enhanced_vulns:
                        runtime_vuln = self._convert_enhanced_to_runtime_vulnerability(enhanced_vuln)
                        if runtime_vuln:
                            detected_vulnerabilities.append(runtime_vuln)
                except Exception as e:
                    self.logger.error(f"Enhanced analysis error: {e}")
            
            return detected_vulnerabilities
            
        except Exception as e:
            self.logger.error(f"❌ Error analyzing hook data: {e}")
            return []
    
    def detect_crypto_weaknesses(self, crypto_calls: List[Dict[str, Any]]) -> List[RuntimeVulnerability]:
        """
        Detect weak cryptography during runtime.
        
        Args:
            crypto_calls: List of cryptographic API calls
            
        Returns:
            List of crypto-related vulnerabilities
        """
        vulnerabilities = []
        
        try:
            for call_data in crypto_calls:
                algorithm = call_data.get('algorithm', '').upper()
                method = call_data.get('method', '')
                transformation = call_data.get('transformation', '')
                stack_trace = call_data.get('stack_trace', '')
                
                # Check for weak hash algorithms
                if algorithm in ['MD5', 'SHA1']:
                    vulnerability = RuntimeVulnerability(
                        vulnerability_type=VulnerabilityType.WEAK_CRYPTOGRAPHY,
                        title=f'Weak Cryptographic Algorithm: {algorithm}',
                        description=f'Application uses cryptographically weak {algorithm} algorithm during runtime execution',
                        severity=Severity.HIGH,
                        confidence=0.95,
                        cwe_id='CWE-327',
                        masvs_control='MASVS-CRYPTO-1',
                        evidence={
                            'algorithm': algorithm,
                            'method': method,
                            'transformation': transformation,
                            'detection_method': 'runtime_crypto_monitoring'
                        },
                        runtime_context={
                            'timestamp': call_data.get('timestamp'),
                            'thread': call_data.get('thread'),
                            'hook_name': call_data.get('hook_name')
                        },
                        call_stack=stack_trace.split('\n') if stack_trace else [],
                        affected_apis=[method],
                        remediation=f'Replace {algorithm} with SHA-256 or stronger cryptographic algorithms'
                    )
                    vulnerabilities.append(vulnerability)
                
                # Check for weak encryption algorithms
                elif algorithm in ['DES', '3DES', 'RC4']:
                    vulnerability = RuntimeVulnerability(
                        vulnerability_type=VulnerabilityType.WEAK_CRYPTOGRAPHY,
                        title=f'Weak Encryption Algorithm: {algorithm}',
                        description=f'Application uses weak {algorithm} encryption algorithm during runtime',
                        severity=Severity.HIGH,
                        confidence=0.9,
                        cwe_id='CWE-326',
                        masvs_control='MASVS-CRYPTO-2',
                        evidence={
                            'algorithm': algorithm,
                            'method': method,
                            'transformation': transformation
                        },
                        runtime_context={
                            'timestamp': call_data.get('timestamp'),
                            'thread': call_data.get('thread')
                        },
                        call_stack=stack_trace.split('\n') if stack_trace else [],
                        affected_apis=[method],
                        remediation=f'Replace {algorithm} with AES-256 or other strong encryption algorithms'
                    )
                    vulnerabilities.append(vulnerability)
                
                # Check for weak cipher modes
                if 'ECB' in transformation:
                    vulnerability = RuntimeVulnerability(
                        vulnerability_type=VulnerabilityType.WEAK_CRYPTOGRAPHY,
                        title='Weak Cipher Mode: ECB',
                        description='Application uses ECB cipher mode which is cryptographically weak',
                        severity=Severity.MEDIUM,
                        confidence=0.85,
                        cwe_id='CWE-327',
                        masvs_control='MASVS-CRYPTO-2',
                        evidence={
                            'transformation': transformation,
                            'cipher_mode': 'ECB'
                        },
                        runtime_context=call_data,
                        remediation='Use CBC, GCM, or other secure cipher modes instead of ECB'
                    )
                    vulnerabilities.append(vulnerability)
            
        except Exception as e:
            self.logger.error(f"❌ Error detecting crypto weaknesses: {e}")
        
        return vulnerabilities
    
    def detect_network_issues(self, network_calls: List[Dict[str, Any]]) -> List[RuntimeVulnerability]:
        """
        Detect insecure network communications.
        
        Args:
            network_calls: List of network API calls
            
        Returns:
            List of network-related vulnerabilities
        """
        vulnerabilities = []
        
        try:
            for call_data in network_calls:
                url = call_data.get('url', '')
                method = call_data.get('method', 'GET')
                is_https = call_data.get('is_https', True)
                library = call_data.get('library', 'Unknown')
                
                # Check for HTTP usage
                if not is_https and 'http://' in url.lower():
                    vulnerability = RuntimeVulnerability(
                        vulnerability_type=VulnerabilityType.INSECURE_NETWORK,
                        title='Insecure HTTP Communication',
                        description=f'Application makes unencrypted HTTP request during runtime: {url}',
                        severity=Severity.HIGH,
                        confidence=0.9,
                        cwe_id='CWE-319',
                        masvs_control='MASVS-NETWORK-1',
                        evidence={
                            'url': url,
                            'method': method,
                            'protocol': 'HTTP',
                            'library': library
                        },
                        runtime_context=call_data,
                        affected_apis=[call_data.get('method', 'unknown')],
                        remediation='Use HTTPS instead of HTTP for all network communications'
                    )
                    vulnerabilities.append(vulnerability)
                
                # Check for sensitive data in URLs
                if any(sensitive in url.lower() for sensitive in ['password', 'token', 'key', 'secret', 'api_key']):
                    vulnerability = RuntimeVulnerability(
                        vulnerability_type=VulnerabilityType.DATA_LEAKAGE,
                        title='Sensitive Data in URL',
                        description=f'Sensitive data detected in URL during runtime: {url[:100]}...',
                        severity=Severity.HIGH,
                        confidence=0.8,
                        cwe_id='CWE-200',
                        masvs_control='MASVS-NETWORK-1',
                        evidence={
                            'url': url,
                            'detected_sensitive_keywords': [word for word in ['password', 'token', 'key', 'secret', 'api_key'] if word in url.lower()]
                        },
                        runtime_context=call_data,
                        remediation='Move sensitive data from URL parameters to request body or headers'
                    )
                    vulnerabilities.append(vulnerability)
            
        except Exception as e:
            self.logger.error(f"❌ Error detecting network issues: {e}")
        
        return vulnerabilities
    
    def detect_storage_issues(self, storage_operations: List[Dict[str, Any]]) -> List[RuntimeVulnerability]:
        """
        Detect insecure storage operations.
        
        Args:
            storage_operations: List of storage API calls
            
        Returns:
            List of storage-related vulnerabilities
        """
        vulnerabilities = []
        
        try:
            for operation in storage_operations:
                operation_type = operation.get('operation', '')
                file_path = operation.get('file_path', '')
                key = operation.get('key', '')
                has_sensitive_data = operation.get('has_sensitive_data', False)
                
                # Check for sensitive file access
                if any(sensitive in file_path.lower() for sensitive in ['password', 'key', 'token', 'secret', 'credential']):
                    vulnerability = RuntimeVulnerability(
                        vulnerability_type=VulnerabilityType.INSECURE_STORAGE,
                        title='Sensitive File Access',
                        description=f'Application accesses potentially sensitive file during runtime: {file_path}',
                        severity=Severity.MEDIUM,
                        confidence=0.8,
                        cwe_id='CWE-200',
                        masvs_control='MASVS-STORAGE-1',
                        evidence={
                            'file_path': file_path,
                            'operation': operation_type,
                            'access_pattern': 'sensitive_file_access'
                        },
                        runtime_context=operation,
                        remediation='Ensure sensitive files are properly encrypted and access is restricted'
                    )
                    vulnerabilities.append(vulnerability)
                
                # Check for external storage usage
                if '/sdcard/' in file_path or '/external/' in file_path:
                    vulnerability = RuntimeVulnerability(
                        vulnerability_type=VulnerabilityType.INSECURE_STORAGE,
                        title='External Storage Usage',
                        description=f'Application uses external storage during runtime: {file_path}',
                        severity=Severity.MEDIUM,
                        confidence=0.7,
                        cwe_id='CWE-200',
                        masvs_control='MASVS-STORAGE-2',
                        evidence={
                            'file_path': file_path,
                            'storage_type': 'external'
                        },
                        runtime_context=operation,
                        remediation='Use internal storage for sensitive data or implement proper encryption for external storage'
                    )
                    vulnerabilities.append(vulnerability)
                
                # Check for sensitive SharedPreferences
                if has_sensitive_data and operation.get('type') == 'shared_preferences':
                    vulnerability = RuntimeVulnerability(
                        vulnerability_type=VulnerabilityType.INSECURE_STORAGE,
                        title='Sensitive Data in SharedPreferences',
                        description=f'Sensitive data stored in SharedPreferences during runtime: {key}',
                        severity=Severity.MEDIUM,
                        confidence=0.8,
                        cwe_id='CWE-200',
                        masvs_control='MASVS-STORAGE-1',
                        evidence={
                            'key': key,
                            'storage_type': 'shared_preferences',
                            'has_sensitive_data': True
                        },
                        runtime_context=operation,
                        remediation='Encrypt sensitive data before storing in SharedPreferences or use Android Keystore'
                    )
                    vulnerabilities.append(vulnerability)
            
        except Exception as e:
            self.logger.error(f"❌ Error detecting storage issues: {e}")
        
        return vulnerabilities
    
    def detect_authentication_issues(self, security_events: List[Dict[str, Any]]) -> List[RuntimeVulnerability]:
        """
        Detect authentication and authorization issues.
        
        Args:
            security_events: List of security-related events
            
        Returns:
            List of authentication-related vulnerabilities
        """
        vulnerabilities = []
        
        try:
            for event in security_events:
                operation = event.get('operation', '')
                
                # Check for certificate pinning bypass
                if operation == 'certificate_pinning_check':
                    vulnerability = RuntimeVulnerability(
                        vulnerability_type=VulnerabilityType.AUTHENTICATION_BYPASS,
                        title='Certificate Pinning Check Detected',
                        description='Application performs certificate pinning validation during runtime',
                        severity=Severity.INFO,
                        confidence=0.9,
                        cwe_id='CWE-295',
                        masvs_control='MASVS-NETWORK-3',
                        evidence={
                            'hostname': event.get('hostname'),
                            'certificate_count': event.get('certificate_count')
                        },
                        runtime_context=event,
                        remediation='Ensure certificate pinning is properly implemented and cannot be bypassed'
                    )
                    vulnerabilities.append(vulnerability)
                
                # Check for trust manager validation
                elif operation == 'server_trust_check':
                    vulnerability = RuntimeVulnerability(
                        vulnerability_type=VulnerabilityType.AUTHENTICATION_BYPASS,
                        title='Server Trust Validation',
                        description='Application validates server trust during runtime',
                        severity=Severity.INFO,
                        confidence=0.8,
                        cwe_id='CWE-295',
                        masvs_control='MASVS-NETWORK-3',
                        evidence={
                            'auth_type': event.get('auth_type'),
                            'chain_length': event.get('chain_length')
                        },
                        runtime_context=event,
                        remediation='Ensure proper certificate validation is implemented'
                    )
                    vulnerabilities.append(vulnerability)
            
        except Exception as e:
            self.logger.error(f"❌ Error detecting authentication issues: {e}")
        
        return vulnerabilities
    
    def detect_logging_issues(self, logging_events: List[Dict[str, Any]]) -> List[RuntimeVulnerability]:
        """
        Detect insecure logging vulnerabilities.
        
        Analyzes runtime logging events to identify sensitive data being
        logged in production applications.
        
        Args:
            logging_events: List of logging events from runtime hooks
            
        Returns:
            List of logging-related vulnerabilities
        """
        vulnerabilities = []
        
        try:
            for event in logging_events:
                log_level = event.get('log_level', 'UNKNOWN')
                message = event.get('message', '')
                tag = event.get('tag', '')
                framework = event.get('framework', 'Android Log')
                timestamp = event.get('timestamp', time.time())
                stack_trace = event.get('stack_trace', '')
                
                # Analyze message content for sensitive data
                sensitive_patterns_detected = []
                severity = Severity.MEDIUM
                
                # Use built-in sensitive data detection (YAML patterns loaded separately)
                # This ensures universal detection without depending on external pattern files
                builtin_patterns = [
                        (r'password|passwd|pwd|passphrase', 'password', Severity.HIGH),
                        (r'token|jwt|bearer|oauth|auth.*token', 'authentication_token', Severity.HIGH),
                        (r'secret|api.*key|private.*key', 'secret_key', Severity.HIGH),
                        (r'credit.*card|debit.*card|ssn|social.*security', 'financial_pii', Severity.HIGH),
                        (r'session|cookie|credential', 'session_data', Severity.HIGH),
                        (r'email|phone|address|location', 'personal_info', Severity.MEDIUM),
                        (r'device.*id|imei|android.*id', 'device_identifier', Severity.MEDIUM)
                ]
                
                for pattern, category, pattern_severity in builtin_patterns:
                    if re.search(pattern, message, re.IGNORECASE) or re.search(pattern, tag, re.IGNORECASE):
                        sensitive_patterns_detected.append({
                            'pattern': pattern,
                            'category': category,
                            'severity': pattern_severity.value
                        })
                        if pattern_severity.value == 'HIGH':
                            severity = Severity.HIGH
                
                # Create vulnerability if sensitive data detected
                if sensitive_patterns_detected:
                    # Calculate confidence based on patterns detected
                    confidence = min(0.95, 0.7 + (len(sensitive_patterns_detected) * 0.1))
                    
                    # Determine MASVS control based on content
                    masvs_control = 'MASVS-CODE-8'  # Default for logging
                    if any('password' in p.get('category', '') or 'token' in p.get('category', '') 
                           for p in sensitive_patterns_detected):
                        masvs_control = 'MASVS-AUTH-1'
                    elif any('financial' in p.get('category', '') or 'pii' in p.get('category', '') 
                             for p in sensitive_patterns_detected):
                        masvs_control = 'MASVS-STORAGE-1'
                    
                    vulnerability = RuntimeVulnerability(
                        vulnerability_type=VulnerabilityType.DATA_LEAKAGE,
                        title=f'Insecure Logging - {log_level}',
                        description=f'Sensitive data detected in application logs ({framework}): {message[:100]}...',
                        severity=severity,
                        confidence=confidence,
                        cwe_id='CWE-532',
                        masvs_control=masvs_control,
                        evidence={
                            'log_level': log_level,
                            'log_message': message[:200],  # Limit message length
                            'log_tag': tag,
                            'framework': framework,
                            'sensitive_patterns': [p.get('category', p.get('pattern', '')) 
                                                 for p in sensitive_patterns_detected],
                            'stack_trace': stack_trace[:500] if stack_trace else None
                        },
                        runtime_context=event,
                        remediation='Remove sensitive data from application logs in production builds'
                    )
                    vulnerabilities.append(vulnerability)
                    
                    self.logger.info(f"🚨 Insecure logging detected: {len(sensitive_patterns_detected)} patterns matched in {framework}")
                
        except Exception as e:
            self.logger.error(f"❌ Error detecting logging issues: {e}")
        
        return vulnerabilities
    
    def detect_shared_preferences_issues(self, shared_prefs_events: List[Dict[str, Any]]) -> List[RuntimeVulnerability]:
        """
        Detect SharedPreferences vulnerabilities.
        
        Analyzes runtime SharedPreferences events to identify:
        1. Sensitive data storage without encryption (Task 1.1)
        2. Insecure world-accessible modes (Task 1.2)
        
        Args:
            shared_prefs_events: List of SharedPreferences events from runtime hooks
            
        Returns:
            List of SharedPreferences-related vulnerabilities
        """
        vulnerabilities = []
        
        try:
            for event in shared_prefs_events:
                vulnerability_type = event.get('vulnerability_type', '')
                severity = event.get('severity', 'MEDIUM')
                timestamp = event.get('timestamp', time.time())
                stack_trace = event.get('stack_trace', '')
                
                if vulnerability_type == 'sensitive_data_storage':
                    # Task 1.1: Sensitive data stored without encryption
                    key = event.get('key', '')
                    value = event.get('value', '')
                    operation = event.get('evidence', {}).get('operation', 'unknown')
                    
                    # Calculate confidence based on evidence
                    evidence = event.get('evidence', {})
                    key_analysis = evidence.get('key_analysis', False)
                    value_analysis = evidence.get('value_analysis', False)
                    
                    confidence = 0.7
                    if key_analysis and value_analysis:
                        confidence = 0.95
                    elif key_analysis or value_analysis:
                        confidence = 0.85
                    
                    # Determine severity based on operation and content
                    vuln_severity = Severity.HIGH
                    if operation in ['putInt', 'putLong']:
                        vuln_severity = Severity.MEDIUM
                    elif operation == 'putBoolean':
                        vuln_severity = Severity.LOW
                    
                    vulnerability = RuntimeVulnerability(
                        vulnerability_type=VulnerabilityType.INSECURE_STORAGE,
                        title=f'Sensitive Data in SharedPreferences - {operation}',
                        description=f'Sensitive data stored in SharedPreferences without encryption: {key}',
                        severity=vuln_severity,
                        confidence=confidence,
                        cwe_id='CWE-200',
                        masvs_control='MASVS-STORAGE-1',
                        evidence={
                            'key': key,
                            'operation': operation,
                            'has_sensitive_key': key_analysis,
                            'has_sensitive_value': value_analysis,
                            'storage_type': 'shared_preferences',
                            'encryption_status': 'unencrypted',
                            'stack_trace': stack_trace[:500] if stack_trace else None
                        },
                        runtime_context=event,
                        remediation='Encrypt sensitive data before storing in SharedPreferences or use Android Keystore for secure storage'
                    )
                    vulnerabilities.append(vulnerability)
                    
                    self.logger.info(f"🚨 SharedPreferences sensitive data vulnerability detected: {key} ({operation})")
                
                elif vulnerability_type == 'insecure_mode':
                    # Task 1.2: World-accessible SharedPreferences
                    preference_name = event.get('preference_name', '')
                    mode = event.get('mode', 0)
                    mode_description = event.get('mode_description', 'UNKNOWN')
                    
                    # High confidence for clear mode violations
                    confidence = 0.95
                    
                    # Determine severity based on mode
                    vuln_severity = Severity.HIGH
                    if mode == 1:  # WORLD_READABLE
                        vuln_severity = Severity.HIGH
                    elif mode == 2:  # WORLD_WRITEABLE
                        vuln_severity = Severity.CRITICAL
                    elif (mode & 3) != 0:  # Any world access
                        vuln_severity = Severity.HIGH
                    
                    vulnerability = RuntimeVulnerability(
                        vulnerability_type=VulnerabilityType.PRIVILEGE_ESCALATION,
                        title=f'Insecure SharedPreferences Mode - {mode_description}',
                        description=f'SharedPreferences created with world-accessible mode: {preference_name}',
                        severity=vuln_severity,
                        confidence=confidence,
                        cwe_id='CWE-732',
                        masvs_control='MASVS-STORAGE-2',
                        evidence={
                            'preference_name': preference_name,
                            'mode': mode,
                            'mode_description': mode_description,
                            'access_level': 'world_accessible',
                            'security_risk': 'data_exposure_and_tampering',
                            'stack_trace': stack_trace[:500] if stack_trace else None
                        },
                        runtime_context=event,
                        remediation='Use Context.MODE_PRIVATE (0) for SharedPreferences to restrict access to the application only'
                    )
                    vulnerabilities.append(vulnerability)
                    
                    self.logger.info(f"🚨 SharedPreferences insecure mode vulnerability detected: {preference_name} ({mode_description})")
                
        except Exception as e:
            self.logger.error(f"❌ Error detecting SharedPreferences issues: {e}")
        
        return vulnerabilities
    
    def detect_keyboard_cache_issues(self, keyboard_cache_events: List[Dict[str, Any]]) -> List[RuntimeVulnerability]:
        """
        Detect keyboard cache vulnerabilities.
        
        Analyzes runtime keyboard/input events to identify:
        1. Sensitive fields allowing keyboard caching (Task 1.4)
        2. IME exposure of sensitive data
        
        Args:
            keyboard_cache_events: List of keyboard cache events from runtime hooks
            
        Returns:
            List of keyboard cache-related vulnerabilities
        """
        vulnerabilities = []
        
        try:
            for event in keyboard_cache_events:
                vulnerability_type = event.get('vulnerability_type', '')
                severity = event.get('severity', 'MEDIUM')
                timestamp = event.get('timestamp', time.time())
                stack_trace = event.get('stack_trace', '')
                view_info = event.get('view_info', {})
                
                if vulnerability_type == 'sensitive_field_caching':
                    # Task 1.4: Sensitive field allows keyboard caching
                    input_type = event.get('input_type', -1)
                    expected_input_type = event.get('expected_input_type', 'password_type_required')
                    is_sensitive_field = event.get('is_sensitive_field', False)
                    is_password_type = event.get('is_password_type', False)
                    
                    # Extract field identification details
                    evidence = event.get('evidence', {})
                    field_identification = evidence.get('field_identification', {})
                    input_type_analysis = evidence.get('input_type_analysis', {})
                    
                    # Calculate confidence based on field identification strength
                    confidence = 0.7
                    if field_identification.get('by_hint', False) and field_identification.get('by_id', False):
                        confidence = 0.95
                    elif field_identification.get('by_hint', False) or field_identification.get('by_id', False):
                        confidence = 0.85
                    elif field_identification.get('by_description', False):
                        confidence = 0.75
                    
                    # Determine severity based on field type and exposure
                    vuln_severity = Severity.HIGH  # Default for sensitive caching
                    if any('password' in str(v).lower() for v in view_info.values() if v):
                        vuln_severity = Severity.CRITICAL
                    elif any('pin' in str(v).lower() or 'code' in str(v).lower() for v in view_info.values() if v):
                        vuln_severity = Severity.HIGH
                    
                    # Build field description
                    field_desc = view_info.get('hint') or view_info.get('id') or view_info.get('contentDescription') or 'unknown field'
                    
                    vulnerability = RuntimeVulnerability(
                        vulnerability_type=VulnerabilityType.DATA_LEAKAGE,
                        title=f'Keyboard Cache Vulnerability - {field_desc}',
                        description=f'Sensitive input field allows keyboard caching: {field_desc}',
                        severity=vuln_severity,
                        confidence=confidence,
                        cwe_id='CWE-200',
                        masvs_control='MASVS-STORAGE-1',
                        evidence={
                            'field_info': view_info,
                            'input_type': input_type,
                            'expected_input_type': expected_input_type,
                            'allows_caching': input_type_analysis.get('allows_caching', True),
                            'field_identification_method': field_identification,
                            'cache_risk': 'high_sensitive_data_exposure',
                            'stack_trace': stack_trace[:500] if stack_trace else None
                        },
                        runtime_context=event,
                        remediation='Set appropriate InputType (e.g., TYPE_TEXT_VARIATION_PASSWORD) for sensitive input fields to prevent keyboard caching'
                    )
                    vulnerabilities.append(vulnerability)
                    
                    self.logger.info(f"🚨 Keyboard cache vulnerability detected: {field_desc} (input type: {input_type})")
                
                elif vulnerability_type == 'sensitive_ime_exposure':
                    # IME exposure of sensitive data
                    input_type = event.get('input_type', -1)
                    ime_flags = event.get('ime_flags', 0)
                    
                    # High confidence for IME exposure detection
                    confidence = 0.9
                    
                    # Critical severity for direct IME exposure
                    vuln_severity = Severity.HIGH
                    
                    field_desc = view_info.get('hint') or view_info.get('id') or view_info.get('contentDescription') or 'unknown field'
                    
                    vulnerability = RuntimeVulnerability(
                        vulnerability_type=VulnerabilityType.DATA_LEAKAGE,
                        title=f'Sensitive IME Exposure - {field_desc}',
                        description=f'Sensitive field exposed to Input Method Editor without protection: {field_desc}',
                        severity=vuln_severity,
                        confidence=confidence,
                        cwe_id='CWE-200',
                        masvs_control='MASVS-STORAGE-1',
                        evidence={
                            'field_info': view_info,
                            'input_type': input_type,
                            'ime_flags': ime_flags,
                            'exposure_type': 'ime_direct_access',
                            'protection_level': 'insufficient',
                            'data_at_risk': 'sensitive_user_input',
                            'stack_trace': stack_trace[:500] if stack_trace else None
                        },
                        runtime_context=event,
                        remediation='Configure sensitive input fields with proper InputType and IME options to prevent data exposure to keyboard applications'
                    )
                    vulnerabilities.append(vulnerability)
                    
                    self.logger.info(f"🚨 Sensitive IME exposure detected: {field_desc} (IME flags: {ime_flags})")
                
        except Exception as e:
            self.logger.error(f"❌ Error detecting keyboard cache issues: {e}")
        
        return vulnerabilities
    
    def detect_certificate_pinning_issues(self, cert_pinning_events: List[Dict[str, Any]]) -> List[RuntimeVulnerability]:
        """
        Detect certificate pinning vulnerabilities.
        
        Analyzes runtime certificate pinning events to identify:
        1. Weak certificate validation (no pinning)
        2. Hostname verification bypass
        3. Certificate pinning bypass attempts
        4. OkHttp pinning failures
        
        Args:
            cert_pinning_events: List of certificate pinning events from runtime hooks
            
        Returns:
            List of certificate pinning-related vulnerabilities
        """
        vulnerabilities = []
        
        try:
            for event in cert_pinning_events:
                vulnerability_type = event.get('vulnerability_type', '')
                severity = event.get('severity', 'MEDIUM')
                timestamp = event.get('timestamp', time.time())
                stack_trace = event.get('stack_trace', '')
                
                if vulnerability_type == 'weak_certificate_validation':
                    # No certificate pinning detected
                    trust_managers = event.get('trust_managers', [])
                    has_custom_pinning = event.get('has_custom_pinning', False)
                    
                    # Extract evidence details
                    evidence = event.get('evidence', {})
                    trust_manager_types = evidence.get('trust_manager_types', trust_managers)
                    validation_strength = evidence.get('validation_strength', 'default')
                    
                    # Calculate confidence based on trust manager analysis
                    confidence = 0.8
                    if len(trust_manager_types) > 0:
                        # High confidence when we can analyze trust managers
                        confidence = 0.9
                    
                    # Determine severity based on trust manager types
                    vuln_severity = Severity.MEDIUM  # Default for weak validation
                    if any('default' in tm.lower() or 'system' in tm.lower() for tm in trust_manager_types):
                        vuln_severity = Severity.HIGH
                    
                    vulnerability = RuntimeVulnerability(
                        vulnerability_type=VulnerabilityType.INSECURE_NETWORK,
                        title=f'Weak Certificate Validation - No Pinning',
                        description=f'SSL context uses default trust managers without certificate pinning',
                        severity=vuln_severity,
                        confidence=confidence,
                        cwe_id='CWE-295',
                        masvs_control='MASVS-NETWORK-3',
                        evidence={
                            'trust_managers': trust_manager_types,
                            'has_custom_pinning': has_custom_pinning,
                            'validation_strength': validation_strength,
                            'pinning_detected': False,
                            'mitm_risk': 'high_without_pinning',
                            'stack_trace': stack_trace[:500] if stack_trace else None
                        },
                        runtime_context=event,
                        remediation='Implement certificate pinning using TrustManager customization, OkHttp CertificatePinner, or Network Security Config'
                    )
                    vulnerabilities.append(vulnerability)
                    
                    self.logger.info(f"🚨 Weak certificate validation detected: {len(trust_manager_types)} default trust managers")
                
                elif vulnerability_type == 'hostname_verification_bypass':
                    # Hostname verification bypassed
                    hostname_verifier = event.get('hostname_verifier', 'unknown')
                    
                    # Extract evidence details
                    evidence = event.get('evidence', {})
                    verifier_class = evidence.get('verifier_class', hostname_verifier)
                    bypass_detected = evidence.get('bypass_detected', True)
                    
                    # High confidence for hostname bypass detection
                    confidence = 0.95
                    
                    # High severity for hostname bypass
                    vuln_severity = Severity.HIGH
                    
                    vulnerability = RuntimeVulnerability(
                        vulnerability_type=VulnerabilityType.AUTHENTICATION_BYPASS,
                        title=f'Hostname Verification Bypass',
                        description=f'Hostname verification bypassed with permissive verifier: {verifier_class}',
                        severity=vuln_severity,
                        confidence=confidence,
                        cwe_id='CWE-295',
                        masvs_control='MASVS-NETWORK-3',
                        evidence={
                            'hostname_verifier': verifier_class,
                            'bypass_detected': bypass_detected,
                            'security_risk': 'mitm_vulnerability',
                            'verification_status': 'bypassed',
                            'stack_trace': stack_trace[:500] if stack_trace else None
                        },
                        runtime_context=event,
                        remediation='Use proper hostname verification instead of bypassing with AllowAllHostnameVerifier or similar'
                    )
                    vulnerabilities.append(vulnerability)
                    
                    self.logger.info(f"🚨 Hostname verification bypass detected: {verifier_class}")
                
                elif vulnerability_type == 'certificate_pinning_failure':
                    # Certificate pinning validation failed
                    hostname = event.get('hostname', 'unknown')
                    certificate_count = event.get('certificate_count', 0)
                    pinning_library = event.get('pinning_library', 'unknown')
                    
                    # Extract evidence details
                    evidence = event.get('evidence', {})
                    failure_reason = evidence.get('failure_reason', 'unknown')
                    pinning_enforced = evidence.get('pinning_enforced', True)
                    
                    # High confidence for pinning failure detection
                    confidence = 0.95
                    
                    # Note: This is actually good security behavior (pinning working)
                    # but we log it as info for forensic purposes
                    vuln_severity = Severity.INFO
                    
                    vulnerability = RuntimeVulnerability(
                        vulnerability_type=VulnerabilityType.AUTHENTICATION_BYPASS,
                        title=f'Certificate Pinning Failure - {hostname}',
                        description=f'Certificate pinning validation failed for {hostname} using {pinning_library}',
                        severity=vuln_severity,
                        confidence=confidence,
                        cwe_id='CWE-295',
                        masvs_control='MASVS-NETWORK-3',
                        evidence={
                            'hostname': hostname,
                            'certificate_count': certificate_count,
                            'pinning_library': pinning_library,
                            'failure_reason': failure_reason[:200] if failure_reason else None,
                            'pinning_enforced': pinning_enforced,
                            'security_status': 'pinning_working_correctly',
                            'stack_trace': stack_trace[:500] if stack_trace else None
                        },
                        runtime_context=event,
                        remediation='Certificate pinning is working correctly - this indicates proper security implementation'
                    )
                    vulnerabilities.append(vulnerability)
                    
                    self.logger.info(f"🚨 Certificate pinning failure (good security): {hostname} - {pinning_library}")
                
                elif vulnerability_type == 'pinning_bypass_detected':
                    # Suspicious certificate pinning bypass class detected
                    suspicious_class = event.get('suspicious_class', 'unknown')
                    
                    # Extract evidence details
                    evidence = event.get('evidence', {})
                    class_name = evidence.get('class_name', suspicious_class)
                    bypass_type = evidence.get('bypass_type', 'unknown')
                    
                    # High confidence for suspicious class detection
                    confidence = 0.9
                    
                    # High severity for pinning bypass attempts
                    vuln_severity = Severity.HIGH
                    
                    vulnerability = RuntimeVulnerability(
                        vulnerability_type=VulnerabilityType.AUTHENTICATION_BYPASS,
                        title=f'Certificate Pinning Bypass Detected',
                        description=f'Suspicious certificate validation bypass class detected: {class_name}',
                        severity=vuln_severity,
                        confidence=confidence,
                        cwe_id='CWE-295',
                        masvs_control='MASVS-NETWORK-3',
                        evidence={
                            'suspicious_class': class_name,
                            'bypass_type': bypass_type,
                            'security_risk': 'certificate_validation_bypass',
                            'detection_method': 'class_enumeration',
                            'bypass_indication': 'class_naming_pattern',
                            'stack_trace': stack_trace[:500] if stack_trace else None
                        },
                        runtime_context=event,
                        remediation='Remove certificate pinning bypass code and implement proper certificate validation'
                    )
                    vulnerabilities.append(vulnerability)
                    
                    self.logger.info(f"🚨 Certificate pinning bypass detected: {class_name}")
                
        except Exception as e:
            self.logger.error(f"❌ Error detecting certificate pinning issues: {e}")
        
        return vulnerabilities
    
    def _load_vulnerability_patterns(self):
        """Load vulnerability patterns from configuration files."""
        try:
            # Load built-in patterns
            self._load_builtin_patterns()
            
            # Load external pattern files if available
            if self.patterns_dir.exists():
                for pattern_file in self.patterns_dir.glob("*.yaml"):
                    try:
                        with open(pattern_file, 'r') as f:
                            pattern_data = yaml.safe_load(f)
                            self._parse_pattern_file(pattern_data, pattern_file.name)
                    except Exception as e:
                        self.logger.warning(f"⚠️ Failed to load pattern file {pattern_file}: {e}")
            
            self.logger.info(f"✅ Loaded {len(self.patterns)} vulnerability patterns")
            
        except Exception as e:
            self.logger.error(f"❌ Error loading vulnerability patterns: {e}")
    
    def _load_builtin_patterns(self):
        """Load built-in vulnerability patterns."""
        # Crypto patterns
        self.patterns['md5_usage'] = VulnerabilityPattern(
            pattern_id='md5_usage',
            name='MD5 Hash Algorithm Usage',
            description='MD5 cryptographic hash algorithm detected during runtime',
            vulnerability_type=VulnerabilityType.WEAK_CRYPTOGRAPHY,
            severity=Severity.HIGH,
            cwe_id='CWE-327',
            masvs_control='MASVS-CRYPTO-1',
            pattern_regex=r'MD5',
            detection_logic='algorithm_match',
            confidence_base=0.95,
            remediation='Replace MD5 with SHA-256 or stronger cryptographic algorithms'
        )
        
        self.patterns['des_usage'] = VulnerabilityPattern(
            pattern_id='des_usage',
            name='DES Encryption Usage',
            description='DES encryption algorithm detected during runtime',
            vulnerability_type=VulnerabilityType.WEAK_CRYPTOGRAPHY,
            severity=Severity.HIGH,
            cwe_id='CWE-326',
            masvs_control='MASVS-CRYPTO-2',
            pattern_regex=r'DES',
            detection_logic='algorithm_match',
            confidence_base=0.9,
            remediation='Replace DES with AES-256 or other strong encryption algorithms'
        )
        
        # Network patterns
        self.patterns['http_usage'] = VulnerabilityPattern(
            pattern_id='http_usage',
            name='HTTP Communication',
            description='Unencrypted HTTP communication detected during runtime',
            vulnerability_type=VulnerabilityType.INSECURE_NETWORK,
            severity=Severity.HIGH,
            cwe_id='CWE-319',
            masvs_control='MASVS-NETWORK-1',
            pattern_regex=r'http://',
            detection_logic='url_match',
            confidence_base=0.9,
            remediation='Use HTTPS instead of HTTP for all network communications'
        )
    
    def _parse_pattern_file(self, pattern_data: Dict[str, Any], filename: str):
        """Parse external pattern file."""
        try:
            # Handle different YAML structures
            vulnerabilities_section = None
            
            # Look for vulnerability patterns in common sections
            for section_name in ['qr_code_vulnerabilities', 'vulnerabilities', 'patterns']:
                if section_name in pattern_data and isinstance(pattern_data[section_name], dict):
                    vulnerabilities_section = pattern_data[section_name]
                    break
            
            # If no nested structure, assume flat pattern structure
            if vulnerabilities_section is None:
                # Check if this looks like a flat pattern structure
                has_pattern_structure = any(
                    isinstance(value, dict) and 'pattern' in str(value).lower()
                    for value in pattern_data.values()
                    if isinstance(value, dict)
                )
                if has_pattern_structure:
                    vulnerabilities_section = pattern_data
                else:
                    self.logger.debug(f"ℹ️ No vulnerability patterns found in {filename}")
                    return
            
            # Parse vulnerability categories
            for category_name, category_data in vulnerabilities_section.items():
                if not isinstance(category_data, list):
                    continue
                
                # Process each pattern in the category
                for i, pattern_config in enumerate(category_data):
                    if not isinstance(pattern_config, dict):
                        continue
                    
                    pattern_id = f"{category_name}_{i}"
                    pattern = VulnerabilityPattern(
                        pattern_id=pattern_id,
                        name=pattern_config.get('name', pattern_config.get('description', pattern_id)),
                        description=pattern_config.get('description', ''),
                        vulnerability_type=VulnerabilityType.BEHAVIORAL_ANOMALY,  # Default for external patterns
                        severity=Severity(pattern_config.get('severity', 'MEDIUM')),
                        cwe_id=pattern_config.get('cwe_id', pattern_config.get('cwe', 'CWE-200')),
                        masvs_control=pattern_config.get('masvs_control', pattern_config.get('masvs', 'V1.1')),
                        pattern_regex=pattern_config.get('pattern', ''),
                        detection_logic=pattern_config.get('logic', 'regex_match'),
                        confidence_base=pattern_config.get('confidence', 0.5),
                        remediation=pattern_config.get('remediation', '')
                    )
                    self.patterns[pattern_id] = pattern
                
        except Exception as e:
            self.logger.error(f"❌ Error parsing pattern file {filename}: {e}")
            self.logger.debug(f"Pattern data structure: {list(pattern_data.keys()) if isinstance(pattern_data, dict) else type(pattern_data)}")
    
    def _initialize_behavioral_analysis(self):
        """Initialize behavioral analysis components."""
        self.behavioral_thresholds = {
            'crypto_call_frequency': 10,  # Threshold for suspicious crypto call frequency
            'network_request_rate': 50,   # Requests per minute threshold
            'file_access_pattern': 20,    # File access operations threshold
            'api_abuse_threshold': 100    # API abuse detection threshold
        }
        
        self.behavioral_counters = {
            'crypto_calls': 0,
            'network_requests': 0,
            'file_operations': 0,
            'api_calls': 0
        }
    
    def _update_behavioral_analysis(self, hook_data: Dict[str, Any]):
        """Update behavioral analysis with new hook data."""
        event_type = hook_data.get('type', '')
        
        # Update counters
        if event_type == 'crypto_vulnerability':
            self.behavioral_counters['crypto_calls'] += 1
        elif event_type == 'network_communication':
            self.behavioral_counters['network_requests'] += 1
        elif event_type in ['file_access', 'shared_preferences', 'database_access']:
            self.behavioral_counters['file_operations'] += 1
        
        self.behavioral_counters['api_calls'] += 1
        
        # Store behavioral patterns
        timestamp = hook_data.get('timestamp', time.time())
        if event_type not in self.runtime_context['behavioral_patterns']:
            self.runtime_context['behavioral_patterns'][event_type] = []
        
        self.runtime_context['behavioral_patterns'][event_type].append({
            'timestamp': timestamp,
            'data': hook_data
        })
    
    def _detect_behavioral_anomalies(self) -> List[RuntimeVulnerability]:
        """Detect behavioral anomalies based on runtime patterns."""
        vulnerabilities = []
        
        try:
            # Check for excessive crypto calls (possible crypto abuse)
            if self.behavioral_counters['crypto_calls'] > self.behavioral_thresholds['crypto_call_frequency']:
                vulnerability = RuntimeVulnerability(
                    vulnerability_type=VulnerabilityType.BEHAVIORAL_ANOMALY,
                    title='Excessive Cryptographic Operations',
                    description=f'Application makes excessive cryptographic calls ({self.behavioral_counters["crypto_calls"]}) during runtime',
                    severity=Severity.MEDIUM,
                    confidence=0.7,
                    cwe_id='CWE-405',
                    masvs_control='MASVS-CRYPTO-1',
                    evidence={
                        'crypto_call_count': self.behavioral_counters['crypto_calls'],
                        'threshold': self.behavioral_thresholds['crypto_call_frequency']
                    },
                    runtime_context={'analysis_type': 'behavioral'},
                    remediation='Review cryptographic operations for efficiency and necessity'
                )
                vulnerabilities.append(vulnerability)
            
            # Check for excessive network requests (possible data exfiltration)
            if self.behavioral_counters['network_requests'] > self.behavioral_thresholds['network_request_rate']:
                vulnerability = RuntimeVulnerability(
                    vulnerability_type=VulnerabilityType.BEHAVIORAL_ANOMALY,
                    title='Excessive Network Activity',
                    description=f'Application makes excessive network requests ({self.behavioral_counters["network_requests"]}) during runtime',
                    severity=Severity.MEDIUM,
                    confidence=0.6,
                    cwe_id='CWE-200',
                    masvs_control='MASVS-NETWORK-1',
                    evidence={
                        'network_request_count': self.behavioral_counters['network_requests'],
                        'threshold': self.behavioral_thresholds['network_request_rate']
                    },
                    runtime_context={'analysis_type': 'behavioral'},
                    remediation='Review network usage patterns and implement request throttling if necessary'
                )
                vulnerabilities.append(vulnerability)
            
        except Exception as e:
            self.logger.error(f"❌ Error detecting behavioral anomalies: {e}")
        
        return vulnerabilities
    
    def get_detection_summary(self) -> Dict[str, Any]:
        """Get summary of vulnerability detection results."""
        return {
            'total_vulnerabilities': len(self.vulnerabilities),
            'vulnerabilities_by_type': self._get_vulnerabilities_by_type(),
            'vulnerabilities_by_severity': self._get_vulnerabilities_by_severity(),
            'detection_stats': self.detection_stats,
            'runtime_context': self.runtime_context,
            'patterns_loaded': len(self.patterns)
        }
    
    def _get_vulnerabilities_by_type(self) -> Dict[str, int]:
        """Get count of vulnerabilities by type."""
        type_counts = {}
        for vuln in self.vulnerabilities:
            vuln_type = vuln.vulnerability_type.value
            type_counts[vuln_type] = type_counts.get(vuln_type, 0) + 1
        return type_counts
    
    def _get_vulnerabilities_by_severity(self) -> Dict[str, int]:
        """Get count of vulnerabilities by severity."""
        severity_counts = {}
        for vuln in self.vulnerabilities:
            severity = vuln.severity.value
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        return severity_counts
    
    def _convert_enhanced_to_runtime_vulnerability(self, enhanced_vuln) -> Optional[RuntimeVulnerability]:
        """Convert enhanced vulnerability to runtime vulnerability format."""
        try:
            if not ENHANCED_DETECTOR_AVAILABLE:
                return None
            
            # Map enhanced vulnerability types to runtime types
            type_mapping = {
                EnhancedVulnerabilityType.DATABASE_CONTENT_EXPOSURE: VulnerabilityType.DATA_LEAKAGE,
                EnhancedVulnerabilityType.SHARED_PREFERENCES_INSECURE: VulnerabilityType.INSECURE_STORAGE,
                EnhancedVulnerabilityType.SSL_PINNING_BYPASSABLE: VulnerabilityType.INSECURE_NETWORK,
                EnhancedVulnerabilityType.WEBVIEW_URL_REDIRECTION: VulnerabilityType.CODE_INJECTION,
                EnhancedVulnerabilityType.SENSITIVE_DATA_UNENCRYPTED: VulnerabilityType.DATA_LEAKAGE,
                EnhancedVulnerabilityType.INSECURE_STORAGE_MODE: VulnerabilityType.INSECURE_STORAGE,
                EnhancedVulnerabilityType.CERTIFICATE_VALIDATION_BYPASS: VulnerabilityType.INSECURE_NETWORK,
                EnhancedVulnerabilityType.JAVASCRIPT_INJECTION: VulnerabilityType.CODE_INJECTION
            }
            
            # Map severity strings to Severity enum
            severity_mapping = {
                'CRITICAL': Severity.CRITICAL,
                'HIGH': Severity.HIGH,
                'MEDIUM': Severity.MEDIUM,
                'LOW': Severity.LOW,
                'INFO': Severity.INFO
            }
            
            vuln_type = type_mapping.get(enhanced_vuln.vulnerability_type, VulnerabilityType.BEHAVIORAL_ANOMALY)
            severity = severity_mapping.get(enhanced_vuln.severity, Severity.MEDIUM)
            
            return RuntimeVulnerability(
                vulnerability_type=vuln_type,
                severity=severity,
                confidence=enhanced_vuln.confidence,
                description=enhanced_vuln.description,
                evidence=enhanced_vuln.evidence,
                remediation=enhanced_vuln.remediation,
                timestamp=enhanced_vuln.timestamp or time.time(),
                cwe_id=enhanced_vuln.cwe_id,
                masvs_control=enhanced_vuln.masvs_control,
                attack_vector="Runtime Analysis",
                api_calls=[],
                behavioral_indicators={}
            )
            
        except Exception as e:
            self.logger.error(f"Error converting enhanced vulnerability: {e}")
            return None
    
    def export_vulnerabilities(self) -> List[Dict[str, Any]]:
        """Export all detected vulnerabilities as dictionaries."""
        return [vuln.to_dict() for vuln in self.vulnerabilities]
    
    def clear_vulnerabilities(self):
        """Clear all detected vulnerabilities and reset state."""
        self.vulnerabilities.clear()
        self.detection_stats = {
            'total_events_analyzed': 0,
            'vulnerabilities_detected': 0,
            'false_positive_rate': 0.0,
            'detection_accuracy': 0.0
        }
        self.runtime_context['detection_timeline'].clear()
        self.behavioral_counters = {key: 0 for key in self.behavioral_counters}
        
        self.logger.info("🧹 Vulnerability detection state cleared")
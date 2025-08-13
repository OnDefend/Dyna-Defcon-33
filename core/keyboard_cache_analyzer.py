#!/usr/bin/env python3
"""
AODS Keyboard Cache Analyzer
============================

Advanced keyboard cache vulnerability detection and analysis for Android applications.
Extends the existing AODS Frida infrastructure to provide specialized keyboard 
cache vulnerability detection while leveraging existing script generation,
template management, and integration capabilities.

Features:
- Integrates with existing AODS FridaScriptGenerator
- Uses existing Frida template system (keyboard_hooks)
- Leverages FridaIntegrationAdapter for execution
- Extends existing analysis result structures
- Integrates with coordinator pattern

This analyzer extends AODS dynamic analysis capabilities by adding keyboard cache
vulnerability detection to the existing comprehensive Frida framework.
"""

import logging
import json
import time
import sqlite3
import re
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum

# AODS imports
from core.shared_infrastructure.analysis_exceptions import AnalysisError, ValidationError, ContextualLogger

# Existing AODS Frida infrastructure
try:
    from plugins.runtime_decryption_analysis.frida_script_generator import (
        FridaScriptGenerator, ScriptGenerationContext
    )
    from plugins.runtime_decryption_analysis.frida_integration_adapter import (
        FridaIntegrationAdapter
    )
    from plugins.runtime_decryption_analysis.data_structures import (
        RuntimeDecryptionFinding, VulnerabilitySeverity
    )
    AODS_FRIDA_AVAILABLE = True
except ImportError:
    AODS_FRIDA_AVAILABLE = False

logger = logging.getLogger(__name__)

class KeyboardCacheVulnerabilityType(Enum):
    """Types of keyboard cache vulnerabilities."""
    INSECURE_INPUT_TYPE = "insecure_input_type"
    CACHED_SENSITIVE_DATA = "cached_sensitive_data"
    PERSONAL_DICTIONARY_LEAKAGE = "personal_dictionary_leakage"
    TRAINING_CACHE_EXPOSURE = "training_cache_exposure"
    INPUT_METHOD_MISCONFIGURATION = "input_method_misconfiguration"

class SensitiveDataType(Enum):
    """Types of sensitive data that might be cached."""
    PASSWORD = "password"
    CREDIT_CARD = "credit_card"
    SSN = "ssn"
    EMAIL = "email"
    PHONE_NUMBER = "phone_number"
    API_KEY = "api_key"
    TOKEN = "token"
    PERSONAL_NAME = "personal_name"
    ADDRESS = "address"

@dataclass
class KeyboardCacheFinding:
    """Represents a keyboard cache vulnerability finding."""
    vulnerability_type: KeyboardCacheVulnerabilityType
    sensitive_data_type: SensitiveDataType
    severity: str
    confidence: float
    description: str
    evidence: Dict[str, Any]
    input_field: Optional[str] = None
    cached_location: Optional[str] = None
    remediation: str = ""
    timestamp: datetime = field(default_factory=datetime.now)

@dataclass
class KeyboardInputEvent:
    """Represents a keyboard input event captured via Frida."""
    timestamp: datetime
    package_name: str
    activity_name: str
    input_field_id: str
    input_type: str
    text_content: str
    is_sensitive: bool
    cache_disabled: bool

class SensitiveDataClassifier:
    """Classifies text content for sensitive data patterns."""
    
    def __init__(self):
        """Initialize the sensitive data classifier."""
        self.patterns = {
            SensitiveDataType.PASSWORD: [
                r'(?i)password',
                r'(?i)passwd',
                r'(?i)pwd',
                r'[a-zA-Z0-9!@#$%^&*]{8,}',  # Complex passwords
            ],
            SensitiveDataType.CREDIT_CARD: [
                r'\b4[0-9]{12}(?:[0-9]{3})?\b',  # Visa
                r'\b5[1-5][0-9]{14}\b',  # MasterCard
                r'\b3[47][0-9]{13}\b',  # American Express
                r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b'
            ],
            SensitiveDataType.SSN: [
                r'\b\d{3}-\d{2}-\d{4}\b',
                r'\b\d{3}\s\d{2}\s\d{4}\b',
                r'\b\d{9}\b'
            ],
            SensitiveDataType.EMAIL: [
                r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
            ],
            SensitiveDataType.PHONE_NUMBER: [
                r'\b\d{3}-\d{3}-\d{4}\b',
                r'\b\(\d{3}\)\s\d{3}-\d{4}\b',
                r'\b\d{10}\b'
            ],
            SensitiveDataType.API_KEY: [
                r'(?i)api[_-]?key\s*[=:]\s*[a-zA-Z0-9_]{16,}',
                r'(?i)secret[_-]?key\s*[:\s]\s*[a-zA-Z0-9_]{16,}',
                r'(?i)access[_-]?token\s*[=:]\s*[a-zA-Z0-9_]{16,}',
                r'sk_test_[a-zA-Z0-9]{20,}',
                r'sk_live_[a-zA-Z0-9]{20,}'
            ],
            SensitiveDataType.TOKEN: [
                r'[a-zA-Z0-9]{32,}',  # Generic long tokens
                r'eyJ[a-zA-Z0-9-_=]+\.[a-zA-Z0-9-_=]+\.[a-zA-Z0-9-_.+/=]*',  # JWT
            ]
        }
    
    def classify_text(self, text: str) -> List[SensitiveDataType]:
        """Classify text for sensitive data types."""
        detected_types = []
        
        for data_type, patterns in self.patterns.items():
            for pattern in patterns:
                if re.search(pattern, text):
                    detected_types.append(data_type)
                    break  # Don't check other patterns for this type
        
        return detected_types

class KeyboardCacheAnalyzer:
    """
    Analyzes keyboard cache vulnerabilities in Android applications.
    Extends existing AODS Frida infrastructure for comprehensive integration.
    """
    
    def __init__(self, package_name: str, config: Optional[Dict[str, Any]] = None):
        """Initialize the keyboard cache analyzer."""
        self.package_name = package_name
        self.config = config or {}
        
        # Initialize logging
        self.contextual_logger = ContextualLogger("KeyboardCacheAnalyzer")
        
        # Initialize classifier
        self.classifier = SensitiveDataClassifier()
        
        # State tracking
        self.input_events: List[KeyboardInputEvent] = []
        self.findings: List[KeyboardCacheFinding] = []
        self.monitored_fields: Set[str] = set()
        
        # Initialize existing AODS Frida infrastructure
        if AODS_FRIDA_AVAILABLE:
            try:
                # Use existing FridaScriptGenerator
                self.script_generator = FridaScriptGenerator(self.config)
                
                # Use existing FridaIntegrationAdapter
                self.frida_adapter = FridaIntegrationAdapter(package_name, self.config)
                
                self.aods_frida_enabled = True
                self.contextual_logger.info("✅ AODS Frida infrastructure integration successful")
            except Exception as e:
                self.contextual_logger.warning(f"⚠️ AODS Frida integration failed: {e}")
                self.aods_frida_enabled = False
        else:
            self.contextual_logger.warning("⚠️ AODS Frida infrastructure not available")
            self.aods_frida_enabled = False
        
        # Cache locations for device analysis
        self.cache_locations = [
            "/data/data/com.android.providers.userdictionary/databases/user_dict.db",
            "/data/data/com.google.android.inputmethod.latin/databases/",
            "/data/data/com.google.android.inputmethod.latin/files/personal/"
        ]
        
        self.contextual_logger.info(f"⌨️ Keyboard cache analyzer initialized for {package_name}")
    
    def generate_keyboard_monitoring_script(self) -> Optional[str]:
        """Generate Frida script using existing AODS infrastructure."""
        if not self.aods_frida_enabled:
            self.contextual_logger.warning("AODS Frida infrastructure not available for script generation")
            return None
            
        try:
            # Create keyboard cache specific findings to trigger keyboard hooks
            keyboard_findings = [
                self._create_keyboard_finding("input_cache_vulnerability", "Keyboard cache monitoring required")
            ]
            
            # Create generation context for keyboard monitoring
            context = ScriptGenerationContext(
                findings=keyboard_findings,
                config=self._get_keyboard_config(),
                hooks_to_generate=['keyboard_hooks'],  # Use our new template
                include_usage_instructions=True
            )
            
            # Generate script using existing infrastructure
            result = self.script_generator.generate_script(keyboard_findings, context)
            
            if result.has_errors:
                self.contextual_logger.warning(f"Script generation had errors: {result.error_message}")
            
            self.contextual_logger.info(f"⌨️ Generated keyboard monitoring script with {len(result.hooks_generated)} hooks")
            return result.script_content
            
        except Exception as e:
            self.contextual_logger.error(f"Failed to generate script using AODS infrastructure: {e}")
            return None
    
    def _create_keyboard_finding(self, finding_type: str, description: str) -> Dict[str, Any]:
        """Create a keyboard-specific finding for script generation."""
        return {
            'finding_type': finding_type,
            'description': description,
            'type': 'keyboard_cache',
            'severity': 'HIGH',
            'confidence': 0.9,
            'pattern_type': 'keyboard_input'
        }
    
    def _get_keyboard_config(self) -> Dict[str, Any]:
        """Get keyboard-specific configuration for script generation."""
        base_config = self.config.copy()
        
        # Add keyboard-specific template parameters
        keyboard_config = {
            'report_vulnerabilities': True,
            'monitor_text_input': True,
            'monitor_input_method': True,
            'detect_sensitive_patterns': True,
            'min_text_length': 3
        }
        
        base_config.update(keyboard_config)
        return base_config
    
    def process_frida_message(self, message: Dict[str, Any]) -> None:
        """Process messages from Frida keyboard monitoring script."""
        try:
            if message.get('type') == 'text_input':
                self._process_text_input_event(message)
            elif message.get('type') == 'input_type_set':
                self._process_input_type_event(message)
            elif message.get('type') == 'input_method_start':
                self._process_input_method_event(message)
                
        except Exception as e:
            self.contextual_logger.error(f"Failed to process Frida message: {e}")
    
    def _process_text_input_event(self, message: Dict[str, Any]) -> None:
        """Process text input events from Frida."""
        text_content = message.get('text_content', '')
        input_type = message.get('input_type', 'unknown')
        field_id = message.get('field_id', 'unknown')
        
        # Classify the text for sensitive data
        sensitive_types = self.classifier.classify_text(text_content)
        is_sensitive = len(sensitive_types) > 0
        
        # Check if cache is disabled based on input type
        cache_disabled = self._is_cache_disabled_input_type(input_type)
        
        # Create input event
        event = KeyboardInputEvent(
            timestamp=datetime.fromtimestamp(message.get('timestamp', 0) / 1000),
            package_name=message.get('package', self.package_name),
            activity_name=message.get('activity', 'unknown'),
            input_field_id=field_id,
            input_type=input_type,
            text_content=text_content,
            is_sensitive=is_sensitive,
            cache_disabled=cache_disabled
        )
        
        self.input_events.append(event)
        
        # Generate finding if sensitive data and cache not disabled
        if is_sensitive and not cache_disabled:
            for sensitive_type in sensitive_types:
                finding = KeyboardCacheFinding(
                    vulnerability_type=KeyboardCacheVulnerabilityType.INSECURE_INPUT_TYPE,
                    sensitive_data_type=sensitive_type,
                    severity="HIGH",
                    confidence=0.8,
                    description=f"Sensitive data ({sensitive_type.value}) entered in input field without disabled keyboard cache",
                    evidence={
                        'input_field': field_id,
                        'input_type': input_type,
                        'activity': message.get('activity'),
                        'text_length': len(text_content),
                        'cache_disabled': cache_disabled
                    },
                    input_field=field_id,
                    remediation=f"Set android:inputType to textPassword, textNoSuggestions, or similar for field {field_id}"
                )
                self.findings.append(finding)
                
                self.contextual_logger.warning(f"⌨️ Keyboard cache vulnerability detected: {sensitive_type.value} in field {field_id}")
    
    def _process_input_type_event(self, message: Dict[str, Any]) -> None:
        """Process input type setting events from Frida."""
        field_id = message.get('field_id', 'unknown')
        input_type = message.get('input_type', 'unknown')
        cache_disabled = message.get('cache_disabled', False)
        
        self.monitored_fields.add(field_id)
        
        self.contextual_logger.info(f"Input type configured for field {field_id}: cache_disabled={cache_disabled}")
    
    def _process_input_method_event(self, message: Dict[str, Any]) -> None:
        """Process input method service events from Frida."""
        target_package = message.get('target_package')
        input_type = message.get('input_type')
        
        if target_package == self.package_name:
            self.contextual_logger.info(f"Input method service activated for {target_package}")
    
    def _is_cache_disabled_input_type(self, input_type_str: str) -> bool:
        """Check if input type disables keyboard cache."""
        try:
            input_type = int(input_type_str)
            
            # Check for secure input type flags
            # These constants match Android InputType flags
            TYPE_TEXT_VARIATION_PASSWORD = 0x00000080
            TYPE_TEXT_VARIATION_VISIBLE_PASSWORD = 0x00000090
            TYPE_NUMBER_VARIATION_PASSWORD = 0x00000010
            TYPE_TEXT_VARIATION_WEB_PASSWORD = 0x000000e0
            TYPE_TEXT_FLAG_NO_SUGGESTIONS = 0x00080000
            
            secure_flags = [
                TYPE_TEXT_VARIATION_PASSWORD,
                TYPE_TEXT_VARIATION_VISIBLE_PASSWORD,
                TYPE_NUMBER_VARIATION_PASSWORD,
                TYPE_TEXT_VARIATION_WEB_PASSWORD,
                TYPE_TEXT_FLAG_NO_SUGGESTIONS
            ]
            
            for flag in secure_flags:
                if (input_type & flag) != 0:
                    return True
                    
            return False
            
        except (ValueError, TypeError):
            return False
    
    def analyze_keyboard_cache_files(self, device_id: Optional[str] = None) -> None:
        """Analyze keyboard cache files on device."""
        # Note: This requires root access and would use ADB commands
        # For now, we'll implement the analysis framework
        
        findings = []
        
        for cache_location in self.cache_locations:
            try:
                if cache_location.endswith('.db'):
                    findings.extend(self._analyze_sqlite_cache(cache_location))
                else:
                    findings.extend(self._analyze_dictionary_cache(cache_location))
                    
            except Exception as e:
                self.contextual_logger.warning(f"Failed to analyze cache location {cache_location}: {e}")
        
        self.findings.extend(findings)
    
    def _analyze_sqlite_cache(self, db_path: str) -> List[KeyboardCacheFinding]:
        """Analyze SQLite keyboard cache databases."""
        findings = []
        
        # This would require actual device access
        # For now, return framework for future implementation
        self.contextual_logger.info(f"SQLite cache analysis initiated for {db_path}")
        
        return findings
    
    def _analyze_dictionary_cache(self, dict_path: str) -> List[KeyboardCacheFinding]:
        """Analyze dictionary cache files."""
        findings = []
        
        # This would require actual device access
        # For now, return framework for future implementation
        self.contextual_logger.info("Dictionary cache analysis initiated",
                                  context={'dict_path': dict_path})
        
        return findings
    
    def get_analysis_results(self) -> Dict[str, Any]:
        """Get comprehensive analysis results."""
        return {
            'package_name': self.package_name,
            'analysis_timestamp': datetime.now().isoformat(),
            'input_events_captured': len(self.input_events),
            'monitored_fields': len(self.monitored_fields),
            'findings': [
                {
                    'vulnerability_type': f.vulnerability_type.value,
                    'sensitive_data_type': f.sensitive_data_type.value,
                    'severity': f.severity,
                    'confidence': f.confidence,
                    'description': f.description,
                    'evidence': f.evidence,
                    'input_field': f.input_field,
                    'remediation': f.remediation,
                    'timestamp': f.timestamp.isoformat()
                }
                for f in self.findings
            ],
            'statistics': {
                'total_findings': len(self.findings),
                'high_severity_findings': len([f for f in self.findings if f.severity == "HIGH"]),
                'sensitive_input_events': len([e for e in self.input_events if e.is_sensitive]),
                'unprotected_sensitive_inputs': len([e for e in self.input_events if e.is_sensitive and not e.cache_disabled])
            }
        }

def create_keyboard_cache_analyzer(package_name: str, config: Optional[Dict[str, Any]] = None) -> KeyboardCacheAnalyzer:
    """Factory function to create keyboard cache analyzer."""
    return KeyboardCacheAnalyzer(package_name, config) 
#!/usr/bin/env python3
"""
Runtime Evidence Validator

Validates runtime evidence to ensure vulnerabilities are accurately classified
as runtime-detected vs static analysis.

Author: AODS Team
Date: January 2025
"""

import logging
import time
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, field
from enum import Enum
import json
import hashlib
import re


class ValidationResult(Enum):
    """Results of runtime evidence validation."""
    VALID_RUNTIME = "valid_runtime"
    INVALID_RUNTIME = "invalid_runtime"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"
    VALIDATION_ERROR = "validation_error"


class EvidenceStrength(Enum):
    """Strength levels of runtime evidence."""
    STRONG = "strong"        # High confidence runtime evidence
    MODERATE = "moderate"    # Some runtime indicators
    WEAK = "weak"           # Minimal runtime indicators
    NONE = "none"           # No runtime evidence


@dataclass
class ValidationCriteria:
    """Criteria for validating runtime evidence."""
    require_hook_timestamp: bool = True
    require_stack_trace: bool = True
    require_execution_context: bool = False
    require_frida_session: bool = False
    min_evidence_score: float = 0.6
    strict_validation: bool = True


@dataclass
class EvidenceValidationResult:
    """Result of evidence validation."""
    validation_result: ValidationResult
    evidence_strength: EvidenceStrength
    evidence_score: float
    validation_details: Dict[str, Any] = field(default_factory=dict)
    missing_evidence: List[str] = field(default_factory=list)
    found_evidence: List[str] = field(default_factory=list)
    validation_timestamp: float = field(default_factory=time.time)
    validation_metadata: Dict[str, Any] = field(default_factory=dict)


class RuntimeEvidenceValidator:
    """
    Validates runtime evidence to ensure vulnerabilities are accurately classified
    as runtime-detected vs static analysis.
    """
    
    def __init__(self, validation_criteria: ValidationCriteria = None):
        """Initialize runtime evidence validator."""
        self.logger = logging.getLogger(__name__)
        self.criteria = validation_criteria or ValidationCriteria()
        
        # Runtime evidence patterns
        self.runtime_patterns = {
            'hook_indicators': [
                r'hook_timestamp',
                r'frida\..*\.hook',
                r'Java\.perform',
                r'Interceptor\.attach',
                r'runtime_context'
            ],
            'execution_patterns': [
                r'stack_trace',
                r'execution_context',
                r'call_stack',
                r'runtime_parameters',
                r'execution_state'
            ],
            'frida_patterns': [
                r'frida_session',
                r'frida\.attach',
                r'frida\.spawn',
                r'send\(\{.*\}\)',
                r'recv\(.*\)'
            ],
            'timestamp_patterns': [
                r'timestamp.*\d{10,13}',
                r'time.*\d{10,13}',
                r'executed_at.*\d{10,13}'
            ]
        }
        
        # Static analysis indicators (should NOT be present for runtime)
        self.static_indicators = [
            'decompiled',
            'static_analysis',
            'jadx',
            'source_code',
            'bytecode_analysis',
            'disassembly'
        ]
        
        self.logger.info("✅ RuntimeEvidenceValidator initialized")
    
    def validate_runtime_evidence(self, vulnerability: Union[Dict[str, Any], Any]) -> EvidenceValidationResult:
        """
        Validate runtime evidence for a vulnerability.
        
        Args:
            vulnerability: Vulnerability object or dictionary
            
        Returns:
            EvidenceValidationResult with validation details
        """
        try:
            # Normalize vulnerability data
            vuln_data = self._normalize_vulnerability_data(vulnerability)
            
            # Perform evidence validation
            evidence_score = self._calculate_evidence_score(vuln_data)
            evidence_strength = self._determine_evidence_strength(evidence_score)
            validation_result = self._determine_validation_result(evidence_score, vuln_data)
            
            # Extract validation details
            validation_details = self._extract_validation_details(vuln_data)
            missing_evidence = self._identify_missing_evidence(vuln_data)
            found_evidence = self._identify_found_evidence(vuln_data)
            
            # Create validation metadata
            validation_metadata = {
                'validator_version': '1.0',
                'validation_algorithm': 'pattern_based_evidence_analysis',
                'criteria_used': {
                    'require_hook_timestamp': self.criteria.require_hook_timestamp,
                    'require_stack_trace': self.criteria.require_stack_trace,
                    'require_execution_context': self.criteria.require_execution_context,
                    'min_evidence_score': self.criteria.min_evidence_score,
                    'strict_validation': self.criteria.strict_validation
                },
                'vulnerability_source': vuln_data.get('source', 'unknown'),
                'plugin_name': vuln_data.get('plugin_name', 'unknown')
            }
            
            result = EvidenceValidationResult(
                validation_result=validation_result,
                evidence_strength=evidence_strength,
                evidence_score=evidence_score,
                validation_details=validation_details,
                missing_evidence=missing_evidence,
                found_evidence=found_evidence,
                validation_metadata=validation_metadata
            )
            
            self.logger.debug(f"✅ Evidence validation completed: {validation_result.value} "
                            f"(score: {evidence_score:.2f}, strength: {evidence_strength.value})")
            
            return result
            
        except Exception as e:
            self.logger.error(f"❌ Evidence validation failed: {e}")
            return EvidenceValidationResult(
                validation_result=ValidationResult.VALIDATION_ERROR,
                evidence_strength=EvidenceStrength.NONE,
                evidence_score=0.0,
                validation_metadata={'error': str(e)}
            )
    
    def _normalize_vulnerability_data(self, vulnerability: Union[Dict[str, Any], Any]) -> Dict[str, Any]:
        """Normalize vulnerability data to dictionary format."""
        if isinstance(vulnerability, dict):
            return vulnerability
        elif hasattr(vulnerability, 'to_dict'):
            return vulnerability.to_dict()
        elif hasattr(vulnerability, '__dict__'):
            return vulnerability.__dict__
        else:
            # Extract common attributes
            vuln_data = {}
            for attr in ['title', 'description', 'source', 'plugin_name', 'runtime_context']:
                if hasattr(vulnerability, attr):
                    vuln_data[attr] = getattr(vulnerability, attr)
            return vuln_data
    
    def _calculate_evidence_score(self, vuln_data: Dict[str, Any]) -> float:
        """Calculate evidence score based on runtime indicators."""
        score = 0.0
        max_score = 10.0
        
        # Check for hook timestamp (weight: 2.0)
        if self._has_hook_timestamp(vuln_data):
            score += 2.0
            
        # Check for stack trace (weight: 2.0)
        if self._has_stack_trace(vuln_data):
            score += 2.0
            
        # Check for execution context (weight: 1.5)
        if self._has_execution_context(vuln_data):
            score += 1.5
            
        # Check for Frida session indicators (weight: 1.5)
        if self._has_frida_indicators(vuln_data):
            score += 1.5
            
        # Check for runtime parameters (weight: 1.0)
        if self._has_runtime_parameters(vuln_data):
            score += 1.0
            
        # Check for hook-specific data (weight: 1.0)
        if self._has_hook_data(vuln_data):
            score += 1.0
            
        # Check for runtime plugin source (weight: 1.0)
        if self._from_runtime_plugin(vuln_data):
            score += 1.0
            
        # Penalty for static indicators (weight: -2.0)
        if self._has_static_indicators(vuln_data):
            score -= 2.0
            
        # Normalize score
        return max(0.0, min(1.0, score / max_score))
    
    def _determine_evidence_strength(self, evidence_score: float) -> EvidenceStrength:
        """Determine evidence strength based on score."""
        if evidence_score >= 0.8:
            return EvidenceStrength.STRONG
        elif evidence_score >= 0.6:
            return EvidenceStrength.MODERATE
        elif evidence_score >= 0.3:
            return EvidenceStrength.WEAK
        else:
            return EvidenceStrength.NONE
    
    def _determine_validation_result(self, evidence_score: float, vuln_data: Dict[str, Any]) -> ValidationResult:
        """Determine validation result based on evidence and criteria."""
        
        # Check minimum score requirement
        if evidence_score < self.criteria.min_evidence_score:
            return ValidationResult.INSUFFICIENT_EVIDENCE
        
        # Strict validation checks
        if self.criteria.strict_validation:
            if self.criteria.require_hook_timestamp and not self._has_hook_timestamp(vuln_data):
                return ValidationResult.INVALID_RUNTIME
            
            if self.criteria.require_stack_trace and not self._has_stack_trace(vuln_data):
                return ValidationResult.INVALID_RUNTIME
            
            if self.criteria.require_execution_context and not self._has_execution_context(vuln_data):
                return ValidationResult.INVALID_RUNTIME
            
            if self.criteria.require_frida_session and not self._has_frida_indicators(vuln_data):
                return ValidationResult.INVALID_RUNTIME
        
        # Check for disqualifying static indicators
        if self._has_static_indicators(vuln_data) and evidence_score < 0.7:
            return ValidationResult.INVALID_RUNTIME
        
        return ValidationResult.VALID_RUNTIME
    
    def _extract_validation_details(self, vuln_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract detailed validation information."""
        return {
            'has_hook_timestamp': self._has_hook_timestamp(vuln_data),
            'has_stack_trace': self._has_stack_trace(vuln_data),
            'has_execution_context': self._has_execution_context(vuln_data),
            'has_frida_indicators': self._has_frida_indicators(vuln_data),
            'has_runtime_parameters': self._has_runtime_parameters(vuln_data),
            'has_hook_data': self._has_hook_data(vuln_data),
            'from_runtime_plugin': self._from_runtime_plugin(vuln_data),
            'has_static_indicators': self._has_static_indicators(vuln_data),
            'runtime_context_type': type(vuln_data.get('runtime_context', None)).__name__,
            'data_structure_analysis': self._analyze_data_structure(vuln_data)
        }
    
    def _identify_missing_evidence(self, vuln_data: Dict[str, Any]) -> List[str]:
        """Identify missing runtime evidence."""
        missing = []
        
        if not self._has_hook_timestamp(vuln_data):
            missing.append('hook_timestamp')
        
        if not self._has_stack_trace(vuln_data):
            missing.append('stack_trace')
        
        if not self._has_execution_context(vuln_data):
            missing.append('execution_context')
        
        if not self._has_frida_indicators(vuln_data):
            missing.append('frida_indicators')
        
        if not self._has_runtime_parameters(vuln_data):
            missing.append('runtime_parameters')
        
        return missing
    
    def _identify_found_evidence(self, vuln_data: Dict[str, Any]) -> List[str]:
        """Identify found runtime evidence."""
        found = []
        
        if self._has_hook_timestamp(vuln_data):
            found.append('hook_timestamp')
        
        if self._has_stack_trace(vuln_data):
            found.append('stack_trace')
        
        if self._has_execution_context(vuln_data):
            found.append('execution_context')
        
        if self._has_frida_indicators(vuln_data):
            found.append('frida_indicators')
        
        if self._has_runtime_parameters(vuln_data):
            found.append('runtime_parameters')
        
        if self._has_hook_data(vuln_data):
            found.append('hook_data')
        
        return found
    
    def _analyze_data_structure(self, vuln_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze data structure for runtime indicators."""
        analysis = {
            'total_keys': len(vuln_data),
            'runtime_keys': [],
            'static_keys': [],
            'nested_structures': 0
        }
        
        for key, value in vuln_data.items():
            key_lower = key.lower()
            
            # Check for runtime-related keys
            if any(pattern in key_lower for pattern in ['runtime', 'hook', 'frida', 'execution']):
                analysis['runtime_keys'].append(key)
            
            # Check for static-related keys
            elif any(pattern in key_lower for pattern in ['static', 'decompiled', 'source']):
                analysis['static_keys'].append(key)
            
            # Count nested structures
            if isinstance(value, (dict, list)):
                analysis['nested_structures'] += 1
        
        return analysis
    
    def _has_hook_timestamp(self, vuln_data: Dict[str, Any]) -> bool:
        """Check for hook timestamp evidence."""
        # Direct timestamp fields
        if vuln_data.get('hook_timestamp') is not None:
            return True
        
        # Runtime context timestamp
        runtime_context = vuln_data.get('runtime_context', {})
        if isinstance(runtime_context, dict) and runtime_context.get('timestamp') is not None:
            return True
        
        # Pattern-based detection
        text_content = str(vuln_data).lower()
        return any(re.search(pattern, text_content) for pattern in self.runtime_patterns['timestamp_patterns'])
    
    def _has_stack_trace(self, vuln_data: Dict[str, Any]) -> bool:
        """Check for stack trace evidence."""
        # Direct stack trace fields
        if vuln_data.get('stack_trace') is not None:
            return True
        
        # Runtime context stack trace
        runtime_context = vuln_data.get('runtime_context', {})
        if isinstance(runtime_context, dict) and runtime_context.get('stack_trace') is not None:
            return True
        
        # Pattern-based detection
        text_content = str(vuln_data).lower()
        return any(re.search(pattern, text_content) for pattern in self.runtime_patterns['execution_patterns'])
    
    def _has_execution_context(self, vuln_data: Dict[str, Any]) -> bool:
        """Check for execution context evidence."""
        # Direct execution context
        if vuln_data.get('execution_context') is not None:
            return True
        
        # Runtime context with execution data
        runtime_context = vuln_data.get('runtime_context', {})
        if isinstance(runtime_context, dict):
            return (
                runtime_context.get('context') is not None or
                runtime_context.get('execution_context') is not None or
                runtime_context.get('parameters') is not None
            )
        
        return False
    
    def _has_frida_indicators(self, vuln_data: Dict[str, Any]) -> bool:
        """Check for Frida-specific indicators."""
        # Direct Frida fields
        if vuln_data.get('frida_session_id') is not None:
            return True
        
        # Pattern-based detection
        text_content = str(vuln_data).lower()
        return any(re.search(pattern, text_content) for pattern in self.runtime_patterns['frida_patterns'])
    
    def _has_runtime_parameters(self, vuln_data: Dict[str, Any]) -> bool:
        """Check for runtime parameters evidence."""
        # Direct parameters
        if vuln_data.get('runtime_parameters') is not None:
            return True
        
        # Runtime context parameters
        runtime_context = vuln_data.get('runtime_context', {})
        if isinstance(runtime_context, dict):
            return runtime_context.get('parameters') is not None
        
        return False
    
    def _has_hook_data(self, vuln_data: Dict[str, Any]) -> bool:
        """Check for hook-specific data."""
        # Direct hook fields
        if vuln_data.get('hook_name') is not None or vuln_data.get('hook_data') is not None:
            return True
        
        # Pattern-based detection
        text_content = str(vuln_data).lower()
        return any(re.search(pattern, text_content) for pattern in self.runtime_patterns['hook_indicators'])
    
    def _from_runtime_plugin(self, vuln_data: Dict[str, Any]) -> bool:
        """Check if vulnerability originated from runtime plugin."""
        plugin_name = vuln_data.get('plugin_name', '').lower()
        source = vuln_data.get('source', '').lower()
        
        runtime_plugins = ['frida_dynamic_analysis', 'runtime_hooks', 'dynamic_analysis']
        
        return (
            any(plugin in plugin_name for plugin in runtime_plugins) or
            any(plugin in source for plugin in runtime_plugins)
        )
    
    def _has_static_indicators(self, vuln_data: Dict[str, Any]) -> bool:
        """Check for static analysis indicators (disqualifying)."""
        text_content = str(vuln_data).lower()
        return any(indicator in text_content for indicator in self.static_indicators)
    
    def is_valid_runtime_vulnerability(self, vulnerability: Union[Dict[str, Any], Any]) -> bool:
        """Check if vulnerability has valid runtime evidence (convenience method)."""
        result = self.validate_runtime_evidence(vulnerability)
        return result.validation_result == ValidationResult.VALID_RUNTIME
    
    def get_evidence_strength(self, vulnerability: Union[Dict[str, Any], Any]) -> EvidenceStrength:
        """Get evidence strength for vulnerability (convenience method)."""
        result = self.validate_runtime_evidence(vulnerability)
        return result.evidence_strength
    
    def validate_vulnerability_batch(self, vulnerabilities: List[Union[Dict[str, Any], Any]]) -> List[EvidenceValidationResult]:
        """Validate evidence for a batch of vulnerabilities."""
        results = []
        
        for vuln in vulnerabilities:
            result = self.validate_runtime_evidence(vuln)
            results.append(result)
        
        return results
    
    def get_validation_summary(self, vulnerabilities: List[Union[Dict[str, Any], Any]]) -> Dict[str, Any]:
        """Get validation summary for a batch of vulnerabilities."""
        results = self.validate_vulnerability_batch(vulnerabilities)
        
        # Count validation results
        result_counts = {}
        strength_counts = {}
        total_score = 0.0
        
        for result in results:
            validation_result = result.validation_result.value
            evidence_strength = result.evidence_strength.value
            
            result_counts[validation_result] = result_counts.get(validation_result, 0) + 1
            strength_counts[evidence_strength] = strength_counts.get(evidence_strength, 0) + 1
            total_score += result.evidence_score
        
        return {
            'total_vulnerabilities': len(vulnerabilities),
            'validation_results': result_counts,
            'evidence_strengths': strength_counts,
            'average_evidence_score': total_score / max(1, len(vulnerabilities)),
            'valid_runtime_count': result_counts.get(ValidationResult.VALID_RUNTIME.value, 0),
            'invalid_runtime_count': result_counts.get(ValidationResult.INVALID_RUNTIME.value, 0),
            'insufficient_evidence_count': result_counts.get(ValidationResult.INSUFFICIENT_EVIDENCE.value, 0),
            'strong_evidence_count': strength_counts.get(EvidenceStrength.STRONG.value, 0),
            'validation_timestamp': time.time()
        }


# Convenience functions
def validate_runtime_evidence(vulnerability: Union[Dict[str, Any], Any], 
                            criteria: ValidationCriteria = None) -> EvidenceValidationResult:
    """Validate runtime evidence for a single vulnerability."""
    validator = RuntimeEvidenceValidator(criteria)
    return validator.validate_runtime_evidence(vulnerability)


def is_valid_runtime_vulnerability(vulnerability: Union[Dict[str, Any], Any]) -> bool:
    """Check if vulnerability has valid runtime evidence."""
    result = validate_runtime_evidence(vulnerability)
    return result.validation_result == ValidationResult.VALID_RUNTIME


def get_runtime_validation_summary(vulnerabilities: List[Union[Dict[str, Any], Any]]) -> Dict[str, Any]:
    """Get runtime validation summary for vulnerabilities."""
    validator = RuntimeEvidenceValidator()
    return validator.get_validation_summary(vulnerabilities)


if __name__ == "__main__":
    # Demo usage
    print("✅ Runtime Evidence Validator Demo")
    print("=" * 40)
    
    # Create validator
    validator = RuntimeEvidenceValidator()
    
    print("✅ RuntimeEvidenceValidator initialized")
    print("🎯 Validation Results:")
    results = list(ValidationResult)
    for result in results:
        print(f"   • {result.value}")
    
    print("\n📊 Evidence Strengths:")
    strengths = list(EvidenceStrength)
    for strength in strengths:
        print(f"   • {strength.value}")
    
    print("\n🔍 Validation Features:")
    print("   ✅ Hook timestamp validation")
    print("   ✅ Stack trace verification")
    print("   ✅ Execution context analysis")
    print("   ✅ Frida session detection")
    print("   ✅ Static indicator filtering")
    print("   ✅ Pattern-based evidence scoring")
    
    print("\n✅ Validator ready for evidence validation!")
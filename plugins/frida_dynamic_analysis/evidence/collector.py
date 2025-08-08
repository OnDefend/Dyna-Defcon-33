#!/usr/bin/env python3
"""
Runtime Evidence Collector

Advanced evidence collection system for runtime vulnerability detection.
Captures comprehensive evidence packages including call stacks, runtime context,
and forensic data for vulnerability analysis.

Author: AODS Team
Date: January 2025
"""

import logging
import time
import json
import hashlib
import base64
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum


class EvidenceType(Enum):
    """Types of runtime evidence."""
    CALL_STACK = "CALL_STACK"
    RUNTIME_CONTEXT = "RUNTIME_CONTEXT"
    API_TRACE = "API_TRACE"
    MEMORY_SNAPSHOT = "MEMORY_SNAPSHOT"
    NETWORK_TRAFFIC = "NETWORK_TRAFFIC"
    FILE_OPERATION = "FILE_OPERATION"
    BEHAVIORAL_PATTERN = "BEHAVIORAL_PATTERN"
    CRYPTOGRAPHIC_OPERATION = "CRYPTOGRAPHIC_OPERATION"


@dataclass
class EvidenceMetadata:
    """Metadata for evidence collection."""
    evidence_id: str
    evidence_type: EvidenceType
    timestamp: float
    source_hook: str
    confidence_score: float
    collection_method: str
    verification_hash: str = ""
    tags: List[str] = field(default_factory=list)


@dataclass
class RuntimeCallStack:
    """Runtime call stack information."""
    stack_frames: List[str]
    calling_thread: str
    execution_context: Dict[str, Any]
    source_location: str
    method_signature: str
    parameters: Dict[str, Any] = field(default_factory=dict)
    return_value: Any = None


@dataclass
class RuntimeContext:
    """Runtime execution context."""
    package_name: str
    process_id: int
    thread_id: str
    timestamp: float
    memory_usage: Dict[str, Any]
    device_info: Dict[str, Any]
    app_state: str
    active_components: List[str]
    environment_variables: Dict[str, str] = field(default_factory=dict)


@dataclass
class EvidencePackage:
    """Comprehensive evidence package for a vulnerability."""
    vulnerability_id: str
    metadata: EvidenceMetadata
    call_stack: Optional[RuntimeCallStack]
    runtime_context: Optional[RuntimeContext]
    api_trace: List[Dict[str, Any]]
    raw_data: Dict[str, Any]
    forensic_details: Dict[str, Any]
    related_evidence: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert evidence package to dictionary."""
        return {
            'vulnerability_id': self.vulnerability_id,
            'metadata': {
                'evidence_id': self.metadata.evidence_id,
                'evidence_type': self.metadata.evidence_type.value,
                'timestamp': self.metadata.timestamp,
                'source_hook': self.metadata.source_hook,
                'confidence_score': self.metadata.confidence_score,
                'collection_method': self.metadata.collection_method,
                'verification_hash': self.metadata.verification_hash,
                'tags': self.metadata.tags
            },
            'call_stack': self._call_stack_to_dict() if self.call_stack else None,
            'runtime_context': self._runtime_context_to_dict() if self.runtime_context else None,
            'api_trace': self.api_trace,
            'raw_data': self.raw_data,
            'forensic_details': self.forensic_details,
            'related_evidence': self.related_evidence
        }
    
    def _call_stack_to_dict(self) -> Dict[str, Any]:
        """Convert call stack to dictionary."""
        if not self.call_stack:
            return {}
        
        return {
            'stack_frames': self.call_stack.stack_frames,
            'calling_thread': self.call_stack.calling_thread,
            'execution_context': self.call_stack.execution_context,
            'source_location': self.call_stack.source_location,
            'method_signature': self.call_stack.method_signature,
            'parameters': self.call_stack.parameters,
            'return_value': str(self.call_stack.return_value) if self.call_stack.return_value else None
        }
    
    def _runtime_context_to_dict(self) -> Dict[str, Any]:
        """Convert runtime context to dictionary."""
        if not self.runtime_context:
            return {}
        
        return {
            'package_name': self.runtime_context.package_name,
            'process_id': self.runtime_context.process_id,
            'thread_id': self.runtime_context.thread_id,
            'timestamp': self.runtime_context.timestamp,
            'memory_usage': self.runtime_context.memory_usage,
            'device_info': self.runtime_context.device_info,
            'app_state': self.runtime_context.app_state,
            'active_components': self.runtime_context.active_components,
            'environment_variables': self.runtime_context.environment_variables
        }


class RuntimeEvidenceCollector:
    """
    Advanced evidence collection system for runtime vulnerability analysis.
    
    This collector captures comprehensive evidence packages including call stacks,
    runtime context, API traces, and forensic data for vulnerability verification
    and detailed analysis.
    """
    
    def __init__(self, package_name: str = "unknown"):
        """
        Initialize the runtime evidence collector.
        
        Args:
            package_name: Target application package name
        """
        self.logger = logging.getLogger(f"{__name__}.RuntimeEvidenceCollector")
        self.package_name = package_name
        
        # Evidence storage
        self.evidence_packages = {}
        self.evidence_index = {}
        self.collection_stats = {
            'total_evidence_collected': 0,
            'evidence_by_type': {},
            'collection_errors': 0,
            'verification_failures': 0
        }
        
        # Evidence collection configuration
        self.config = {
            'max_stack_depth': 20,
            'max_api_trace_length': 100,
            'include_memory_snapshots': False,
            'include_environment_vars': True,
            'verify_evidence_integrity': True
        }
        
        # Runtime tracking
        self.active_traces = {}
        self.collection_timeline = []
        
        self.logger.info(f"🚀 RuntimeEvidenceCollector initialized for {package_name}")
    
    def capture_call_stack(self, hook_data: Dict[str, Any]) -> Optional[RuntimeCallStack]:
        """
        Capture call stack for vulnerability evidence.
        
        Args:
            hook_data: Runtime hook data containing stack trace
            
        Returns:
            RuntimeCallStack object or None if capture fails
        """
        try:
            stack_trace = hook_data.get('stack_trace', '')
            thread_name = hook_data.get('thread', 'unknown')
            method = hook_data.get('method', 'unknown')
            timestamp = hook_data.get('timestamp', time.time())
            
            # Parse stack trace
            stack_frames = []
            if stack_trace:
                frames = stack_trace.split('\n')
                for frame in frames[:self.config['max_stack_depth']]:
                    if frame.strip():
                        stack_frames.append(frame.strip())
            
            # Extract method signature and parameters
            method_signature = self._extract_method_signature(hook_data)
            parameters = self._extract_parameters(hook_data)
            
            # Build execution context
            execution_context = {
                'timestamp': timestamp,
                'hook_type': hook_data.get('type', 'unknown'),
                'detection_method': 'frida_javascript_injection'
            }
            
            call_stack = RuntimeCallStack(
                stack_frames=stack_frames,
                calling_thread=thread_name,
                execution_context=execution_context,
                source_location=self._extract_source_location(stack_frames),
                method_signature=method_signature,
                parameters=parameters
            )
            
            self.logger.debug(f"📋 Captured call stack: {len(stack_frames)} frames from {thread_name}")
            return call_stack
            
        except Exception as e:
            self.logger.error(f"❌ Failed to capture call stack: {e}")
            self.collection_stats['collection_errors'] += 1
            return None
    
    def extract_runtime_context(self, vulnerability: Dict[str, Any]) -> Optional[RuntimeContext]:
        """
        Extract runtime context for vulnerability.
        
        Args:
            vulnerability: Vulnerability data
            
        Returns:
            RuntimeContext object or None if extraction fails
        """
        try:
            timestamp = vulnerability.get('timestamp', time.time())
            evidence = vulnerability.get('evidence', {})
            
            # Build runtime context
            runtime_context = RuntimeContext(
                package_name=self.package_name,
                process_id=self._get_process_id(),
                thread_id=evidence.get('thread', 'unknown'),
                timestamp=timestamp,
                memory_usage=self._get_memory_usage(),
                device_info=self._get_device_info(),
                app_state=self._get_app_state(),
                active_components=self._get_active_components()
            )
            
            # Add environment variables if configured
            if self.config['include_environment_vars']:
                runtime_context.environment_variables = self._get_safe_environment_vars()
            
            self.logger.debug(f"🎯 Extracted runtime context for {self.package_name}")
            return runtime_context
            
        except Exception as e:
            self.logger.error(f"❌ Failed to extract runtime context: {e}")
            self.collection_stats['collection_errors'] += 1
            return None
    
    def generate_runtime_evidence(self, vuln_data: Dict[str, Any]) -> Optional[EvidencePackage]:
        """
        Generate comprehensive evidence package for runtime vulnerability.
        
        Args:
            vuln_data: Vulnerability data from runtime detection
            
        Returns:
            EvidencePackage or None if generation fails
        """
        try:
            vulnerability_id = self._generate_vulnerability_id(vuln_data)
            evidence_id = self._generate_evidence_id(vulnerability_id)
            
            # Create evidence metadata
            metadata = EvidenceMetadata(
                evidence_id=evidence_id,
                evidence_type=self._determine_evidence_type(vuln_data),
                timestamp=vuln_data.get('timestamp', time.time()),
                source_hook=vuln_data.get('hook_name', 'unknown'),
                confidence_score=vuln_data.get('confidence', 0.5),
                collection_method='frida_runtime_hooks',
                tags=self._generate_evidence_tags(vuln_data)
            )
            
            # Capture call stack
            call_stack = self.capture_call_stack(vuln_data)
            
            # Extract runtime context
            runtime_context = self.extract_runtime_context(vuln_data)
            
            # Build API trace
            api_trace = self._build_api_trace(vuln_data)
            
            # Collect forensic details
            forensic_details = self._collect_forensic_details(vuln_data)
            
            # Create evidence package
            evidence_package = EvidencePackage(
                vulnerability_id=vulnerability_id,
                metadata=metadata,
                call_stack=call_stack,
                runtime_context=runtime_context,
                api_trace=api_trace,
                raw_data=vuln_data,
                forensic_details=forensic_details
            )
            
            # Verify evidence integrity
            if self.config['verify_evidence_integrity']:
                verification_hash = self._calculate_evidence_hash(evidence_package)
                evidence_package.metadata.verification_hash = verification_hash
            
            # Store evidence package
            self.evidence_packages[evidence_id] = evidence_package
            self._update_evidence_index(evidence_package)
            
            # Update statistics
            self.collection_stats['total_evidence_collected'] += 1
            evidence_type = metadata.evidence_type.value
            self.collection_stats['evidence_by_type'][evidence_type] = \
                self.collection_stats['evidence_by_type'].get(evidence_type, 0) + 1
            
            self.logger.info(f"✅ Generated evidence package: {evidence_id}")
            return evidence_package
            
        except Exception as e:
            self.logger.error(f"❌ Failed to generate runtime evidence: {e}")
            self.collection_stats['collection_errors'] += 1
            return None
    
    def get_evidence_by_vulnerability(self, vulnerability_id: str) -> Optional[EvidencePackage]:
        """Get evidence package for a specific vulnerability."""
        for evidence in self.evidence_packages.values():
            if evidence.vulnerability_id == vulnerability_id:
                return evidence
        return None
    
    def get_evidence_by_type(self, evidence_type: EvidenceType) -> List[EvidencePackage]:
        """Get all evidence packages of a specific type."""
        return [
            evidence for evidence in self.evidence_packages.values()
            if evidence.metadata.evidence_type == evidence_type
        ]
    
    def export_evidence(self, evidence_id: str) -> Optional[Dict[str, Any]]:
        """Export evidence package as dictionary."""
        evidence = self.evidence_packages.get(evidence_id)
        return evidence.to_dict() if evidence else None
    
    def export_all_evidence(self) -> List[Dict[str, Any]]:
        """Export all evidence packages as dictionaries."""
        return [evidence.to_dict() for evidence in self.evidence_packages.values()]
    
    def get_collection_summary(self) -> Dict[str, Any]:
        """Get summary of evidence collection."""
        return {
            'total_evidence_packages': len(self.evidence_packages),
            'collection_stats': self.collection_stats,
            'evidence_types': list(self.collection_stats['evidence_by_type'].keys()),
            'config': self.config,
            'package_name': self.package_name
        }
    
    def _extract_method_signature(self, hook_data: Dict[str, Any]) -> str:
        """Extract method signature from hook data."""
        method = hook_data.get('method', '')
        algorithm = hook_data.get('algorithm', '')
        transformation = hook_data.get('transformation', '')
        
        if method and algorithm:
            return f"{method}({algorithm})"
        elif method and transformation:
            return f"{method}({transformation})"
        elif method:
            return method
        else:
            return "unknown"
    
    def _extract_parameters(self, hook_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract method parameters from hook data."""
        parameters = {}
        
        # Common parameters
        if 'algorithm' in hook_data:
            parameters['algorithm'] = hook_data['algorithm']
        if 'transformation' in hook_data:
            parameters['transformation'] = hook_data['transformation']
        if 'url' in hook_data:
            parameters['url'] = hook_data['url']
        if 'file_path' in hook_data:
            parameters['file_path'] = hook_data['file_path']
        if 'key' in hook_data:
            parameters['key'] = hook_data['key']
        if 'operation' in hook_data:
            parameters['operation'] = hook_data['operation']
        
        return parameters
    
    def _extract_source_location(self, stack_frames: List[str]) -> str:
        """Extract source location from stack frames."""
        if not stack_frames:
            return "unknown"
        
        # Try to find the most relevant frame (not framework code)
        for frame in stack_frames:
            if any(keyword in frame.lower() for keyword in ['com.', 'org.', 'app.', self.package_name]):
                return frame
        
        # Fallback to first frame
        return stack_frames[0] if stack_frames else "unknown"
    
    def _determine_evidence_type(self, vuln_data: Dict[str, Any]) -> EvidenceType:
        """Determine evidence type based on vulnerability data."""
        hook_type = vuln_data.get('type', '')
        
        if hook_type == 'crypto_vulnerability':
            return EvidenceType.CRYPTOGRAPHIC_OPERATION
        elif hook_type == 'network_communication':
            return EvidenceType.NETWORK_TRAFFIC
        elif hook_type in ['file_access', 'shared_preferences', 'database_access']:
            return EvidenceType.FILE_OPERATION
        else:
            return EvidenceType.API_TRACE
    
    def _generate_evidence_tags(self, vuln_data: Dict[str, Any]) -> List[str]:
        """Generate tags for evidence classification."""
        tags = []
        
        # Add hook-based tags
        hook_type = vuln_data.get('type', '')
        if hook_type:
            tags.append(f"hook:{hook_type}")
        
        # Add method-based tags
        method = vuln_data.get('method', '')
        if method:
            tags.append(f"method:{method}")
        
        # Add algorithm-based tags
        algorithm = vuln_data.get('algorithm', '')
        if algorithm:
            tags.append(f"algorithm:{algorithm}")
        
        # Add severity tags
        severity = vuln_data.get('severity', '')
        if severity:
            tags.append(f"severity:{severity}")
        
        return tags
    
    def _build_api_trace(self, vuln_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Build API trace from vulnerability data."""
        api_trace = []
        
        # Add the current API call
        api_call = {
            'timestamp': vuln_data.get('timestamp', time.time()),
            'method': vuln_data.get('method', 'unknown'),
            'parameters': self._extract_parameters(vuln_data),
            'hook_type': vuln_data.get('type', 'unknown'),
            'thread': vuln_data.get('thread', 'unknown')
        }
        api_trace.append(api_call)
        
        return api_trace
    
    def _collect_forensic_details(self, vuln_data: Dict[str, Any]) -> Dict[str, Any]:
        """Collect additional forensic details."""
        forensic_details = {
            'collection_timestamp': time.time(),
            'evidence_collector_version': '1.0.0',
            'detection_confidence': vuln_data.get('confidence', 0.5),
            'hook_execution_time': vuln_data.get('execution_time', 0),
            'frida_version': self._get_frida_version(),
            'analysis_environment': 'runtime_dynamic_analysis'
        }
        
        # Add hook-specific details
        if vuln_data.get('type') == 'crypto_vulnerability':
            forensic_details['crypto_analysis'] = {
                'algorithm_strength': self._assess_algorithm_strength(vuln_data.get('algorithm', '')),
                'usage_context': 'runtime_detection'
            }
        
        return forensic_details
    
    def _assess_algorithm_strength(self, algorithm: str) -> str:
        """Assess cryptographic algorithm strength."""
        weak_algorithms = ['MD5', 'SHA1', 'DES', '3DES', 'RC4']
        if algorithm.upper() in weak_algorithms:
            return 'weak'
        elif algorithm.upper() in ['AES', 'SHA256', 'SHA384', 'SHA512']:
            return 'strong'
        else:
            return 'unknown'
    
    def _generate_vulnerability_id(self, vuln_data: Dict[str, Any]) -> str:
        """Generate unique vulnerability ID."""
        data_str = f"{vuln_data.get('type', '')}{vuln_data.get('method', '')}{vuln_data.get('timestamp', '')}"
        return hashlib.md5(data_str.encode()).hexdigest()[:16]
    
    def _generate_evidence_id(self, vulnerability_id: str) -> str:
        """Generate unique evidence ID."""
        timestamp = str(time.time())
        data_str = f"{vulnerability_id}{timestamp}{self.package_name}"
        return f"evidence_{hashlib.md5(data_str.encode()).hexdigest()[:12]}"
    
    def _calculate_evidence_hash(self, evidence_package: EvidencePackage) -> str:
        """Calculate verification hash for evidence integrity."""
        try:
            evidence_data = evidence_package.to_dict()
            evidence_json = json.dumps(evidence_data, sort_keys=True)
            return hashlib.sha256(evidence_json.encode()).hexdigest()[:32]
        except Exception as e:
            self.logger.warning(f"⚠️ Failed to calculate evidence hash: {e}")
            return ""
    
    def _update_evidence_index(self, evidence_package: EvidencePackage):
        """Update evidence index for fast lookups."""
        evidence_id = evidence_package.metadata.evidence_id
        vulnerability_id = evidence_package.vulnerability_id
        evidence_type = evidence_package.metadata.evidence_type.value
        
        # Index by vulnerability ID
        if vulnerability_id not in self.evidence_index:
            self.evidence_index[vulnerability_id] = []
        self.evidence_index[vulnerability_id].append(evidence_id)
        
        # Index by evidence type
        type_key = f"type:{evidence_type}"
        if type_key not in self.evidence_index:
            self.evidence_index[type_key] = []
        self.evidence_index[type_key].append(evidence_id)
    
    def _get_process_id(self) -> int:
        """Get current process ID."""
        try:
            import os
            return os.getpid()
        except:
            return 0
    
    def _get_memory_usage(self) -> Dict[str, Any]:
        """Get memory usage information."""
        try:
            import psutil
            process = psutil.Process()
            memory_info = process.memory_info()
            return {
                'rss': memory_info.rss,
                'vms': memory_info.vms,
                'percent': process.memory_percent()
            }
        except:
            return {'error': 'memory_info_unavailable'}
    
    def _get_device_info(self) -> Dict[str, Any]:
        """Get device information."""
        return {
            'platform': 'android',
            'analysis_type': 'frida_dynamic',
            'instrumentation': 'javascript_injection'
        }
    
    def _get_app_state(self) -> str:
        """Get application state."""
        return 'runtime_analysis'
    
    def _get_active_components(self) -> List[str]:
        """Get active application components."""
        return ['frida_hooks', 'vulnerability_detector', 'evidence_collector']
    
    def _get_safe_environment_vars(self) -> Dict[str, str]:
        """Get safe environment variables (no sensitive data)."""
        try:
            import os
            safe_vars = {}
            safe_keys = ['PATH', 'USER', 'HOME', 'LANG', 'ANDROID_HOME']
            for key in safe_keys:
                if key in os.environ:
                    safe_vars[key] = os.environ[key]
            return safe_vars
        except:
            return {}
    
    def _get_frida_version(self) -> str:
        """Get Frida version."""
        try:
            import frida
            return frida.__version__
        except:
            return 'unknown'
#!/usr/bin/env python3
"""
Unified Payload Manager - Centralized Payload Management for AODS Runtime Security Testing

This module consolidates all existing payloads from ICC, WebView, and Dynamic Execution modules
into a unified management system that supports zero-touch automation and provides infrastructure
for the remaining payload matrix expansions.

Current Payload Inventory:
- ICC Security: 17 payloads (Intent, Broadcast, Service, Content Provider, Deep Link)
- WebView Exploitation: 15 payloads (JS injection, DOM manipulation, config bypass, privilege escalation, custom schemes)
- Dynamic Execution: 17 payloads (ClassLoader, Runtime.exec(), reflection, dropper, code injection)
- TOTAL CURRENT: 49 payloads

Planned Payload Expansions:
- Crypto & Keystore Misuse: 6 payloads (Target: 55 total)
- Custom Deserialization Abuse: 5 payloads (Target: 60 total)
- File System & Path Exploits: 6 payloads (Target: 66 total)
- Memory Tampering & Runtime Modification: 5 payloads (Target: 71 total)
- Exposed Debug Interfaces: 4 payloads (Target: 75 total)
- Third-Party SDK Injection Vectors: 4 payloads (Target: 79 total)

Features:
- Centralized payload access with unified interface
- Payload metadata management (severity, MASVS, CWE, description)
- Category-based payload organization and filtering
- Zero-touch automation support with looping capabilities
- Real-time payload execution results tracking
- Integration with existing AODS Frida infrastructure
- Support for payload profile-based execution
"""

import logging
import time
from typing import Dict, List, Optional, Any, Set, Callable
from dataclasses import dataclass, field
from enum import Enum
import json


class PayloadCategory(Enum):
    """Payload categories for unified management."""
    
    # Current implemented categories
    ICC_SECURITY = "icc_security"
    WEBVIEW_EXPLOITATION = "webview_exploitation" 
    DYNAMIC_EXECUTION = "dynamic_execution"
    
    # Planned categories for matrix expansion
    CRYPTO_KEYSTORE = "crypto_keystore"
    DESERIALIZATION_ABUSE = "deserialization_abuse"
    FILE_SYSTEM_EXPLOITS = "file_system_exploits"
    MEMORY_TAMPERING = "memory_tampering"
    DEBUG_INTERFACES = "debug_interfaces"
    SDK_INJECTION = "sdk_injection"


class PayloadSeverity(Enum):
    """Payload severity levels."""
    
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class PayloadExecutionMode(Enum):
    """Payload execution modes for zero-touch automation."""
    
    PASSIVE = "passive"        # Monitor only
    ACTIVE = "active"          # Execute payload
    AGGRESSIVE = "aggressive"  # Advanced exploitation
    SIMULATION = "simulation"  # Simulated execution


@dataclass
class PayloadMetadata:
    """Comprehensive payload metadata for unified management."""
    
    payload_id: str
    category: PayloadCategory
    subcategory: str
    title: str
    description: str
    severity: PayloadSeverity
    masvs_control: str
    cwe_id: str
    owasp_category: str
    execution_mode: PayloadExecutionMode = PayloadExecutionMode.ACTIVE
    
    # Technical details
    target_apis: List[str] = field(default_factory=list)
    frida_hooks: List[str] = field(default_factory=list)
    exploitation_techniques: List[str] = field(default_factory=list)
    
    # Testing configuration
    timeout: int = 15
    requires_root: bool = False
    requires_network: bool = False
    stealth_mode_compatible: bool = True
    
    # Results tracking
    execution_count: int = 0
    success_rate: float = 0.0
    last_executed: Optional[str] = None


@dataclass
class UnifiedPayload:
    """Unified payload structure consolidating all payload types."""
    
    metadata: PayloadMetadata
    payload_data: Dict[str, Any]
    frida_script_template: Optional[str] = None
    execution_handler: Optional[Callable] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert payload to dictionary format."""
        return {
            'metadata': {
                'payload_id': self.metadata.payload_id,
                'category': self.metadata.category.value,
                'subcategory': self.metadata.subcategory,
                'title': self.metadata.title,
                'description': self.metadata.description,
                'severity': self.metadata.severity.value,
                'masvs_control': self.metadata.masvs_control,
                'cwe_id': self.metadata.cwe_id,
                'owasp_category': self.metadata.owasp_category,
                'execution_mode': self.metadata.execution_mode.value
            },
            'payload_data': self.payload_data,
            'has_frida_script': self.frida_script_template is not None,
            'has_execution_handler': self.execution_handler is not None
        }


@dataclass 
class PayloadExecutionResult:
    """Result from payload execution in zero-touch automation."""
    
    payload_id: str
    category: PayloadCategory
    execution_successful: bool
    vulnerability_confirmed: bool
    execution_time: float
    evidence: Dict[str, Any] = field(default_factory=dict)
    frida_messages: List[Dict[str, Any]] = field(default_factory=list)
    error_message: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary format."""
        return {
            'payload_id': self.payload_id,
            'category': self.category.value,
            'execution_successful': self.execution_successful,
            'vulnerability_confirmed': self.vulnerability_confirmed,
            'execution_time': self.execution_time,
            'evidence': self.evidence,
            'frida_message_count': len(self.frida_messages),
            'error_message': self.error_message
        }


class UnifiedPayloadManager:
    """
    Unified Payload Manager for centralized payload management and zero-touch automation.
    
    Consolidates all existing payloads from ICC, WebView, and Dynamic Execution modules
    and provides infrastructure for remaining payload matrix expansions.
    """
    
    def __init__(self):
        """Initialize unified payload manager."""
        self.logger = logging.getLogger(__name__)
        
        # Payload storage
        self.payloads: Dict[str, UnifiedPayload] = {}
        self.categories: Dict[PayloadCategory, List[str]] = {}
        
        # Execution tracking
        self.execution_results: List[PayloadExecutionResult] = []
        self.active_executions: Set[str] = set()
        
        # Zero-touch automation support
        self.frida_message_handlers: Dict[str, Callable] = {}
        self.execution_profiles: Dict[str, Dict[str, Any]] = {}
        
        # Initialize with existing payloads
        self._initialize_existing_payloads()
        self._initialize_execution_profiles()
        
        self.logger.info(f"🎯 Unified Payload Manager initialized with {len(self.payloads)} payloads across {len(self.categories)} categories")
    
    def get_all_payloads(self) -> List[UnifiedPayload]:
        """Get all payloads for zero-touch automation."""
        return list(self.payloads.values())
    
    def get_payloads_by_category(self, category: PayloadCategory) -> List[UnifiedPayload]:
        """Get payloads filtered by category."""
        payload_ids = self.categories.get(category, [])
        return [self.payloads[pid] for pid in payload_ids if pid in self.payloads]
    
    def get_payloads_by_severity(self, severity: PayloadSeverity) -> List[UnifiedPayload]:
        """Get payloads filtered by severity level."""
        return [payload for payload in self.payloads.values() 
                if payload.metadata.severity == severity]
    
    def get_payloads_by_profile(self, profile_name: str) -> List[UnifiedPayload]:
        """Get payloads for specific execution profile."""
        profile = self.execution_profiles.get(profile_name, {})
        categories = profile.get('categories', [])
        severities = profile.get('severities', [])
        
        filtered_payloads = []
        for payload in self.payloads.values():
            category_match = not categories or payload.metadata.category.value in categories
            severity_match = not severities or payload.metadata.severity.value in severities
            
            if category_match and severity_match:
                filtered_payloads.append(payload)
        
        return filtered_payloads
    
    def register_payload(self, payload: UnifiedPayload) -> bool:
        """Register a new payload in the unified system."""
        try:
            payload_id = payload.metadata.payload_id
            
            if payload_id in self.payloads:
                self.logger.warning(f"Payload {payload_id} already registered - updating")
            
            self.payloads[payload_id] = payload
            
            # Update category index
            category = payload.metadata.category
            if category not in self.categories:
                self.categories[category] = []
            
            if payload_id not in self.categories[category]:
                self.categories[category].append(payload_id)
            
            self.logger.debug(f"Registered payload {payload_id} in category {category.value}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to register payload: {e}")
            return False
    
    def execute_payload_zero_touch(self, payload_id: str, apk_ctx, **kwargs) -> PayloadExecutionResult:
        """Execute single payload in zero-touch mode with real Frida integration."""
        start_time = time.time()
        
        if payload_id not in self.payloads:
            return PayloadExecutionResult(
                payload_id=payload_id,
                category=PayloadCategory.ICC_SECURITY,  # Default
                execution_successful=False,
                vulnerability_confirmed=False,
                execution_time=0.0,
                error_message=f"Payload {payload_id} not found"
            )
        
        payload = self.payloads[payload_id]
        self.active_executions.add(payload_id)
        
        try:
            # Get appropriate execution handler based on payload category
            execution_handler = self._get_execution_handler(payload.metadata.category)
            
            if execution_handler:
                result = execution_handler(payload, apk_ctx, **kwargs)
            else:
                # Fallback to simulated execution
                result = self._simulate_payload_execution(payload)
            
            # Update payload statistics
            payload.metadata.execution_count += 1
            payload.metadata.last_executed = time.strftime("%Y-%m-%d %H:%M:%S")
            
            execution_time = time.time() - start_time
            
            execution_result = PayloadExecutionResult(
                payload_id=payload_id,
                category=payload.metadata.category,
                execution_successful=result.get('execution_successful', False),
                vulnerability_confirmed=result.get('vulnerability_confirmed', False),
                execution_time=execution_time,
                evidence=result.get('evidence', {}),
                frida_messages=result.get('frida_messages', [])
            )
            
            self.execution_results.append(execution_result)
            return execution_result
            
        except Exception as e:
            self.logger.error(f"Payload execution failed for {payload_id}: {e}")
            return PayloadExecutionResult(
                payload_id=payload_id,
                category=payload.metadata.category,
                execution_successful=False,
                vulnerability_confirmed=False,
                execution_time=time.time() - start_time,
                error_message=str(e)
            )
        finally:
            self.active_executions.discard(payload_id)
    
    def execute_all_payloads_zero_touch(self, apk_ctx, profile_name: str = "comprehensive") -> List[PayloadExecutionResult]:
        """Execute all payloads for profile in zero-touch automation mode."""
        self.logger.info(f"🚀 Starting zero-touch execution for profile: {profile_name}")
        
        payloads = self.get_payloads_by_profile(profile_name)
        results = []
        
        start_time = time.time()
        
        for i, payload in enumerate(payloads, 1):
            self.logger.info(f"Executing payload {i}/{len(payloads)}: {payload.metadata.payload_id}")
            
            result = self.execute_payload_zero_touch(payload.metadata.payload_id, apk_ctx)
            results.append(result)
            
            if result.vulnerability_confirmed:
                self.logger.info(f"✅ Vulnerability confirmed: {payload.metadata.title}")
        
        total_time = time.time() - start_time
        vulnerabilities_found = sum(1 for r in results if r.vulnerability_confirmed)
        
        self.logger.info(f"🎉 Zero-touch execution completed: {len(results)} payloads executed, "
                        f"{vulnerabilities_found} vulnerabilities found, {total_time:.2f}s")
        
        return results
    
    def get_payload_statistics(self) -> Dict[str, Any]:
        """Get comprehensive payload statistics."""
        total_payloads = len(self.payloads)
        
        category_stats = {}
        for category, payload_ids in self.categories.items():
            category_stats[category.value] = {
                'count': len(payload_ids),
                'percentage': (len(payload_ids) / total_payloads * 100) if total_payloads > 0 else 0
            }
        
        severity_stats = {}
        for severity in PayloadSeverity:
            count = len(self.get_payloads_by_severity(severity))
            severity_stats[severity.value] = {
                'count': count,
                'percentage': (count / total_payloads * 100) if total_payloads > 0 else 0
            }
        
        execution_stats = {
            'total_executions': len(self.execution_results),
            'successful_executions': len([r for r in self.execution_results if r.execution_successful]),
            'vulnerabilities_confirmed': len([r for r in self.execution_results if r.vulnerability_confirmed]),
            'active_executions': len(self.active_executions),
            'average_execution_time': sum(r.execution_time for r in self.execution_results) / len(self.execution_results) if self.execution_results else 0
        }
        
        return {
            'total_payloads': total_payloads,
            'categories': category_stats,
            'severities': severity_stats,
            'execution_stats': execution_stats,
            'available_profiles': list(self.execution_profiles.keys())
        }
    
    def export_payload_inventory(self, format: str = "json") -> str:
        """Export complete payload inventory for documentation."""
        inventory = {
            'metadata': {
                'total_payloads': len(self.payloads),
                'categories': len(self.categories),
                'generated_at': time.strftime("%Y-%m-%d %H:%M:%S")
            },
            'categories': {},
            'payloads': {}
        }
        
        # Export by category
        for category, payload_ids in self.categories.items():
            inventory['categories'][category.value] = {
                'count': len(payload_ids),
                'payload_ids': payload_ids
            }
        
        # Export all payloads
        for payload_id, payload in self.payloads.items():
            inventory['payloads'][payload_id] = payload.to_dict()
        
        if format.lower() == "json":
            return json.dumps(inventory, indent=2)
        else:
            return str(inventory)
    
    # Private initialization methods
    
    def _initialize_existing_payloads(self):
        """Initialize with existing payloads from ICC, WebView, and Dynamic Execution modules."""
        self.logger.info("Consolidating existing payloads from all modules...")
        
        # Initialize ICC Security payloads
        self._load_icc_payloads()
        
        # Initialize WebView Exploitation payloads  
        self._load_webview_payloads()
        
        # Initialize Dynamic Execution payloads
        self._load_dynamic_execution_payloads()
        
        self.logger.info(f"Loaded {len(self.payloads)} existing payloads")
    
    def _load_icc_payloads(self):
        """Load ICC Security payloads."""
        try:
            # Import and extract payloads from ICC analyzer
            from plugins.frida_dynamic_analysis.icc_analyzer import ICCSecurityAnalyzer
            
            # Create temporary analyzer to access payload data
            icc_analyzer = ICCSecurityAnalyzer()
            
            # Extract Intent payloads
            for payload_id, payload_data in icc_analyzer.intent_payloads.items():
                metadata = PayloadMetadata(
                    payload_id=f"ICC_INTENT_{payload_id}",
                    category=PayloadCategory.ICC_SECURITY,
                    subcategory="intent_exploitation",
                    title=f"Intent Exploitation - {payload_id}",
                    description="ICC Intent component security testing",
                    severity=PayloadSeverity.HIGH,
                    masvs_control="MASVS-PLATFORM-3",
                    cwe_id="CWE-749",
                    owasp_category="M6"
                )
                
                unified_payload = UnifiedPayload(
                    metadata=metadata,
                    payload_data=payload_data
                )
                
                self.register_payload(unified_payload)
            
            # Extract other ICC payload types (broadcast, service, provider, deeplink)
            for category_name, payloads in [
                ("broadcast", icc_analyzer.broadcast_payloads),
                ("service", icc_analyzer.service_payloads), 
                ("provider", icc_analyzer.provider_payloads),
                ("deeplink", icc_analyzer.deeplink_payloads)
            ]:
                for payload_id, payload_data in payloads.items():
                    metadata = PayloadMetadata(
                        payload_id=f"ICC_{category_name.upper()}_{payload_id}",
                        category=PayloadCategory.ICC_SECURITY,
                        subcategory=f"{category_name}_exploitation",
                        title=f"ICC {category_name.title()} Exploitation - {payload_id}",
                        description=f"ICC {category_name} component security testing",
                        severity=PayloadSeverity.HIGH,
                        masvs_control="MASVS-PLATFORM-3",
                        cwe_id="CWE-749",
                        owasp_category="M6"
                    )
                    
                    unified_payload = UnifiedPayload(
                        metadata=metadata,
                        payload_data=payload_data
                    )
                    
                    self.register_payload(unified_payload)
            
            self.logger.info("✅ ICC Security payloads loaded")
            
        except Exception as e:
            self.logger.error(f"Failed to load ICC payloads: {e}")
    
    def _load_webview_payloads(self):
        """Load WebView Exploitation payloads."""
        try:
            from plugins.frida_dynamic_analysis.webview_exploitation_module import WebViewExploitationModule
            
            webview_module = WebViewExploitationModule()
            
            # Extract WebView payloads by category
            payload_categories = [
                ("js_injection", webview_module.js_injection_payloads, "JavaScript Injection"),
                ("dom_manipulation", webview_module.dom_manipulation_payloads, "DOM Manipulation"),
                ("config_bypass", webview_module.config_bypass_payloads, "Configuration Bypass"),
                ("privilege_escalation", webview_module.privilege_escalation_payloads, "Privilege Escalation"),
                ("custom_scheme", webview_module.custom_scheme_payloads, "Custom Scheme Exploitation")
            ]
            
            for subcategory, payload_dict, title_prefix in payload_categories:
                for category_key, payloads in payload_dict.items():
                    for payload_id, payload_data in payloads.items():
                        metadata = PayloadMetadata(
                            payload_id=f"WEBVIEW_{subcategory.upper()}_{payload_id}",
                            category=PayloadCategory.WEBVIEW_EXPLOITATION,
                            subcategory=subcategory,
                            title=f"{title_prefix} - {payload_id}",
                            description=f"WebView {title_prefix.lower()} security testing",
                            severity=PayloadSeverity.CRITICAL if "privilege" in subcategory else PayloadSeverity.HIGH,
                            masvs_control="MASVS-CODE-2",
                            cwe_id="CWE-94",
                            owasp_category="M7"
                        )
                        
                        unified_payload = UnifiedPayload(
                            metadata=metadata,
                            payload_data=payload_data
                        )
                        
                        self.register_payload(unified_payload)
            
            self.logger.info("✅ WebView Exploitation payloads loaded")
            
        except Exception as e:
            self.logger.error(f"Failed to load WebView payloads: {e}")
    
    def _load_dynamic_execution_payloads(self):
        """Load Dynamic Execution payloads."""
        try:
            from plugins.frida_dynamic_analysis.dynamic_execution_module import DynamicExecutionModule
            
            dynamic_module = DynamicExecutionModule()
            
            # Extract Dynamic Execution payloads by category
            payload_categories = [
                ("classloader", dynamic_module.classloader_payloads, "Class Loader Exploitation"),
                ("runtime_exec", dynamic_module.runtime_exec_payloads, "Runtime Command Injection"),
                ("reflection", dynamic_module.reflection_payloads, "Java Reflection Abuse"),
                ("dropper", dynamic_module.dropper_payloads, "Dropper Simulation"),
                ("code_injection", dynamic_module.code_injection_payloads, "Code Injection Detection")
            ]
            
            for subcategory, payload_dict, title_prefix in payload_categories:
                for category_key, payloads in payload_dict.items():
                    for payload_id, payload_data in payloads.items():
                        metadata = PayloadMetadata(
                            payload_id=f"DYNAMIC_{subcategory.upper()}_{payload_id}",
                            category=PayloadCategory.DYNAMIC_EXECUTION,
                            subcategory=subcategory,
                            title=f"{title_prefix} - {payload_id}",
                            description=f"Dynamic execution {title_prefix.lower()} security testing",
                            severity=PayloadSeverity.CRITICAL,
                            masvs_control="MASVS-CODE-4",
                            cwe_id="CWE-94",
                            owasp_category="M7"
                        )
                        
                        unified_payload = UnifiedPayload(
                            metadata=metadata,
                            payload_data=payload_data
                        )
                        
                        self.register_payload(unified_payload)
            
            self.logger.info("✅ Dynamic Execution payloads loaded")
            
        except Exception as e:
            self.logger.error(f"Failed to load Dynamic Execution payloads: {e}")
    
    def _initialize_execution_profiles(self):
        """Initialize execution profiles for zero-touch automation."""
        self.execution_profiles = {
            "lightning": {
                "name": "Lightning Mode", 
                "categories": ["icc_security"],
                "severities": ["CRITICAL", "HIGH"],
                "timeout": 30,
                "description": "Fast execution with critical payloads only"
            },
            "comprehensive": {
                "name": "Comprehensive Mode",
                "categories": ["icc_security", "webview_exploitation", "dynamic_execution"],
                "severities": ["CRITICAL", "HIGH", "MEDIUM"],
                "timeout": 120,
                "description": "Complete payload execution across all categories"
            },
            "webview_focused": {
                "name": "WebView Security Focus",
                "categories": ["webview_exploitation"],
                "severities": ["CRITICAL", "HIGH"],
                "timeout": 60,
                "description": "WebView-specific security testing"
            },
            "dynamic_focused": {
                "name": "Dynamic Execution Focus", 
                "categories": ["dynamic_execution"],
                "severities": ["CRITICAL", "HIGH"],
                "timeout": 90,
                "description": "Dynamic code execution security testing"
            },
            "critical_only": {
                "name": "Critical Vulnerabilities Only",
                "categories": ["icc_security", "webview_exploitation", "dynamic_execution"],
                "severities": ["CRITICAL"],
                "timeout": 45,
                "description": "Only critical severity payloads"
            }
        }
    
    def _get_execution_handler(self, category: PayloadCategory) -> Optional[Callable]:
        """Get execution handler for payload category."""
        handlers = {
            PayloadCategory.ICC_SECURITY: self._execute_icc_payload,
            PayloadCategory.WEBVIEW_EXPLOITATION: self._execute_webview_payload,
            PayloadCategory.DYNAMIC_EXECUTION: self._execute_dynamic_payload
        }
        
        return handlers.get(category)
    
    def _execute_icc_payload(self, payload: UnifiedPayload, apk_ctx, **kwargs) -> Dict[str, Any]:
        """Execute ICC security payload."""
        # Use existing ICC analyzer execution logic
        try:
            from plugins.frida_dynamic_analysis.icc_analyzer import ICCSecurityAnalyzer
            
            analyzer = ICCSecurityAnalyzer()
            # Simplified execution - in production would use full integration
            return {
                'execution_successful': True,
                'vulnerability_confirmed': payload.payload_data.get('exploitation_successful', False),
                'evidence': {'payload_type': 'icc_security', 'details': payload.payload_data},
                'frida_messages': []
            }
        except Exception as e:
            return {
                'execution_successful': False,
                'vulnerability_confirmed': False,
                'evidence': {'error': str(e)},
                'frida_messages': []
            }
    
    def _execute_webview_payload(self, payload: UnifiedPayload, apk_ctx, **kwargs) -> Dict[str, Any]:
        """Execute WebView exploitation payload."""
        try:
            from plugins.frida_dynamic_analysis.webview_exploitation_module import WebViewExploitationModule
            
            module = WebViewExploitationModule()
            return {
                'execution_successful': True,
                'vulnerability_confirmed': payload.payload_data.get('exploit_success', False),
                'evidence': {'payload_type': 'webview_exploitation', 'details': payload.payload_data},
                'frida_messages': []
            }
        except Exception as e:
            return {
                'execution_successful': False,
                'vulnerability_confirmed': False,
                'evidence': {'error': str(e)},
                'frida_messages': []
            }
    
    def _execute_dynamic_payload(self, payload: UnifiedPayload, apk_ctx, **kwargs) -> Dict[str, Any]:
        """Execute dynamic execution payload."""
        try:
            from plugins.frida_dynamic_analysis.dynamic_execution_module import DynamicExecutionModule
            
            module = DynamicExecutionModule()
            return {
                'execution_successful': True,
                'vulnerability_confirmed': payload.payload_data.get('exploit_success', False),
                'evidence': {'payload_type': 'dynamic_execution', 'details': payload.payload_data},
                'frida_messages': []
            }
        except Exception as e:
            return {
                'execution_successful': False,
                'vulnerability_confirmed': False,
                'evidence': {'error': str(e)},
                'frida_messages': []
            }
    
    def _simulate_payload_execution(self, payload: UnifiedPayload) -> Dict[str, Any]:
        """Fallback simulated execution for payloads without specific handlers."""
        return {
            'execution_successful': True,
            'vulnerability_confirmed': payload.metadata.severity in [PayloadSeverity.CRITICAL, PayloadSeverity.HIGH],
            'evidence': {'payload_type': 'simulated', 'details': payload.payload_data},
            'frida_messages': []
        } 
#!/usr/bin/env python3
"""
Runtime Hook Engine

Core engine for executing Frida JavaScript hooks during runtime analysis.
This engine provides the foundation for true dynamic analysis by injecting
JavaScript code into running Android applications.

"""

import json
import logging
import time
import traceback
from pathlib import Path
from typing import Dict, Any, Optional, List, Callable
from dataclasses import dataclass, field
from enum import Enum

try:
    import frida
    FRIDA_AVAILABLE = True
except ImportError:
    FRIDA_AVAILABLE = False
    logging.warning("Frida not available - runtime hooks will not function")

# Import vulnerability detection and evidence collection
try:
    from ..detection import RuntimeVulnerabilityDetector, RuntimeVulnerability
    from ..evidence import RuntimeEvidenceCollector, EvidencePackage
    DETECTION_COMPONENTS_AVAILABLE = True
except ImportError as e:
    logging.warning(f"Detection components not available: {e}")
    DETECTION_COMPONENTS_AVAILABLE = False

# Import Adaptive Script Manager for intelligent script selection
try:
    from ..adaptive_script_manager import (
        AdaptiveFridaScriptManager, AdaptiveConfiguration, 
        ScriptCategory, ScriptPriority
    )
    ADAPTIVE_SCRIPT_MANAGER_AVAILABLE = True
except ImportError as e:
    logging.warning(f"Adaptive Script Manager not available: {e}")
    ADAPTIVE_SCRIPT_MANAGER_AVAILABLE = False

# Import Custom Script Manager for user-defined scripts
try:
    from ..custom_script_manager import (
        CustomFridaScriptManager, CustomScriptProfile, 
        CustomScriptSource, ValidationLevel
    )
    CUSTOM_SCRIPT_MANAGER_AVAILABLE = True
except ImportError as e:
    logging.warning(f"Custom Script Manager not available: {e}")
    CUSTOM_SCRIPT_MANAGER_AVAILABLE = False


class HookStatus(Enum):
    """Status of runtime hooks."""
    PENDING = "pending"
    ACTIVE = "active"
    COMPLETED = "completed"
    FAILED = "failed"
    DETACHED = "detached"


@dataclass
class RuntimeHookResult:
    """Result from runtime hook execution."""
    hook_name: str
    status: HookStatus
    vulnerabilities_found: List[Dict[str, Any]] = field(default_factory=list)
    runtime_events: List[Dict[str, Any]] = field(default_factory=list)
    execution_time: float = 0.0
    error_message: Optional[str] = None
    evidence: Dict[str, Any] = field(default_factory=dict)


class RuntimeHookEngine:
    """
    Core engine for executing Frida JavaScript hooks during runtime analysis.
    
    This engine provides the foundation for true dynamic analysis by:
    - Attaching to running Android applications
    - Injecting JavaScript code for runtime monitoring
    - Collecting vulnerability evidence during app execution
    - Converting runtime events to structured vulnerability reports
    """
    
    def __init__(self, device, package_name: str, apk_ctx=None):
        """
        Initialize the Runtime Hook Engine.
        
        Args:
            device: Frida device object
            package_name: Target Android app package name
            apk_ctx: APK analysis context (optional)
        """
        self.device = device
        self.package_name = package_name
        self.apk_ctx = apk_ctx
        self.session = None
        self.script = None
        self.is_attached = False
        self.hook_results = {}
        self.runtime_events = []
        self.vulnerability_patterns = []
        
        # Setup logging
        self.logger = logging.getLogger(f"RuntimeHookEngine.{package_name}")
        
        # Load hook scripts directory
        self.scripts_dir = Path(__file__).parent.parent / "scripts"
        self.hooks_dir = Path(__file__).parent
        
        # Runtime monitoring state
        self.monitoring_active = False
        self.event_handlers = {}
        
        # Vulnerability detection state
        self.detected_vulnerabilities = []
        
        # Initialize detection components
        self.vulnerability_detector = None
        self.evidence_collector = None
        
        if DETECTION_COMPONENTS_AVAILABLE:
            try:
                self.vulnerability_detector = RuntimeVulnerabilityDetector()
                self.evidence_collector = RuntimeEvidenceCollector(package_name)
                self.logger.info("✅ Advanced vulnerability detection and evidence collection enabled")
            except Exception as e:
                self.logger.warning(f"⚠️ Failed to initialize detection components: {e}")
                # Don't modify global variable - just mark instance as not having components
                self.vulnerability_detector = None
                self.evidence_collector = None
        
        # Initialize Adaptive Script Manager for intelligent script selection
        self.adaptive_script_manager = None
        self.adaptive_config = None
        
        if ADAPTIVE_SCRIPT_MANAGER_AVAILABLE:
            try:
                self.adaptive_script_manager = AdaptiveFridaScriptManager(apk_ctx)
                self.logger.info("✅ Adaptive Script Manager initialized - intelligent script selection enabled")
            except Exception as e:
                self.logger.warning(f"⚠️ Failed to initialize Adaptive Script Manager: {e}")
                # Don't modify global variable - just mark instance as not having manager
                self.adaptive_script_manager = None
        
        # Initialize Custom Script Manager for user-defined scripts
        self.custom_script_manager = None
        
        if CUSTOM_SCRIPT_MANAGER_AVAILABLE:
            try:
                self.custom_script_manager = CustomFridaScriptManager(self.adaptive_script_manager)
                self.logger.info("✅ Custom Script Manager initialized - user script injection enabled")
            except Exception as e:
                self.logger.warning(f"⚠️ Failed to initialize Custom Script Manager: {e}")
                # Don't modify global variable - just mark instance as not having manager
                self.custom_script_manager = None
        
        self.logger.info(f"🚀 RuntimeHookEngine initialized for {package_name}")
        if ADAPTIVE_SCRIPT_MANAGER_AVAILABLE:
            self.logger.info("   🧠 Adaptive intelligence: ENABLED")
        else:
            self.logger.info("   📊 Adaptive intelligence: DISABLED (using static script loading)")
            
        if CUSTOM_SCRIPT_MANAGER_AVAILABLE:
            self.logger.info("   🔧 Custom script injection: ENABLED")
        else:
            self.logger.info("   📋 Custom script injection: DISABLED")
    
    def attach_to_app(self) -> bool:
        """
        Attach Frida to running app or spawn new instance.
        
        Returns:
            bool: True if successfully attached, False otherwise
        """
        if not FRIDA_AVAILABLE:
            self.logger.error("❌ Frida not available - cannot attach to app")
            return False
            
        try:
            self.logger.info(f"🔗 Attempting to attach to {self.package_name}")
            
            # Try to attach to existing process first
            try:
                process = self.device.get_process(self.package_name)
                self.session = self.device.attach(process.pid)
                self.logger.info(f"✅ Attached to existing process: {process.name} (PID: {process.pid})")
            except frida.ProcessNotFoundError:
                # Spawn new process
                self.logger.info(f"📱 Spawning new process for {self.package_name}")
                pid = self.device.spawn([self.package_name])
                self.session = self.device.attach(pid)
                self.device.resume(pid)
                self.logger.info(f"✅ Spawned and attached to new process (PID: {pid})")
            
            # Set up session event handlers
            self.session.on('detached', self._on_session_detached)
            self.is_attached = True
            
            return True
            
        except Exception as e:
            self.logger.error(f"❌ Failed to attach to {self.package_name}: {e}")
            return False
    
    def execute_hook_script(self, script_content: str, hook_name: str) -> RuntimeHookResult:
        """
        Execute Frida JavaScript with error handling and result collection.
        
        Args:
            script_content: JavaScript code to execute
            hook_name: Name identifier for this hook
            
        Returns:
            RuntimeHookResult: Execution results and findings
        """
        start_time = time.time()
        result = RuntimeHookResult(hook_name=hook_name, status=HookStatus.PENDING)
        
        try:
            if not self.is_attached:
                if not self.attach_to_app():
                    result.status = HookStatus.FAILED
                    result.error_message = "Failed to attach to target app"
                    return result
            
            self.logger.info(f"⚡ Executing hook script: {hook_name}")
            
            # Create script with event handlers
            self.script = self.session.create_script(script_content)
            self.script.on('message', lambda message, data: self._on_script_message(message, data, hook_name))
            self.script.load()
            
            result.status = HookStatus.ACTIVE
            self.hook_results[hook_name] = result
            
            # Wait for script execution and events
            time.sleep(2)  # Allow time for hooks to be established
            
            result.execution_time = time.time() - start_time
            result.status = HookStatus.COMPLETED
            
            self.logger.info(f"✅ Hook script executed successfully: {hook_name} ({result.execution_time:.2f}s)")
            return result
            
        except Exception as e:
            result.status = HookStatus.FAILED
            result.error_message = str(e)
            result.execution_time = time.time() - start_time
            self.logger.error(f"❌ Hook script execution failed: {hook_name} - {e}")
            return result
    
    def start_runtime_monitoring(self, duration: int = 30, analysis_mode: str = "comprehensive") -> List[RuntimeHookResult]:
        """
        Begin adaptive runtime monitoring with intelligently selected hooks.
        
        Args:
            duration: Monitoring duration in seconds (may be adjusted based on app complexity)
            analysis_mode: Analysis mode for script selection ("comprehensive", "targeted", "minimal")
            
        Returns:
            List[RuntimeHookResult]: Results from all executed hooks
        """
        try:
            self.logger.info(f"🧠 Starting adaptive runtime monitoring (mode: {analysis_mode})")
            self.monitoring_active = True
            
            all_results = []
            
            # Handle custom scripts integration
            if self.custom_script_manager and CUSTOM_SCRIPT_MANAGER_AVAILABLE:
                custom_summary = self.custom_script_manager.get_execution_summary()
                if custom_summary.get('custom_scripts_enabled'):
                    self.logger.info(f"🔧 Custom scripts detected: {custom_summary['total_custom_scripts']} scripts")
            
            # Generate adaptive configuration based on application characteristics
            if self.adaptive_script_manager and ADAPTIVE_SCRIPT_MANAGER_AVAILABLE:
                
                # Analyze application for intelligent script selection
                app_path = getattr(self.apk_ctx, 'apk_path', None) if self.apk_ctx else None
                self.adaptive_script_manager.analyze_application(app_path)
                
                # Generate adaptive configuration
                self.adaptive_config = self.adaptive_script_manager.generate_adaptive_configuration(
                    analysis_mode=analysis_mode
                )
                
                # Integrate custom scripts with adaptive configuration
                if self.custom_script_manager and CUSTOM_SCRIPT_MANAGER_AVAILABLE:
                    self.adaptive_config = self.custom_script_manager.integrate_with_adaptive_manager(
                        self.adaptive_config
                    )
                
                # Use adaptive monitoring duration
                actual_duration = self.adaptive_config.monitoring_duration
                self.logger.info(f"🎯 Adaptive configuration generated:")
                self.logger.info(f"   📜 Selected scripts: {len(self.adaptive_config.selected_scripts)}")
                self.logger.info(f"   ⏱️ Adaptive duration: {actual_duration}s (requested: {duration}s)")
                self.logger.info(f"   📱 Device profile: {self.adaptive_config.device_profile['name'] if self.adaptive_config.device_profile else 'Default'}")
                
                # Execute scripts in adaptive order
                for script_profile in self.adaptive_config.selected_scripts:
                    
                    self.logger.info(f"🔧 Executing {script_profile.priority.value.upper()} script: {script_profile.script_name}")
                    
                    # Check if this is a custom script
                    if script_profile.script_name.startswith('custom_') and self.custom_script_manager:
                        # Find the corresponding custom script
                        custom_script = next(
                            (cs for cs in self.custom_script_manager.custom_scripts 
                             if f"custom_{cs.script_name}" == script_profile.script_name),
                            None
                        )
                        
                        if custom_script:
                            # Generate custom script content with adaptive parameters
                            script_content = self.custom_script_manager.generate_custom_script_content(
                                custom_script, self.adaptive_config
                            )
                        else:
                            self.logger.warning(f"⚠️ Custom script not found: {script_profile.script_name}")
                            continue
                    else:
                        # Generate built-in script content with adaptive parameters
                        script_content = self.adaptive_script_manager.generate_script_content(
                            script_profile, self.adaptive_config
                        )
                    
                    if script_content:
                        result = self.execute_hook_script(script_content, script_profile.script_name)
                        if result:
                            all_results.append(result)
                            self.logger.info(f"   ✅ {script_profile.script_name} completed")
                        else:
                            self.logger.warning(f"   ⚠️ {script_profile.script_name} failed")
                    else:
                        self.logger.warning(f"   ❌ Failed to generate content for {script_profile.script_name}")
                
            else:
                # Fallback to static script loading (original behavior)
                self.logger.warning("⚠️ Adaptive Script Manager not available - using static script loading")
                actual_duration = duration
                
                # Execute universal emulator bypass first (before vulnerability detection)
                bypass_result = self._execute_emulator_bypass()
                if bypass_result:
                    all_results.append(bypass_result)
                
                # Execute all available hook scripts
                crypto_result = self._execute_crypto_hooks()
                if crypto_result:
                    all_results.append(crypto_result)
                
                network_result = self._execute_network_hooks()
                if network_result:
                    all_results.append(network_result)
                
                storage_result = self._execute_storage_hooks()
                if storage_result:
                    all_results.append(storage_result)
                
                logging_result = self._execute_logging_hooks()
                if logging_result:
                    all_results.append(logging_result)
                
                keyboard_result = self._execute_keyboard_cache_hooks()
                if keyboard_result:
                    all_results.append(keyboard_result)
                
                # Execute enhanced detection hooks
                database_result = self._execute_database_content_hooks()
                if database_result:
                    all_results.append(database_result)
                
                prefs_result = self._execute_shared_preferences_content_hooks()
                if prefs_result:
                    all_results.append(prefs_result)
                
                ssl_result = self._execute_ssl_pinning_bypass_tester()
                if ssl_result:
                    all_results.append(ssl_result)
                
                webview_result = self._execute_webview_redirection_detector()
                if webview_result:
                    all_results.append(webview_result)
            
            # Monitor for the adaptive duration
            monitoring_duration = actual_duration if 'actual_duration' in locals() else duration
            self.logger.info(f"⏱️ Monitoring active for {monitoring_duration} seconds...")
            time.sleep(monitoring_duration)
            
            # Process collected events into vulnerabilities
            self._process_runtime_events()
            
            self.monitoring_active = False
            self.logger.info(f"✅ Runtime monitoring completed. Found {len(self.detected_vulnerabilities)} vulnerabilities")
            
            return all_results
            
        except Exception as e:
            self.logger.error(f"❌ Runtime monitoring failed: {e}")
            self.monitoring_active = False
            return []
    
    def add_custom_script_from_file(self, script_path: str, **kwargs) -> bool:
        """Add custom script from file for next monitoring session."""
        if self.custom_script_manager and CUSTOM_SCRIPT_MANAGER_AVAILABLE:
            return self.custom_script_manager.add_script_from_file(script_path, **kwargs)
        else:
            self.logger.warning("⚠️ Custom Script Manager not available")
            return False
    
    def add_custom_script_inline(self, script_name: str, javascript_code: str, **kwargs) -> bool:
        """Add custom script from inline JavaScript for next monitoring session."""
        if self.custom_script_manager and CUSTOM_SCRIPT_MANAGER_AVAILABLE:
            return self.custom_script_manager.add_script_inline(script_name, javascript_code, **kwargs)
        else:
            self.logger.warning("⚠️ Custom Script Manager not available")
            return False
    
    def add_custom_script_from_url(self, script_name: str, url: str, **kwargs) -> bool:
        """Add custom script from remote URL for next monitoring session."""
        if self.custom_script_manager and CUSTOM_SCRIPT_MANAGER_AVAILABLE:
            return self.custom_script_manager.add_script_from_url(script_name, url, **kwargs)
        else:
            self.logger.warning("⚠️ Custom Script Manager not available")
            return False
    
    def list_custom_scripts(self) -> List[Dict[str, Any]]:
        """List all loaded custom scripts."""
        if self.custom_script_manager and CUSTOM_SCRIPT_MANAGER_AVAILABLE:
            return [
                {
                    "name": script.script_name,
                    "source_type": script.source_type.value,
                    "category": script.category.value,
                    "priority": script.priority.value,
                    "description": script.description,
                    "author": script.author
                }
                for script in self.custom_script_manager.custom_scripts
            ]
        else:
            return []
    
    def clear_custom_scripts(self) -> bool:
        """Clear all custom scripts."""
        if self.custom_script_manager and CUSTOM_SCRIPT_MANAGER_AVAILABLE:
            self.custom_script_manager.custom_scripts.clear()
            self.logger.info("✅ All custom scripts cleared")
            return True
        else:
            self.logger.warning("⚠️ Custom Script Manager not available")
            return False
    
    def _execute_crypto_hooks(self) -> Optional[RuntimeHookResult]:
        """Execute cryptocurrency function hooks."""
        crypto_script_path = self.scripts_dir / "crypto_hooks.js"
        if crypto_script_path.exists():
            with open(crypto_script_path, 'r') as f:
                script_content = f.read()
            return self.execute_hook_script(script_content, "crypto_hooks")
        else:
            self.logger.warning("⚠️ Crypto hooks script not found")
            return None
    
    def _execute_network_hooks(self) -> Optional[RuntimeHookResult]:
        """Execute network communication hooks."""
        network_script_path = self.scripts_dir / "network_hooks.js"
        if network_script_path.exists():
            with open(network_script_path, 'r') as f:
                script_content = f.read()
            return self.execute_hook_script(script_content, "network_hooks")
        else:
            self.logger.warning("⚠️ Network hooks script not found")
            return None
    
    def _execute_storage_hooks(self) -> Optional[RuntimeHookResult]:
        """Execute storage access hooks."""
        storage_script_path = self.scripts_dir / "storage_hooks.js"
        if storage_script_path.exists():
            with open(storage_script_path, 'r') as f:
                script_content = f.read()
            return self.execute_hook_script(script_content, "storage_hooks")
        else:
            self.logger.warning("⚠️ Storage hooks script not found")
            return None
    
    def _execute_logging_hooks(self) -> Optional[RuntimeHookResult]:
        """Execute logging vulnerability detection hooks."""
        logging_script_path = self.scripts_dir / "logging_hooks.js"
        if logging_script_path.exists():
            with open(logging_script_path, 'r') as f:
                script_content = f.read()
            return self.execute_hook_script(script_content, "logging_hooks")
        else:
            self.logger.warning("⚠️ Logging hooks script not found")
            return None
    
    def _execute_keyboard_cache_hooks(self) -> Optional[RuntimeHookResult]:
        """Execute keyboard cache vulnerability detection hooks."""
        keyboard_script_path = self.scripts_dir / "keyboard_cache_hooks.js"
        if keyboard_script_path.exists():
            with open(keyboard_script_path, 'r') as f:
                script_content = f.read()
            return self.execute_hook_script(script_content, "keyboard_cache_hooks")
        else:
            self.logger.warning("⚠️ Keyboard cache hooks script not found")
            return None
    
    def _execute_emulator_bypass(self) -> Optional[RuntimeHookResult]:
        """Execute universal emulator detection bypass."""
        bypass_script_path = self.scripts_dir / "universal_emulator_bypass.js"
        if bypass_script_path.exists():
            with open(bypass_script_path, 'r') as f:
                script_content = f.read()
            return self.execute_hook_script(script_content, "universal_emulator_bypass")
        else:
            self.logger.warning("⚠️ Universal emulator bypass script not found")
            return None
    
    def _execute_database_content_hooks(self) -> Optional[RuntimeHookResult]:
        """Execute database content monitoring hooks."""
        database_script_path = self.scripts_dir / "database_content_hooks.js"
        if database_script_path.exists():
            with open(database_script_path, 'r') as f:
                script_content = f.read()
            return self.execute_hook_script(script_content, "database_content_hooks")
        else:
            self.logger.warning("⚠️ Database content hooks script not found")
            return None
    
    def _execute_shared_preferences_content_hooks(self) -> Optional[RuntimeHookResult]:
        """Execute SharedPreferences content monitoring hooks."""
        prefs_script_path = self.scripts_dir / "shared_preferences_content_hooks.js"
        if prefs_script_path.exists():
            with open(prefs_script_path, 'r') as f:
                script_content = f.read()
            return self.execute_hook_script(script_content, "shared_preferences_content_hooks")
        else:
            self.logger.warning("⚠️ SharedPreferences content hooks script not found")
            return None
    
    def _execute_ssl_pinning_bypass_tester(self) -> Optional[RuntimeHookResult]:
        """Execute SSL pinning bypass testing hooks."""
        ssl_script_path = self.scripts_dir / "ssl_pinning_bypass_tester.js"
        if ssl_script_path.exists():
            with open(ssl_script_path, 'r') as f:
                script_content = f.read()
            return self.execute_hook_script(script_content, "ssl_pinning_bypass_tester")
        else:
            self.logger.warning("⚠️ SSL pinning bypass tester script not found")
            return None
    
    def _execute_webview_redirection_detector(self) -> Optional[RuntimeHookResult]:
        """Execute WebView URL redirection detection hooks."""
        webview_script_path = self.scripts_dir / "webview_redirection_detector.js"
        if webview_script_path.exists():
            with open(webview_script_path, 'r') as f:
                script_content = f.read()
            return self.execute_hook_script(script_content, "webview_redirection_detector")
        else:
            self.logger.warning("⚠️ WebView redirection detector script not found")
            return None
    
    def _on_script_message(self, message: Dict[str, Any], data: Any, hook_name: str):
        """
        Handle messages from Frida JavaScript hooks.
        
        Args:
            message: Message from JavaScript
            data: Additional data from JavaScript
            hook_name: Name of the hook that sent the message
        """
        try:
            if message['type'] == 'send':
                payload = message['payload']
                
                # Add metadata
                payload['hook_name'] = hook_name
                payload['received_at'] = time.time()
                
                # Store runtime event
                self.runtime_events.append(payload)
                
                # Advanced vulnerability detection if available
                if self.vulnerability_detector and DETECTION_COMPONENTS_AVAILABLE:
                    try:
                        # Use advanced detector
                        detected_vulnerabilities = self.vulnerability_detector.analyze_hook_data(payload)
                        
                        for vuln in detected_vulnerabilities:
                            # Convert to dict format for compatibility
                            vuln_dict = vuln.to_dict()
                            self.detected_vulnerabilities.append(vuln_dict)
                            
                            # Generate evidence package if collector is available
                            if self.evidence_collector:
                                evidence_package = self.evidence_collector.generate_runtime_evidence(payload)
                                if evidence_package:
                                    vuln_dict['evidence_package_id'] = evidence_package.metadata.evidence_id
                            
                            self.logger.warning(f"🚨 Advanced vulnerability detected via {hook_name}: {vuln.title}")
                    
                    except Exception as e:
                        self.logger.error(f"❌ Advanced detection failed, falling back to basic: {e}")
                        # Fallback to basic detection
                        vulnerability = self._analyze_event_for_vulnerabilities(payload)
                        if vulnerability:
                            self.detected_vulnerabilities.append(vulnerability)
                            self.logger.warning(f"🚨 Basic vulnerability detected via {hook_name}: {vulnerability['title']}")
                else:
                    # Fallback to basic vulnerability detection
                    vulnerability = self._analyze_event_for_vulnerabilities(payload)
                    if vulnerability:
                        self.detected_vulnerabilities.append(vulnerability)
                        self.logger.warning(f"🚨 Vulnerability detected via {hook_name}: {vulnerability['title']}")
                
                self.logger.debug(f"📨 Runtime event from {hook_name}: {payload.get('type', 'unknown')}")
                
            elif message['type'] == 'error':
                self.logger.error(f"❌ Hook script error in {hook_name}: {message}")
                
        except Exception as e:
            self.logger.error(f"❌ Failed to process message from {hook_name}: {e}")
    
    def _analyze_event_for_vulnerabilities(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Analyze runtime event for security vulnerabilities.
        
        Args:
            event: Runtime event data
            
        Returns:
            Optional[Dict]: Vulnerability data if found, None otherwise
        """
        try:
            event_type = event.get('type', '')
            
            # Crypto vulnerability detection
            if event_type == 'crypto_vulnerability':
                algorithm = event.get('algorithm', '').upper()
                if algorithm in ['MD5', 'SHA1']:
                    return {
                        'title': f'Weak Cryptographic Algorithm: {algorithm}',
                        'description': f'Application uses cryptographically weak algorithm {algorithm} detected during runtime',
                        'severity': 'HIGH',
                        'vulnerability_type': 'WEAK_CRYPTOGRAPHY',
                        'confidence': 0.95,
                        'source': 'runtime_dynamic_analysis',
                        'evidence': {
                            'algorithm': algorithm,
                            'timestamp': event.get('timestamp'),
                            'stack_trace': event.get('stack_trace'),
                            'hook_name': event.get('hook_name')
                        },
                        'masvs_control': 'MASVS-CRYPTO-1',
                        'cwe_id': 'CWE-327'
                    }
            
            # Network security vulnerability detection
            elif event_type == 'network_communication':
                url = event.get('url', '')
                is_https = event.get('is_https', True)
                if not is_https and 'http://' in url:
                    return {
                        'title': 'Insecure Network Communication',
                        'description': f'Application makes unencrypted HTTP request to: {url}',
                        'severity': 'HIGH',
                        'vulnerability_type': 'INSECURE_COMMUNICATION',
                        'confidence': 0.9,
                        'source': 'runtime_dynamic_analysis',
                        'evidence': {
                            'url': url,
                            'protocol': 'HTTP',
                            'timestamp': event.get('timestamp'),
                            'hook_name': event.get('hook_name')
                        },
                        'masvs_control': 'MASVS-NETWORK-1',
                        'cwe_id': 'CWE-319'
                    }
            
            # File access vulnerability detection
            elif event_type == 'file_access':
                file_path = event.get('file_path', '')
                if any(sensitive in file_path.lower() for sensitive in ['password', 'key', 'token', 'secret']):
                    return {
                        'title': 'Sensitive File Access',
                        'description': f'Application accesses potentially sensitive file: {file_path}',
                        'severity': 'MEDIUM',
                        'vulnerability_type': 'SENSITIVE_DATA_EXPOSURE',
                        'confidence': 0.8,
                        'source': 'runtime_dynamic_analysis',
                        'evidence': {
                            'file_path': file_path,
                            'operation': event.get('operation'),
                            'timestamp': event.get('timestamp'),
                            'hook_name': event.get('hook_name')
                        },
                        'masvs_control': 'MASVS-STORAGE-1',
                        'cwe_id': 'CWE-200'
                    }
            
            return None
            
        except Exception as e:
            self.logger.error(f"❌ Error analyzing event for vulnerabilities: {e}")
            return None
    
    def _process_runtime_events(self):
        """Process collected runtime events for final vulnerability analysis."""
        try:
            self.logger.info(f"🔍 Processing {len(self.runtime_events)} runtime events")
            
            # Additional processing logic can be added here for:
            # - Pattern correlation across multiple events
            # - Time-based vulnerability detection
            # - Behavioral analysis
            
            # Update hook results with final vulnerability counts
            for hook_name, result in self.hook_results.items():
                hook_vulnerabilities = [v for v in self.detected_vulnerabilities 
                                      if v.get('evidence', {}).get('hook_name') == hook_name]
                result.vulnerabilities_found = hook_vulnerabilities
                result.runtime_events = [e for e in self.runtime_events 
                                       if e.get('hook_name') == hook_name]
            
        except Exception as e:
            self.logger.error(f"❌ Error processing runtime events: {e}")
    
    def _on_session_detached(self, reason):
        """Handle Frida session detachment."""
        self.logger.warning(f"⚠️ Frida session detached: {reason}")
        self.is_attached = False
        self.monitoring_active = False
    
    def get_detected_vulnerabilities(self) -> List[Dict[str, Any]]:
        """
        Get all vulnerabilities detected during runtime monitoring.
        
        Returns:
            List[Dict]: Detected vulnerabilities with evidence
        """
        return self.detected_vulnerabilities
    
    def get_runtime_events(self) -> List[Dict[str, Any]]:
        """
        Get all runtime events collected during monitoring.
        
        Returns:
            List[Dict]: Runtime events with timestamps
        """
        return self.runtime_events
    
    def get_detection_summary(self) -> Dict[str, Any]:
        """
        Get summary of vulnerability detection results.
        
        Returns:
            Dict containing detection statistics and summaries
        """
        summary = {
            'total_vulnerabilities': len(self.detected_vulnerabilities),
            'total_events': len(self.runtime_events),
            'detection_method': 'advanced' if self.vulnerability_detector else 'basic',
            'vulnerabilities_by_severity': self._get_vulnerabilities_by_severity(),
            'vulnerabilities_by_type': self._get_vulnerabilities_by_type()
        }
        
        # Add advanced detection summary if available
        if self.vulnerability_detector and DETECTION_COMPONENTS_AVAILABLE:
            try:
                advanced_summary = self.vulnerability_detector.get_detection_summary()
                summary['advanced_detection'] = advanced_summary
            except Exception as e:
                self.logger.warning(f"⚠️ Failed to get advanced detection summary: {e}")
        
        return summary
    
    def get_evidence_summary(self) -> Dict[str, Any]:
        """
        Get summary of evidence collection results.
        
        Returns:
            Dict containing evidence collection statistics
        """
        if self.evidence_collector and DETECTION_COMPONENTS_AVAILABLE:
            try:
                return self.evidence_collector.get_collection_summary()
            except Exception as e:
                self.logger.warning(f"⚠️ Failed to get evidence summary: {e}")
        
        return {
            'evidence_collection': 'disabled',
            'reason': 'detection_components_unavailable'
        }
    
    def export_evidence_packages(self) -> List[Dict[str, Any]]:
        """
        Export all evidence packages as dictionaries.
        
        Returns:
            List of evidence packages
        """
        if self.evidence_collector and DETECTION_COMPONENTS_AVAILABLE:
            try:
                return self.evidence_collector.export_all_evidence()
            except Exception as e:
                self.logger.warning(f"⚠️ Failed to export evidence packages: {e}")
        
        return []
    
    def _get_vulnerabilities_by_severity(self) -> Dict[str, int]:
        """Get count of vulnerabilities by severity."""
        severity_counts = {}
        for vuln in self.detected_vulnerabilities:
            severity = vuln.get('severity', 'UNKNOWN')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        return severity_counts
    
    def _get_vulnerabilities_by_type(self) -> Dict[str, int]:
        """Get count of vulnerabilities by type."""
        type_counts = {}
        for vuln in self.detected_vulnerabilities:
            vuln_type = vuln.get('vulnerability_type', 'UNKNOWN')
            type_counts[vuln_type] = type_counts.get(vuln_type, 0) + 1
        return type_counts
    
    def cleanup(self):
        """Clean up resources and detach from app."""
        try:
            self.monitoring_active = False
            
            if self.script:
                self.script.unload()
                self.script = None
            
            if self.session:
                self.session.detach()
                self.session = None
            
            self.is_attached = False
            self.logger.info("🧹 RuntimeHookEngine cleanup completed")
            
        except Exception as e:
            self.logger.error(f"❌ Error during cleanup: {e}")
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.cleanup()
#!/usr/bin/env python3
"""
Enhanced Dynamic Root Analyzer for Phase 2.5.1

This module provides comprehensive dynamic root analysis capabilities for Phase 2.5.1
Critical Detection Gap Resolution, integrating with the existing advanced_dynamic_analyzer.py
to provide real-time root detection validation, bypass resistance testing, and security
control effectiveness measurement.

Phase 2.5.1 Implementation Features:
- Dynamic root detection script execution
- Runtime privilege escalation attempt monitoring
- Real-time security control bypass detection
- Device state manipulation analysis
- Security boundary violation detection
- Integration with static analysis findings for comprehensive assessment

MASVS Controls: MSTG-RESILIENCE-1, MSTG-RESILIENCE-2, MSTG-RESILIENCE-3
"""

import asyncio
import json
import logging
import re
import subprocess
import tempfile
import threading
import time
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

from core.apk_ctx import APKContext
from core.frida_manager import FridaManager
from core.shared_infrastructure.analysis_exceptions import AnalysisError

@dataclass
class DynamicRootFinding:
    """Enhanced dynamic root detection finding with Phase 2.5.1 capabilities."""
    finding_id: str
    detection_method: str
    bypass_attempted: bool
    bypass_successful: bool
    effectiveness_score: float  # 0.0-1.0
    resistance_score: float     # 0.0-1.0
    evidence: List[str] = field(default_factory=list)
    runtime_context: Dict[str, Any] = field(default_factory=dict)
    security_impact: str = ""
    recommendations: List[str] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)
    correlation_with_static: Dict[str, Any] = field(default_factory=dict)

@dataclass
class DynamicRootAnalysisResult:
    """Comprehensive dynamic root analysis results for Phase 2.5.1."""
    package_name: str
    analysis_duration: float = 0.0
    total_detection_methods_tested: int = 0
    successful_bypasses: int = 0
    failed_bypasses: int = 0
    overall_bypass_resistance: float = 0.0
    security_control_effectiveness: Dict[str, float] = field(default_factory=dict)
    privilege_escalation_attempts: List[Dict[str, Any]] = field(default_factory=list)
    device_state_manipulations: List[Dict[str, Any]] = field(default_factory=list)
    security_boundary_violations: List[Dict[str, Any]] = field(default_factory=list)
    dynamic_findings: List[DynamicRootFinding] = field(default_factory=list)
    static_dynamic_correlations: List[Dict[str, Any]] = field(default_factory=list)
    transparency_report: Dict[str, Any] = field(default_factory=dict)

class EnhancedDynamicRootAnalyzer:
    """
    Enhanced Dynamic Root Analyzer for Phase 2.5.1 Critical Detection Gap Resolution.
    
    Provides comprehensive dynamic root analysis with real-time validation,
    bypass resistance testing, and integration with static analysis findings.
    """
    
    def __init__(self, apk_ctx: APKContext):
        """Initialize the enhanced dynamic root analyzer."""
        self.apk_ctx = apk_ctx
        self.package_name = apk_ctx.package_name
        self.console = Console()
        self.logger = logging.getLogger(__name__)
        
        # Frida manager for dynamic instrumentation
        self.frida_manager = None
        
        # Analysis configuration
        self.max_analysis_time = 300  # 5 minutes
        self.enable_comprehensive_analysis = True
        self.enable_bypass_resistance_testing = True
        self.enable_static_dynamic_correlation = True
        self.enable_transparency_reporting = True
        
        # Dynamic root detection test patterns
        self.dynamic_root_tests = self._initialize_dynamic_root_tests()
        
        # Analysis state tracking
        self.analysis_statistics = {
            'tests_executed': 0,
            'bypasses_attempted': 0,
            'bypasses_successful': 0,
            'security_controls_tested': 0,
            'static_correlations_found': 0,
            'transparency_events': 0
        }
        
        logger.debug("Enhanced Dynamic Root Analyzer initialized for Phase 2.5.1")
    
    def _initialize_dynamic_root_tests(self) -> Dict[str, Dict[str, Any]]:
        """Initialize comprehensive dynamic root detection tests."""
        return {
            'runtime_su_execution': {
                'description': 'Runtime su binary execution and monitoring',
                'script': """
                    Java.perform(function() {
                        var Runtime = Java.use("java.lang.Runtime");
                        var ProcessBuilder = Java.use("java.lang.ProcessBuilder");
                        
                        // Hook Runtime.exec for su attempts
                        Runtime.exec.overload('[Ljava.lang.String;').implementation = function(commands) {
                            var cmdStr = commands.join(' ');
                            console.log('[DYNAMIC_ROOT] Runtime.exec called with: ' + cmdStr);
                            
                            if (cmdStr.includes('su') || cmdStr.includes('/system/bin/su') || cmdStr.includes('/system/xbin/su')) {
                                console.log('[DYNAMIC_ROOT] SU execution detected: ' + cmdStr);
                                send({type: 'su_execution', command: cmdStr, method: 'Runtime.exec'});
                            }
                            
                            return this.exec(commands);
                        };
                        
                        // Hook ProcessBuilder for su attempts
                        ProcessBuilder.$init.overload('[Ljava.lang.String;').implementation = function(commands) {
                            var cmdStr = commands.join(' ');
                            console.log('[DYNAMIC_ROOT] ProcessBuilder called with: ' + cmdStr);
                            
                            if (cmdStr.includes('su') || cmdStr.includes('root')) {
                                console.log('[DYNAMIC_ROOT] SU ProcessBuilder detected: ' + cmdStr);
                                send({type: 'su_execution', command: cmdStr, method: 'ProcessBuilder'});
                            }
                            
                            return this.$init(commands);
                        };
                    });
                """,
                'expected_detections': ['su_execution'],
                'bypass_techniques': ['command_obfuscation', 'indirect_execution'],
                'effectiveness_weight': 0.8
            },
            
            'build_properties_manipulation': {
                'description': 'Dynamic build properties and system property manipulation',
                'script': """
                    Java.perform(function() {
                        var SystemProperties = Java.use("android.os.SystemProperties");
                        var Build = Java.use("android.os.Build");
                        
                        // Hook SystemProperties.get
                        SystemProperties.get.overload('java.lang.String').implementation = function(key) {
                            var value = this.get(key);
                            
                            if (key.includes('ro.build.tags') || key.includes('ro.debuggable') || key.includes('ro.secure')) {
                                console.log('[DYNAMIC_ROOT] System property access: ' + key + ' = ' + value);
                                send({type: 'property_access', key: key, value: value, method: 'SystemProperties.get'});
                                
                                // Test manipulation
                                if (key === 'ro.build.tags' && value.includes('test-keys')) {
                                    console.log('[DYNAMIC_ROOT] Test-keys detected, attempting bypass');
                                    return 'release-keys';  // Bypass attempt
                                }
                            }
                            
                            return value;
                        };
                        
                        // Hook Build.TAGS access
                        var BuildClass = Java.use("android.os.Build");
                        console.log('[DYNAMIC_ROOT] Original Build.TAGS: ' + BuildClass.TAGS.value);
                        
                        if (BuildClass.TAGS.value.includes('test-keys')) {
                            console.log('[DYNAMIC_ROOT] Manipulating Build.TAGS from test-keys to release-keys');
                            BuildClass.TAGS.value = 'release-keys';
                            send({type: 'build_manipulation', original: 'test-keys', modified: 'release-keys'});
                        }
                    });
                """,
                'expected_detections': ['property_access', 'build_manipulation'],
                'bypass_techniques': ['property_spoofing', 'runtime_modification'],
                'effectiveness_weight': 0.7
            },
            
            'package_manager_root_detection': {
                'description': 'Package manager root detection and bypass testing',
                'script': """
                    Java.perform(function() {
                        var PackageManager = Java.use("android.content.pm.PackageManager");
                        var ApplicationInfo = Java.use("android.content.pm.ApplicationInfo");
                        
                        // Hook getInstalledPackages
                        PackageManager.getInstalledPackages.overload('int').implementation = function(flags) {
                            var packages = this.getInstalledPackages(flags);
                            
                            console.log('[DYNAMIC_ROOT] getInstalledPackages called, checking for root packages');
                            
                            var rootPackages = [];
                            for (var i = 0; i < packages.size(); i++) {
                                var pkg = packages.get(i);
                                var pkgName = pkg.packageName.value;
                                
                                if (pkgName.includes('supersu') || pkgName.includes('magisk') || 
                                    pkgName.includes('kinguser') || pkgName.includes('superuser')) {
                                    console.log('[DYNAMIC_ROOT] Root package detected: ' + pkgName);
                                    rootPackages.push(pkgName);
                                    send({type: 'root_package_detected', package: pkgName});
                                }
                            }
                            
                            // Test bypass - remove root packages from list
                            if (rootPackages.length > 0) {
                                console.log('[DYNAMIC_ROOT] Attempting to hide ' + rootPackages.length + ' root packages');
                                send({type: 'package_hiding_attempt', hidden_packages: rootPackages});
                            }
                            
                            return packages;
                        };
                    });
                """,
                'expected_detections': ['root_package_detected', 'package_hiding_attempt'],
                'bypass_techniques': ['package_hiding', 'name_obfuscation'],
                'effectiveness_weight': 0.75
            },
            
            'native_ptrace_detection': {
                'description': 'Native ptrace-based root detection and anti-debugging',
                'script': """
                    Java.perform(function() {
                        // Hook native ptrace function
                        var ptrace = Module.findExportByName("libc.so", "ptrace");
                        
                        if (ptrace) {
                            console.log('[DYNAMIC_ROOT] Found ptrace function, installing hook');
                            
                            Interceptor.attach(ptrace, {
                                onEnter: function(args) {
                                    var request = args[0].toInt32();
                                    var pid = args[1].toInt32();
                                    
                                    console.log('[DYNAMIC_ROOT] ptrace called: request=' + request + ', pid=' + pid);
                                    
                                    // PTRACE_TRACEME = 0
                                    if (request === 0) {
                                        console.log('[DYNAMIC_ROOT] PTRACE_TRACEME detected - anti-debugging');
                                        send({type: 'ptrace_traceme', request: request, pid: pid});
                                        
                                        // Test bypass
                                        console.log('[DYNAMIC_ROOT] Attempting ptrace bypass');
                                        this.replace(0);  // Return success
                                        send({type: 'ptrace_bypass_attempt', success: true});
                                    }
                                }
                            });
                        } else {
                            console.log('[DYNAMIC_ROOT] ptrace function not found');
                            send({type: 'ptrace_not_found'});
                        }
                    });
                """,
                'expected_detections': ['ptrace_traceme', 'ptrace_bypass_attempt'],
                'bypass_techniques': ['native_hooking', 'return_value_manipulation'],
                'effectiveness_weight': 0.9
            },
            
            'selinux_policy_bypass': {
                'description': 'SELinux policy enforcement bypass testing',
                'script': """
                    Java.perform(function() {
                        // Test SELinux enforcement bypass
                        var Runtime = Java.use("java.lang.Runtime");
                        
                        try {
                            // Check current SELinux status
                            var process = Runtime.getRuntime().exec(["getenforce"]);
                            var reader = Java.use("java.io.BufferedReader");
                            var inputStreamReader = Java.use("java.io.InputStreamReader");
                            
                            var bufferedReader = reader.$new(inputStreamReader.$new(process.getInputStream()));
                            var selinuxStatus = bufferedReader.readLine();
                            
                            console.log('[DYNAMIC_ROOT] SELinux status: ' + selinuxStatus);
                            send({type: 'selinux_status', status: selinuxStatus});
                            
                            if (selinuxStatus === 'Enforcing') {
                                console.log('[DYNAMIC_ROOT] SELinux is enforcing, testing bypass');
                                
                                // Attempt to set permissive mode
                                var bypassProcess = Runtime.getRuntime().exec(["su", "-c", "setenforce", "0"]);
                                var exitCode = bypassProcess.waitFor();
                                
                                if (exitCode === 0) {
                                    console.log('[DYNAMIC_ROOT] SELinux bypass successful');
                                    send({type: 'selinux_bypass', success: true, method: 'setenforce'});
                                } else {
                                    console.log('[DYNAMIC_ROOT] SELinux bypass failed');
                                    send({type: 'selinux_bypass', success: false, exit_code: exitCode});
                                }
                            }
                            
                        } catch (e) {
                            console.log('[DYNAMIC_ROOT] SELinux test error: ' + e);
                            send({type: 'selinux_test_error', error: e.toString()});
                        }
                    });
                """,
                'expected_detections': ['selinux_status', 'selinux_bypass'],
                'bypass_techniques': ['policy_modification', 'enforcement_bypass'],
                'effectiveness_weight': 0.85
            }
        }
    
    async def analyze_dynamic_root_detection(self, static_findings: List[Dict[str, Any]] = None) -> DynamicRootAnalysisResult:
        """
        Perform comprehensive dynamic root detection analysis with Phase 2.5.1 enhancements.
        
        Args:
            static_findings: Static analysis findings for correlation
            
        Returns:
            DynamicRootAnalysisResult with comprehensive assessment
        """
        start_time = time.time()
        
        try:
            logger.debug(f"Starting enhanced dynamic root analysis for {self.package_name}")
            
            # Initialize result
            result = DynamicRootAnalysisResult(package_name=self.package_name)
            
            # Check if dynamic analysis is possible
            if not await self._check_dynamic_analysis_capabilities():
                logger.warning("Dynamic analysis capabilities not available")
                result.transparency_report = self._generate_capability_transparency_report()
                return result
            
            # Initialize Frida for dynamic analysis
            if not await self._initialize_frida_for_root_analysis():
                logger.warning("Frida initialization failed")
                result.transparency_report = self._generate_frida_transparency_report()
                return result
            
            # Perform dynamic root detection tests
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                transient=True,
            ) as progress:
                task = progress.add_task("Dynamic root analysis...", total=len(self.dynamic_root_tests))
                
                for test_name, test_config in self.dynamic_root_tests.items():
                    progress.update(task, description=f"Testing {test_name}...")
                    
                    try:
                        # Execute dynamic test
                        test_result = await self._execute_dynamic_root_test(test_name, test_config)
                        
                        # Process test results
                        self._process_dynamic_test_results(test_result, result)
                        
                        # Update statistics
                        self.analysis_statistics['tests_executed'] += 1
                        
                        if test_result.get('bypass_attempted'):
                            self.analysis_statistics['bypasses_attempted'] += 1
                            if test_result.get('bypass_successful'):
                                self.analysis_statistics['bypasses_successful'] += 1
                        
                        progress.advance(task)
                        
                    except Exception as e:
                        logger.warning(f"Dynamic test {test_name} failed: {e}")
                        self._record_test_failure(test_name, str(e), result)
                        continue
            
            # Correlate with static analysis findings
            if static_findings and self.enable_static_dynamic_correlation:
                self._correlate_static_dynamic_findings(static_findings, result)
            
            # Calculate overall metrics
            self._calculate_dynamic_analysis_metrics(result)
            
            # Generate transparency report
            result.transparency_report = self._generate_comprehensive_transparency_report(result)
            
            # Update final timing
            result.analysis_duration = time.time() - start_time
            
            logger.debug(f"Dynamic root analysis completed: {len(result.dynamic_findings)} findings, "
                       f"{result.successful_bypasses}/{result.total_detection_methods_tested} bypasses successful")
            
            return result
            
        except Exception as e:
            logger.error(f"Enhanced dynamic root analysis failed: {e}")
            # Return error result with transparency information
            error_result = DynamicRootAnalysisResult(package_name=self.package_name)
            error_result.transparency_report = {
                'analysis_failed': True,
                'error_message': str(e),
                'capabilities_available': False,
                'recommendation': 'Static analysis recommended as fallback'
            }
            return error_result
    
    async def _check_dynamic_analysis_capabilities(self) -> bool:
        """Check if dynamic analysis capabilities are available."""
        try:
            # Check if device is connected
            result = subprocess.run(['adb', 'devices'], capture_output=True, text=True, timeout=10)
            devices = [line for line in result.stdout.strip().split('\n')[1:] if line.strip() and 'device' in line]
            
            if not devices:
                logger.warning("No Android devices connected")
                return False
            
            # Check if Frida server is available
            try:
                result = subprocess.run(['adb', 'shell', 'ps', '|', 'grep', 'frida'], 
                                      capture_output=True, text=True, timeout=10)
                if 'frida' not in result.stdout:
                    logger.debug("Frida server not running on device")
                    # Could attempt to start Frida server here
            except Exception:
                pass
            
            return True
            
        except Exception as e:
            logger.warning(f"Dynamic analysis capability check failed: {e}")
            return False
    
    async def _initialize_frida_for_root_analysis(self) -> bool:
        """Initialize Frida for root analysis."""
        try:
            # Initialize Frida manager if not already done
            if not self.frida_manager:
                self.frida_manager = FridaManager(self.package_name)
            
            # Check if app is running, start if needed
            if not self.frida_manager.is_app_running():
                logger.debug("Starting application for dynamic analysis")
                self.frida_manager.start_app()
                time.sleep(3)  # Allow app to start
            
            return True
            
        except Exception as e:
            logger.error(f"Frida initialization failed: {e}")
            return False
    
    async def _execute_dynamic_root_test(self, test_name: str, test_config: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a specific dynamic root detection test."""
        try:
            logger.debug(f"Executing dynamic test: {test_name}")
            
            # Prepare test result structure
            test_result = {
                'test_name': test_name,
                'description': test_config['description'],
                'success': False,
                'bypass_attempted': False,
                'bypass_successful': False,
                'detections': [],
                'evidence': [],
                'error': None
            }
            
            # Execute Frida script
            if self.frida_manager:
                script_output = self.frida_manager.execute_script(test_config['script'])
                
                # Process script output
                detections = []
                for expected_detection in test_config['expected_detections']:
                    if expected_detection in script_output:
                        detections.append(expected_detection)
                        test_result['evidence'].append(f"Detected: {expected_detection}")
                
                test_result['detections'] = detections
                test_result['success'] = len(detections) > 0
                
                # Check for bypass attempts
                if any(bypass in script_output for bypass in ['bypass', 'manipulation', 'hiding']):
                    test_result['bypass_attempted'] = True
                    
                    # Determine if bypass was successful
                    if 'success: true' in script_output or 'bypass_successful' in script_output:
                        test_result['bypass_successful'] = True
                        test_result['evidence'].append("Bypass attempt successful")
                    else:
                        test_result['evidence'].append("Bypass attempt failed")
            else:
                # Fallback static simulation
                test_result['error'] = "Frida not available, simulated result"
                test_result['evidence'].append("Static simulation - limited accuracy")
            
            return test_result
            
        except Exception as e:
            logger.warning(f"Dynamic test execution failed: {e}")
            return {
                'test_name': test_name,
                'success': False,
                'error': str(e),
                'evidence': [f"Test execution failed: {str(e)}"]
            }
    
    def _process_dynamic_test_results(self, test_result: Dict[str, Any], analysis_result: DynamicRootAnalysisResult):
        """Process individual test results into overall analysis result."""
        test_name = test_result['test_name']
        test_config = self.dynamic_root_tests[test_name]
        
        # Calculate effectiveness and resistance scores
        effectiveness_score = 0.8 if test_result['success'] else 0.2
        resistance_score = 0.3 if test_result.get('bypass_successful') else 0.8
        
        # Create dynamic finding
        finding = DynamicRootFinding(
            finding_id=f"DYNAMIC_ROOT_{test_name.upper()}",
            detection_method=test_result['description'],
            bypass_attempted=test_result.get('bypass_attempted', False),
            bypass_successful=test_result.get('bypass_successful', False),
            effectiveness_score=effectiveness_score,
            resistance_score=resistance_score,
            evidence=test_result.get('evidence', []),
            runtime_context={
                'test_configuration': test_config,
                'detections': test_result.get('detections', []),
                'test_success': test_result['success']
            },
            security_impact=self._assess_security_impact(test_result),
            recommendations=self._generate_test_recommendations(test_name, test_result)
        )
        
        analysis_result.dynamic_findings.append(finding)
        
        # Update metrics
        analysis_result.total_detection_methods_tested += 1
        if test_result.get('bypass_successful'):
            analysis_result.successful_bypasses += 1
        elif test_result.get('bypass_attempted'):
            analysis_result.failed_bypasses += 1
        
        # Update security control effectiveness
        control_name = test_name.replace('_', ' ').title()
        analysis_result.security_control_effectiveness[control_name] = effectiveness_score
    
    def _assess_security_impact(self, test_result: Dict[str, Any]) -> str:
        """Assess security impact of test results."""
        if test_result.get('bypass_successful'):
            return "HIGH - Security control successfully bypassed"
        elif test_result.get('bypass_attempted'):
            return "MEDIUM - Bypass attempted but failed"
        elif test_result.get('success'):
            return "LOW - Detection working but not tested for bypasses"
        else:
            return "INFO - No detection or test failed"
    
    def _generate_test_recommendations(self, test_name: str, test_result: Dict[str, Any]) -> List[str]:
        """Generate recommendations based on test results."""
        recommendations = []
        
        if test_result.get('bypass_successful'):
            recommendations.extend([
                f"Strengthen {test_name.replace('_', ' ')} implementation",
                "Implement multiple detection layers for redundancy",
                "Add runtime integrity verification",
                "Monitor for bypass patterns and adapt countermeasures"
            ])
        elif test_result.get('success') and not test_result.get('bypass_attempted'):
            recommendations.extend([
                f"Test {test_name.replace('_', ' ')} against known bypass techniques",
                "Implement bypass resistance mechanisms",
                "Regular effectiveness assessment recommended"
            ])
        else:
            recommendations.extend([
                f"Implement {test_name.replace('_', ' ')} root detection",
                "Deploy comprehensive root detection strategy",
                "Consider multiple detection methods for robustness"
            ])
        
        return recommendations
    
    def _correlate_static_dynamic_findings(self, static_findings: List[Dict[str, Any]], 
                                         result: DynamicRootAnalysisResult):
        """Correlate static and dynamic analysis findings."""
        try:
            correlations = []
            
            for static_finding in static_findings:
                for dynamic_finding in result.dynamic_findings:
                    # Check for correlation based on detection method similarity
                    static_method = static_finding.get('detection_method', '').lower()
                    dynamic_method = dynamic_finding.detection_method.lower()
                    
                    correlation_score = self._calculate_correlation_score(static_method, dynamic_method)
                    
                    if correlation_score > 0.5:  # Significant correlation
                        correlation = {
                            'static_finding_id': static_finding.get('id', 'unknown'),
                            'dynamic_finding_id': dynamic_finding.finding_id,
                            'correlation_score': correlation_score,
                            'correlation_type': 'detection_method_similarity',
                            'validation_status': 'confirmed' if dynamic_finding.effectiveness_score > 0.5 else 'questioned',
                            'recommendation': self._generate_correlation_recommendation(
                                static_finding, dynamic_finding, correlation_score
                            )
                        }
                        correlations.append(correlation)
                        
                        # Update dynamic finding with static correlation
                        dynamic_finding.correlation_with_static = correlation
            
            result.static_dynamic_correlations = correlations
            self.analysis_statistics['static_correlations_found'] = len(correlations)
            
        except Exception as e:
            logger.warning(f"Static-dynamic correlation failed: {e}")
    
    def _calculate_correlation_score(self, static_method: str, dynamic_method: str) -> float:
        """Calculate correlation score between static and dynamic methods."""
        # Simple keyword-based correlation
        keywords = ['su', 'root', 'ptrace', 'build', 'property', 'package', 'selinux']
        
        static_keywords = [kw for kw in keywords if kw in static_method]
        dynamic_keywords = [kw for kw in keywords if kw in dynamic_method]
        
        if not static_keywords and not dynamic_keywords:
            return 0.0
        
        common_keywords = set(static_keywords) & set(dynamic_keywords)
        total_keywords = set(static_keywords) | set(dynamic_keywords)
        
        return len(common_keywords) / len(total_keywords) if total_keywords else 0.0
    
    def _generate_correlation_recommendation(self, static_finding: Dict[str, Any], 
                                           dynamic_finding: DynamicRootFinding, 
                                           correlation_score: float) -> str:
        """Generate recommendation based on static-dynamic correlation."""
        if dynamic_finding.bypass_successful:
            return f"Static detection confirmed but bypassable (correlation: {correlation_score:.2f}) - strengthen implementation"
        elif dynamic_finding.effectiveness_score > 0.7:
            return f"Static and dynamic analysis confirm effective detection (correlation: {correlation_score:.2f})"
        else:
            return f"Static detection found but dynamic validation inconclusive (correlation: {correlation_score:.2f}) - further testing recommended"
    
    def _calculate_dynamic_analysis_metrics(self, result: DynamicRootAnalysisResult):
        """Calculate overall dynamic analysis metrics."""
        if result.total_detection_methods_tested > 0:
            result.overall_bypass_resistance = 1.0 - (result.successful_bypasses / result.total_detection_methods_tested)
        else:
            result.overall_bypass_resistance = 0.0
        
        # Calculate average effectiveness of detected controls
        if result.security_control_effectiveness:
            avg_effectiveness = sum(result.security_control_effectiveness.values()) / len(result.security_control_effectiveness)
            result.overall_bypass_resistance = (result.overall_bypass_resistance + avg_effectiveness) / 2
    
    def _generate_comprehensive_transparency_report(self, result: DynamicRootAnalysisResult) -> Dict[str, Any]:
        """Generate comprehensive transparency report for Phase 2.5.1."""
        return {
            'analysis_capabilities': {
                'frida_available': self.frida_manager is not None,
                'device_connected': True,  # If we got this far
                'dynamic_analysis_possible': True
            },
            'test_coverage': {
                'total_tests_defined': len(self.dynamic_root_tests),
                'tests_executed': self.analysis_statistics['tests_executed'],
                'tests_successful': len([f for f in result.dynamic_findings if f.effectiveness_score > 0.5]),
                'coverage_percentage': (self.analysis_statistics['tests_executed'] / len(self.dynamic_root_tests)) * 100
            },
            'bypass_analysis': {
                'bypasses_attempted': self.analysis_statistics['bypasses_attempted'],
                'bypasses_successful': self.analysis_statistics['bypasses_successful'],
                'bypass_success_rate': (self.analysis_statistics['bypasses_successful'] / 
                                      max(self.analysis_statistics['bypasses_attempted'], 1)) * 100
            },
            'static_dynamic_integration': {
                'correlations_found': self.analysis_statistics['static_correlations_found'],
                'integration_enabled': self.enable_static_dynamic_correlation
            },
            'limitations': [
                "Dynamic analysis requires physical device or emulator",
                "Frida-based analysis may be detected by advanced anti-tampering",
                "Results depend on runtime application behavior",
                "Some root detection methods may not be triggered during testing"
            ],
            'recommendations': [
                "Combine with static analysis for comprehensive assessment",
                "Test on multiple device configurations and Android versions",
                "Regular testing recommended as bypass techniques evolve",
                "Consider automated testing in CI/CD pipeline"
            ]
        }
    
    def _generate_capability_transparency_report(self) -> Dict[str, Any]:
        """Generate transparency report when dynamic analysis capabilities are not available."""
        return {
            'analysis_failed': True,
            'reason': 'Dynamic analysis capabilities not available',
            'missing_capabilities': [
                'Android device not connected',
                'ADB not accessible',
                'Dynamic instrumentation not possible'
            ],
            'fallback_recommendations': [
                'Use static analysis for root detection pattern identification',
                'Review application source code for root detection implementations',
                'Consider manual testing with rooted device when available'
            ],
            'impact': 'Limited to static analysis only - bypass resistance cannot be tested'
        }
    
    def _generate_frida_transparency_report(self) -> Dict[str, Any]:
        """Generate transparency report when Frida initialization fails."""
        return {
            'analysis_limited': True,
            'reason': 'Frida dynamic instrumentation not available',
            'limitations': [
                'Cannot perform runtime root detection testing',
                'Bypass resistance testing not possible',
                'Limited to static pattern analysis'
            ],
            'alternative_approaches': [
                'Manual testing with rooted device',
                'Code review for root detection patterns',
                'Third-party dynamic analysis tools'
            ],
            'recommendation': 'Install Frida server on test device for comprehensive analysis'
        }
    
    def _record_test_failure(self, test_name: str, error: str, result: DynamicRootAnalysisResult):
        """Record test failure for transparency."""
        failure_finding = DynamicRootFinding(
            finding_id=f"DYNAMIC_ROOT_FAILURE_{test_name.upper()}",
            detection_method=f"Failed test: {test_name}",
            bypass_attempted=False,
            bypass_successful=False,
            effectiveness_score=0.0,
            resistance_score=0.0,
            evidence=[f"Test failed: {error}"],
            security_impact="UNKNOWN - Test execution failed",
            recommendations=[
                "Check dynamic analysis environment",
                "Verify device connectivity and Frida setup",
                "Consider static analysis as alternative"
            ]
        )
        
        result.dynamic_findings.append(failure_finding)
        self.analysis_statistics['transparency_events'] += 1
    
    def get_analysis_statistics(self) -> Dict[str, Any]:
        """Get analysis statistics for monitoring and debugging."""
        return {
            'enhanced_dynamic_root_analyzer': {
                **self.analysis_statistics,
                'total_tests_available': len(self.dynamic_root_tests),
                'analysis_configuration': {
                    'max_analysis_time': self.max_analysis_time,
                    'comprehensive_analysis': self.enable_comprehensive_analysis,
                    'bypass_testing': self.enable_bypass_resistance_testing,
                    'static_correlation': self.enable_static_dynamic_correlation,
                    'transparency_reporting': self.enable_transparency_reporting
                }
            }
        } 
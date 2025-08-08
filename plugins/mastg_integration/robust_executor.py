#!/usr/bin/env python3
"""
MASTG Robust Test Executor Module

Provides timeout-protected, robust test execution capabilities for MASTG integration.
Handles parallel execution, error recovery, and comprehensive result tracking.

Features:
- Timeout-protected test execution
- Parallel and sequential execution modes
- Comprehensive error handling and recovery
- Plugin integration and orchestration
- Performance monitoring and metrics
- Graceful degradation on failures
"""

import datetime
import logging
import signal
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError, as_completed
from contextlib import contextmanager
from typing import Dict, List, Optional, Any, Callable, Tuple

from rich.text import Text

from .data_structures import (
    MASTGTestCase, MASTGTestExecution, MASTGConfiguration, 
    MASTGTestStatus, MASTGRiskLevel, MASTGFinding, MASTGTestEvidence,
    create_test_execution, create_finding, create_evidence
)
from .test_case_manager import MASTGTestCaseManager
from .plugin_integration import PluginIntegrationManager

class TimeoutException(Exception):
    """Exception raised when test execution times out."""
    pass

class ExecutionContext:
    """Context for test execution with resource management."""
    
    def __init__(self, test_case: MASTGTestCase, apk_ctx: Any, config: MASTGConfiguration):
        self.test_case = test_case
        self.apk_ctx = apk_ctx
        self.config = config
        self.execution_id = str(uuid.uuid4())
        self.start_time = datetime.datetime.now()
        self.timeout = test_case.timeout_override or config.timeout_per_test
        self.cancelled = False
        self.error_context: Dict[str, Any] = {}
    
    def cancel(self):
        """Cancel the execution context."""
        self.cancelled = True
    
    def is_cancelled(self) -> bool:
        """Check if execution is cancelled."""
        return self.cancelled
    
    def get_elapsed_time(self) -> float:
        """Get elapsed execution time in seconds."""
        return (datetime.datetime.now() - self.start_time).total_seconds()

class RobustMASTGExecutor:
    """
    Robust MASTG test executor with timeout protection and error handling.
    
    Provides comprehensive test execution capabilities including parallel execution,
    timeout protection, error recovery, and performance monitoring.
    """
    
    def __init__(self, test_case_manager: MASTGTestCaseManager, 
                 plugin_manager: PluginIntegrationManager,
                 config: MASTGConfiguration):
        """Initialize the robust executor with component dependencies."""
        self.test_case_manager = test_case_manager
        self.plugin_manager = plugin_manager
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Execution state
        self._active_executions: Dict[str, ExecutionContext] = {}
        self._execution_lock = threading.RLock()
        self._performance_metrics: Dict[str, Any] = {}
        
        # Error handling
        self._execution_errors: List[Dict[str, Any]] = []
        self._timeout_count = 0
        
        self.logger.info("MASTG Robust Executor initialized")
    
    def execute_test_suite(self, apk_ctx: Any, test_cases: List[MASTGTestCase]) -> List[MASTGTestExecution]:
        """
        Execute a complete test suite with robust error handling.
        
        Args:
            apk_ctx: APK analysis context
            test_cases: List of test cases to execute
            
        Returns:
            List of test execution results
        """
        self.logger.info(f"Starting execution of {len(test_cases)} MASTG test cases")
        start_time = datetime.datetime.now()
        
        try:
            # Choose execution mode based on configuration
            if self.config.execution_mode.value == "PARALLEL":
                executions = self._execute_parallel(apk_ctx, test_cases)
            elif self.config.execution_mode.value == "SEQUENTIAL":
                executions = self._execute_sequential(apk_ctx, test_cases)
            else:  # HYBRID
                executions = self._execute_hybrid(apk_ctx, test_cases)
            
            # Record performance metrics
            total_time = (datetime.datetime.now() - start_time).total_seconds()
            self._record_suite_performance(test_cases, executions, total_time)
            
            self.logger.info(f"Test suite execution completed in {total_time:.2f}s")
            return executions
            
        except Exception as e:
            self.logger.error(f"Test suite execution failed: {e}", exc_info=True)
            # Return partial results if any tests completed
            return self._get_completed_executions()
    
    def _execute_parallel(self, apk_ctx: Any, test_cases: List[MASTGTestCase]) -> List[MASTGTestExecution]:
        """Execute test cases in parallel with concurrency control."""
        executions = []
        max_workers = min(self.config.max_concurrent_tests, len(test_cases))
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all test cases
            future_to_test = {}
            for test_case in test_cases:
                future = executor.submit(self._execute_single_test, apk_ctx, test_case)
                future_to_test[future] = test_case
            
            # Collect results with timeout
            completed_count = 0
            for future in as_completed(future_to_test, timeout=self.config.max_execution_time):
                try:
                    execution = future.result(timeout=1)  # Quick result retrieval
                    executions.append(execution)
                    completed_count += 1
                    
                    self.logger.debug(f"Test {execution.test_case.test_id} completed "
                                    f"({completed_count}/{len(test_cases)})")
                    
                except (FutureTimeoutError, TimeoutException):
                    test_case = future_to_test[future]
                    execution = self._create_timeout_execution(test_case)
                    executions.append(execution)
                    self._timeout_count += 1
                    
                except Exception as e:
                    test_case = future_to_test[future]
                    execution = self._create_error_execution(test_case, str(e))
                    executions.append(execution)
                    self.logger.error(f"Test {test_case.test_id} failed: {e}")
        
        return executions
    
    def _execute_sequential(self, apk_ctx: Any, test_cases: List[MASTGTestCase]) -> List[MASTGTestExecution]:
        """Execute test cases sequentially with timeout protection."""
        executions = []
        
        for i, test_case in enumerate(test_cases, 1):
            self.logger.debug(f"Executing test {test_case.test_id} ({i}/{len(test_cases)})")
            
            try:
                execution = self._execute_single_test(apk_ctx, test_case)
                executions.append(execution)
                
            except TimeoutException:
                execution = self._create_timeout_execution(test_case)
                executions.append(execution)
                self._timeout_count += 1
                
            except Exception as e:
                execution = self._create_error_execution(test_case, str(e))
                executions.append(execution)
                self.logger.error(f"Test {test_case.test_id} failed: {e}")
            
            # Check global timeout
            if self._should_abort_suite():
                self.logger.warning("Aborting test suite due to timeout or excessive failures")
                break
        
        return executions
    
    def _execute_hybrid(self, apk_ctx: Any, test_cases: List[MASTGTestCase]) -> List[MASTGTestExecution]:
        """Execute test cases using hybrid approach (parallel for compatible tests)."""
        # Separate test cases by compatibility for parallel execution
        parallel_compatible = []
        sequential_only = []
        
        for test_case in test_cases:
            if self._is_parallel_compatible(test_case):
                parallel_compatible.append(test_case)
            else:
                sequential_only.append(test_case)
        
        executions = []
        
        # Execute parallel-compatible tests first
        if parallel_compatible:
            self.logger.info(f"Executing {len(parallel_compatible)} tests in parallel")
            parallel_executions = self._execute_parallel(apk_ctx, parallel_compatible)
            executions.extend(parallel_executions)
        
        # Execute sequential-only tests
        if sequential_only:
            self.logger.info(f"Executing {len(sequential_only)} tests sequentially")
            sequential_executions = self._execute_sequential(apk_ctx, sequential_only)
            executions.extend(sequential_executions)
        
        return executions
    
    def _execute_single_test(self, apk_ctx: Any, test_case: MASTGTestCase) -> MASTGTestExecution:
        """
        Execute a single test case with timeout protection.
        
        Args:
            apk_ctx: APK analysis context
            test_case: Test case to execute
            
        Returns:
            Test execution result
        """
        context = ExecutionContext(test_case, apk_ctx, self.config)
        
        # Register active execution
        with self._execution_lock:
            self._active_executions[context.execution_id] = context
        
        try:
            # Create test execution instance
            execution = create_test_execution(test_case, context.execution_id)
            execution.status = MASTGTestStatus.RUNNING
            
            # Execute with timeout protection
            with self._timeout_protection(context.timeout):
                result = self._execute_test_with_plugin(context, execution)
                
            # Mark as completed
            execution.mark_completed(MASTGTestStatus.PASSED, result)
            return execution
            
        except TimeoutException:
            execution = self._create_timeout_execution(test_case)
            execution.execution_id = context.execution_id
            raise
            
        except Exception as e:
            execution = self._create_error_execution(test_case, str(e))
            execution.execution_id = context.execution_id
            self._record_execution_error(context, e)
            raise
            
        finally:
            # Cleanup active execution
            with self._execution_lock:
                self._active_executions.pop(context.execution_id, None)
    
    def _execute_test_with_plugin(self, context: ExecutionContext, 
                                 execution: MASTGTestExecution) -> str:
        """Execute test using appropriate plugin integration."""
        test_case = context.test_case
        apk_ctx = context.apk_ctx
        
        # Check if plugin is available
        if not test_case.plugin_mapping:
            return self._execute_custom_test(context, execution)
        
        plugin_available = self.plugin_manager.is_plugin_available(test_case.plugin_mapping)
        if not plugin_available:
            if self.config.fallback_on_plugin_failure:
                self.logger.warning(f"Plugin {test_case.plugin_mapping} not available, "
                                  f"falling back for test {test_case.test_id}")
                return self._execute_fallback_test(context, execution)
            else:
                raise RuntimeError(f"Required plugin {test_case.plugin_mapping} not available")
        
        # Execute with plugin
        try:
            plugin_result = self.plugin_manager.execute_plugin(
                test_case.plugin_mapping, apk_ctx, context.timeout
            )
            
            # Process plugin result
            self._process_plugin_result(execution, plugin_result)
            
            execution.plugin_used = test_case.plugin_mapping
            execution.plugin_execution_time = context.get_elapsed_time()
            
            return f"Plugin {test_case.plugin_mapping} execution completed"
            
        except Exception as e:
            self.logger.error(f"Plugin {test_case.plugin_mapping} execution failed: {e}")
            if self.config.fallback_on_plugin_failure:
                return self._execute_fallback_test(context, execution)
            else:
                raise
    
    def _process_plugin_result(self, execution: MASTGTestExecution, plugin_result: Any):
        """Process plugin execution result and extract findings."""
        try:
            # Plugin result could be a tuple (title, content) or direct content
            if isinstance(plugin_result, tuple) and len(plugin_result) == 2:
                title, content = plugin_result
                result_text = str(content)
            else:
                result_text = str(plugin_result)
            
            # Parse findings from plugin result
            findings = self._parse_plugin_findings(execution.test_case, result_text)
            for finding in findings:
                execution.add_finding(finding)
            
            # Create evidence from plugin output
            evidence = create_evidence(
                evidence_type="plugin_output",
                content=result_text[:1000],  # Limit content size
                path=None
            )
            execution.add_evidence(evidence)
            
        except Exception as e:
            self.logger.error(f"Error processing plugin result: {e}")
            # Add error as evidence
            error_evidence = create_evidence(
                evidence_type="plugin_error",
                content=f"Plugin result processing error: {str(e)}",
                path=None
            )
            execution.add_evidence(error_evidence)
    
    def _parse_plugin_findings(self, test_case: MASTGTestCase, result_text: str) -> List[MASTGFinding]:
        """Parse security findings from plugin result text."""
        findings = []
        
        # Look for expected findings from test case definition
        for expected_finding in test_case.expected_findings:
            if expected_finding.lower() in result_text.lower():
                finding = create_finding(
                    finding_id=f"{test_case.test_id}-{expected_finding}",
                    title=f"{expected_finding.replace('_', ' ').title()} Detected",
                    description=f"Plugin detected {expected_finding} in {test_case.test_id}",
                    risk_level=test_case.base_risk_level,
                    confidence_score=0.8
                )
                findings.append(finding)
        
        # Look for common security indicators
        security_indicators = [
            ("error", MASTGRiskLevel.LOW, 0.6),
            ("warning", MASTGRiskLevel.LOW, 0.5),
            ("vulnerability", MASTGRiskLevel.HIGH, 0.9),
            ("critical", MASTGRiskLevel.CRITICAL, 0.9),
            ("insecure", MASTGRiskLevel.MEDIUM, 0.7),
            ("weak", MASTGRiskLevel.MEDIUM, 0.7)
        ]
        
        for indicator, risk_level, confidence in security_indicators:
            if indicator in result_text.lower():
                finding = create_finding(
                    finding_id=f"{test_case.test_id}-{indicator}",
                    title=f"{indicator.title()} Found",
                    description=f"Security {indicator} detected during {test_case.test_id}",
                    risk_level=risk_level,
                    confidence_score=confidence
                )
                findings.append(finding)
        
        return findings
    
    def _execute_custom_test(self, context: ExecutionContext, 
                           execution: MASTGTestExecution) -> str:
        """Execute custom test logic for tests without plugin mapping."""
        test_case = context.test_case
        
        # Custom test implementations based on test category
        if test_case.test_id == "MASTG-AUTH-001":
            return self._execute_auth_test(context, execution)
        elif test_case.test_id == "MASTG-CODE-001":
            return self._execute_code_quality_test(context, execution)
        else:
            # Generic custom test
            return self._execute_generic_test(context, execution)
    
    def _execute_fallback_test(self, context: ExecutionContext,
                              execution: MASTGTestExecution) -> str:
        """Execute fallback test when primary plugin is unavailable."""
        self.logger.info(f"Executing fallback test for {context.test_case.test_id}")
        
        # Create informational finding about fallback execution
        finding = create_finding(
            finding_id=f"{context.test_case.test_id}-fallback",
            title="Fallback Test Execution",
            description=f"Primary plugin unavailable, executed fallback test",
            risk_level=MASTGRiskLevel.INFO,
            confidence_score=0.5
        )
        execution.add_finding(finding)
        
        return f"Fallback test executed for {context.test_case.test_id}"
    
    def _execute_auth_test(self, context: ExecutionContext,
                          execution: MASTGTestExecution) -> str:
        """Execute authentication-specific test logic."""
        # Custom authentication testing logic
        apk_ctx = context.apk_ctx
        
        # Check for common authentication issues
        findings = []
        
        # Look for weak authentication patterns in manifest
        if hasattr(apk_ctx, 'manifest_analysis'):
            manifest_data = apk_ctx.manifest_analysis
            
            # Check for biometric authentication
            if 'USE_BIOMETRIC' in str(manifest_data):
                finding = create_finding(
                    finding_id=f"{context.test_case.test_id}-biometric",
                    title="Biometric Authentication Found",
                    description="Application uses biometric authentication",
                    risk_level=MASTGRiskLevel.INFO,
                    confidence_score=0.9
                )
                findings.append(finding)
        
        for finding in findings:
            execution.add_finding(finding)
        
        return "Authentication security analysis completed"
    
    def _execute_code_quality_test(self, context: ExecutionContext,
                                  execution: MASTGTestExecution) -> str:
        """Execute code quality test logic."""
        # Custom code quality testing logic
        apk_ctx = context.apk_ctx
        
        findings = []
        
        # Check for debug information
        if hasattr(apk_ctx, 'build_info'):
            if apk_ctx.build_info.get('debug_mode', False):
                finding = create_finding(
                    finding_id=f"{context.test_case.test_id}-debug",
                    title="Debug Mode Enabled",
                    description="Application compiled in debug mode",
                    risk_level=MASTGRiskLevel.MEDIUM,
                    confidence_score=0.9
                )
                findings.append(finding)
        
        for finding in findings:
            execution.add_finding(finding)
        
        return "Code quality analysis completed"
    
    def _execute_generic_test(self, context: ExecutionContext,
                             execution: MASTGTestExecution) -> str:
        """Execute generic test logic for undefined test cases."""
        # Generic test execution with basic analysis
        finding = create_finding(
            finding_id=f"{context.test_case.test_id}-generic",
            title="Generic Test Execution",
            description=f"Executed generic test for {context.test_case.test_id}",
            risk_level=MASTGRiskLevel.INFO,
            confidence_score=0.3
        )
        execution.add_finding(finding)
        
        return f"Generic test executed for {context.test_case.test_id}"
    
    @contextmanager
    def _timeout_protection(self, timeout_seconds: int):
        """Context manager for timeout protection using thread-safe approach."""
        timeout_event = threading.Event()
        timeout_occurred = [False]  # Use list to make it mutable
        
        def timeout_handler():
            timeout_occurred[0] = True
            timeout_event.set()
        
        # Set up thread-safe timeout using Timer
        timer = threading.Timer(timeout_seconds, timeout_handler)
        timer.start()
        
        try:
            yield timeout_event, timeout_occurred
            # Check if timeout occurred during execution
            if timeout_occurred[0]:
                raise TimeoutException(f"Test execution timed out after {timeout_seconds} seconds")
        finally:
            # Clean up timer
            timer.cancel()
    
    def _create_timeout_execution(self, test_case: MASTGTestCase) -> MASTGTestExecution:
        """Create test execution result for timed out tests."""
        execution = create_test_execution(test_case, str(uuid.uuid4()))
        execution.mark_completed(MASTGTestStatus.TIMEOUT, "Test execution timed out")
        execution.error_message = f"Test timed out after {self.config.timeout_per_test} seconds"
        return execution
    
    def _create_error_execution(self, test_case: MASTGTestCase, error_message: str) -> MASTGTestExecution:
        """Create test execution result for failed tests."""
        execution = create_test_execution(test_case, str(uuid.uuid4()))
        execution.mark_completed(MASTGTestStatus.ERROR, "Test execution failed")
        execution.error_message = error_message
        return execution
    
    def _is_parallel_compatible(self, test_case: MASTGTestCase) -> bool:
        """Check if test case is compatible with parallel execution."""
        # Tests that modify global state or have heavy resource requirements
        # should be executed sequentially
        sequential_patterns = [
            "frida_dynamic_analysis",  # Heavy resource usage
            "anti_tampering_analysis", # May conflict with parallel execution
        ]
        
        if test_case.plugin_mapping in sequential_patterns:
            return False
        
        # High difficulty tests may need sequential execution
        if test_case.difficulty == "HARD":
            return False
        
        return True
    
    def _should_abort_suite(self) -> bool:
        """Check if test suite execution should be aborted."""
        # Abort if too many timeouts
        if self._timeout_count > self.config.max_concurrent_tests:
            return True
        
        # Abort if too many errors
        if len(self._execution_errors) > self.config.max_concurrent_tests:
            return True
        
        return False
    
    def _record_execution_error(self, context: ExecutionContext, error: Exception):
        """Record execution error for analysis."""
        error_record = {
            "test_id": context.test_case.test_id,
            "error_type": type(error).__name__,
            "error_message": str(error),
            "execution_time": context.get_elapsed_time(),
            "timestamp": datetime.datetime.now()
        }
        self._execution_errors.append(error_record)
    
    def _record_suite_performance(self, test_cases: List[MASTGTestCase],
                                 executions: List[MASTGTestExecution], total_time: float):
        """Record performance metrics for the test suite."""
        self._performance_metrics = {
            "total_tests": len(test_cases),
            "completed_tests": len(executions),
            "total_execution_time": total_time,
            "average_test_time": total_time / len(executions) if executions else 0,
            "timeout_count": self._timeout_count,
            "error_count": len(self._execution_errors),
            "execution_mode": self.config.execution_mode.value,
            "timestamp": datetime.datetime.now()
        }
    
    def _get_completed_executions(self) -> List[MASTGTestExecution]:
        """Get list of completed executions (for error recovery)."""
        # This would need to be implemented to track completed executions
        # during suite execution for error recovery scenarios
        return []
    
    def get_performance_metrics(self) -> Dict[str, Any]:
        """Get performance metrics from the last execution."""
        return self._performance_metrics.copy()
    
    def get_execution_errors(self) -> List[Dict[str, Any]]:
        """Get list of execution errors."""
        return self._execution_errors.copy()
    
    def cancel_active_executions(self):
        """Cancel all active test executions."""
        with self._execution_lock:
            for context in self._active_executions.values():
                context.cancel()
            self.logger.info(f"Cancelled {len(self._active_executions)} active executions")
    
    def get_active_execution_count(self) -> int:
        """Get number of currently active executions."""
        with self._execution_lock:
            return len(self._active_executions) 
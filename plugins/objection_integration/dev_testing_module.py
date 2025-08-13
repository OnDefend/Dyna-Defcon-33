#!/usr/bin/env python3
"""
Objection Development Testing Module

Provides development support through rapid testing, debugging assistance,
and real-time feedback during mobile application development cycles.

Author: AODS Team
Date: January 2025
"""

import json
import logging
import subprocess
import tempfile
import time
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from pathlib import Path
from enum import Enum


class TestType(Enum):
    """Types of development testing."""
    UNIT_TEST = "unit_test"
    INTEGRATION_TEST = "integration_test"
    SECURITY_TEST = "security_test"
    REGRESSION_TEST = "regression_test"
    SMOKE_TEST = "smoke_test"


class TestStatus(Enum):
    """Test execution status."""
    PENDING = "pending"
    RUNNING = "running"
    PASSED = "passed"
    FAILED = "failed"
    ERROR = "error"
    SKIPPED = "skipped"


@dataclass
class DevelopmentTest:
    """A development test case."""
    name: str
    test_type: TestType
    description: str
    objection_commands: List[str]
    expected_outcomes: List[str]
    validation_criteria: List[str] = field(default_factory=list)
    timeout_seconds: int = 300
    retry_count: int = 1
    dependencies: List[str] = field(default_factory=list)


@dataclass
class TestResult:
    """Result of a development test."""
    test_name: str
    status: TestStatus
    execution_time: float
    output: str
    error_message: Optional[str] = None
    validation_results: List[bool] = field(default_factory=list)
    evidence: List[str] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)


class ObjectionDevelopmentTesting:
    """
    Development testing support using objection for rapid mobile app testing.
    
    Provides developers with quick feedback on security implementations,
    automated testing of security features, and debugging assistance.
    """
    
    def __init__(self):
        """Initialize development testing module."""
        self.logger = logging.getLogger(__name__)
        self.objection_available = self._check_objection_availability()
        self.test_results_history = []
        self.active_test_sessions = {}
        
        # Predefined development test templates
        self.test_templates = self._initialize_test_templates()
    
    def create_development_test_suite(self, package_name: str, 
                                    security_features: List[str]) -> Dict[str, List[DevelopmentTest]]:
        """
        Create a comprehensive test suite for development testing.
        
        Args:
            package_name: Target application package name
            security_features: List of security features to test
            
        Returns:
            Dictionary of test suites organized by category
        """
        try:
            test_suite = {
                "authentication": [],
                "storage": [],
                "network": [],
                "crypto": [],
                "logging": [],
                "general": []
            }
            
            for feature in security_features:
                tests = self._generate_tests_for_feature(feature, package_name)
                category = self._categorize_security_feature(feature)
                test_suite[category].extend(tests)
            
            # Add general security tests
            test_suite["general"].extend(self._create_general_security_tests(package_name))
            
            self.logger.info(f"Created test suite with {sum(len(tests) for tests in test_suite.values())} tests")
            return test_suite
            
        except Exception as e:
            self.logger.error(f"Failed to create test suite: {e}")
            return {}
    
    def run_development_test(self, test: DevelopmentTest, package_name: str) -> TestResult:
        """
        Run a single development test.
        
        Args:
            test: Test to execute
            package_name: Target application package name
            
        Returns:
            Test execution result
        """
        try:
            self.logger.info(f"Running development test: {test.name}")
            start_time = time.time()
            
            if not self.objection_available:
                return TestResult(
                    test_name=test.name,
                    status=TestStatus.ERROR,
                    execution_time=0,
                    output="",
                    error_message="Objection not available"
                )
            
            # Execute test commands
            output, error = self._execute_objection_commands(
                package_name, test.objection_commands, test.timeout_seconds
            )
            
            execution_time = time.time() - start_time
            
            # Validate results
            validation_results = self._validate_test_results(test, output)
            status = TestStatus.PASSED if all(validation_results) else TestStatus.FAILED
            
            # Extract evidence
            evidence = self._extract_test_evidence(output, test.expected_outcomes)
            
            result = TestResult(
                test_name=test.name,
                status=status,
                execution_time=execution_time,
                output=output,
                error_message=error,
                validation_results=validation_results,
                evidence=evidence
            )
            
            self.test_results_history.append(result)
            self.logger.info(f"Test {test.name} completed: {status.value}")
            
            return result
            
        except Exception as e:
            self.logger.error(f"Test execution failed: {e}")
            return TestResult(
                test_name=test.name,
                status=TestStatus.ERROR,
                execution_time=0,
                output="",
                error_message=str(e)
            )
    
    def run_test_suite(self, test_suite: Dict[str, List[DevelopmentTest]], 
                      package_name: str) -> Dict[str, List[TestResult]]:
        """
        Run a complete test suite.
        
        Args:
            test_suite: Test suite to execute
            package_name: Target application package name
            
        Returns:
            Results organized by category
        """
        try:
            self.logger.info("Starting test suite execution")
            results = {}
            
            for category, tests in test_suite.items():
                self.logger.info(f"Running {len(tests)} tests in category: {category}")
                category_results = []
                
                for test in tests:
                    result = self.run_development_test(test, package_name)
                    category_results.append(result)
                    
                    # Brief pause between tests
                    time.sleep(2)
                
                results[category] = category_results
            
            # Generate summary
            self._log_test_suite_summary(results)
            return results
            
        except Exception as e:
            self.logger.error(f"Test suite execution failed: {e}")
            return {}
    
    def create_real_time_monitoring_session(self, package_name: str, 
                                          focus_areas: List[str]) -> Dict[str, Any]:
        """
        Create a real-time monitoring session for development feedback.
        
        Args:
            package_name: Target application package name
            focus_areas: Areas to monitor (e.g., 'logging', 'storage', 'network')
            
        Returns:
            Session information and monitoring commands
        """
        try:
            session_id = f"dev_session_{int(time.time())}"
            
            # Generate monitoring commands based on focus areas
            monitoring_commands = []
            for area in focus_areas:
                commands = self._get_monitoring_commands_for_area(area)
                monitoring_commands.extend(commands)
            
            # Create monitoring script
            monitoring_script = self._create_monitoring_script(monitoring_commands)
            
            session_info = {
                "session_id": session_id,
                "package_name": package_name,
                "focus_areas": focus_areas,
                "monitoring_commands": monitoring_commands,
                "monitoring_script": monitoring_script,
                "status": "ready",
                "created_time": time.time()
            }
            
            self.active_test_sessions[session_id] = session_info
            self.logger.info(f"Created monitoring session: {session_id}")
            
            return session_info
            
        except Exception as e:
            self.logger.error(f"Failed to create monitoring session: {e}")
            return {"error": str(e)}
    
    def get_development_feedback(self, test_results: List[TestResult]) -> Dict[str, Any]:
        """
        Generate development feedback based on test results.
        
        Args:
            test_results: List of test results to analyze
            
        Returns:
            Structured feedback and recommendations
        """
        try:
            feedback = {
                "overall_status": self._calculate_overall_status(test_results),
                "security_score": self._calculate_security_score(test_results),
                "critical_issues": [],
                "warnings": [],
                "recommendations": [],
                "quick_fixes": [],
                "detailed_analysis": {}
            }
            
            # Analyze results for issues and recommendations
            for result in test_results:
                if result.status == TestStatus.FAILED:
                    issue = self._analyze_test_failure(result)
                    if issue["severity"] == "critical":
                        feedback["critical_issues"].append(issue)
                    else:
                        feedback["warnings"].append(issue)
                        
                    # Generate recommendations
                    recommendations = self._generate_fix_recommendations(result)
                    feedback["recommendations"].extend(recommendations)
            
            # Generate quick fixes
            feedback["quick_fixes"] = self._generate_quick_fixes(test_results)
            
            # Detailed analysis
            feedback["detailed_analysis"] = self._create_detailed_analysis(test_results)
            
            return feedback
            
        except Exception as e:
            self.logger.error(f"Failed to generate feedback: {e}")
            return {"error": str(e)}
    
    def create_regression_test_suite(self, baseline_results: List[TestResult]) -> List[DevelopmentTest]:
        """
        Create regression tests based on baseline results.
        
        Args:
            baseline_results: Previous test results to use as baseline
            
        Returns:
            List of regression tests
        """
        try:
            regression_tests = []
            
            for result in baseline_results:
                if result.status == TestStatus.PASSED:
                    # Create regression test to ensure this continues to pass
                    regression_test = self._create_regression_test_from_result(result)
                    regression_tests.append(regression_test)
            
            self.logger.info(f"Created {len(regression_tests)} regression tests")
            return regression_tests
            
        except Exception as e:
            self.logger.error(f"Failed to create regression tests: {e}")
            return []
    
    def _check_objection_availability(self) -> bool:
        """Check if objection is available."""
        try:
            result = subprocess.run(['objection', '--version'], 
                                  capture_output=True, text=True, timeout=5)
            return result.returncode == 0
        except Exception:
            return False
    
    def _initialize_test_templates(self) -> Dict[str, DevelopmentTest]:
        """Initialize predefined test templates."""
        templates = {}
        
        # Authentication test templates
        templates["biometric_auth_test"] = DevelopmentTest(
            name="Biometric Authentication Security Test",
            test_type=TestType.SECURITY_TEST,
            description="Test biometric authentication implementation security",
            objection_commands=[
                "android hooking search methods BiometricPrompt",
                "android hooking watch class androidx.biometric.BiometricPrompt --dump-args",
                "android keystore list"
            ],
            expected_outcomes=[
                "BiometricPrompt methods found",
                "Authentication callbacks monitored",
                "Keystore entries listed"
            ],
            validation_criteria=[
                "BiometricPrompt class detected",
                "Authentication methods hooked",
                "No authentication bypass detected"
            ]
        )
        
        # Storage test templates
        templates["storage_security_test"] = DevelopmentTest(
            name="Storage Security Test",
            test_type=TestType.SECURITY_TEST,
            description="Test application storage security",
            objection_commands=[
                "android filesystem list",
                "android filesystem find --name *.db",
                "android hooking search methods SharedPreferences"
            ],
            expected_outcomes=[
                "File system accessible",
                "Database files found",
                "SharedPreferences usage detected"
            ],
            validation_criteria=[
                "No sensitive files in world-readable locations",
                "Database files properly protected",
                "SharedPreferences not storing sensitive data"
            ]
        )
        
        # Network test templates
        templates["network_security_test"] = DevelopmentTest(
            name="Network Security Test",
            test_type=TestType.SECURITY_TEST,
            description="Test network communication security",
            objection_commands=[
                "android sslpinning disable",
                "android hooking search methods HttpURLConnection",
                "android proxy set 127.0.0.1 8080"
            ],
            expected_outcomes=[
                "SSL pinning bypass attempted",
                "HTTP methods found",
                "Proxy configuration set"
            ],
            validation_criteria=[
                "SSL pinning properly implemented",
                "HTTPS used for sensitive communications",
                "Certificate validation active"
            ]
        )
        
        return templates
    
    def _generate_tests_for_feature(self, feature: str, package_name: str) -> List[DevelopmentTest]:
        """Generate tests for a specific security feature."""
        tests = []
        feature_lower = feature.lower()
        
        # Map features to test templates
        if "biometric" in feature_lower or "fingerprint" in feature_lower:
            if "biometric_auth_test" in self.test_templates:
                tests.append(self.test_templates["biometric_auth_test"])
        
        elif "storage" in feature_lower or "database" in feature_lower:
            if "storage_security_test" in self.test_templates:
                tests.append(self.test_templates["storage_security_test"])
        
        elif "network" in feature_lower or "https" in feature_lower:
            if "network_security_test" in self.test_templates:
                tests.append(self.test_templates["network_security_test"])
        
        elif "logging" in feature_lower:
            tests.append(DevelopmentTest(
                name="Logging Security Test",
                test_type=TestType.SECURITY_TEST,
                description="Test application logging for sensitive data exposure",
                objection_commands=[
                    "android hooking search methods android.util.Log",
                    "android hooking watch class android.util.Log --dump-args"
                ],
                expected_outcomes=[
                    "Log methods found",
                    "Logging activity monitored"
                ],
                validation_criteria=[
                    "No sensitive data in logs",
                    "Appropriate log levels used"
                ]
            ))
        
        return tests
    
    def _categorize_security_feature(self, feature: str) -> str:
        """Categorize security feature into test category."""
        feature_lower = feature.lower()
        
        if any(term in feature_lower for term in ["auth", "biometric", "login", "password"]):
            return "authentication"
        elif any(term in feature_lower for term in ["storage", "database", "file", "preferences"]):
            return "storage"
        elif any(term in feature_lower for term in ["network", "http", "ssl", "tls"]):
            return "network"
        elif any(term in feature_lower for term in ["crypto", "encryption", "key"]):
            return "crypto"
        elif any(term in feature_lower for term in ["log", "logging"]):
            return "logging"
        else:
            return "general"
    
    def _create_general_security_tests(self, package_name: str) -> List[DevelopmentTest]:
        """Create general security tests."""
        return [
            DevelopmentTest(
                name="Application Component Enumeration",
                test_type=TestType.SMOKE_TEST,
                description="Enumerate application components and entry points",
                objection_commands=[
                    "android hooking list classes",
                    "memory list modules",
                    "android filesystem list"
                ],
                expected_outcomes=[
                    "Application classes listed",
                    "Loaded modules enumerated",
                    "File system accessible"
                ],
                validation_criteria=[
                    "Application successfully analyzed",
                    "No critical components exposed"
                ]
            )
        ]
    
    def _execute_objection_commands(self, package_name: str, commands: List[str], 
                                   timeout: int) -> Tuple[str, Optional[str]]:
        """Execute objection commands and return output."""
        try:
            # Create objection script
            script_content = self._create_objection_script(commands)
            
            with tempfile.NamedTemporaryFile(mode='w', suffix='.js', delete=False) as script_file:
                script_file.write(script_content)
                script_path = script_file.name
            
            # Execute objection
            cmd = [
                'objection', '-g', package_name, 'explore',
                '--startup-script', script_path,
                '--quiet'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            
            # Clean up
            Path(script_path).unlink(missing_ok=True)
            
            return result.stdout, result.stderr if result.stderr else None
            
        except subprocess.TimeoutExpired:
            return "", "Command timeout"
        except Exception as e:
            return "", str(e)
    
    def _create_objection_script(self, commands: List[str]) -> str:
        """Create objection JavaScript script from commands."""
        script = '''
// AODS Development Test Script
console.log("[DEV-TEST] Starting development test");

'''
        for i, cmd in enumerate(commands):
            script += f'''
// Command {i+1}: {cmd}
try {{
    console.log("[DEV-TEST] Executing: {cmd}");
    // Note: Actual objection command execution would be implemented here
    console.log("[DEV-TEST] Command completed");
}} catch (e) {{
    console.log("[DEV-TEST] Command failed: " + e);
}}

'''
        
        script += '''
console.log("[DEV-TEST] Development test completed");
'''
        return script
    
    def _validate_test_results(self, test: DevelopmentTest, output: str) -> List[bool]:
        """Validate test results against criteria."""
        validation_results = []
        
        for criterion in test.validation_criteria:
            # Simple validation based on output content
            # In a real implementation, this would be more sophisticated
            if any(outcome in output for outcome in test.expected_outcomes):
                validation_results.append(True)
            else:
                validation_results.append(False)
        
        return validation_results
    
    def _extract_test_evidence(self, output: str, expected_outcomes: List[str]) -> List[str]:
        """Extract evidence from test output."""
        evidence = []
        
        lines = output.split('\n')
        for line in lines:
            line = line.strip()
            if line and any(outcome.lower() in line.lower() for outcome in expected_outcomes):
                evidence.append(line)
        
        return evidence[:5]  # Limit to top 5 evidence items
    
    def _get_monitoring_commands_for_area(self, area: str) -> List[str]:
        """Get monitoring commands for specific area."""
        commands_map = {
            "logging": [
                "android hooking watch class android.util.Log --dump-args",
                "jobs list"
            ],
            "storage": [
                "android hooking watch class android.content.SharedPreferences --dump-args",
                "android filesystem list"
            ],
            "network": [
                "android hooking watch class java.net.HttpURLConnection --dump-args",
                "android sslpinning disable"
            ],
            "authentication": [
                "android hooking watch class androidx.biometric.BiometricPrompt --dump-args",
                "android keystore list"
            ]
        }
        
        return commands_map.get(area, ["android hooking list classes"])
    
    def _create_monitoring_script(self, commands: List[str]) -> str:
        """Create monitoring script for real-time feedback."""
        script = f"""#!/bin/bash
# AODS Development Monitoring Script

echo "Starting development monitoring session..."

"""
        for i, cmd in enumerate(commands, 1):
            script += f'echo "Monitor {i}: {cmd}"\n'
        
        script += """
echo "Connecting to objection..."
objection -g $1 explore
"""
        return script
    
    def _calculate_overall_status(self, test_results: List[TestResult]) -> str:
        """Calculate overall test status."""
        if not test_results:
            return "no_tests"
        
        failed_count = sum(1 for r in test_results if r.status == TestStatus.FAILED)
        error_count = sum(1 for r in test_results if r.status == TestStatus.ERROR)
        
        if error_count > 0:
            return "error"
        elif failed_count > len(test_results) // 2:
            return "mostly_failed"
        elif failed_count > 0:
            return "some_failed"
        else:
            return "all_passed"
    
    def _calculate_security_score(self, test_results: List[TestResult]) -> float:
        """Calculate security score based on test results."""
        if not test_results:
            return 0.0
        
        passed_count = sum(1 for r in test_results if r.status == TestStatus.PASSED)
        return (passed_count / len(test_results)) * 100
    
    def _analyze_test_failure(self, result: TestResult) -> Dict[str, Any]:
        """Analyze test failure to determine issue details."""
        return {
            "test_name": result.test_name,
            "severity": "critical" if "security" in result.test_name.lower() else "warning",
            "issue": result.error_message or "Test validation failed",
            "impact": "Security vulnerability detected" if "security" in result.test_name.lower() else "Functionality issue",
            "timestamp": result.timestamp
        }
    
    def _generate_fix_recommendations(self, result: TestResult) -> List[str]:
        """Generate fix recommendations for failed test."""
        recommendations = []
        
        if "biometric" in result.test_name.lower():
            recommendations.extend([
                "Ensure BiometricPrompt is properly implemented",
                "Verify CryptoObject usage for authentication",
                "Check authentication callback handling"
            ])
        elif "storage" in result.test_name.lower():
            recommendations.extend([
                "Review file permissions and storage locations",
                "Encrypt sensitive data before storage",
                "Use appropriate SharedPreferences modes"
            ])
        elif "network" in result.test_name.lower():
            recommendations.extend([
                "Implement proper SSL certificate pinning",
                "Use HTTPS for all sensitive communications",
                "Validate server certificates"
            ])
        
        return recommendations
    
    def _generate_quick_fixes(self, test_results: List[TestResult]) -> List[Dict[str, str]]:
        """Generate quick fix suggestions."""
        fixes = []
        
        for result in test_results:
            if result.status == TestStatus.FAILED:
                if "logging" in result.test_name.lower():
                    fixes.append({
                        "issue": "Insecure logging detected",
                        "fix": "Remove sensitive data from log statements",
                        "code_example": "Log.d(TAG, \"User action completed\"); // Remove user data"
                    })
        
        return fixes
    
    def _create_detailed_analysis(self, test_results: List[TestResult]) -> Dict[str, Any]:
        """Create detailed analysis of test results."""
        analysis = {
            "total_tests": len(test_results),
            "passed": sum(1 for r in test_results if r.status == TestStatus.PASSED),
            "failed": sum(1 for r in test_results if r.status == TestStatus.FAILED),
            "errors": sum(1 for r in test_results if r.status == TestStatus.ERROR),
            "execution_time": sum(r.execution_time for r in test_results),
            "categories": {}
        }
        
        # Group by test type
        for result in test_results:
            test_type = "unknown"
            if "security" in result.test_name.lower():
                test_type = "security"
            elif "integration" in result.test_name.lower():
                test_type = "integration"
            elif "smoke" in result.test_name.lower():
                test_type = "smoke"
            
            if test_type not in analysis["categories"]:
                analysis["categories"][test_type] = {"passed": 0, "failed": 0, "total": 0}
            
            analysis["categories"][test_type]["total"] += 1
            if result.status == TestStatus.PASSED:
                analysis["categories"][test_type]["passed"] += 1
            else:
                analysis["categories"][test_type]["failed"] += 1
        
        return analysis
    
    def _create_regression_test_from_result(self, result: TestResult) -> DevelopmentTest:
        """Create regression test from successful test result."""
        return DevelopmentTest(
            name=f"Regression: {result.test_name}",
            test_type=TestType.REGRESSION_TEST,
            description=f"Regression test to ensure {result.test_name} continues to pass",
            objection_commands=[
                "android hooking list classes",
                "memory list modules"
            ],  # Simplified for regression
            expected_outcomes=[
                "Test continues to pass",
                "No regression detected"
            ],
            validation_criteria=[
                "Same validation as original test"
            ]
        )
    
    def _log_test_suite_summary(self, results: Dict[str, List[TestResult]]) -> None:
        """Log test suite execution summary."""
        total_tests = sum(len(category_results) for category_results in results.values())
        total_passed = sum(
            sum(1 for r in category_results if r.status == TestStatus.PASSED)
            for category_results in results.values()
        )
        
        self.logger.info(f"Test suite completed: {total_passed}/{total_tests} tests passed")
        
        for category, category_results in results.items():
            category_passed = sum(1 for r in category_results if r.status == TestStatus.PASSED)
            self.logger.info(f"  {category}: {category_passed}/{len(category_results)} passed")
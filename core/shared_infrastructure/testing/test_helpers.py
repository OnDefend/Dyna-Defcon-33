#!/usr/bin/env python3
"""
AODS Shared Infrastructure - Test Helpers

Comprehensive testing utilities for AODS framework validation, providing:
- Common test patterns and fixtures
- APK test data generation
- Analysis result validation helpers
- Plugin testing utilities
- Framework integration testing
- Performance test utilities
- Mock data generators for consistent testing

These utilities ensure reliable, consistent testing across all AODS components
while reducing test code duplication and improving test maintainability.
"""

import os
import json
import tempfile
import zipfile
import logging
import time
import hashlib
import random
import string
from pathlib import Path
from typing import Dict, List, Any, Optional, Union, Callable, Generator
from dataclasses import dataclass, field
from unittest.mock import Mock, MagicMock, patch
from contextlib import contextmanager
import threading

from ..analysis_exceptions import AnalysisError
from ..file_handlers import SafeFileReader, FileTypeDetector

logger = logging.getLogger(__name__)

@dataclass
class TestAPKMetadata:
    """Test APK metadata for consistent test data."""
    package_name: str
    version_name: str
    version_code: int
    min_sdk_version: int
    target_sdk_version: int
    file_size: int = 1000000  # 1MB default
    vulnerabilities: List[str] = field(default_factory=list)
    permissions: List[str] = field(default_factory=list)
    activities: List[str] = field(default_factory=list)

@dataclass
class TestAnalysisResult:
    """Standard test analysis result structure."""
    plugin_name: str
    success: bool
    findings: List[Dict[str, Any]] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    execution_time: float = 0.0
    confidence_scores: Dict[str, float] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

class TestDataGenerator:
    """Generates consistent test data for AODS testing."""
    
    def __init__(self, seed: int = 42):
        """Initialize test data generator with reproducible seed."""
        self.seed = seed
        random.seed(seed)
        
    def generate_apk_metadata(self, package_name: str = None) -> TestAPKMetadata:
        """Generate consistent APK metadata for testing."""
        if not package_name:
            package_name = f"com.test.app{random.randint(1000, 9999)}"
            
        return TestAPKMetadata(
            package_name=package_name,
            version_name=f"{random.randint(1, 10)}.{random.randint(0, 9)}.{random.randint(0, 9)}",
            version_code=random.randint(1, 100),
            min_sdk_version=random.choice([21, 23, 26, 28, 29, 30]),
            target_sdk_version=random.choice([28, 29, 30, 31, 32, 33]),
            file_size=random.randint(500000, 50000000),  # 500KB - 50MB
            vulnerabilities=random.sample([
                "sql_injection", "xss", "hardcoded_secrets", "weak_crypto",
                "insecure_storage", "network_cleartext", "exported_components"
            ], k=random.randint(0, 4)),
            permissions=random.sample([
                "android.permission.INTERNET",
                "android.permission.ACCESS_NETWORK_STATE",
                "android.permission.READ_EXTERNAL_STORAGE",
                "android.permission.WRITE_EXTERNAL_STORAGE",
                "android.permission.CAMERA",
                "android.permission.ACCESS_FINE_LOCATION"
            ], k=random.randint(1, 4)),
            activities=random.sample([
                "MainActivity", "LoginActivity", "SettingsActivity",
                "ProfileActivity", "WebViewActivity"
            ], k=random.randint(1, 3))
        )
    
    def generate_vulnerability_finding(self, vuln_type: str = None) -> Dict[str, Any]:
        """Generate consistent vulnerability finding for testing."""
        if not vuln_type:
            vuln_type = random.choice([
                "sql_injection", "xss", "hardcoded_secrets", "weak_crypto",
                "insecure_storage", "network_cleartext", "exported_components"
            ])
            
        return {
            "type": vuln_type,
            "severity": random.choice(["Low", "Medium", "High", "Critical"]),
            "confidence": round(random.uniform(0.3, 1.0), 2),
            "description": f"Test {vuln_type} vulnerability",
            "location": f"com/test/app/{vuln_type.replace('_', '/')}.java",
            "line_number": random.randint(1, 500),
            "evidence": f"Test evidence for {vuln_type}",
            "remediation": f"Fix {vuln_type} by implementing secure practices",
            "cwe_id": random.choice([20, 79, 89, 295, 327, 798]),
            "masvs_control": random.choice([
                "MASVS-STORAGE-1", "MASVS-CRYPTO-1", "MASVS-NETWORK-1",
                "MASVS-AUTH-1", "MASVS-PLATFORM-1", "MASVS-CODE-1"
            ])
        }
    
    def generate_test_analysis_result(self, plugin_name: str, 
                                    success: bool = True,
                                    num_findings: int = None) -> TestAnalysisResult:
        """Generate test analysis result."""
        if num_findings is None:
            num_findings = random.randint(0, 5)
            
        findings = [self.generate_vulnerability_finding() 
                   for _ in range(num_findings)]
        
        return TestAnalysisResult(
            plugin_name=plugin_name,
            success=success,
            findings=findings,
            errors=[] if success else [f"Test error in {plugin_name}"],
            execution_time=round(random.uniform(0.1, 10.0), 2),
            confidence_scores={
                f"confidence_{i}": round(random.uniform(0.5, 1.0), 2) 
                for i in range(len(findings))
            },
            metadata={
                "test_mode": True,
                "generated_at": time.time(),
                "generator_seed": self.seed
            }
        )

class PluginTestHelper:
    """Helper utilities for plugin testing."""
    
    @staticmethod
    def create_mock_apk_context(package_name: str = "com.test.app") -> Mock:
        """Create mock APK context for plugin testing."""
        context = Mock()
        context.package_name = package_name
        context.apk_path = f"/tmp/test/{package_name}.apk"
        context.extracted_path = f"/tmp/test/{package_name}_extracted"
        context.manifest_path = f"/tmp/test/{package_name}_extracted/AndroidManifest.xml"
        
        # Add common attributes
        context.version_name = "1.0.0"
        context.version_code = 1
        context.min_sdk_version = 21
        context.target_sdk_version = 30
        context.file_size = 1000000
        
        # Add mock methods
        context.get_file_content = Mock(return_value="Test file content")
        context.get_extracted_files = Mock(return_value=["classes.dex", "AndroidManifest.xml"])
        context.get_permissions = Mock(return_value=["android.permission.INTERNET"])
        
        return context
    
    @staticmethod
    def create_mock_analysis_result(success: bool = True, 
                                  findings: List[Dict] = None) -> Dict[str, Any]:
        """Create mock analysis result for testing."""
        if findings is None:
            findings = []
            
        return {
            "success": success,
            "findings": findings,
            "errors": [] if success else ["Test error"],
            "execution_time": 1.0,
            "plugin_name": "test_plugin",
            "timestamp": time.time(),
            "metadata": {"test_mode": True}
        }
    
    @staticmethod
    @contextmanager
    def temporary_test_files(file_structure: Dict[str, str]) -> Generator[Path, None, None]:
        """Create temporary test files with specified structure."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            
            for file_path, content in file_structure.items():
                full_path = temp_path / file_path
                full_path.parent.mkdir(parents=True, exist_ok=True)
                
                if isinstance(content, str):
                    full_path.write_text(content, encoding='utf-8')
                elif isinstance(content, bytes):
                    full_path.write_bytes(content)
                    
            yield temp_path
    
    @staticmethod
    def create_test_apk(output_path: Path, 
                       package_name: str = "com.test.app",
                       include_manifest: bool = True) -> Path:
        """Create minimal test APK for testing."""
        apk_path = output_path / f"{package_name}.apk"
        
        with zipfile.ZipFile(apk_path, 'w', zipfile.ZIP_DEFLATED) as apk:
            # Add minimal AndroidManifest.xml
            if include_manifest:
                manifest_content = f'''<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="{package_name}"
    android:versionCode="1"
    android:versionName="1.0">
    <uses-sdk android:minSdkVersion="21" android:targetSdkVersion="30" />
    <uses-permission android:name="android.permission.INTERNET" />
    <application android:label="Test App">
        <activity android:name=".MainActivity"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>'''
                apk.writestr("AndroidManifest.xml", manifest_content)
            
            # Add minimal classes.dex
            apk.writestr("classes.dex", b"\x64\x65\x78\x0a\x30\x33\x35\x00")  # Minimal DEX header
            
            # Add test resources
            apk.writestr("resources.arsc", b"\x02\x00\x0c\x00")
            apk.writestr("META-INF/CERT.SF", "Test signature file")
            apk.writestr("META-INF/CERT.RSA", b"Test certificate")
            
        return apk_path

class FrameworkTestHelper:
    """Helper utilities for framework-level testing."""
    
    @staticmethod
    def run_plugin_test_suite(plugin_class: type, 
                            test_cases: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Run comprehensive test suite for a plugin."""
        results = {
            "plugin_name": plugin_class.__name__,
            "total_tests": len(test_cases),
            "passed": 0,
            "failed": 0,
            "errors": [],
            "execution_times": [],
            "test_results": []
        }
        
        for i, test_case in enumerate(test_cases):
            test_name = test_case.get("name", f"test_{i}")
            
            try:
                start_time = time.time()
                
                # Create plugin instance
                plugin = plugin_class()
                
                # Run test case
                if "setup" in test_case:
                    test_case["setup"]()
                
                test_result = test_case["test_function"](plugin)
                execution_time = time.time() - start_time
                
                if test_case.get("cleanup"):
                    test_case["cleanup"]()
                
                # Validate result
                if test_case.get("validator"):
                    is_valid = test_case["validator"](test_result)
                else:
                    is_valid = test_result.get("success", False)
                
                if is_valid:
                    results["passed"] += 1
                else:
                    results["failed"] += 1
                    results["errors"].append(f"Test {test_name} validation failed")
                
                results["execution_times"].append(execution_time)
                results["test_results"].append({
                    "name": test_name,
                    "success": is_valid,
                    "execution_time": execution_time,
                    "result": test_result
                })
                
            except Exception as e:
                results["failed"] += 1
                results["errors"].append(f"Test {test_name} failed: {str(e)}")
                results["test_results"].append({
                    "name": test_name,
                    "success": False,
                    "error": str(e)
                })
        
        # Calculate summary statistics
        if results["execution_times"]:
            results["avg_execution_time"] = sum(results["execution_times"]) / len(results["execution_times"])
            results["total_execution_time"] = sum(results["execution_times"])
        
        results["success_rate"] = (results["passed"] / results["total_tests"]) * 100
        
        return results
    
    @staticmethod
    def validate_plugin_interface(plugin_instance: Any) -> Dict[str, bool]:
        """Validate that plugin implements required interface."""
        required_methods = [
            "run_plugin", "__init__"
        ]
        
        optional_methods = [
            "setup", "cleanup", "get_metadata", "validate_config"
        ]
        
        validation_result = {
            "has_required_methods": True,
            "required_methods_found": [],
            "required_methods_missing": [],
            "optional_methods_found": [],
            "is_valid_plugin": True
        }
        
        # Check required methods
        for method in required_methods:
            if hasattr(plugin_instance, method) and callable(getattr(plugin_instance, method)):
                validation_result["required_methods_found"].append(method)
            else:
                validation_result["required_methods_missing"].append(method)
                validation_result["has_required_methods"] = False
        
        # Check optional methods
        for method in optional_methods:
            if hasattr(plugin_instance, method) and callable(getattr(plugin_instance, method)):
                validation_result["optional_methods_found"].append(method)
        
        validation_result["is_valid_plugin"] = validation_result["has_required_methods"]
        
        return validation_result

class PerformanceTestHelper:
    """Helper utilities for performance testing."""
    
    @staticmethod
    def benchmark_function(func: Callable, 
                          args: tuple = (), 
                          kwargs: Dict = None,
                          iterations: int = 10) -> Dict[str, Any]:
        """Benchmark function performance."""
        if kwargs is None:
            kwargs = {}
            
        execution_times = []
        results = []
        errors = []
        
        for i in range(iterations):
            try:
                start_time = time.perf_counter()
                result = func(*args, **kwargs)
                end_time = time.perf_counter()
                
                execution_time = end_time - start_time
                execution_times.append(execution_time)
                results.append(result)
                
            except Exception as e:
                errors.append(f"Iteration {i}: {str(e)}")
        
        # Calculate statistics
        if execution_times:
            avg_time = sum(execution_times) / len(execution_times)
            min_time = min(execution_times)
            max_time = max(execution_times)
            
            # Calculate standard deviation
            variance = sum((t - avg_time) ** 2 for t in execution_times) / len(execution_times)
            std_dev = variance ** 0.5
        else:
            avg_time = min_time = max_time = std_dev = 0
        
        return {
            "function_name": func.__name__,
            "iterations": iterations,
            "successful_runs": len(execution_times),
            "failed_runs": len(errors),
            "execution_times": execution_times,
            "avg_execution_time": avg_time,
            "min_execution_time": min_time,
            "max_execution_time": max_time,
            "std_deviation": std_dev,
            "errors": errors,
            "results": results
        }
    
    @staticmethod
    def memory_usage_test(func: Callable, 
                         args: tuple = (), 
                         kwargs: Dict = None) -> Dict[str, Any]:
        """Test memory usage of function."""
        import psutil
        import gc
        
        if kwargs is None:
            kwargs = {}
        
        # Force garbage collection before test
        gc.collect()
        
        process = psutil.Process()
        memory_before = process.memory_info().rss
        
        try:
            start_time = time.perf_counter()
            result = func(*args, **kwargs)
            end_time = time.perf_counter()
            
            memory_after = process.memory_info().rss
            memory_used = memory_after - memory_before
            execution_time = end_time - start_time
            
            # Force garbage collection after test
            gc.collect()
            memory_after_gc = process.memory_info().rss
            memory_freed = memory_after - memory_after_gc
            
            return {
                "function_name": func.__name__,
                "success": True,
                "execution_time": execution_time,
                "memory_before_mb": memory_before / (1024 * 1024),
                "memory_after_mb": memory_after / (1024 * 1024),
                "memory_used_mb": memory_used / (1024 * 1024),
                "memory_freed_mb": memory_freed / (1024 * 1024),
                "memory_net_mb": (memory_used - memory_freed) / (1024 * 1024),
                "result": result
            }
            
        except Exception as e:
            return {
                "function_name": func.__name__,
                "success": False,
                "error": str(e),
                "memory_before_mb": memory_before / (1024 * 1024)
            }

# Convenience functions
def get_test_data_generator(seed: int = 42) -> TestDataGenerator:
    """Get test data generator instance."""
    return TestDataGenerator(seed)

def create_test_apk_context(package_name: str = "com.test.app") -> Mock:
    """Create mock APK context for testing."""
    return PluginTestHelper.create_mock_apk_context(package_name)

def run_plugin_tests(plugin_class: type, test_cases: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Run plugin test suite."""
    return FrameworkTestHelper.run_plugin_test_suite(plugin_class, test_cases)

def benchmark_plugin(plugin_instance: Any, apk_context: Any, iterations: int = 5) -> Dict[str, Any]:
    """Benchmark plugin performance."""
    return PerformanceTestHelper.benchmark_function(
        plugin_instance.run_plugin, 
        args=(apk_context,), 
        iterations=iterations
    )

# Export all public components
__all__ = [
    "TestAPKMetadata",
    "TestAnalysisResult", 
    "TestDataGenerator",
    "PluginTestHelper",
    "FrameworkTestHelper",
    "PerformanceTestHelper",
    "get_test_data_generator",
    "create_test_apk_context",
    "run_plugin_tests",
    "benchmark_plugin"
]

logger.info("AODS Test Helpers initialized - comprehensive testing utilities ready") 
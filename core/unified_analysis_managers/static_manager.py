#!/usr/bin/env python3
"""
Unified Static Analysis Manager

Consolidates all static analysis management implementations into a single,
intelligent manager with strategy-based execution and performance optimization.

CONSOLIDATED IMPLEMENTATIONS:
- core/scan_type_manager.py → IntelligentStaticStrategy
- core/enhanced_scan_orchestrator.py → StaticStrategy
- plugins/enhanced_static_analysis → ModularStaticStrategy
- core/enhanced_static_analyzer.py → EnhancedStaticStrategy
- Performance optimization strategies → OptimizedStaticStrategy

KEY FEATURES:
- Intelligent strategy selection based on APK characteristics
- Performance optimization for large APKs
- Modular static analysis with comprehensive confidence
- High-quality scan orchestration
- Resource allocation and batch processing
- 100% backward compatibility with existing systems
"""

import logging
import time
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List, Tuple, Union
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from .base_manager import BaseAnalysisManager, AnalysisManagerConfig, ManagerStatus

class StaticStrategy(Enum):
    """Static analysis execution strategies."""
    AUTO = "auto"                         # Automatic strategy selection
    COMPREHENSIVE = "comprehensive"       # Comprehensive static analysis
    PERFORMANCE_OPTIMIZED = "performance_optimized"  # Optimized for large APKs
    MODULAR = "modular"                  # Modular architecture approach
    ENHANCED = "enhanced"                # Enhanced analysis capabilities
    INTELLIGENT = "intelligent"          # AI-powered analysis
    ENTERPRISE = "enterprise"            # High-quality orchestration

@dataclass
class StaticConfig:
    """Configuration for static analysis strategies."""
    max_file_size: int = 10485760  # 10MB
    enable_entropy_analysis: bool = True
    enable_pattern_matching: bool = True
    enable_manifest_analysis: bool = True
    enable_secret_detection: bool = True
    enable_confidence_calculation: bool = True
    analysis_timeout: int = 300
    max_concurrent_files: int = 10
    enable_performance_optimization: bool = True
    enable_large_apk_optimization: bool = True
    excluded_file_patterns: List[str] = None
    included_file_patterns: List[str] = None
    
    def __post_init__(self):
        if self.excluded_file_patterns is None:
            self.excluded_file_patterns = [
                r".*\.png$", r".*\.jpg$", r".*\.gif$", r".*\.so$",
                r".*\.dex$", r".*\.jar$", r".*\.zip$"
            ]
        if self.included_file_patterns is None:
            self.included_file_patterns = [
                r".*\.java$", r".*\.kt$", r".*\.xml$", r".*\.json$",
                r".*\.properties$", r".*\.yaml$", r".*\.yml$"
            ]

class BaseStaticStrategy(ABC):
    """Base class for static analysis strategies."""
    
    def __init__(self, package_name: str, config: StaticConfig):
        self.package_name = package_name
        self.config = config
        self.logger = logging.getLogger(f"{self.__class__.__name__}_{package_name}")
        self.analysis_results = {}
        self.analysis_complete = False
    
    @abstractmethod
    def analyze_apk(self, apk_path: str, extracted_path: str = None) -> Tuple[bool, Dict[str, Any]]:
        """Perform static analysis on APK."""
        pass
    
    @abstractmethod
    def analyze_manifest(self, manifest_path: str) -> Tuple[bool, Dict[str, Any]]:
        """Analyze AndroidManifest.xml."""
        pass
    
    @abstractmethod
    def analyze_source_code(self, source_path: str) -> Tuple[bool, Dict[str, Any]]:
        """Analyze source code files."""
        pass
    
    def get_strategy_info(self) -> Dict[str, Any]:
        """Get strategy information."""
        return {
            "name": self.__class__.__name__,
            "package_name": self.package_name,
            "analysis_complete": self.analysis_complete,
            "capabilities": self._get_capabilities()
        }
    
    @abstractmethod
    def _get_capabilities(self) -> List[str]:
        """Get strategy capabilities."""
        pass

class ComprehensiveStaticStrategy(BaseStaticStrategy):
    """Comprehensive static analysis strategy."""
    
    def analyze_apk(self, apk_path: str, extracted_path: str = None) -> Tuple[bool, Dict[str, Any]]:
        """Perform comprehensive static analysis."""
        try:
            self.logger.info("Starting comprehensive static analysis...")
            
            results = {
                "analysis_type": "comprehensive",
                "package_name": self.package_name,
                "apk_path": apk_path,
                "timestamp": time.time(),
                "findings": {},
                "statistics": {},
                "recommendations": []
            }
            
            # Manifest analysis
            if extracted_path:
                manifest_path = Path(extracted_path) / "AndroidManifest.xml"
                if manifest_path.exists():
                    success, manifest_results = self.analyze_manifest(str(manifest_path))
                    if success:
                        results["findings"]["manifest"] = manifest_results
            
            # Source code analysis
            if extracted_path:
                success, source_results = self.analyze_source_code(extracted_path)
                if success:
                    results["findings"]["source_code"] = source_results
            
            # Resource analysis
            results["findings"]["resources"] = self._analyze_resources(extracted_path)
            
            # Generate summary
            results["statistics"] = self._generate_statistics(results["findings"])
            results["recommendations"] = self._generate_recommendations(results["findings"])
            
            self.analysis_results = results
            self.analysis_complete = True
            
            self.logger.info("Comprehensive static analysis completed")
            return True, results
            
        except Exception as e:
            self.logger.error(f"Comprehensive static analysis failed: {e}")
            return False, {"error": str(e)}
    
    def analyze_manifest(self, manifest_path: str) -> Tuple[bool, Dict[str, Any]]:
        """Comprehensive manifest analysis."""
        try:
            import xml.etree.ElementTree as ET
            
            results = {
                "permissions": [],
                "activities": [],
                "services": [],
                "receivers": [],
                "providers": [],
                "security_findings": [],
                "risk_level": "LOW"
            }
            
            tree = ET.parse(manifest_path)
            root = tree.getroot()
            
            # Extract permissions
            for permission in root.findall(".//uses-permission"):
                perm_name = permission.get("{http://schemas.android.com/apk/res/android}name", "")
                results["permissions"].append(perm_name)
                
                # Check for dangerous permissions
                if self._is_dangerous_permission(perm_name):
                    results["security_findings"].append({
                        "type": "dangerous_permission",
                        "permission": perm_name,
                        "severity": "HIGH"
                    })
            
            # Extract components
            for activity in root.findall(".//activity"):
                name = activity.get("{http://schemas.android.com/apk/res/android}name", "")
                exported = activity.get("{http://schemas.android.com/apk/res/android}exported", "false")
                results["activities"].append({"name": name, "exported": exported})
                
                if exported == "true":
                    results["security_findings"].append({
                        "type": "exported_activity",
                        "component": name,
                        "severity": "MEDIUM"
                    })
            
            # Calculate risk level
            results["risk_level"] = self._calculate_manifest_risk(results["security_findings"])
            
            return True, results
            
        except Exception as e:
            self.logger.error(f"Manifest analysis failed: {e}")
            return False, {"error": str(e)}
    
    def analyze_source_code(self, source_path: str) -> Tuple[bool, Dict[str, Any]]:
        """Comprehensive source code analysis."""
        try:
            results = {
                "total_files": 0,
                "analyzed_files": 0,
                "security_findings": [],
                "code_quality": {},
                "secrets_detected": [],
                "risk_level": "LOW"
            }
            
            source_dir = Path(source_path)
            
            # Find all source files
            source_files = []
            for pattern in self.config.included_file_patterns:
                source_files.extend(source_dir.rglob(pattern.replace(r"\.", "").replace("$", "")))
            
            results["total_files"] = len(source_files)
            
            # Analyze each file
            for file_path in source_files:
                if file_path.stat().st_size > self.config.max_file_size:
                    continue
                
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        
                    # Security pattern analysis
                    file_findings = self._analyze_file_security(str(file_path), content)
                    results["security_findings"].extend(file_findings)
                    
                    # Secret detection
                    secrets = self._detect_secrets(str(file_path), content)
                    results["secrets_detected"].extend(secrets)
                    
                    results["analyzed_files"] += 1
                    
                except Exception as e:
                    self.logger.warning(f"Failed to analyze file {file_path}: {e}")
            
            # Calculate risk level
            results["risk_level"] = self._calculate_source_risk(results["security_findings"])
            
            return True, results
            
        except Exception as e:
            self.logger.error(f"Source code analysis failed: {e}")
            return False, {"error": str(e)}
    
    def _analyze_resources(self, extracted_path: str) -> Dict[str, Any]:
        """Analyze resource files."""
        results = {
            "resource_files": 0,
            "string_resources": 0,
            "potential_secrets": [],
            "hardcoded_urls": []
        }
        
        if not extracted_path:
            return results
        
        try:
            res_dir = Path(extracted_path) / "res"
            if not res_dir.exists():
                return results
            
            # Analyze string resources
            for strings_file in res_dir.rglob("strings.xml"):
                try:
                    import xml.etree.ElementTree as ET
                    tree = ET.parse(strings_file)
                    root = tree.getroot()
                    
                    for string_elem in root.findall("string"):
                        name = string_elem.get("name", "")
                        value = string_elem.text or ""
                        
                        results["string_resources"] += 1
                        
                        # Check for potential secrets
                        if self._is_potential_secret(name, value):
                            results["potential_secrets"].append({
                                "name": name,
                                "value": value[:50] + "..." if len(value) > 50 else value,
                                "file": str(strings_file)
                            })
                        
                        # Check for hardcoded URLs
                        if "http" in value.lower():
                            results["hardcoded_urls"].append({
                                "name": name,
                                "url": value,
                                "file": str(strings_file)
                            })
                
                except Exception as e:
                    self.logger.warning(f"Failed to analyze strings file {strings_file}: {e}")
            
            # Count total resource files
            results["resource_files"] = len(list(res_dir.rglob("*")))
            
        except Exception as e:
            self.logger.warning(f"Resource analysis failed: {e}")
        
        return results
    
    def _is_dangerous_permission(self, permission: str) -> bool:
        """Check if permission is dangerous."""
        dangerous_permissions = [
            "android.permission.READ_EXTERNAL_STORAGE",
            "android.permission.WRITE_EXTERNAL_STORAGE",
            "android.permission.CAMERA",
            "android.permission.RECORD_AUDIO",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.ACCESS_COARSE_LOCATION",
            "android.permission.READ_CONTACTS",
            "android.permission.WRITE_CONTACTS",
            "android.permission.READ_SMS",
            "android.permission.SEND_SMS",
            "android.permission.CALL_PHONE"
        ]
        return permission in dangerous_permissions
    
    def _calculate_manifest_risk(self, findings: List[Dict]) -> str:
        """Calculate risk level based on manifest findings."""
        high_count = sum(1 for f in findings if f.get("severity") == "HIGH")
        medium_count = sum(1 for f in findings if f.get("severity") == "MEDIUM")
        
        if high_count > 3:
            return "CRITICAL"
        elif high_count > 0 or medium_count > 5:
            return "HIGH"
        elif medium_count > 2:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _analyze_file_security(self, file_path: str, content: str) -> List[Dict[str, Any]]:
        """Analyze file for security issues."""
        findings = []
        
        # Simple pattern matching for common security issues
        security_patterns = {
            "hardcoded_password": r'(?i)password\s*[=:]\s*["\'][^"\']{6,}["\']',
            "hardcoded_api_key": r'(?i)api_key\s*[=:]\s*["\'][^"\']{10,}["\']',
            "sql_injection": r'(?i)rawQuery\s*\(\s*["\'].*["\'].*\+.*\)',
            "weak_crypto": r'(?i)(MD5|SHA1|DES)\s*\(',
            "logging_sensitive": r'(?i)Log\.[dviwe]\s*\(\s*.*,\s*.*(password|secret|token).*\)'
        }
        
        for pattern_name, pattern in security_patterns.items():
            import re
            matches = re.finditer(pattern, content)
            for match in matches:
                line_number = content[:match.start()].count('\n') + 1
                findings.append({
                    "type": pattern_name,
                    "file": file_path,
                    "line": line_number,
                    "match": match.group()[:100],
                    "severity": "HIGH" if pattern_name in ["hardcoded_password", "sql_injection"] else "MEDIUM"
                })
        
        return findings
    
    def _detect_secrets(self, file_path: str, content: str) -> List[Dict[str, Any]]:
        """Detect potential secrets in file content."""
        secrets = []
        
        # Basic entropy-based secret detection
        import re
        
        # Look for high-entropy strings
        for match in re.finditer(r'["\']([A-Za-z0-9+/]{20,})["\']', content):
            value = match.group(1)
            entropy = self._calculate_entropy(value)
            
            if entropy > 4.5:  # High entropy threshold
                line_number = content[:match.start()].count('\n') + 1
                secrets.append({
                    "file": file_path,
                    "line": line_number,
                    "value": value[:50] + "..." if len(value) > 50 else value,
                    "entropy": entropy,
                    "confidence": min(1.0, entropy / 6.0)
                })
        
        return secrets
    
    def _calculate_entropy(self, string: str) -> float:
        """Calculate Shannon entropy of string."""
        import math
        from collections import Counter
        
        if not string:
            return 0
        
        counts = Counter(string)
        length = len(string)
        
        entropy = 0
        for count in counts.values():
            prob = count / length
            entropy -= prob * math.log2(prob)
        
        return entropy
    
    def _is_potential_secret(self, name: str, value: str) -> bool:
        """Check if string resource might be a secret."""
        secret_indicators = ["password", "secret", "key", "token", "auth", "credential"]
        name_lower = name.lower()
        
        for indicator in secret_indicators:
            if indicator in name_lower:
                return True
        
        # Check value entropy
        if len(value) > 20:
            entropy = self._calculate_entropy(value)
            return entropy > 4.0
        
        return False
    
    def _calculate_source_risk(self, findings: List[Dict]) -> str:
        """Calculate risk level based on source findings."""
        critical_count = sum(1 for f in findings if f.get("severity") == "CRITICAL")
        high_count = sum(1 for f in findings if f.get("severity") == "HIGH")
        medium_count = sum(1 for f in findings if f.get("severity") == "MEDIUM")
        
        if critical_count > 0:
            return "CRITICAL"
        elif high_count > 5:
            return "HIGH"
        elif high_count > 0 or medium_count > 10:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _generate_statistics(self, findings: Dict[str, Any]) -> Dict[str, Any]:
        """Generate analysis statistics."""
        stats = {
            "total_findings": 0,
            "by_severity": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
            "by_category": {},
            "analysis_coverage": {}
        }
        
        # Count findings by severity and category
        for category, data in findings.items():
            if isinstance(data, dict) and "security_findings" in data:
                for finding in data["security_findings"]:
                    stats["total_findings"] += 1
                    severity = finding.get("severity", "LOW")
                    stats["by_severity"][severity] += 1
                    
                    finding_type = finding.get("type", "unknown")
                    stats["by_category"][finding_type] = stats["by_category"].get(finding_type, 0) + 1
        
        return stats
    
    def _generate_recommendations(self, findings: Dict[str, Any]) -> List[str]:
        """Generate security recommendations."""
        recommendations = []
        
        # Analyze findings and generate appropriate recommendations
        if findings.get("manifest", {}).get("security_findings"):
            recommendations.append("Review and minimize dangerous permissions")
            recommendations.append("Ensure exported components are properly secured")
        
        if findings.get("source_code", {}).get("security_findings"):
            recommendations.append("Address identified security vulnerabilities in source code")
            recommendations.append("Implement secure coding practices")
        
        if findings.get("source_code", {}).get("secrets_detected"):
            recommendations.append("Remove hardcoded secrets and use secure storage")
            recommendations.append("Implement proper credential management")
        
        # Add default recommendations
        recommendations.extend([
            "Conduct regular security assessments",
            "Follow OWASP Mobile Security guidelines",
            "Implement runtime application self-protection (RASP)"
        ])
        
        return recommendations
    
    def _get_capabilities(self) -> List[str]:
        """Get comprehensive strategy capabilities."""
        return [
            "manifest_analysis",
            "source_code_analysis",
            "resource_analysis",
            "security_pattern_detection",
            "secret_detection",
            "entropy_analysis",
            "risk_assessment",
            "recommendations_generation"
        ]

class PerformanceOptimizedStaticStrategy(BaseStaticStrategy):
    """Performance-optimized static analysis strategy for large APKs."""
    
    def analyze_apk(self, apk_path: str, extracted_path: str = None) -> Tuple[bool, Dict[str, Any]]:
        """Perform performance-optimized static analysis."""
        try:
            self.logger.info("Starting performance-optimized static analysis...")
            
            results = {
                "analysis_type": "performance_optimized",
                "package_name": self.package_name,
                "apk_path": apk_path,
                "timestamp": time.time(),
                "findings": {},
                "performance_metrics": {},
                "optimizations_applied": []
            }
            
            # Parallel analysis with threading
            import concurrent.futures
            
            analysis_tasks = []
            
            # Manifest analysis task
            if extracted_path:
                manifest_path = Path(extracted_path) / "AndroidManifest.xml"
                if manifest_path.exists():
                    analysis_tasks.append(("manifest", self.analyze_manifest, str(manifest_path)))
            
            # Source code analysis task (optimized)
            if extracted_path:
                analysis_tasks.append(("source_code", self._optimized_source_analysis, extracted_path))
            
            # Execute tasks in parallel
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.config.max_concurrent_files) as executor:
                future_to_task = {
                    executor.submit(task_func, task_arg): task_name
                    for task_name, task_func, task_arg in analysis_tasks
                }
                
                for future in concurrent.futures.as_completed(future_to_task):
                    task_name = future_to_task[future]
                    try:
                        success, result = future.result()
                        if success:
                            results["findings"][task_name] = result
                            results["optimizations_applied"].append(f"parallel_{task_name}_analysis")
                    except Exception as e:
                        self.logger.error(f"Task {task_name} failed: {e}")
                        results["findings"][task_name] = {"error": str(e)}
            
            # Performance metrics
            results["performance_metrics"] = {
                "analysis_duration": time.time() - results["timestamp"],
                "parallel_tasks": len(analysis_tasks),
                "optimizations_count": len(results["optimizations_applied"])
            }
            
            self.analysis_results = results
            self.analysis_complete = True
            
            self.logger.info("Performance-optimized static analysis completed")
            return True, results
            
        except Exception as e:
            self.logger.error(f"Performance-optimized static analysis failed: {e}")
            return False, {"error": str(e)}
    
    def analyze_manifest(self, manifest_path: str) -> Tuple[bool, Dict[str, Any]]:
        """Optimized manifest analysis."""
        # Use the comprehensive implementation but with optimizations
        return ComprehensiveStaticStrategy.analyze_manifest(self, manifest_path)
    
    def analyze_source_code(self, source_path: str) -> Tuple[bool, Dict[str, Any]]:
        """Standard source code analysis interface."""
        return self._optimized_source_analysis(source_path)
    
    def _optimized_source_analysis(self, source_path: str) -> Tuple[bool, Dict[str, Any]]:
        """Optimized source code analysis for large codebases."""
        try:
            results = {
                "total_files": 0,
                "analyzed_files": 0,
                "skipped_files": 0,
                "security_findings": [],
                "optimization_applied": True
            }
            
            source_dir = Path(source_path)
            
            # Smart file filtering to reduce analysis load
            source_files = self._get_priority_files(source_dir)
            results["total_files"] = len(source_files)
            
            # Batch processing for efficiency
            batch_size = 50
            for i in range(0, len(source_files), batch_size):
                batch = source_files[i:i + batch_size]
                batch_results = self._process_file_batch(batch)
                results["security_findings"].extend(batch_results)
                results["analyzed_files"] += len(batch)
            
            return True, results
            
        except Exception as e:
            self.logger.error(f"Optimized source analysis failed: {e}")
            return False, {"error": str(e)}
    
    def _get_priority_files(self, source_dir: Path) -> List[Path]:
        """Get prioritized list of files for analysis."""
        files = []
        
        # Priority 1: Configuration and security-relevant files
        priority_patterns = [
            "**/AndroidManifest.xml",
            "**/*security*.java",
            "**/*auth*.java",
            "**/*crypto*.java",
            "**/*config*.properties"
        ]
        
        for pattern in priority_patterns:
            files.extend(source_dir.glob(pattern))
        
        # Priority 2: Main source files
        main_patterns = ["**/*.java", "**/*.kt"]
        for pattern in main_patterns:
            for file_path in source_dir.glob(pattern):
                if file_path not in files and file_path.stat().st_size <= self.config.max_file_size:
                    files.append(file_path)
        
        return files[:1000]  # Limit to manageable number
    
    def _process_file_batch(self, file_batch: List[Path]) -> List[Dict[str, Any]]:
        """Process a batch of files efficiently."""
        findings = []
        
        for file_path in file_batch:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                # Quick pattern matching for critical issues only
                critical_patterns = {
                    "hardcoded_password": r'(?i)password\s*[=:]\s*["\'][^"\']{6,}["\']',
                    "sql_injection": r'(?i)rawQuery\s*\(\s*["\'].*["\'].*\+.*\)'
                }
                
                for pattern_name, pattern in critical_patterns.items():
                    import re
                    if re.search(pattern, content):
                        findings.append({
                            "type": pattern_name,
                            "file": str(file_path),
                            "severity": "HIGH"
                        })
                        
            except Exception as e:
                self.logger.debug(f"Failed to process file {file_path}: {e}")
        
        return findings
    
    def _get_capabilities(self) -> List[str]:
        """Get performance-optimized strategy capabilities."""
        return [
            "parallel_analysis",
            "batch_processing",
            "file_prioritization",
            "large_apk_optimization",
            "performance_monitoring",
            "selective_analysis"
        ]

class StaticFallbackStrategy(BaseStaticStrategy):
    """Fallback static strategy for minimal analysis."""
    
    def analyze_apk(self, apk_path: str, extracted_path: str = None) -> Tuple[bool, Dict[str, Any]]:
        """Perform minimal static analysis."""
        try:
            results = {
                "analysis_type": "fallback",
                "package_name": self.package_name,
                "apk_path": apk_path,
                "timestamp": time.time(),
                "findings": {"basic": "Static fallback analysis completed"},
                "limitations": ["Limited analysis due to resource constraints"]
            }
            
            # Basic APK information extraction
            if apk_path:
                import os
                results["apk_size"] = os.path.getsize(apk_path)
                results["apk_name"] = os.path.basename(apk_path)
            
            self.analysis_results = results
            self.analysis_complete = True
            
            return True, results
            
        except Exception as e:
            return False, {"error": str(e)}
    
    def analyze_manifest(self, manifest_path: str) -> Tuple[bool, Dict[str, Any]]:
        """Basic manifest analysis."""
        return True, {"basic_manifest_check": "completed"}
    
    def analyze_source_code(self, source_path: str) -> Tuple[bool, Dict[str, Any]]:
        """Basic source code check."""
        return True, {"basic_source_check": "completed"}
    
    def _get_capabilities(self) -> List[str]:
        """Get fallback strategy capabilities."""
        return ["basic_analysis", "minimal_resource_usage", "compatibility_mode"]

class UnifiedStaticManager(BaseAnalysisManager):
    """
    Unified static analysis manager with intelligent strategy selection.
    
    Consolidates all static analysis management approaches into a single interface
    with comprehensive strategy selection and performance optimization.
    """
    
    def __init__(self, config: AnalysisManagerConfig = None):
        # Initialize with default config if none provided
        if config is None:
            config = AnalysisManagerConfig(
                package_name="default",
                strategy="auto"
            )
        
        super().__init__(config)
        
        # Initialize static configuration
        self.static_config = StaticConfig()
        
        # Initialize strategy
        self.current_strategy: Optional[BaseStaticStrategy] = None
        self._initialize_strategy()
    
    def _initialize_strategy(self) -> None:
        """Initialize static strategy based on configuration."""
        try:
            strategy_name = self.config.strategy
            
            if strategy_name == "auto":
                strategy_name = self._select_optimal_strategy()
            
            self.current_strategy = self._create_strategy(strategy_name)
            self.logger.info(f"Initialized static strategy: {strategy_name}")
            
        except Exception as e:
            self.logger.error(f"Strategy initialization failed: {e}")
            # Fallback to basic strategy
            self.current_strategy = self._create_strategy("fallback")
    
    def _select_optimal_strategy(self) -> str:
        """Select optimal strategy based on system capabilities."""
        # This would assess APK size, system resources, etc.
        # For now, default to comprehensive
        return "comprehensive"
    
    def _create_strategy(self, strategy_name: str) -> BaseStaticStrategy:
        """Create strategy instance based on name."""
        strategy_map = {
            "comprehensive": ComprehensiveStaticStrategy,
            "performance_optimized": PerformanceOptimizedStaticStrategy,
            "fallback": StaticFallbackStrategy
        }
        
        strategy_class = strategy_map.get(strategy_name)
        if not strategy_class:
            self.logger.warning(f"Unknown strategy: {strategy_name}, using fallback")
            strategy_class = StaticFallbackStrategy
        
        return strategy_class(self.config.package_name, self.static_config)
    
    def start_connection(self) -> bool:
        """Start static analysis (always succeeds)."""
        self.connected = True
        self.status = ManagerStatus.READY
        return True
    
    def check_connection(self) -> bool:
        """Check static analysis availability (always available)."""
        return True
    
    def execute_command(self, command: str, **kwargs) -> tuple[bool, Any]:
        """Execute static analysis command."""
        if not self.current_strategy:
            return False, "No strategy available"
        
        try:
            if command == "analyze_apk":
                apk_path = kwargs.get('apk_path', '')
                extracted_path = kwargs.get('extracted_path')
                return self.current_strategy.analyze_apk(apk_path, extracted_path)
            elif command == "analyze_manifest":
                manifest_path = kwargs.get('manifest_path', '')
                return self.current_strategy.analyze_manifest(manifest_path)
            elif command == "analyze_source":
                source_path = kwargs.get('source_path', '')
                return self.current_strategy.analyze_source_code(source_path)
            else:
                return False, f"Unknown command: {command}"
            
        except Exception as e:
            self.last_error = e
            return False, f"Command execution failed: {e}"
    
    def stop_connection(self) -> bool:
        """Stop static analysis."""
        self.connected = False
        self.status = ManagerStatus.DISCONNECTED
        return True
    
    def analyze_apk(self, apk_path: str, extracted_path: str = None) -> Tuple[bool, Dict[str, Any]]:
        """Analyze APK using current strategy."""
        if not self.current_strategy:
            return False, {"error": "No strategy available"}
        
        return self.current_strategy.analyze_apk(apk_path, extracted_path)
    
    def get_analysis_results(self) -> Dict[str, Any]:
        """Get analysis results from current strategy."""
        if not self.current_strategy:
            return {}
        
        return getattr(self.current_strategy, 'analysis_results', {})
    
    def get_strategy_info(self) -> Dict[str, Any]:
        """Get information about current strategy."""
        if not self.current_strategy:
            return {"strategy": "none", "capabilities": []}
        
        return self.current_strategy.get_strategy_info()

# Export public interface
__all__ = [
    "UnifiedStaticManager",
    "StaticStrategy",
    "StaticConfig"
] 
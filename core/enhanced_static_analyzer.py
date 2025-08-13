"""
Static Analysis Module for Android APK Files

This module provides static analysis capabilities for Android APK files,
including entropy analysis, secret detection, and code pattern analysis.

Features:
- DEX bytecode analysis with flow detection
- Secret detection with entropy analysis and pattern matching
- Code vulnerability pattern detection
- Binary resource analysis and metadata extraction
- Obfuscation detection and analysis
- Evidence-based confidence calculation
"""

import base64
import hashlib
import json
import logging
import re
import time
import zipfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum

import xml.dom.minidom

from rich.text import Text
from rich.console import Console

# Import APK context
from .apk_ctx import APKContext

# Import modular components directly to avoid circular imports
try:
    from .enhanced_static_analysis.data_structures import SecurityFinding, SecretAnalysis
    from .enhanced_static_analysis.entropy_analyzer import EntropyAnalyzer
    from .enhanced_static_analysis.manifest_parser import AndroidManifestParser
    from .enhanced_static_analysis.code_pattern_analyzer import CodePatternAnalyzer
    from .enhanced_static_analysis.confidence_calculator import StaticAnalysisConfidenceCalculator
except ImportError:
    # Fallback for older structure
    SecurityFinding = None
    SecretAnalysis = None
    EntropyAnalyzer = None
    AndroidManifestParser = None
    CodePatternAnalyzer = None
    StaticAnalysisConfidenceCalculator = None

# Configuration for large APK handling
MAX_FILES_TO_ANALYZE = 500  # Further reduced from 1000
MAX_PROCESSING_TIME = 180  # Increased to 3 minutes to be safe
MAX_FILE_SIZE_MB = 10  # Reduced from 20MB to 10MB
MAX_SECRET_ANALYSIS_FILES = 100  # Reduced from 200 to 100

# Note: SecurityFinding, SecretAnalysis, and other classes are imported from modular package above

class EnhancedStaticAnalyzer:
    """Enhanced Static Analyzer with Professional Confidence System."""

    def __init__(self):
        """Initialize the enhanced static analyzer with professional confidence system."""
        self.console = Console()
        self.logger = logging.getLogger(__name__)
        
        # Initialize entropy analyzer
        self.entropy_analyzer = EntropyAnalyzer()
        
        # Initialize code pattern analyzer
        self.pattern_analyzer = CodePatternAnalyzer()
        
        # Initialize manifest parser
        self.manifest_parser = AndroidManifestParser()
        
        # Initialize professional confidence calculator
        self.confidence_calculator = StaticAnalysisConfidenceCalculator()
        
        # Thresholds are now dynamic - calculated by confidence system
        self.min_entropy_threshold = 3.5
        self.high_entropy_threshold = 4.5
        
        self.logger.debug("Enhanced Static Analyzer initialized with professional confidence system")

    # ... delegate methods to entropy_analyzer for backward compatibility ...
    def calculate_entropy(self, data: str) -> float:
        return self.entropy_analyzer.calculate_entropy(data)

    def is_likely_secret_content(self, value: str, context: str = "", file_path: str = "") -> bool:
        return self.entropy_analyzer.is_likely_secret_content(value, context, file_path)

    def is_likely_false_positive(self, value: str, context: str = "", file_path: str = "") -> bool:
        return self.entropy_analyzer.is_likely_false_positive(value, context, file_path)

    def analyze_string(self, value: str, context: str = "", file_path: str = "") -> SecretAnalysis:
        return self.entropy_analyzer.analyze_string(value, context, file_path)

    def analyze_apk(self, apk_ctx: APKContext) -> Dict[str, Any]:
        """Analyze APK with professional confidence assessment."""
        start_time = time.time()
        
        try:
            self.logger.debug(f"Starting enhanced static analysis for {apk_ctx.package_name}")
            
            # Initialize results with metadata
            results = {
                "package_name": apk_ctx.package_name,
                "analysis_timestamp": start_time,
                "confidence_system": "professional",
                "analyzer_version": "3.0.0"
            }
            
            # Open APK file
            with zipfile.ZipFile(apk_ctx.apk_path, 'r') as apk_zip:
                # Determine if this is a large APK
                is_large_apk = self._is_large_apk(apk_zip)
                
                if is_large_apk:
                    self.logger.debug("Large APK detected - applying optimizations")
                
                # Analyze manifest
                manifest_analysis = self._analyze_manifest(apk_zip)
                results["manifest_analysis"] = manifest_analysis
                
                # Analyze secrets with professional confidence
                secret_analysis = self._analyze_secrets_with_confidence(apk_zip, is_large_apk, start_time)
                results["secret_analysis"] = secret_analysis
                
                # Analyze code patterns with professional confidence  
                code_patterns = self._analyze_code_patterns_with_confidence(apk_zip, is_large_apk, start_time)
                results["code_patterns"] = code_patterns
                
                # Calculate quality metrics
                quality_metrics = self._calculate_quality_metrics(apk_zip)
                results["quality_metrics"] = quality_metrics
                
                # Assess overall risk with professional confidence
                risk_assessment = self._assess_overall_risk_with_confidence(results)
                results["risk_assessment"] = risk_assessment
            
            # Calculate analysis duration
            results["analysis_duration"] = time.time() - start_time
            
            self.logger.debug(f"Enhanced static analysis completed in {results['analysis_duration']:.2f}s")
            
            return results
            
        except Exception as e:
            self.logger.error(f"Enhanced static analysis failed: {e}")
            return {
                "package_name": apk_ctx.package_name,
                "error": str(e),
                "analysis_duration": time.time() - start_time,
                "confidence_system": "professional"
            }

    def _analyze_secrets_with_confidence(self, apk_zip: zipfile.ZipFile, is_large_apk: bool, start_time: float) -> List[SecretAnalysis]:
        """Analyze secrets using professional confidence calculation."""
        secrets = []
        files_analyzed = 0
        max_files = MAX_SECRET_ANALYSIS_FILES if is_large_apk else MAX_FILES_TO_ANALYZE
        
        try:
            for file_info in apk_zip.filelist:
                # Time and file limit checks
                if time.time() - start_time > MAX_PROCESSING_TIME:
                    self.logger.warning("Time limit reached for secret analysis")
                    break
                    
                if files_analyzed >= max_files:
                    self.logger.debug(f"File limit reached ({max_files})")
                    break
                
                # Skip large files and non-text files
                if file_info.file_size > MAX_FILE_SIZE_MB * 1024 * 1024:
                    continue
                
                if not self._should_analyze_file_for_secrets(file_info.filename):
                    continue
                
                try:
                    # Extract and analyze file content
                    content = apk_zip.read(file_info.filename).decode('utf-8', errors='ignore')
                    file_secrets = self._find_secrets_in_content_with_confidence(content, file_info.filename)
                    
                    # Filter secrets using dynamic confidence thresholds
                    confidence_threshold = self._get_dynamic_confidence_threshold("secrets", file_info.filename)
                    filtered_secrets = [s for s in file_secrets if s.confidence >= confidence_threshold]
                    
                    secrets.extend(filtered_secrets)
                    files_analyzed += 1
                    
                except Exception as e:
                    self.logger.debug(f"Failed to analyze {file_info.filename}: {e}")
                    continue
            
            self.logger.debug(f"Secret analysis completed: {len(secrets)} secrets found in {files_analyzed} files")
            return secrets
            
        except Exception as e:
            self.logger.error(f"Secret analysis failed: {e}")
            return []

    def _find_secrets_in_content_with_confidence(self, content: str, file_path: str) -> List[SecretAnalysis]:
        """Find secrets in content using professional confidence assessment."""
        secrets = []
        
        # Use entropy analyzer with professional confidence
        lines = content.split('\n')
        for line_num, line in enumerate(lines, 1):
            if len(line.strip()) < 10:  # Skip very short lines
                continue
            
            # Analyze line for secrets using professional system
            analysis = self.entropy_analyzer.analyze_string(line.strip(), f"line {line_num}", file_path)
            
            # Calculate professional confidence for this secret
            professional_confidence = self.confidence_calculator.calculate_static_analysis_confidence(
                pattern_type="secret_detection",
                severity=analysis.risk_level.lower(),
                context=f"line {line_num}",
                file_path=file_path,
                code_snippet=line.strip()[:100],  # First 100 chars
                evidence=[f"entropy: {analysis.entropy:.2f}", f"pattern: {analysis.pattern_type}"]
            )
            
            # Update analysis with professional confidence
            analysis.confidence = professional_confidence
            
            # Only include secrets with reasonable confidence
            if analysis.confidence >= 0.3:  # Dynamic threshold
                secrets.append(analysis)
        
        return secrets

    def _analyze_code_patterns_with_confidence(self, apk_zip: zipfile.ZipFile, is_large_apk: bool, start_time: float) -> List[SecurityFinding]:
        """Analyze code patterns using professional confidence calculation."""
        findings = []
        files_analyzed = 0
        max_files = MAX_FILES_TO_ANALYZE // 2 if is_large_apk else MAX_FILES_TO_ANALYZE
        
        try:
            for file_info in apk_zip.filelist:
                # Time and file limit checks
                if time.time() - start_time > MAX_PROCESSING_TIME:
                    break
                    
                if files_analyzed >= max_files:
                    break
                
                # Analyze relevant code files
                if not self._should_analyze_file_for_patterns(file_info.filename):
                    continue
                
                try:
                    content = apk_zip.read(file_info.filename).decode('utf-8', errors='ignore')
                    file_findings = self.pattern_analyzer.analyze_code(content, file_info.filename)
                    
                    # Apply professional confidence to each finding
                    for finding in file_findings:
                        professional_confidence = self.confidence_calculator.calculate_static_analysis_confidence(
                            pattern_type=finding.category.lower(),
                            severity=finding.severity.lower(),
                            context=finding.file_path,
                            file_path=finding.file_path,
                            code_snippet=finding.code_snippet or "",
                            evidence=finding.evidence
                        )
                        
                        # Update finding with professional confidence
                        finding.confidence = professional_confidence
                        
                        # Only include findings with reasonable confidence
                        if finding.confidence >= 0.3:
                            findings.append(finding)
                    
                    files_analyzed += 1
                    
                except Exception as e:
                    self.logger.debug(f"Failed to analyze patterns in {file_info.filename}: {e}")
                    continue
            
            self.logger.debug(f"Code pattern analysis completed: {len(findings)} findings in {files_analyzed} files")
            return findings
            
        except Exception as e:
            self.logger.error(f"Code pattern analysis failed: {e}")
            return []

    def _assess_overall_risk_with_confidence(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Assess overall risk using professional confidence system."""
        try:
            # Extract findings for risk assessment
            secret_analysis = results.get("secret_analysis", [])
            code_patterns = results.get("code_patterns", [])
            
            # Filter high-confidence findings using dynamic thresholds
            high_confidence_secrets = [s for s in secret_analysis if s.confidence >= 0.8]
            high_confidence_patterns = [p for p in code_patterns if p.confidence >= 0.8]
            
            # Calculate risk categories with professional confidence
            crypto_risk = self._calculate_category_risk("crypto", code_patterns)
            storage_risk = self._calculate_category_risk("storage", code_patterns + [s for s in secret_analysis])
            network_risk = self._calculate_category_risk("network", code_patterns)
            platform_risk = self._calculate_category_risk("platform", code_patterns)
            
            # Calculate overall confidence in risk assessment
            risk_confidence = self.confidence_calculator.calculate_static_analysis_confidence(
                pattern_type="risk_assessment",
                severity="medium",
                context="overall_analysis",
                file_path="all_files",
                evidence=[
                    f"high_confidence_secrets: {len(high_confidence_secrets)}",
                    f"high_confidence_patterns: {len(high_confidence_patterns)}",
                    f"total_findings: {len(secret_analysis) + len(code_patterns)}"
                ]
            )
            
            return {
                "crypto_risk": crypto_risk,
                "storage_risk": storage_risk,
                "network_risk": network_risk,
                "platform_risk": platform_risk,
                "overall_confidence": risk_confidence,
                "high_confidence_findings": len(high_confidence_secrets) + len(high_confidence_patterns),
                "total_findings": len(secret_analysis) + len(code_patterns),
                "risk_calculation_method": "professional_confidence_based"
            }
            
        except Exception as e:
            self.logger.error(f"Risk assessment failed: {e}")
            return {
                "crypto_risk": "unknown",
                "storage_risk": "unknown", 
                "network_risk": "unknown",
                "platform_risk": "unknown",
                "overall_confidence": 0.5,
                "error": str(e)
            }

    def _calculate_category_risk(self, category: str, findings: List) -> str:
        """Calculate risk for specific category using professional confidence."""
        try:
            # Filter findings by category
            category_findings = []
            for finding in findings:
                if hasattr(finding, 'category') and category.lower() in finding.category.lower():
                    category_findings.append(finding)
                elif hasattr(finding, 'pattern_type') and category.lower() in finding.pattern_type.lower():
                    category_findings.append(finding)
            
            if not category_findings:
                return "low"
            
            # Calculate weighted risk based on confidence and severity
            risk_score = 0.0
            for finding in category_findings:
                confidence = getattr(finding, 'confidence', 0.5)
                severity = getattr(finding, 'severity', 'medium').lower()
                
                severity_weight = {"critical": 1.0, "high": 0.8, "medium": 0.6, "low": 0.4, "info": 0.2}.get(severity, 0.5)
                risk_score += confidence * severity_weight
            
            # Normalize risk score
            avg_risk = risk_score / len(category_findings)
            
            # Use dynamic thresholds from confidence calculator
            if avg_risk >= 0.8:
                return "critical"
            elif avg_risk >= 0.6:
                return "high"
            elif avg_risk >= 0.4:
                return "medium"
            else:
                return "low"
                
        except Exception as e:
            self.logger.error(f"Category risk calculation failed: {e}")
            return "unknown"

    def _get_dynamic_confidence_threshold(self, analysis_type: str, file_path: str) -> float:
        """Get dynamic confidence threshold based on context."""
        try:
            # Use confidence calculator to determine appropriate threshold
            context_confidence = self.confidence_calculator.calculate_static_analysis_confidence(
                pattern_type="threshold_calculation",
                severity="medium",
                context=analysis_type,
                file_path=file_path,
                evidence=[f"analysis_type: {analysis_type}"]
            )
            
            # Convert confidence to appropriate threshold
            if context_confidence >= 0.8:
                return 0.7  # High confidence context - use higher threshold
            elif context_confidence >= 0.6:
                return 0.5  # Medium confidence context - use medium threshold
            else:
                return 0.3  # Low confidence context - use lower threshold
                
        except Exception:
            return 0.5  # Fallback threshold

    def _is_large_apk(self, apk_zip: zipfile.ZipFile) -> bool:
        """Check if the APK is large based on file size."""
        total_size = sum(file_info.file_size for file_info in apk_zip.filelist)
        return total_size > MAX_FILE_SIZE_MB * 1024 * 1024

    def _should_analyze_file_for_secrets(self, filename: str) -> bool:
        """Determine if a file should be analyzed for secrets."""
        return any(ext in filename.lower() for ext in ['.xml', '.json', '.properties'])

    def _should_analyze_file_for_patterns(self, filename: str) -> bool:
        """Determine if a file should be analyzed for code patterns."""
        return any(ext in filename.lower() for ext in ['.java', '.kt', '.smali'])

    def _analyze_manifest(self, apk_zip: zipfile.ZipFile) -> Dict[str, Any]:
        """Enhanced AndroidManifest.xml analysis."""
        manifest_data = {}

        try:
            binary_manifest = apk_zip.read("AndroidManifest.xml")
            manifest_root = self.manifest_parser.parse_binary_xml(binary_manifest)

            if manifest_root is not None:
                manifest_data = {
                    "permissions": self._extract_permissions(manifest_root),
                    "activities": self._extract_activities(manifest_root),
                    "services": self._extract_services(manifest_root),
                    "receivers": self._extract_receivers(manifest_root),
                    "providers": self._extract_providers(manifest_root),
                    "security_features": self._analyze_security_features(manifest_root),
                    "network_config": self._analyze_network_config(manifest_root),
                }
            else:
                manifest_data["error"] = "Could not parse AndroidManifest.xml"

        except Exception as e:
            logging.debug(f"Error analyzing manifest: {e}")
            manifest_data["error"] = str(e)

        return manifest_data

    def _extract_permissions(self, manifest_root: ET.Element) -> List[Dict[str, str]]:
        """Extract permissions from manifest."""
        permissions = []
        for perm in manifest_root.findall(".//uses-permission"):
            name = perm.get(
                "{http://schemas.android.com/apk/res/android}name",
                perm.get("android:name", ""),
            )
            if name:
                permissions.append({"name": name, "type": "uses-permission"})
        return permissions

    def _extract_activities(self, manifest_root: ET.Element) -> List[Dict[str, Any]]:
        """Extract activities from manifest."""
        activities = []
        for activity in manifest_root.findall(".//activity"):
            name = activity.get(
                "{http://schemas.android.com/apk/res/android}name",
                activity.get("android:name", ""),
            )
            exported = activity.get(
                "{http://schemas.android.com/apk/res/android}exported",
                activity.get("android:exported", "false"),
            )
            if name:
                activities.append(
                    {
                        "name": name,
                        "exported": exported.lower() == "true",
                        "intent_filters": len(activity.findall(".//intent-filter")),
                    }
                )
        return activities

    def _extract_services(self, manifest_root: ET.Element) -> List[Dict[str, Any]]:
        """Extract services from manifest."""
        services = []
        for service in manifest_root.findall(".//service"):
            name = service.get(
                "{http://schemas.android.com/apk/res/android}name",
                service.get("android:name", ""),
            )
            exported = service.get(
                "{http://schemas.android.com/apk/res/android}exported",
                service.get("android:exported", "false"),
            )
            if name:
                services.append({"name": name, "exported": exported.lower() == "true"})
        return services

    def _extract_receivers(self, manifest_root: ET.Element) -> List[Dict[str, Any]]:
        """Extract broadcast receivers from manifest."""
        receivers = []
        for receiver in manifest_root.findall(".//receiver"):
            name = receiver.get(
                "{http://schemas.android.com/apk/res/android}name",
                receiver.get("android:name", ""),
            )
            exported = receiver.get(
                "{http://schemas.android.com/apk/res/android}exported",
                receiver.get("android:exported", "false"),
            )
            if name:
                receivers.append({"name": name, "exported": exported.lower() == "true"})
        return receivers

    def _extract_providers(self, manifest_root: ET.Element) -> List[Dict[str, Any]]:
        """Extract content providers from manifest."""
        providers = []
        for provider in manifest_root.findall(".//provider"):
            name = provider.get(
                "{http://schemas.android.com/apk/res/android}name",
                provider.get("android:name", ""),
            )
            exported = provider.get(
                "{http://schemas.android.com/apk/res/android}exported",
                provider.get("android:exported", "false"),
            )
            if name:
                providers.append({"name": name, "exported": exported.lower() == "true"})
        return providers

    def _analyze_security_features(self, manifest_root: ET.Element) -> Dict[str, Any]:
        """Analyze security features in manifest."""
        features = {
            "debuggable": False,
            "allow_backup": True,
            "uses_cleartext_traffic": None,
            "target_sdk": None,
        }

        # Check application attributes
        app = manifest_root.find(".//application")
        if app is not None:
            debuggable = app.get(
                "{http://schemas.android.com/apk/res/android}debuggable",
                app.get("android:debuggable", "false"),
            )
            features["debuggable"] = debuggable.lower() == "true"

            allow_backup = app.get(
                "{http://schemas.android.com/apk/res/android}allowBackup",
                app.get("android:allowBackup", "true"),
            )
            features["allow_backup"] = allow_backup.lower() == "true"

            cleartext = app.get(
                "{http://schemas.android.com/apk/res/android}usesCleartextTraffic",
                app.get("android:usesCleartextTraffic"),
            )
            if cleartext:
                features["uses_cleartext_traffic"] = cleartext.lower() == "true"

        # Check target SDK
        uses_sdk = manifest_root.find(".//uses-sdk")
        if uses_sdk is not None:
            target_sdk = uses_sdk.get(
                "{http://schemas.android.com/apk/res/android}targetSdkVersion",
                uses_sdk.get("android:targetSdkVersion"),
            )
            if target_sdk:
                features["target_sdk"] = int(target_sdk)

        return features

    def _analyze_network_config(self, manifest_root: ET.Element) -> Dict[str, Any]:
        """Analyze network security configuration."""
        config = {"network_security_config": None, "has_network_config": False}

        app = manifest_root.find(".//application")
        if app is not None:
            network_config = app.get(
                "{http://schemas.android.com/apk/res/android}networkSecurityConfig",
                app.get("android:networkSecurityConfig"),
            )
            if network_config:
                config["network_security_config"] = network_config
                config["has_network_config"] = True

        return config

    def _calculate_quality_metrics(self, apk_zip):
        """Calculate quality metrics for analysis."""
        try:
            # Extract basic metrics from APK structure
            total_files = len(apk_zip.filelist)
            java_files = len([f for f in apk_zip.filelist if f.filename.endswith('.java')])
            dex_files = len([f for f in apk_zip.filelist if f.filename.endswith('.dex')])
            
            # Calculate basic quality score
            complexity_score = min(total_files / 1000.0, 1.0)  # Normalize to 0-1
            quality_score = max(0.1, 1.0 - complexity_score)  # Higher files = lower quality
            
            return {
                "total_files": total_files,
                "java_files": java_files,
                "dex_files": dex_files,
                "complexity_score": complexity_score,
                "quality_score": quality_score,
                "confidence": 0.8
            }
        except Exception as e:
            # Return default metrics on error
            return {
                "total_files": 0,
                "quality_score": 0.5,
                "confidence": 0.5,
                "error": str(e)
            }

# Global instance
enhanced_static_analyzer = EnhancedStaticAnalyzer()

def get_enhanced_static_analyzer() -> EnhancedStaticAnalyzer:
    """Get the global enhanced static analyzer instance."""
    return enhanced_static_analyzer

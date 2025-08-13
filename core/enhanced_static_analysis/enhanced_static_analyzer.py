#!/usr/bin/env python3
"""
Enhanced Static Analyzer

Main orchestrator for static analysis that coordinates all analysis components
and produces comprehensive security findings with confidence scores.
"""

import logging
import time
import zipfile
from typing import Any, Dict, List

from rich.console import Console

from core.apk_ctx import APKContext
from .data_structures import SecurityFinding, SecretAnalysis
from .entropy_analyzer import EntropyAnalyzer
from .manifest_parser import AndroidManifestParser
from .code_pattern_analyzer import CodePatternAnalyzer
from .confidence_calculator import StaticAnalysisConfidenceCalculator

# Configuration for large APK handling
MAX_FILES_TO_ANALYZE = 500
MAX_PROCESSING_TIME = 180
MAX_FILE_SIZE_MB = 10
MAX_SECRET_ANALYSIS_FILES = 100

class EnhancedStaticAnalyzer:
    """Enhanced Static Analyzer with Professional Confidence System."""

    def __init__(self):
        """Initialize the enhanced static analyzer with professional confidence system."""
        self.console = Console()
        self.logger = logging.getLogger(__name__)
        
        # Initialize modular components
        self.entropy_analyzer = EntropyAnalyzer()
        self.pattern_analyzer = CodePatternAnalyzer()
        self.manifest_parser = AndroidManifestParser()
        self.confidence_calculator = StaticAnalysisConfidenceCalculator()
        
        # Thresholds are now dynamic - calculated by confidence system
        self.min_entropy_threshold = 3.5
        self.high_entropy_threshold = 4.5
        
        self.logger.info("Enhanced Static Analyzer initialized with professional confidence system")

    # Delegate methods to entropy_analyzer for backward compatibility
    def calculate_entropy(self, data: str) -> float:
        """Calculate entropy using the modular entropy analyzer."""
        return self.entropy_analyzer.calculate_entropy(data)

    def is_likely_secret_content(self, value: str, context: str = "", file_path: str = "") -> bool:
        """Check if content is likely a secret using the modular entropy analyzer."""
        return self.entropy_analyzer.is_likely_secret_content(value, context, file_path)

    def is_likely_false_positive(self, value: str, context: str = "", file_path: str = "") -> bool:
        """Check if content is likely a false positive using the modular entropy analyzer."""
        return self.entropy_analyzer.is_likely_false_positive(value, context, file_path)

    def analyze_string(self, value: str, context: str = "", file_path: str = "") -> SecretAnalysis:
        """Analyze string using the modular entropy analyzer."""
        return self.entropy_analyzer.analyze_string(value, context, file_path)

    def analyze_apk(self, apk_ctx: APKContext) -> Dict[str, Any]:
        """Analyze APK with professional confidence assessment."""
        start_time = time.time()
        
        try:
            self.logger.info(f"Starting enhanced static analysis for {apk_ctx.package_name}")
            
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
                    self.logger.info("Large APK detected - applying optimizations")
                
                # Analyze manifest using modular parser
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
            
            self.logger.info(f"Enhanced static analysis completed in {results['analysis_duration']:.2f}s")
            
            return results
            
        except Exception as e:
            self.logger.error(f"Enhanced static analysis failed: {e}")
            return {
                "package_name": apk_ctx.package_name,
                "error": str(e),
                "analysis_duration": time.time() - start_time,
                "confidence_system": "professional"
            }

    def _is_large_apk(self, apk_zip: zipfile.ZipFile) -> bool:
        """Determine if APK is large and needs optimization."""
        file_count = len(apk_zip.filelist)
        total_size = sum(f.file_size for f in apk_zip.filelist)
        
        return file_count > 1000 or total_size > 50 * 1024 * 1024  # 50MB

    def _analyze_manifest(self, apk_zip: zipfile.ZipFile) -> Dict[str, Any]:
        """Analyze AndroidManifest.xml using the modular parser."""
        try:
            manifest_data = apk_zip.read("AndroidManifest.xml")
            manifest_xml = self.manifest_parser.parse_binary_xml(manifest_data)
            
            if manifest_xml is None:
                return {"error": "Failed to parse AndroidManifest.xml"}
            
            return {
                "parsed": True,
                "permissions": self._extract_permissions(manifest_xml),
                "exported_components": self._extract_exported_components(manifest_xml),
                "confidence": 0.9
            }
            
        except Exception as e:
            self.logger.error(f"Manifest analysis failed: {e}")
            return {"error": str(e), "confidence": 0.0}

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
                    self.logger.info(f"File limit reached ({max_files})")
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
            
            self.logger.info(f"Secret analysis completed: {len(secrets)} secrets found in {files_analyzed} files")
            return secrets
            
        except Exception as e:
            self.logger.error(f"Secret analysis failed: {e}")
            return []

    def _analyze_code_patterns_with_confidence(self, apk_zip: zipfile.ZipFile, is_large_apk: bool, start_time: float) -> List[SecurityFinding]:
        """Analyze code patterns using the modular pattern analyzer."""
        findings = []
        files_analyzed = 0
        max_files = MAX_FILES_TO_ANALYZE if not is_large_apk else MAX_FILES_TO_ANALYZE // 2
        
        try:
            for file_info in apk_zip.filelist:
                # Time and file limit checks
                if time.time() - start_time > MAX_PROCESSING_TIME:
                    self.logger.warning("Time limit reached for pattern analysis")
                    break
                    
                if files_analyzed >= max_files:
                    break
                
                # Only analyze source code files
                if not self._should_analyze_file_for_patterns(file_info.filename):
                    continue
                
                try:
                    content = apk_zip.read(file_info.filename).decode('utf-8', errors='ignore')
                    file_findings = self.pattern_analyzer.analyze_code(content, file_info.filename)
                    findings.extend(file_findings)
                    files_analyzed += 1
                    
                except Exception as e:
                    self.logger.debug(f"Failed to analyze {file_info.filename}: {e}")
                    continue
            
            self.logger.info(f"Pattern analysis completed: {len(findings)} findings in {files_analyzed} files")
            return findings
            
        except Exception as e:
            self.logger.error(f"Pattern analysis failed: {e}")
            return []

    def _should_analyze_file_for_secrets(self, filename: str) -> bool:
        """Determine if file should be analyzed for secrets."""
        # Skip binary and large files
        skip_extensions = {'.png', '.jpg', '.jpeg', '.gif', '.webp', '.so', '.a', '.o'}
        skip_patterns = {'META-INF/', 'res/drawable', 'assets/flutter_assets/fonts/'}
        
        filename_lower = filename.lower()
        
        if any(filename_lower.endswith(ext) for ext in skip_extensions):
            return False
        
        if any(pattern in filename_lower for pattern in skip_patterns):
            return False
        
        return True

    def _should_analyze_file_for_patterns(self, filename: str) -> bool:
        """Determine if file should be analyzed for code patterns."""
        code_extensions = {'.java', '.kt', '.xml', '.js', '.json', '.properties'}
        return any(filename.lower().endswith(ext) for ext in code_extensions)

    def _find_secrets_in_content_with_confidence(self, content: str, file_path: str) -> List[SecretAnalysis]:
        """Find secrets in content using the modular entropy analyzer."""
        secrets = []
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines):
            # Skip very long lines and empty lines
            if len(line) > 1000 or len(line.strip()) < 8:
                continue
            
            # Analyze line for secrets
            analysis = self.entropy_analyzer.analyze_string(line.strip(), f"line {line_num + 1}", file_path)
            
            if analysis.is_likely_secret:
                secrets.append(analysis)
        
        return secrets

    def _get_dynamic_confidence_threshold(self, analysis_type: str, file_path: str) -> float:
        """Get dynamic confidence threshold based on analysis type and context."""
        base_threshold = 0.5
        
        if 'test' in file_path.lower():
            base_threshold += 0.1  # Higher threshold for test files
        
        if analysis_type == "secrets":
            base_threshold = 0.6  # Higher threshold for secret detection
        
        return base_threshold

    def _extract_permissions(self, manifest_xml) -> List[str]:
        """Extract permissions from manifest XML."""
        permissions = []
        if manifest_xml is not None:
            for elem in manifest_xml.iter():
                if elem.tag == "uses-permission":
                    name = elem.get("{http://schemas.android.com/apk/res/android}name")
                    if name:
                        permissions.append(name)
        return permissions

    def _extract_exported_components(self, manifest_xml) -> List[str]:
        """Extract exported components from manifest XML."""
        exported = []
        if manifest_xml is not None:
            for elem in manifest_xml.iter():
                if elem.tag in ["activity", "service", "receiver", "provider"]:
                    exported_attr = elem.get("{http://schemas.android.com/apk/res/android}exported")
                    if exported_attr == "true":
                        name = elem.get("{http://schemas.android.com/apk/res/android}name")
                        if name:
                            exported.append(f"{elem.tag}: {name}")
        return exported

    def _calculate_quality_metrics(self, apk_zip: zipfile.ZipFile) -> Dict[str, Any]:
        """Calculate APK quality metrics."""
        return {
            "file_count": len(apk_zip.filelist),
            "total_size": sum(f.file_size for f in apk_zip.filelist),
            "confidence": 0.8
        }

    def _assess_overall_risk_with_confidence(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Assess overall risk using professional confidence calculation."""
        secret_count = len(results.get("secret_analysis", []))
        finding_count = len(results.get("code_patterns", []))
        
        # Calculate risk score
        risk_score = min(1.0, (secret_count * 0.1) + (finding_count * 0.2))
        
        # Determine risk level
        if risk_score >= 0.8:
            risk_level = "CRITICAL"
        elif risk_score >= 0.6:
            risk_level = "HIGH"
        elif risk_score >= 0.4:
            risk_level = "MEDIUM"
        elif risk_score >= 0.2:
            risk_level = "LOW"
        else:
            risk_level = "INFO"
        
        return {
            "risk_level": risk_level,
            "risk_score": risk_score,
            "confidence": 0.85,
            "factors": {
                "secrets_found": secret_count,
                "patterns_found": finding_count
            }
        }

# Global instance
enhanced_static_analyzer = EnhancedStaticAnalyzer()

def get_enhanced_static_analyzer() -> EnhancedStaticAnalyzer:
    """Get the global enhanced static analyzer instance."""
    return enhanced_static_analyzer

# Export the main components
__all__ = ['EnhancedStaticAnalyzer', 'get_enhanced_static_analyzer'] 
"""
Enhanced Static Analysis Plugin - Modular Architecture

This plugin provides comprehensive static analysis capabilities with modular architecture,
dependency injection, and professional confidence calculation.

Features:
- Advanced static analysis with pattern matching
- Entropy-based secret detection
- AndroidManifest.xml analysis
- Code quality metrics
- Risk assessment and scoring
- confidence calculation
- Modular component architecture
"""

import logging
from typing import Dict, List, Any, Optional, Tuple, Union
from pathlib import Path
import os
import datetime

from rich.text import Text

from core.apk_ctx import APKContext
from core.enhanced_static_analyzer import get_enhanced_static_analyzer

from .data_structures import (
    StaticAnalysisResult, AnalysisContext, SecurityFinding,
    SecretAnalysis, ManifestAnalysis, CodeQualityMetrics,
    RiskAssessment, AnalysisConfiguration, RiskLevel, SeverityLevel,
    FindingCategory, PatternType, AnalysisType
)
from .static_analyzer import StaticAnalyzer
from .secret_detector import SecretDetector
from .manifest_analyzer import ManifestAnalyzer
from .code_quality_analyzer import CodeQualityAnalyzer
from .risk_assessor import RiskAssessor
from .confidence_calculator import StaticAnalysisConfidenceCalculator
from .formatters import StaticAnalysisFormatter

# Initialize logger
logger = logging.getLogger(__name__)

# Plugin metadata
PLUGIN_METADATA = {
    "name": "Enhanced Static Analysis",
    "description": "Comprehensive static code analysis with modular architecture and secret detection",
    "version": "2.0.0",
    "author": "AODS Development Team",
    "category": "STATIC_ANALYSIS",
    "priority": "HIGH",
    "timeout": 120,
    "mode": "comprehensive",
    "requires_device": False,
    "requires_network": False,
    "invasive": False,
    "execution_time_estimate": 90,
    "dependencies": ["jadx"],
    "modular_architecture": True,
    "plugin_dependencies": ["jadx_static_analysis"],  # Ensure JADX runs first for coordination
    "components": [
        "static_analyzer",
        "secret_detector",
        "code_quality_analyzer",
        "manifest_analyzer",
        "confidence_calculator"
    ],
    "security_controls": ["MASVS-CODE-2", "MASVS-STORAGE-1"],
    "owasp_categories": ["M2", "M9", "M10"]
}

class EnhancedStaticAnalysisPlugin:
    """Main enhanced static analysis plugin with modular architecture."""

    def __init__(self, config: Optional[AnalysisConfiguration] = None):
        """Initialize the enhanced static analysis plugin."""
        self.config = config or AnalysisConfiguration()
        self.logger = logging.getLogger(__name__)

        # Initialize modular components
        self.static_analyzer = StaticAnalyzer(self.config)
        self.secret_detector = SecretDetector(self.config)
        self.manifest_analyzer = ManifestAnalyzer(self.config)
        self.code_quality_analyzer = CodeQualityAnalyzer(self.config)
        self.risk_assessor = RiskAssessor(self.config)
        self.confidence_calculator = StaticAnalysisConfidenceCalculator()
        self.formatter = StaticAnalysisFormatter()

        # Analysis state
        self.analysis_results = None

    def analyze_apk(self, apk_ctx: APKContext) -> StaticAnalysisResult:
        """Perform comprehensive static analysis on the APK."""
        self.logger.debug("Starting enhanced static analysis...")

        # Create analysis context
        context = AnalysisContext(
            apk_path=apk_ctx.apk_path,
            package_name=apk_ctx.package_name or "unknown",
            version=getattr(apk_ctx, 'version_name', '1.0'),
            target_sdk=getattr(apk_ctx, 'target_sdk', 30),
            min_sdk=getattr(apk_ctx, 'min_sdk', 21),
            configuration=self.config.to_dict()
        )

        # Initialize result
        result = StaticAnalysisResult(context=context)

        try:
            # Get enhanced static analyzer results
            enhanced_results = self._get_enhanced_analysis(apk_ctx)

            # Perform static analysis
            if self.config.enable_secret_detection:
                security_findings = self._analyze_security_patterns(apk_ctx)
                result.security_findings = security_findings

                # Perform secret detection
                secrets = self._detect_secrets(apk_ctx)
                result.secret_analysis = secrets

            # Perform manifest analysis
            if self.config.enable_manifest_analysis:
                manifest_analysis = self._analyze_manifest(apk_ctx)
                result.manifest_analysis = manifest_analysis

            # Perform code quality analysis
            if self.config.enable_code_quality_metrics:
                code_quality = self._analyze_code_quality(apk_ctx)
                result.code_quality_metrics = code_quality

            # Perform risk assessment
            risk_assessment = self._assess_risk(result)
            result.risk_assessment = risk_assessment

            # Generate analysis summary
            result.analysis_summary = self._generate_summary(result)

            # Cache results
            self.analysis_results = result
            self._cache_results(apk_ctx, result)

            self.logger.debug("Enhanced static analysis completed successfully")
            return result

        except Exception as e:
            self.logger.error(f"Enhanced static analysis failed: {e}")
            # Return partial results with error
            result.analysis_summary = {'error': str(e)}
            return result

    def _get_enhanced_analysis(self, apk_ctx: APKContext) -> Dict[str, Any]:
        """Get results from the enhanced static analyzer."""
        try:
            analyzer = get_enhanced_static_analyzer()
            return analyzer.analyze_apk(apk_ctx)
        except Exception as e:
            self.logger.warning(f"Enhanced static analyzer failed: {e}")
            return {}

    def _get_cached_jadx_results(self, apk_ctx: APKContext) -> Optional[Dict[str, Any]]:
        """Check if JADX static analysis has already processed this APK."""
        try:
            # Simple, non-blocking check for JADX cache (no infinite waits)
            
            # Check if JADX results are cached in APK context
            if hasattr(apk_ctx, 'get_cache'):
                jadx_cache = apk_ctx.get_cache('jadx_static_analysis_results')
                if jadx_cache:
                    self.logger.info("🔄 Found cached JADX static analysis results - avoiding file duplication")
                    return jadx_cache
            
            # Check for JADX results in shared cache location
            cache_file = f"/tmp/jadx_results_{apk_ctx.package_name}.json"
            if os.path.exists(cache_file):
                import json
                try:
                    with open(cache_file, 'r') as f:
                        cached_results = json.load(f)
                        self.logger.info("🔄 Found JADX results in shared cache - avoiding file duplication")
                        return cached_results
                except (json.JSONDecodeError, IOError) as e:
                    self.logger.debug(f"Cache file exists but couldn't read: {e}")
                    # If cache file is corrupted, ignore it and proceed
            
            # Optional: Single brief check if JADX might be running (non-blocking)
            if self._quick_jadx_check():
                import time
                self.logger.debug("🔄 JADX appears to be running - waiting 5 seconds")
                time.sleep(5)  # Single 5-second wait (not a loop)
                
                # One more quick check after brief wait
                if os.path.exists(cache_file):
                    try:
                        import json
                        with open(cache_file, 'r') as f:
                            cached_results = json.load(f)
                            self.logger.info("🔄 Found JADX results after brief wait - avoiding file duplication")
                            return cached_results
                    except (json.JSONDecodeError, IOError):
                        pass
            
            # No cache found - proceed with independent analysis
            self.logger.debug("No JADX cache found - proceeding with independent analysis")
            return None
            
        except Exception as e:
            self.logger.debug(f"Could not retrieve JADX cache: {e}")
            return None

    def _quick_jadx_check(self) -> bool:
        """Quick, non-blocking check if JADX might be running."""
        try:
            # Check for active JADX processes (quick check only)
            import subprocess
            result = subprocess.run(['pgrep', '-f', 'jadx'], capture_output=True, text=True, timeout=2)
            if result.returncode == 0:
                return True
            return False
        except (subprocess.TimeoutExpired, Exception):
            return False

    def _analyze_security_patterns(self, apk_ctx: APKContext) -> List[SecurityFinding]:
        """Analyze security patterns with comprehensive YAML pattern matching."""
        findings = []

        # CRITICAL FIX: Always run our comprehensive YAML pattern analysis
        # The JADX results are basic - we need our comprehensive patterns for SQL injection, etc.
        
        # STEP 1: Run our own comprehensive pattern analysis FIRST
        try:
            # Get APK extraction path
            extraction_path = self._get_extraction_path(apk_ctx)

            if extraction_path and os.path.exists(extraction_path):
                self.logger.info("🔍 Running comprehensive YAML pattern analysis (SQL injection, crypto, secrets, etc.)")
                
                # Analyze extracted files with comprehensive YAML patterns
                comprehensive_findings = self.static_analyzer.analyze_directory(extraction_path)
                findings.extend(comprehensive_findings)
                
                self.logger.info(f"✅ Found {len(comprehensive_findings)} vulnerabilities with comprehensive pattern analysis")
            else:
                self.logger.warning("APK extraction path not found for comprehensive analysis")

        except Exception as e:
            self.logger.error(f"Comprehensive pattern analysis failed: {e}")

        # STEP 2: Check for additional JADX results and merge (avoid duplicates)
        jadx_results = self._get_cached_jadx_results(apk_ctx)
        if jadx_results and ('insecure_patterns' in jadx_results or 'crypto_analysis' in jadx_results):
            self.logger.info("🔄 Merging additional JADX security analysis results")
            
            # **DATA QUALITY FIX**: Get source directory for file context extraction
            source_dir = getattr(apk_ctx, 'decompiled_source_dir', None)
            if not source_dir and hasattr(apk_ctx, 'output_dir'):
                source_dir = apk_ctx.output_dir
            
            # Convert JADX insecure patterns
            insecure_patterns = jadx_results.get('insecure_patterns', {}).get('findings', [])
            for pattern_finding in insecure_patterns:
                try:
                    # **DATA QUALITY FIX**: Extract proper file context instead of using empty defaults
                    file_path = pattern_finding.get('file_path', '')
                    line_number = pattern_finding.get('line_number', 0)
                    code_snippet = pattern_finding.get('code_snippet', '')
                    
                    # If file context is missing, try to extract it from pattern title/description
                    if (not file_path or file_path == 'unknown') and source_dir:
                        file_path, line_number, code_snippet = self._extract_file_context_from_pattern(
                            pattern_finding, source_dir
                        )
                    
                    finding = SecurityFinding(
                        title=pattern_finding.get('title', 'Security Pattern'),
                        description=pattern_finding.get('description', ''),
                        severity=SeverityLevel.MEDIUM,  # Default, will be refined
                        category=FindingCategory.SECURITY_VULNERABILITY,
                        confidence=pattern_finding.get('confidence', 0.7),
                        file_path=file_path,
                        line_number=line_number,
                        code_snippet=code_snippet,
                        owasp_category=pattern_finding.get('owasp_category', ''),
                        masvs_control=pattern_finding.get('masvs_control', ''),
                        recommendations=pattern_finding.get('recommendations', [])
                    )
                    findings.append(finding)
                except Exception as e:
                    self.logger.debug(f"Error converting JADX pattern finding: {e}")
                    continue

            # Convert JADX crypto analysis
            crypto_analysis = jadx_results.get('crypto_analysis', {}).get('crypto_issues', [])
            for crypto_finding in crypto_analysis:
                try:
                    # **DATA QUALITY FIX**: Extract proper file context instead of using empty defaults
                    file_path = crypto_finding.get('file', '')
                    line_number = crypto_finding.get('line_number', 0)
                    code_snippet = crypto_finding.get('evidence', '')
                    
                    # If file context is missing, try to extract it from crypto finding data
                    if (not file_path or file_path == 'unknown') and source_dir:
                        file_path, line_number, code_snippet = self._extract_file_context_from_pattern(
                            crypto_finding, source_dir
                        )
                    
                    finding = SecurityFinding(
                        title=crypto_finding.get('title', 'Cryptographic Issue'),
                        description=crypto_finding.get('description', ''),
                        severity=SeverityLevel.HIGH,  # Crypto issues are typically high severity
                        category=FindingCategory.CRYPTOGRAPHIC_WEAKNESS,
                        confidence=crypto_finding.get('confidence', 0.8),
                        file_path=file_path,
                        line_number=line_number,
                        code_snippet=code_snippet,
                        owasp_category="M10",  # Cryptographic failures
                        masvs_control="MSTG-CRYPTO-1",
                        recommendations=["Use strong cryptographic algorithms", "Implement proper key management"]
                    )
                    findings.append(finding)
                except Exception as e:
                    self.logger.debug(f"Error converting JADX crypto finding: {e}")
                    continue
            
            
            # Merge JADX findings with our comprehensive findings (avoiding duplicates)
            jadx_findings = []
            existing_patterns = set(f.vulnerable_pattern for f in findings if hasattr(f, 'vulnerable_pattern'))
            
            # Convert JADX insecure patterns (only if not already found by comprehensive analysis)
            insecure_patterns = jadx_results.get('insecure_patterns', {}).get('findings', [])
            for pattern_finding in insecure_patterns:
                try:
                    pattern_type = pattern_finding.get('vulnerable_pattern', pattern_finding.get('title', ''))
                    if pattern_type not in existing_patterns:
                        # **DATA QUALITY FIX**: Extract proper file context instead of using empty defaults
                        file_path = pattern_finding.get('file_path', '')
                        line_number = pattern_finding.get('line_number', 0)
                        code_snippet = pattern_finding.get('code_snippet', '')
                        
                        # If file context is missing, try to extract it from pattern title/description
                        if (not file_path or file_path == 'unknown') and source_dir:
                            file_path, line_number, code_snippet = self._extract_file_context_from_pattern(
                                pattern_finding, source_dir
                            )
                        
                        finding = SecurityFinding(
                            title=pattern_finding.get('title', 'Security Pattern'),
                            description=pattern_finding.get('description', ''),
                            severity=SeverityLevel.MEDIUM,  # Default, will be refined
                            category=FindingCategory.SECURITY_VULNERABILITY,
                            confidence=pattern_finding.get('confidence', 0.7),
                            file_path=file_path,
                            line_number=line_number,
                            code_snippet=code_snippet,
                            owasp_category=pattern_finding.get('owasp_category', ''),
                            masvs_control=pattern_finding.get('masvs_control', ''),
                            recommendations=pattern_finding.get('recommendations', [])
                        )
                        jadx_findings.append(finding)
                except Exception as e:
                    self.logger.debug(f"Error converting JADX pattern finding: {e}")
                    continue

            # Convert JADX crypto analysis (only if not already found)
            crypto_analysis = jadx_results.get('crypto_analysis', {}).get('crypto_issues', [])
            for crypto_finding in crypto_analysis:
                try:
                    crypto_type = crypto_finding.get('title', 'crypto')
                    if crypto_type not in existing_patterns:
                        # **DATA QUALITY FIX**: Extract proper file context instead of using empty defaults
                        file_path = crypto_finding.get('file', '')
                        line_number = crypto_finding.get('line_number', 0)
                        code_snippet = crypto_finding.get('evidence', '')
                        
                        # If file context is missing, try to extract it from crypto finding data
                        if (not file_path or file_path == 'unknown') and source_dir:
                            file_path, line_number, code_snippet = self._extract_file_context_from_pattern(
                                crypto_finding, source_dir
                            )
                        
                        finding = SecurityFinding(
                            title=crypto_finding.get('title', 'Cryptographic Issue'),
                            description=crypto_finding.get('description', ''),
                            severity=SeverityLevel.HIGH,  # Crypto issues are typically high severity
                            category=FindingCategory.CRYPTOGRAPHIC_WEAKNESS,
                            confidence=crypto_finding.get('confidence', 0.8),
                            file_path=file_path,
                            line_number=line_number,
                            code_snippet=code_snippet,
                            owasp_category="M10",  # Cryptographic failures
                            masvs_control="MSTG-CRYPTO-1",
                            recommendations=["Use strong cryptographic algorithms", "Implement proper key management"]
                        )
                        jadx_findings.append(finding)
                except Exception as e:
                    self.logger.debug(f"Error converting JADX crypto finding: {e}")
                    continue
            
            findings.extend(jadx_findings)
            self.logger.info(f"✅ Merged {len(jadx_findings)} additional JADX findings (total: {len(findings)})")

        return findings

    def _get_extraction_path(self, apk_ctx: APKContext) -> Optional[str]:
        """Get the path to decompiled source files for pattern analysis."""
        # Try multiple potential locations for decompiled source files
        potential_paths = []
        
        # Check APKContext attributes
        if hasattr(apk_ctx, 'decompiled_path') and apk_ctx.decompiled_path:
            potential_paths.append(apk_ctx.decompiled_path)
        
        if hasattr(apk_ctx, 'source_dir') and apk_ctx.source_dir:
            potential_paths.append(apk_ctx.source_dir)
            
        if hasattr(apk_ctx, 'workspace_dir') and apk_ctx.workspace_dir:
            potential_paths.append(apk_ctx.workspace_dir)
            
        # Check workspace for decompiled directories
        if hasattr(apk_ctx, 'workspace_dir') and apk_ctx.workspace_dir:
            import glob
            workspace_pattern = os.path.join(apk_ctx.workspace_dir, '*_decompiled')
            potential_paths.extend(glob.glob(workspace_pattern))
            
            # Check for common decompiled APK directories
            common_dirs = [
                os.path.join(apk_ctx.workspace_dir, '*_decompiled'),
                os.path.join(apk_ctx.workspace_dir, 'decompiled_*')
            ]
            for pattern in common_dirs:
                potential_paths.extend(glob.glob(pattern))
            
        # Check common workspace locations
        workspace_dir = "workspace"
        if os.path.exists(workspace_dir):
            for item in os.listdir(workspace_dir):
                item_path = os.path.join(workspace_dir, item)
                if os.path.isdir(item_path) and 'decompiled' in item:
                    potential_paths.append(item_path)
        
        # Test each path and return the first valid one
        for path in potential_paths:
            if path and os.path.exists(path):
                # Verify it contains Java source files
                for root, dirs, files in os.walk(path):
                    if any(f.endswith('.java') for f in files):
                        self.logger.info(f"✅ Found decompiled source directory: {path}")
                        return path
                        
        self.logger.warning("❌ No decompiled source directory found for comprehensive pattern analysis")
        return None

    def _extract_file_context_from_pattern(self, pattern_finding: Dict[str, Any], source_dir: str) -> Tuple[str, int, str]:
        """
        **DATA QUALITY FIX**: Extract file context from source files when JADX cache lacks file information.
        
        Args:
            pattern_finding: The pattern finding dictionary from JADX results
            source_dir: Directory containing decompiled source files
            
        Returns:
            Tuple of (file_path, line_number, code_snippet)
        """
        import os
        import re
        from typing import Tuple
        
        # Default fallback values
        default_file_path = "unknown"
        default_line_number = 0
        default_code_snippet = ""
        
        try:
            # Extract pattern information for searching
            title = pattern_finding.get('title', '')
            description = pattern_finding.get('description', '')
            pattern_regex = pattern_finding.get('pattern', '')
            
            # Try to extract method/class names from title or description
            search_terms = []
            
            # Look for method names in title/description (common patterns)
            method_matches = re.findall(r'\b(\w+)\s*\(', title + ' ' + description)
            search_terms.extend(method_matches)
            
            # Look for class names (capitalized words)
            class_matches = re.findall(r'\b([A-Z][a-zA-Z0-9_]+)', title + ' ' + description)
            search_terms.extend(class_matches)
            
            # Look for API calls or specific patterns
            api_matches = re.findall(r'\b(\w+\.\w+)', title + ' ' + description)
            search_terms.extend(api_matches)
            
            # If we have search terms, search through source files
            if search_terms and source_dir and os.path.exists(source_dir):
                self.logger.debug(f"🔍 Searching for pattern context: {search_terms[:3]}")  # Log first 3 terms
                
                for root, dirs, files in os.walk(source_dir):
                    for file in files:
                        if not file.endswith(('.java', '.kt', '.kts')):
                            continue
                            
                        file_path = os.path.join(root, file)
                        try:
                            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                content = f.read()
                                
                            # Search for any of our search terms
                            for term in search_terms[:5]:  # Limit to first 5 terms for performance
                                if term in content:
                                    # Find the line number
                                    lines = content.split('\n')
                                    for i, line in enumerate(lines):
                                        if term in line:
                                            # Extract code snippet (current line + context)
                                            start_line = max(0, i - 2)
                                            end_line = min(len(lines), i + 3)
                                            code_snippet = '\n'.join(lines[start_line:end_line])
                                            
                                            # Return relative path for cleaner reporting
                                            relative_path = os.path.relpath(file_path, source_dir)
                                            
                                            self.logger.debug(f"✅ Found pattern context: {relative_path}:{i+1}")
                                            return relative_path, i + 1, code_snippet.strip()
                                            
                        except (IOError, UnicodeDecodeError) as e:
                            self.logger.debug(f"Could not read file {file_path}: {e}")
                            continue
            
            # If no context found, return defaults with logging
            self.logger.debug(f"⚠️ Could not extract file context for pattern: {title[:50]}")
            return default_file_path, default_line_number, default_code_snippet
            
        except Exception as e:
            self.logger.debug(f"Error extracting file context: {e}")
            return default_file_path, default_line_number, default_code_snippet

    def _detect_secrets(self, apk_ctx: APKContext) -> List[SecretAnalysis]:
        """Detect secrets in the APK with JADX coordination to avoid duplication."""
        secrets = []

        # STEP 1: Check if JADX has already analyzed secrets
        jadx_results = self._get_cached_jadx_results(apk_ctx)
        if jadx_results and 'secrets_analysis' in jadx_results:
            self.logger.info("🔄 Reusing JADX secrets analysis results - avoiding file re-processing")
            
            # Convert JADX secret findings to our format
            jadx_secrets = jadx_results['secrets_analysis'].get('findings', [])
            for jadx_secret in jadx_secrets:
                try:
                    # Map JADX secret format to our SecretAnalysis format
                    secret = SecretAnalysis(
                        id=jadx_secret.get('id', f"jadx_secret_{len(secrets)}"),
                        pattern_type=PatternType.API_KEY,  # Default, will be refined
                        content=jadx_secret.get('content', ''),
                        file_path=jadx_secret.get('file_path', ''),
                        line_number=jadx_secret.get('line_number', 0),
                        confidence=jadx_secret.get('confidence', 0.8),
                        entropy=jadx_secret.get('entropy', 0.0),
                        context=jadx_secret.get('context', ''),
                        risk_level=RiskLevel.MEDIUM,  # Default, will be refined based on pattern
                        analysis_type=AnalysisType.SECRET_DETECTION
                    )
                    secrets.append(secret)
                except Exception as e:
                    self.logger.debug(f"Error converting JADX secret: {e}")
                    continue
            
            self.logger.info(f"✅ Converted {len(secrets)} JADX secrets to enhanced format")
            return secrets

        # STEP 2: If no JADX cache, run our own analysis (but cache results for JADX)
        try:
            # Get APK extraction path
            extraction_path = self._get_extraction_path(apk_ctx)

            if extraction_path and os.path.exists(extraction_path):
                self.logger.info("🔍 Running enhanced secret detection (no JADX cache found)")
                
                # Analyze files for secrets
                for root, dirs, files in os.walk(extraction_path):
                    for file in files:
                        file_path = os.path.join(root, file)

                        # Skip binary files
                        if not self._is_text_file(file_path):
                            continue

                        try:
                            # Skip large files to prevent memory issues and hanging
                            file_size = os.path.getsize(file_path)
                            if file_size > 10 * 1024 * 1024:  # Skip files larger than 10MB
                                self.logger.debug(f"Skipping large file {file_path} ({file_size} bytes)")
                                continue
                                
                            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                # Read with size limit to prevent memory exhaustion
                                content = f.read(1024 * 1024)  # Max 1MB per file
                                if len(content) > 0:
                                    file_secrets = self.secret_detector.analyze_content(content, file_path)
                                    secrets.extend(file_secrets)
                        except Exception as e:
                            self.logger.debug(f"Failed to analyze file {file_path}: {e}")
                            continue
                
                # Cache our results for JADX coordination
                self._cache_enhanced_results_for_jadx(apk_ctx, {"secrets": secrets})
            else:
                self.logger.warning("APK extraction path not found for secret detection")

        except Exception as e:
            self.logger.error(f"Secret detection failed: {e}")

        return secrets

    def _analyze_manifest(self, apk_ctx: APKContext) -> Optional[ManifestAnalysis]:
        """Analyze AndroidManifest.xml."""
        try:
            return self.manifest_analyzer.analyze_manifest(apk_ctx)
        except Exception as e:
            self.logger.error(f"Manifest analysis failed: {e}")
            return None

    def _analyze_code_quality(self, apk_ctx: APKContext) -> Optional[CodeQualityMetrics]:
        """Analyze code quality metrics."""
        try:
            extraction_path = self._get_extraction_path(apk_ctx)
            if extraction_path and os.path.exists(extraction_path):
                return self.code_quality_analyzer.analyze_code_quality(extraction_path)
            return None
        except Exception as e:
            self.logger.error(f"Code quality analysis failed: {e}")
            return None

    def _assess_risk(self, result: StaticAnalysisResult) -> RiskAssessment:
        """Assess overall risk based on analysis results."""
        try:
            return self.risk_assessor.assess_risk(result)
        except Exception as e:
            self.logger.error(f"Risk assessment failed: {e}")
            return RiskAssessment(
                overall_risk=RiskLevel.UNKNOWN,
                risk_score=0.0,
                risk_factors=["Analysis failed"]
            )

    def _generate_summary(self, result: StaticAnalysisResult) -> Dict[str, Any]:
        """Generate analysis summary."""
        summary = {
            'timestamp': result.context.analysis_start_time,
            'total_security_findings': len(result.security_findings),
            'total_secrets': len(result.secret_analysis),
            'overall_risk': result.risk_assessment.overall_risk.value if result.risk_assessment else 'UNKNOWN',
            'risk_score': result.risk_assessment.risk_score if result.risk_assessment else 0.0
        }

        # Add severity breakdown
        severity_counts = {}
        for finding in result.security_findings:
            severity = finding.severity.value
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        summary['severity_breakdown'] = severity_counts

        # Add secret type breakdown
        secret_type_counts = {}
        for secret in result.secret_analysis:
            secret_type = secret.pattern_type.value
            secret_type_counts[secret_type] = secret_type_counts.get(secret_type, 0) + 1

        summary['secret_type_breakdown'] = secret_type_counts

        return summary

    def _get_extraction_path(self, apk_ctx: APKContext) -> Optional[str]:
        """Get APK extraction path."""
        # Primary: Use decompiled_apk_dir from APK context (this is the main extraction directory)
        if hasattr(apk_ctx, 'decompiled_apk_dir') and apk_ctx.decompiled_apk_dir:
            extraction_path = str(apk_ctx.decompiled_apk_dir)
            if os.path.exists(extraction_path):
                return extraction_path
        
        # Secondary: Check for JADX output in the standard JADX output locations
        jadx_base_dir = "/tmp/jadx_decompiled"
        if os.path.exists(jadx_base_dir):
            # Find the most recent JADX directory (JADX creates timestamped directories)
            import glob
            from pathlib import Path
            
            jadx_pattern = os.path.join(jadx_base_dir, "jadx_*")
            jadx_dirs = glob.glob(jadx_pattern)
            
            if jadx_dirs:
                # Get the most recent directory by modification time
                latest_jadx_dir = max(jadx_dirs, key=lambda p: Path(p).stat().st_mtime)
                if os.path.exists(latest_jadx_dir):
                    # Check if this directory has sources (indicating successful JADX decompilation)
                    sources_dir = os.path.join(latest_jadx_dir, "sources")
                    resources_dir = os.path.join(latest_jadx_dir, "resources")
                    
                    if os.path.exists(sources_dir) or os.path.exists(resources_dir):
                        self.logger.info(f"Found JADX decompilation output: {latest_jadx_dir}")
                        return latest_jadx_dir
        
        # Fallback: Try to get from APK context legacy attribute
        if hasattr(apk_ctx, 'extraction_path'):
            return apk_ctx.extraction_path

        # Fallback: Try to get from cached enhanced analysis
        if hasattr(apk_ctx, 'get_cache'):
            cached_results = apk_ctx.get_cache('enhanced_static_analysis_results')
            if cached_results and 'extraction_path' in cached_results:
                return cached_results['extraction_path']

        # Fallback: Try to construct from APK path (legacy support)
        if apk_ctx.apk_path:
            apk_name = os.path.basename(apk_ctx.apk_path).replace('.apk', '')
            extraction_path = os.path.join(os.path.dirname(apk_ctx.apk_path), f"{apk_name}_extracted")
            if os.path.exists(extraction_path):
                return extraction_path

        return None

    def _is_text_file(self, file_path: str) -> bool:
        """Check if file is a text file."""
        text_extensions = {
            '.java', '.kt', '.xml', '.json', '.txt', '.properties',
            '.gradle', '.pro', '.cfg', '.conf', '.yaml', '.yml', '.smali'
        }

        file_ext = os.path.splitext(file_path)[1].lower()
        return file_ext in text_extensions

    def _cache_results(self, apk_ctx: APKContext, result: StaticAnalysisResult) -> None:
        """Cache analysis results."""
        try:
            if hasattr(apk_ctx, 'set_cache'):
                apk_ctx.set_cache('enhanced_static_analysis_results', result.to_dict())
                apk_ctx.set_cache('enhanced_static_analysis_summary', result.analysis_summary)
        except Exception as e:
            self.logger.debug(f"Failed to cache results: {e}")

    def _cache_enhanced_results_for_jadx(self, apk_ctx: APKContext, results: Dict[str, Any]) -> None:
        """Cache enhanced analysis results for JADX coordination."""
        try:
            # Cache in APK context if available
            if hasattr(apk_ctx, 'set_cache'):
                apk_ctx.set_cache('enhanced_static_analysis_cache', results)
            
            # Also cache in shared location for cross-plugin coordination
            cache_file = f"/tmp/enhanced_results_{apk_ctx.package_name}.json"
            import json
            with open(cache_file, 'w') as f:
                # Convert objects to serializable format
                serializable_results = {}
                for key, value in results.items():
                    if key == "secrets":
                        serializable_results[key] = [secret.to_dict() if hasattr(secret, 'to_dict') else str(secret) for secret in value]
                    elif key == "security_findings":
                        serializable_results[key] = [finding.to_dict() if hasattr(finding, 'to_dict') else str(finding) for finding in value]
                    else:
                        serializable_results[key] = value
                
                json.dump(serializable_results, f, indent=2)
            
            self.logger.debug(f"Cached enhanced results for JADX coordination: {cache_file}")
        except Exception as e:
            self.logger.debug(f"Failed to cache enhanced results: {e}")

    def generate_report(self, apk_ctx: APKContext) -> Tuple[str, Text]:
        """Generate formatted report."""
        if not self.analysis_results:
            self.analyze_apk(apk_ctx)

        return self.formatter.format_report(self.analysis_results)

# Factory function for creating plugin instance
def create_enhanced_static_analysis_plugin(config: Optional[AnalysisConfiguration] = None) -> EnhancedStaticAnalysisPlugin:
    """Create an enhanced static analysis plugin instance."""
    return EnhancedStaticAnalysisPlugin(config)

# Plugin interface functions for backward compatibility
def _determine_secret_severity(secret) -> str:
    """
    Determine the appropriate severity level for a detected secret.
    
    Args:
        secret: SecretAnalysis object with type, confidence, and risk data
        
    Returns:
        str: Severity level (CRITICAL, HIGH, MEDIUM, LOW)
    """
    confidence = getattr(secret, 'confidence', 0.0)
    pattern_type = secret.pattern_type.value if hasattr(secret.pattern_type, 'value') else str(secret.pattern_type)
    risk_level = secret.risk_level.value if hasattr(secret.risk_level, 'value') else str(secret.risk_level)
    entropy = getattr(secret, 'entropy', 0.0)
    
    # CRITICAL: High-confidence secrets of critical types
    critical_types = {'api_key', 'private_key', 'aws_access_key', 'database_password', 'jwt_token'}
    if confidence >= 0.9 and pattern_type.lower() in critical_types:
        return "CRITICAL"
    
    # CRITICAL: Very high entropy secrets with high confidence (likely real secrets)
    if confidence >= 0.85 and entropy >= 4.5:
        return "CRITICAL"
    
    # HIGH: High-confidence authentication-related secrets
    high_types = {'password', 'token', 'credential', 'auth_key', 'session_key'}
    if confidence >= 0.8 and pattern_type.lower() in high_types:
        return "HIGH"
    
    # HIGH: Risk level is already assessed as HIGH or CRITICAL
    if risk_level.upper() in ['HIGH', 'CRITICAL']:
        return "HIGH"
    
    # HIGH: Medium confidence but very high entropy (strong indicators)
    if confidence >= 0.7 and entropy >= 4.0:
        return "HIGH"
    
    # MEDIUM: Medium confidence secrets or moderate risk
    medium_types = {'config_value', 'url', 'email', 'username'}
    if confidence >= 0.6 or pattern_type.lower() in medium_types:
        return "MEDIUM"
    
    # MEDIUM: Risk level is assessed as MEDIUM
    if risk_level.upper() == 'MEDIUM':
        return "MEDIUM"
    
    # LOW: Low confidence or low-risk patterns
    if confidence >= 0.4 or risk_level.upper() == 'LOW':
        return "LOW"
    
    # INFO: Very low confidence, likely false positives
    return "INFO"

def run_analysis(apk_ctx: APKContext) -> Dict[str, Any]:
    """
    Run enhanced static analysis with optional JADX integration bridge.
    
    This method converts the plugin's detailed findings into the standard format
    expected by the parallel scan manager (with 'vulnerabilities' key).
    
    CYCLE PREVENTION: Checks for active cycles and runs standalone if needed.
    """
    logger.info("Running enhanced static analysis with integrated JADX bridge")
    
    try:
        # CYCLE PREVENTION: Check if cycle prevention is active
        cycle_prevention_active = getattr(apk_ctx, '_cycle_prevention_active', False)
        
        if not cycle_prevention_active:
            # Try to use the integration bridge for seamless JADX coordination
            try:
                from core.integration_bridge import run_integrated_analysis
                
                logger.info("🌉 Using JADX-Enhanced Static Analysis Integration Bridge")
                integrated_result = run_integrated_analysis(apk_ctx)
                
                # Check for cycle detection
                if integrated_result.get('cycle_detected', False):
                    logger.warning("🔄 Integration cycle detected - falling back to standalone analysis")
                elif integrated_result.get('success', False) and integrated_result.get('unified_vulnerabilities'):
                    # Use unified vulnerabilities from the bridge
                    vulnerabilities = integrated_result['unified_vulnerabilities']
                    
                    # Create enhanced results with bridge integration
                    results = {
                        "vulnerabilities": vulnerabilities,
                        "metadata": {
                            "plugin": "enhanced_static_analysis",
                            "analysis_timestamp": datetime.datetime.now().isoformat(),
                            "total_findings": len(vulnerabilities),
                            "integration_bridge_used": True,
                            "jadx_integrated": True,
                            "jadx_vulnerabilities": integrated_result.get('metadata', {}).get('jadx_vulnerabilities_count', 0),
                            "enhanced_vulnerabilities": integrated_result.get('metadata', {}).get('enhanced_vulnerabilities_count', 0),
                            "files_analyzed": integrated_result.get('metadata', {}).get('files_analyzed', 0),
                            "cycle_prevention": "active"
                        },
                        "summary": {
                            "bridge_integration": "successful",
                            "unified_analysis": True,
                            "deduplication_applied": True,
                            "cycle_prevention": "no_cycles_detected"
                        },
                        "bridge_results": integrated_result
                    }
                    
                    logger.info(f"🌉 Integration bridge successful: {len(vulnerabilities)} unified vulnerabilities")
                    return results
                else:
                    logger.warning("Integration bridge failed or returned no results - falling back to standalone analysis")
                    
            except ImportError:
                logger.info("Integration bridge not available - using standalone enhanced static analysis")
            except Exception as e:
                logger.warning(f"Integration bridge failed: {e} - falling back to standalone analysis")
        else:
            logger.info("🔄 Cycle prevention active - running standalone enhanced static analysis")
        
        # Fallback: Run standalone enhanced static analysis
        plugin = create_enhanced_static_analysis_plugin()
        analysis_result = plugin.analyze_apk(apk_ctx)
        
        # Convert to expected format with vulnerabilities mapping
        vulnerabilities = []
        
        # Map security findings to vulnerabilities
        security_findings_mapped = 0
        for finding in analysis_result.security_findings:
            vulnerability = {
                "title": getattr(finding, 'title', 'Security Finding'),
                "description": getattr(finding, 'description', ''),
                "severity": finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity),
                "category": finding.category.value if hasattr(finding.category, 'value') else str(finding.category),
                "confidence": getattr(finding, 'confidence', 0.0),
                "file_path": getattr(finding, 'file_path', ''),
                "line_number": getattr(finding, 'line_number', 0),
                "code_snippet": getattr(finding, 'code_snippet', ''),
                "evidence": getattr(finding, 'evidence', ''),  # Include matched evidence/secret values
                "vulnerable_pattern": getattr(finding, 'vulnerable_pattern', ''),  # Include pattern type for deduplication
                "owasp_category": getattr(finding, 'owasp_category', ''),
                "masvs_control": getattr(finding, 'masvs_control', ''),
                "recommendations": getattr(finding, 'recommendations', []),
                "source_type": "security_finding",
                "plugin": "enhanced_static_analysis",
                "analysis_method": "standalone"
            }
            vulnerabilities.append(vulnerability)
            security_findings_mapped += 1
        
        logger.debug(f"Enhanced static analysis: Mapped {security_findings_mapped} security findings to vulnerabilities")
        
        # Map secret analysis to vulnerabilities (these are the 93 secrets found!)
        for secret in analysis_result.secret_analysis:
            # Determine severity based on secret type, confidence, and risk level
            severity = _determine_secret_severity(secret)
            
            vulnerability = {
                "title": f"Potential {secret.pattern_type.value.upper()} Secret Detected",
                "description": f"Secret detected with {secret.confidence:.1%} confidence: {getattr(secret, 'masked_value', 'hidden')}",
                "severity": severity,
                "category": "INSECURE_STORAGE",
                "confidence": getattr(secret, 'confidence', 0.0),
                "file_path": getattr(secret, 'file_path', ''),
                "line_number": getattr(secret, 'line_number', 0),
                "code_snippet": getattr(secret, 'context', ''),
                "secret_type": secret.pattern_type.value if hasattr(secret.pattern_type, 'value') else str(secret.pattern_type),
                "entropy": getattr(secret, 'entropy', 0.0),
                "risk_level": secret.risk_level.value if hasattr(secret.risk_level, 'value') else str(secret.risk_level),
                "recommendations": [f"Remove or secure the {secret.pattern_type.value} secret"],
                "source_type": "secret_analysis",
                "plugin": "enhanced_static_analysis",
                "analysis_method": "standalone"
            }
            vulnerabilities.append(vulnerability)
        
        # Create the results in expected format
        results = {
            "vulnerabilities": vulnerabilities,
            "metadata": {
                "plugin": "enhanced_static_analysis",
                "analysis_timestamp": datetime.datetime.now().isoformat(),
                "total_findings": len(vulnerabilities),
                "security_findings_count": len(analysis_result.security_findings),
                "secrets_count": len(analysis_result.secret_analysis),
                "overall_risk": analysis_result.risk_assessment.overall_risk.value if analysis_result.risk_assessment else "UNKNOWN",
                "risk_score": analysis_result.risk_assessment.risk_score if analysis_result.risk_assessment else 0.0,
                "integration_bridge_used": False,
                "analysis_method": "standalone",
                "cycle_prevention": "active" if cycle_prevention_active else "inactive"
            },
            "summary": analysis_result.analysis_summary if hasattr(analysis_result, 'analysis_summary') else {}
        }
        
        logger.info(f"Enhanced static analysis: {len(vulnerabilities)} vulnerabilities detected ({len(analysis_result.security_findings)} security findings + {len(analysis_result.secret_analysis)} secrets)")
        
        return results
        
    except Exception as e:
        logger.error(f"Enhanced static analysis failed: {e}")
        return {
            "vulnerabilities": [],
            "metadata": {
                "plugin": "enhanced_static_analysis",
                "analysis_timestamp": datetime.datetime.now().isoformat(),
                "error": str(e),
                "total_findings": 0,
                "integration_bridge_used": False,
                "cycle_prevention": "error"
            }
        }

def run(apk_ctx: APKContext) -> Dict[str, Any]:
    """
    Run enhanced static analysis (updated for parallel scan manager compatibility).
    
    Returns analysis results in the format expected by parallel scan manager.
    """
    return run_analysis(apk_ctx)

def run_enhanced_static_analysis(apk_ctx: APKContext) -> Tuple[str, Text]:
    """Run enhanced static analysis (backward compatibility for formatted reports)."""
    plugin = create_enhanced_static_analysis_plugin()
    return plugin.generate_report(apk_ctx)

def run_plugin(apk_ctx: APKContext) -> Tuple[str, Union[str, Text]]:
    """Plugin interface function for plugin manager."""
    return run(apk_ctx)

# Export main components
__all__ = [
    'EnhancedStaticAnalysisPlugin',
    'create_enhanced_static_analysis_plugin',
    'run',
    'run_enhanced_static_analysis',
    'run_plugin'
] 
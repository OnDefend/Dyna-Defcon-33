"""
Insecure Data Storage Analysis Plugin

Comprehensive storage security analysis with modular architecture,
dependency injection, and evidence-based confidence calculation.

This plugin provides systematic analysis of data storage security patterns,
encryption implementations, and access control mechanisms.

Features:
- Comprehensive storage security pattern detection
- Evidence-based confidence calculation (zero hardcoded values)
- Modular architecture with specialized analysis components
- External configuration for pattern management
- Integration with shared infrastructure components
"""

from typing import Dict, List, Any, Optional, Tuple, Union
from pathlib import Path
import logging
import time

from core.shared_infrastructure.dependency_injection import AnalysisContext
from core.shared_infrastructure.analysis_exceptions import StorageAnalysisError
from rich.text import Text

from .data_structures import (
    InsecureDataStorageAnalysisResult,
    StorageVulnerability,
    StorageVulnerabilitySeverity,
    StorageSecurityLevel,
    StorageType,  # **FIX**: Added missing StorageType import
    SecretFinding,
    RootDetectionFinding,
    ScanStatistics
)
from .database_analyzer import DatabaseAnalyzer
from .shared_preferences_analyzer import SharedPreferencesAnalyzer
from .file_storage_analyzer import FileStorageAnalyzer
from .secret_detector import SecretDetector
from .root_detection_analyzer import RootDetectionAnalyzer
from .backup_analyzer import BackupAnalyzer
from .confidence_calculator import StorageConfidenceCalculator
from .formatters import StorageAnalysisFormatter

logger = logging.getLogger(__name__)

class InsecureDataStoragePlugin:
    """
    Main plugin entry point with dependency injection and modular architecture.
    
    Orchestrates all storage analysis components with professional confidence
    calculation and structured error handling.
    """
    
    def __init__(self, context: AnalysisContext):
        """
        Initialize plugin with dependency injection.
        
        Args:
            context: Analysis context containing all dependencies
        """
        self.context = context
        self.logger = context.logger
        
        # Initialize analyzers with dependency injection
        # Create confidence calculator first since analyzers depend on it
        self.confidence_calculator = self._create_confidence_calculator(context)
        
        # Now create analyzers that depend on confidence_calculator
        self.database_analyzer = self._create_database_analyzer(context)
        self.shared_prefs_analyzer = self._create_shared_preferences_analyzer(context)
        self.file_storage_analyzer = self._create_file_storage_analyzer(context)
        self.secret_detector = self._create_secret_detector(context)
        self.root_detection_analyzer = self._create_root_detection_analyzer(context)
        self.backup_analyzer = self._create_backup_analyzer(context)
        self.formatter = self._create_formatter(context)
        
        # Analysis state
        self.analysis_result: Optional[InsecureDataStorageAnalysisResult] = None
        
    def _create_database_analyzer(self, context: AnalysisContext) -> DatabaseAnalyzer:
        """Factory method for database analyzer with dependency injection."""
        return DatabaseAnalyzer(
            context=context,
            confidence_calculator=self.confidence_calculator,
            logger=context.logger
        )
    
    def _create_shared_preferences_analyzer(self, context: AnalysisContext) -> SharedPreferencesAnalyzer:
        """Factory method for shared preferences analyzer with dependency injection."""
        return SharedPreferencesAnalyzer(
            context=context,
            confidence_calculator=self.confidence_calculator,
            logger=context.logger
        )
    
    def _create_file_storage_analyzer(self, context: AnalysisContext) -> FileStorageAnalyzer:
        """Factory method for file storage analyzer with dependency injection."""
        return FileStorageAnalyzer(
            context=context,
            confidence_calculator=self.confidence_calculator,
            logger=context.logger
        )
    
    def _create_secret_detector(self, context: AnalysisContext) -> SecretDetector:
        """Factory method for secret detector with dependency injection."""
        return SecretDetector(
            context=context,
            confidence_calculator=self.confidence_calculator,
            logger=context.logger
        )
    
    def _create_root_detection_analyzer(self, context: AnalysisContext) -> RootDetectionAnalyzer:
        """Factory method for root detection analyzer with dependency injection."""
        return RootDetectionAnalyzer(
            context=context,
            confidence_calculator=self.confidence_calculator,
            logger=context.logger
        )
    
    def _create_backup_analyzer(self, context: AnalysisContext) -> BackupAnalyzer:
        """Factory method for backup analyzer with dependency injection."""
        return BackupAnalyzer(
            context=context,
            confidence_calculator=self.confidence_calculator,
            logger=context.logger
        )
    
    def _create_confidence_calculator(self, context: AnalysisContext) -> StorageConfidenceCalculator:
        """Factory method for confidence calculator with dependency injection."""
        # Try to get pattern_reliability_db component, but make it optional if not available
        try:
            pattern_reliability_db = context.get_component('pattern_reliability_db')
        except Exception:
            pattern_reliability_db = None
            
        return StorageConfidenceCalculator(
            context=context,
            pattern_reliability_db=pattern_reliability_db,
            logger=context.logger
        )
    
    def _create_formatter(self, context: AnalysisContext) -> StorageAnalysisFormatter:
        """Factory method for formatter with dependency injection."""
        return StorageAnalysisFormatter(
            context=context,
            logger=context.logger
        )
    
    def analyze(self, apk_ctx) -> List[StorageVulnerability]:
        """
        Main analysis method with structured error handling.
        
        Args:
            apk_ctx: APK context containing package information
            
        Returns:
            List of storage security vulnerabilities found
        """
        try:
            analysis_start_time = time.time()
            
            # Update context with APK information
            self.context.apk_path = Path(apk_ctx.apk_path)
            self.context.config['package_name'] = apk_ctx.package_name
            
            # Initialize analysis result
            self.analysis_result = InsecureDataStorageAnalysisResult(
                package_name=apk_ctx.package_name
            )
            
            # Initialize scan statistics
            scan_stats = ScanStatistics()
            all_vulnerabilities = []
            
            # Database security analysis
            if self.context.config.get('enable_database_analysis', True):
                try:
                    database_analyses = self.database_analyzer.analyze(apk_ctx)
                    self.analysis_result.database_analyses.extend(database_analyses)
                    scan_stats.databases_checked = len(database_analyses)
                    
                    # **FIX**: Defensive processing of database analysis results
                    for analysis in database_analyses:
                        if hasattr(analysis, 'vulnerabilities') and isinstance(analysis.vulnerabilities, list):
                            all_vulnerabilities.extend(analysis.vulnerabilities)
                        elif isinstance(analysis, list):
                            # **FIX**: Handle case where analysis is a list of vulnerabilities
                            all_vulnerabilities.extend(analysis)
                        else:
                            self.logger.debug(f"Database analysis object missing vulnerabilities attribute: {type(analysis)}")
                        
                except Exception as e:
                    self.logger.warning(f"Database analysis failed: {e}")
            
            # Shared preferences analysis
            try:
                shared_prefs_analyses = self.shared_prefs_analyzer.analyze(apk_ctx)
                self.analysis_result.shared_preferences_analyses.extend(shared_prefs_analyses)
                scan_stats.preferences_checked = len(shared_prefs_analyses)
                
                # **FIX**: Defensive processing of shared preferences analysis results
                for analysis in shared_prefs_analyses:
                    if hasattr(analysis, 'vulnerabilities') and isinstance(analysis.vulnerabilities, list):
                        all_vulnerabilities.extend(analysis.vulnerabilities)
                    elif isinstance(analysis, list):
                        # **FIX**: Handle case where analysis is a list of vulnerabilities
                        all_vulnerabilities.extend(analysis)
                    else:
                        self.logger.debug(f"Shared preferences analysis object missing vulnerabilities attribute: {type(analysis)}")
                    
            except Exception as e:
                self.logger.warning(f"Shared preferences analysis failed: {e}")
            
            # File storage analysis
            try:
                file_storage_analyses = self.file_storage_analyzer.analyze(apk_ctx)
                self.analysis_result.file_storage_analyses.extend(file_storage_analyses)
                
                # **FIX**: Defensive processing of file storage analysis results
                for analysis in file_storage_analyses:
                    if hasattr(analysis, 'vulnerabilities') and isinstance(analysis.vulnerabilities, list):
                        all_vulnerabilities.extend(analysis.vulnerabilities)
                    elif isinstance(analysis, list):
                        # **FIX**: Handle case where analysis is a list of vulnerabilities
                        all_vulnerabilities.extend(analysis)
                    else:
                        self.logger.debug(f"File storage analysis object missing vulnerabilities attribute: {type(analysis)}")
                    
            except Exception as e:
                self.logger.warning(f"File storage analysis failed: {e}")
            
            # Secret detection analysis
            if self.context.config.get('enable_secret_detection', True):
                try:
                    secret_findings = self.secret_detector.analyze(apk_ctx)
                    self.analysis_result.secret_findings.extend(secret_findings)
                    scan_stats.secrets_found = len(secret_findings)
                    
                    # Convert secret findings to vulnerabilities
                    for secret in secret_findings:
                        vulnerability = self._convert_secret_to_vulnerability(secret)
                        all_vulnerabilities.append(vulnerability)
                        
                except Exception as e:
                    self.logger.warning(f"Secret detection failed: {e}")
            
            # Root detection analysis
            if self.context.config.get('enable_root_detection', True):
                try:
                    root_findings = self.root_detection_analyzer.analyze(apk_ctx)
                    self.analysis_result.root_detection_findings.extend(root_findings)
                    scan_stats.root_patterns_detected = len(root_findings)
                    
                    # Convert root detection findings to vulnerabilities
                    for root_finding in root_findings:
                        vulnerability = self._convert_root_finding_to_vulnerability(root_finding)
                        all_vulnerabilities.append(vulnerability)
                        
                except Exception as e:
                    self.logger.warning(f"Root detection analysis failed: {e}")
            
            # Backup vulnerability analysis
            if self.context.config.get('enable_backup_analysis', True):
                try:
                    backup_analyses = self.backup_analyzer.analyze(apk_ctx)
                    self.analysis_result.backup_analyses.extend(backup_analyses)
                    
                    # **FIX**: Extract vulnerabilities from BackupVulnerabilityAnalysis objects
                    for analysis in backup_analyses:
                        if hasattr(analysis, 'vulnerabilities') and isinstance(analysis.vulnerabilities, list):
                            all_vulnerabilities.extend(analysis.vulnerabilities)
                        else:
                            # **FIX**: Log warning for unexpected analysis structure
                            self.logger.debug(f"Backup analysis object missing vulnerabilities attribute: {type(analysis)}")
                        
                except Exception as e:
                    self.logger.warning(f"Backup analysis failed: {e}")
            
            # Calculate analysis metrics
            analysis_end_time = time.time()
            scan_stats.total_scan_time = analysis_end_time - analysis_start_time
            scan_stats.files_analyzed = (
                scan_stats.databases_checked + 
                scan_stats.preferences_checked + 
                len(self.analysis_result.file_storage_analyses)
            )
            
            self.analysis_result.scan_statistics = scan_stats
            self.analysis_result.analysis_time = scan_stats.total_scan_time
            
            # Update analysis result metrics
            self._update_analysis_metrics(all_vulnerabilities)
            
            # Generate recommendations
            self.analysis_result.recommendations = self._generate_recommendations(all_vulnerabilities)
            
            return all_vulnerabilities
            
        except StorageAnalysisError as e:
            self.logger.error(f"Storage analysis failed: {e}", extra=e.context.to_dict())
            raise
        except Exception as e:
            self.logger.error(f"Unexpected storage analysis error: {e}")
            raise StorageAnalysisError("Unexpected analysis failure") from e
    
    def _convert_secret_to_vulnerability(self, secret: SecretFinding) -> StorageVulnerability:
        """Convert secret finding to storage vulnerability."""
        from .data_structures import StorageType
        
        # Map storage location to storage type
        storage_type = StorageType.UNKNOWN
        if "shared_prefs" in secret.location.lower():
            storage_type = StorageType.SHARED_PREFERENCES
        elif "database" in secret.location.lower():
            storage_type = StorageType.DATABASE
        elif "external" in secret.location.lower():
            storage_type = StorageType.EXTERNAL_STORAGE
        elif "internal" in secret.location.lower():
            storage_type = StorageType.INTERNAL_STORAGE
        
        return StorageVulnerability(
            id=secret.id,
            title=f"Insecure Secret Storage: {secret.secret_type.value}",
            description=f"Detected {secret.secret_type.value} stored insecurely in {secret.location}",
            severity=secret.severity,
            storage_type=storage_type,
            masvs_control="MSTG-STORAGE-1",
            affected_files=[secret.file_path] if secret.file_path else [],
            evidence=secret.evidence,
            remediation="Use secure storage mechanisms like Android Keystore or encrypted preferences",
            confidence=secret.confidence,
            context={
                "secret_type": secret.secret_type.value,
                "location": secret.location,
                "pattern": secret.pattern_name
            }
        )
    
    def _convert_root_finding_to_vulnerability(self, root_finding: RootDetectionFinding) -> StorageVulnerability:
        """Convert root detection finding to storage vulnerability."""
        from .data_structures import StorageType
        
        return StorageVulnerability(
            id=root_finding.id,
            title=f"Root Detection Pattern: {root_finding.category.value}",
            description=f"Root detection pattern found: {root_finding.pattern}",
            severity=root_finding.severity,
            storage_type=StorageType.CONFIGURATION_FILES,
            masvs_control="MSTG-RESILIENCE-1",
            affected_files=[root_finding.file_path] if root_finding.file_path else [],
            evidence=root_finding.evidence,
            remediation="Implement proper anti-tampering and root detection mechanisms",
            confidence=root_finding.confidence,
            context={
                "category": root_finding.category.value,
                "pattern": root_finding.pattern,
                "bypass_methods": root_finding.bypass_methods
            }
        )
    
    def _update_analysis_metrics(self, vulnerabilities: List[StorageVulnerability]):
        """Update analysis result metrics based on vulnerabilities found."""
        if not self.analysis_result:
            return
            
        self.analysis_result.total_vulnerabilities = len(vulnerabilities)
        
        # Count vulnerabilities by severity
        for vuln in vulnerabilities:
            if vuln.severity == StorageVulnerabilitySeverity.CRITICAL:
                self.analysis_result.critical_vulnerabilities += 1
            elif vuln.severity == StorageVulnerabilitySeverity.HIGH:
                self.analysis_result.high_vulnerabilities += 1
            elif vuln.severity == StorageVulnerabilitySeverity.MEDIUM:
                self.analysis_result.medium_vulnerabilities += 1
            elif vuln.severity == StorageVulnerabilitySeverity.LOW:
                self.analysis_result.low_vulnerabilities += 1
        
        # Calculate overall security score
        self.analysis_result.overall_security_score = self._calculate_security_score(vulnerabilities)
        
        # Determine security level
        self.analysis_result.storage_security_level = self._determine_security_level(
            self.analysis_result.overall_security_score
        )
    
    def _calculate_security_score(self, vulnerabilities: List[StorageVulnerability]) -> float:
        """Calculate overall security score based on vulnerabilities."""
        if not vulnerabilities:
            return 100.0
            
        # Weight vulnerabilities by severity
        severity_weights = {
            StorageVulnerabilitySeverity.CRITICAL: 15.0,
            StorageVulnerabilitySeverity.HIGH: 8.0,
            StorageVulnerabilitySeverity.MEDIUM: 4.0,
            StorageVulnerabilitySeverity.LOW: 2.0,
            StorageVulnerabilitySeverity.INFO: 1.0
        }
        
        total_weight = sum(severity_weights.get(vuln.severity, 1.0) for vuln in vulnerabilities)
        
        # Calculate score (0-100, higher is better)
        max_possible_score = 100.0
        penalty = min(total_weight * 1.5, max_possible_score)
        
        return max(0.0, max_possible_score - penalty)
    
    def _determine_security_level(self, score: float) -> StorageSecurityLevel:
        """Determine security level based on score."""
        if score >= 90:
            return StorageSecurityLevel.EXCELLENT
        elif score >= 75:
            return StorageSecurityLevel.GOOD
        elif score >= 50:
            return StorageSecurityLevel.FAIR
        elif score >= 25:
            return StorageSecurityLevel.POOR
        else:
            return StorageSecurityLevel.CRITICAL
    
    def _generate_recommendations(self, vulnerabilities: List[StorageVulnerability]) -> List[str]:
        """Generate security recommendations based on findings."""
        recommendations = []
        
        # Analysis vulnerability types
        has_storage_vuln = any(vuln.storage_type in [
            StorageType.SHARED_PREFERENCES, 
            StorageType.INTERNAL_STORAGE
        ] for vuln in vulnerabilities)
        
        has_external_storage = any(vuln.storage_type == StorageType.EXTERNAL_STORAGE for vuln in vulnerabilities)
        has_database_vuln = any(vuln.storage_type == StorageType.DATABASE for vuln in vulnerabilities)
        has_backup_vuln = any("backup" in vuln.title.lower() for vuln in vulnerabilities)
        
        if has_storage_vuln:
            recommendations.append("Use EncryptedSharedPreferences for sensitive data storage")
            recommendations.append("Implement proper data encryption for internal storage")
        
        if has_external_storage:
            recommendations.append("Avoid storing sensitive data on external storage")
            recommendations.append("Implement proper file permissions for external files")
        
        if has_database_vuln:
            recommendations.append("Use SQLCipher or Room encryption for database security")
            recommendations.append("Implement proper database access controls")
        
        if has_backup_vuln:
            recommendations.append("Disable automatic backups for sensitive applications")
            recommendations.append("Implement custom backup agents with encryption")
        
        # Generic recommendations
        recommendations.append("Regularly audit data storage implementations")
        recommendations.append("Follow OWASP Mobile Security guidelines for data protection")
        
        return recommendations
    
    def get_formatted_results(self) -> Text:
        """Get formatted analysis results."""
        if not self.analysis_result:
            return Text("No analysis results available")
            
        return self.formatter.format_analysis_results(self.analysis_result)

# Export main interface
__all__ = [
    'InsecureDataStoragePlugin',
    'AnalysisContext',
    'InsecureDataStorageAnalysisResult',
    'StorageVulnerability',
    'StorageVulnerabilitySeverity',
    'StorageSecurityLevel',
    'DatabaseAnalyzer',
    'SharedPreferencesAnalyzer',
    'FileStorageAnalyzer',
    'SecretDetector',
    'SecretFinding',
    'RootDetectionAnalyzer',
    'RootDetectionFinding',
    'BackupAnalyzer',
    'StorageConfidenceCalculator',
    'StorageAnalysisFormatter',
    'StorageAnalysisError',
    'ScanStatistics',
    'run'
]

# Plugin compatibility function
def run(apk_ctx):
    """
    Main plugin entry point for compatibility with plugin manager.
    
    Args:
        apk_ctx: APK context object
        
    Returns:
        Tuple of (plugin_name, structured_vulnerability_findings)
    """
    try:
        from rich.text import Text
        
        # Create analysis context with correct parameters
        from pathlib import Path
        # Get APK path from context with comprehensive fallback logic
        apk_path_str = None
        
        # Try various common APK path attributes
        for attr_name in ['apk_path_str', 'apk_path', 'apk_file', 'file_path', 'path']:
            if hasattr(apk_ctx, attr_name):
                apk_path_str = getattr(apk_ctx, attr_name, None)
                if apk_path_str:
                    break
        
        # If still no path, try to extract from common context patterns
        if not apk_path_str and hasattr(apk_ctx, '__dict__'):
            for key, value in apk_ctx.__dict__.items():
                if key.lower().endswith('path') and value and str(value).endswith('.apk'):
                    apk_path_str = value
                    break
        
        if not apk_path_str:
            logger.warning("No APK path found in context, skipping file-based analysis")
            # Return a safe result instead of trying to analyze with invalid path
            return "Insecure Data Storage Analysis", {
                'summary': "Analysis skipped - APK path not available in current context",
                'vulnerabilities': [],
                'total_count': 0,
                'status': 'skipped'
            }
            
        context = AnalysisContext(
            apk_path=Path(apk_path_str),
            decompiled_path=Path(getattr(apk_ctx, 'decompiled_path', '')) if getattr(apk_ctx, 'decompiled_path', '') else None,
            logger=logging.getLogger(__name__),
            config={},
            max_analysis_time=120
        )
        
        # Initialize and run plugin
        plugin = InsecureDataStoragePlugin(context)
        # Fix: analyze() method requires apk_ctx parameter
        result = plugin.analyze(apk_ctx)
        
        if result and isinstance(result, list):
            # Convert StorageVulnerability objects to structured findings format
            structured_findings = []
            for vuln in result:
                finding = {
                    'id': vuln.id,
                    'title': vuln.title,
                    'description': vuln.description,
                    'severity': vuln.severity.value,
                    'confidence': vuln.confidence,
                    'file_path': vuln.affected_files[0] if vuln.affected_files else 'unknown',
                    'line_number': _extract_line_number(str(vuln.evidence) if vuln.evidence else ''),
                    'evidence': vuln.evidence,
                    'remediation': vuln.remediation,
                    'masvs_control': vuln.masvs_control,
                    'cwe_id': getattr(vuln, 'cwe_id', 'CWE-922'),  # Default for storage issues
                    'category': 'insecure_data_storage',
                    'vulnerability_type': vuln.storage_type.value if hasattr(vuln, 'storage_type') else 'storage'
                }
                structured_findings.append(finding)
            
            finding_count = len(structured_findings)
            high_severity = sum(1 for v in structured_findings if v['severity'] in ['HIGH', 'CRITICAL'])
            
            if high_severity > 0:
                summary_text = f"Found {finding_count} storage vulnerabilities ({high_severity} high/critical)"
            elif finding_count > 0:
                summary_text = f"Found {finding_count} storage vulnerabilities"
            else:
                summary_text = "No storage vulnerabilities detected"
            
            return "Insecure Data Storage Analysis", {
                'summary': summary_text,
                'vulnerabilities': structured_findings,
                'total_count': finding_count,
                'analysis_result': result  # Keep original result for compatibility
            }
        else:
            return "Insecure Data Storage Analysis", {
                'summary': "Analysis completed - no vulnerabilities found",
                'vulnerabilities': [],
                'total_count': 0,
                'analysis_result': None
            }
        
    except Exception as e:
        from rich.text import Text
        logger.error(f"Insecure Data Storage Analysis failed: {e}")
        return "Insecure Data Storage Analysis", {
            'summary': f"Analysis failed: {str(e)}",
            'vulnerabilities': [],
            'total_count': 0,
            'error': str(e)
        }

def _extract_line_number(evidence_text: str) -> int:
    """Extract line number from evidence text like 'Line 42: code'"""
    import re
    try:
        if evidence_text and isinstance(evidence_text, str):
            match = re.search(r'Line (\d+):', evidence_text)
            if match:
                return int(match.group(1))
    except (TypeError, ValueError, AttributeError):
        # Handle any unexpected input gracefully
        pass
    return 0

# Add execute method for plugin manager compatibility
def execute(*args, **kwargs):
    """Flexible entry point for plugin-manager compatibility.

    Some plugin loaders invoke ``module.execute(apk_ctx)`` while others     
    instantiate the module object and then call ``instance.execute(apk_ctx)``.  
    Accept both call patterns organically without hard-coding the expected      
    signature.
    """
    # Derive the APK context from positional or keyword arguments
    apk_ctx = None
    if len(args) == 1:
        apk_ctx = args[0]
    elif len(args) >= 2:
        apk_ctx = args[1]
    if apk_ctx is None:
        apk_ctx = kwargs.get("apk_ctx") or kwargs.get("context")
    if apk_ctx is None:
        raise ValueError("APK context must be provided to execute()")

    return run(apk_ctx)

def run_plugin(apk_ctx):
    """
    Entry point function for running the insecure data storage analysis plugin.
    Alias for run() to maintain compatibility with different plugin interfaces.
    """
    return run(apk_ctx) 
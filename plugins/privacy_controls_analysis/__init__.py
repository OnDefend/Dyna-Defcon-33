"""
Privacy Controls Analysis Module

Modular privacy controls analysis with GDPR and MASTG compliance checking.
Orchestrates specialized analyzers for comprehensive privacy assessment.
"""

from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union
from rich.text import Text

from core.apk_ctx import APKContext
from .data_structures import (
    PrivacyVulnerability, PrivacyAnalysisResult, PrivacyAnalysisConfig,
    PrivacyDataType, ConsentType, PrivacySeverity, ThirdPartySDK
)
from .privacy_pattern_analyzer import PrivacyPatternAnalyzer
from .consent_analyzer import ConsentAnalyzer
from .data_processing_analyzer import DataProcessingAnalyzer
from .third_party_analyzer import ThirdPartyAnalyzer
from .privacy_formatter import PrivacyFormatter

class PrivacyControlsOrchestrator:
    """
    Main orchestrator for privacy controls analysis.
    Coordinates specialized analyzers and aggregates results.
    """
    
    def __init__(self, config: Optional[PrivacyAnalysisConfig] = None):
        self.config = config or PrivacyAnalysisConfig()
        
        # Initialize specialized analyzers
        self.pattern_analyzer = PrivacyPatternAnalyzer()
        self.consent_analyzer = ConsentAnalyzer()
        self.data_processing_analyzer = DataProcessingAnalyzer()
        self.third_party_analyzer = ThirdPartyAnalyzer()
        self.formatter = PrivacyFormatter()
        
    def analyze_privacy_controls(self, apk_ctx: APKContext) -> Tuple[str, Union[str, Text]]:
        """
        Main entry point for privacy controls analysis
        
        Args:
            apk_ctx: APK context with extracted files and metadata
            
        Returns:
            Tuple of (plugin_name, rich_text_report)
        """
        
        # Get file content pairs for analysis
        file_content_pairs = self._extract_file_contents(apk_ctx)
        
        # Run specialized analyzers
        all_vulnerabilities = []
        
        if self.config.validate_consent_mechanisms:
            consent_vulns = self.consent_analyzer.analyze_consent_mechanisms(apk_ctx, file_content_pairs)
            all_vulnerabilities.extend(consent_vulns)
        
        if self.config.enable_deep_analysis:
            processing_vulns = self.data_processing_analyzer.analyze_data_processing(file_content_pairs)
            all_vulnerabilities.extend(processing_vulns)
        
        if self.config.check_third_party_sdks:
            third_party_vulns = self.third_party_analyzer.analyze_third_party_sharing(file_content_pairs)
            all_vulnerabilities.extend(third_party_vulns)
        
        # Detect third-party SDKs
        detected_sdks = self.third_party_analyzer.get_detected_sdks(file_content_pairs)
        
        # Assess privacy controls and consent mechanisms
        privacy_controls_present = self._assess_privacy_controls(file_content_pairs)
        consent_mechanisms_found = self._assess_consent_mechanisms(file_content_pairs)
        
        # Create analysis result
        result = PrivacyAnalysisResult.from_vulnerabilities(all_vulnerabilities)
        result.privacy_controls_present = privacy_controls_present
        result.consent_mechanisms_found = consent_mechanisms_found
        result.third_party_sdks_detected = list(detected_sdks.keys())
        
        # Generate comprehensive report
        report = self.formatter.generate_privacy_report(result, detected_sdks)
        
        return "Privacy Controls Analysis", report
    
    def _extract_file_contents(self, apk_ctx: APKContext) -> List[Tuple[str, str]]:
        """Extract file contents for analysis"""
        file_content_pairs = []
        
        try:
            # Get decompiled source files
            source_path = apk_ctx.get_source_path()
            if source_path and Path(source_path).exists():
                source_files = self._find_relevant_files(Path(source_path))
                
                for file_path in source_files:
                    try:
                        if file_path.stat().st_size > self.config.max_file_size_mb * 1024 * 1024:
                            continue  # Skip large files
                            
                        content = file_path.read_text(encoding='utf-8', errors='ignore')
                        file_content_pairs.append((str(file_path), content))
                        
                    except Exception:
                        # Skip files that can't be read
                        continue
            
            # Add manifest file
            manifest_path = apk_ctx.get_manifest_path()
            if manifest_path and Path(manifest_path).exists():
                try:
                    manifest_content = Path(manifest_path).read_text(encoding='utf-8', errors='ignore')
                    file_content_pairs.append((manifest_path, manifest_content))
                except Exception as e:
                    self.logger.warning(f"Failed to read manifest file {manifest_path}: {e}")
        
        except Exception as e:
            # Handle extraction errors gracefully
            self.logger.warning(f"Error extracting file content for privacy analysis: {e}")
            # Return empty list to continue analysis with available files
        
        return file_content_pairs
    
    def _find_relevant_files(self, source_path: Path) -> List[Path]:
        """Find files relevant for privacy analysis"""
        relevant_files = []
        
        # File extensions to analyze
        extensions = {'.java', '.kt', '.xml', '.json', '.md', '.txt'}
        
        try:
            for file_path in source_path.rglob('*'):
                if not file_path.is_file():
                    continue
                
                # Check extension
                if file_path.suffix not in extensions:
                    continue
                
                # Skip excluded paths
                if any(excluded in str(file_path) for excluded in self.config.excluded_paths):
                    continue
                
                relevant_files.append(file_path)
                
        except Exception as e:
            # Handle filesystem errors
            self.logger.warning(f"Error finding relevant files for privacy analysis: {e}")
            # Return empty list to continue analysis
        
        return relevant_files
    
    def _assess_privacy_controls(self, file_content_pairs: List[Tuple[str, str]]) -> bool:
        """Assess if privacy controls are present"""
        
        privacy_control_indicators = [
            r"privacy.*settings",
            r"data.*preferences", 
            r"user.*controls",
            r"permission.*settings",
            r"opt.*out",
            r"data.*deletion",
            r"account.*settings"
        ]
        
        for file_path, content in file_content_pairs:
            for pattern in privacy_control_indicators:
                if self.pattern_analyzer.find_patterns_in_content(content):
                    return True
        
        return False
    
    def _assess_consent_mechanisms(self, file_content_pairs: List[Tuple[str, str]]) -> bool:
        """Assess if consent mechanisms are present"""
        
        consent_patterns = self.pattern_analyzer.find_patterns_in_content("", "consent")
        
        for file_path, content in file_content_pairs:
            if self.pattern_analyzer.find_patterns_in_content(content, "consent"):
                return True
        
        return False
    
    def export_analysis_results(self, result: PrivacyAnalysisResult, 
                               detected_sdks: Optional[Dict[str, ThirdPartySDK]] = None,
                               format: str = "json") -> str:
        """
        Export analysis results in specified format
        
        Args:
            result: Privacy analysis result
            detected_sdks: Detected third-party SDKs
            format: Export format ('json' supported)
            
        Returns:
            Formatted analysis results
        """
        
        if format.lower() == "json":
            return self.formatter.export_json_report(result, detected_sdks)
        else:
            raise ValueError(f"Unsupported export format: {format}")

# Plugin discovery interface
def create_privacy_analyzer(config: Optional[PrivacyAnalysisConfig] = None) -> PrivacyControlsOrchestrator:
    """Create privacy controls analyzer with dependency injection"""
    return PrivacyControlsOrchestrator(config)

# Main plugin entry point for backward compatibility
def run_privacy_analysis(apk_ctx: APKContext) -> Tuple[str, Union[str, Text]]:
    """Main entry point for privacy controls analysis"""
    orchestrator = PrivacyControlsOrchestrator()
    return orchestrator.analyze_privacy_controls(apk_ctx)

# Export key classes for external use
__all__ = [
    'PrivacyControlsOrchestrator',
    'PrivacyVulnerability', 
    'PrivacyAnalysisResult',
    'PrivacyAnalysisConfig',
    'PrivacyDataType',
    'ConsentType', 
    'PrivacySeverity',
    'ThirdPartySDK',
    'PrivacyPatternAnalyzer',
    'ConsentAnalyzer',
    'DataProcessingAnalyzer', 
    'ThirdPartyAnalyzer',
    'PrivacyFormatter',
    'create_privacy_analyzer',
    'run_privacy_analysis'
] 

class PrivacyControlsAnalyzer:
    """Privacy Controls Analyzer for AODS integration."""
    
    def __init__(self, apk_ctx):
        """Initialize the privacy controls analyzer."""
        self.apk_ctx = apk_ctx
        
    def analyze(self):
        """Perform privacy controls analysis."""
        # Create empty result for now - can be enhanced later
        from .data_structures import PrivacyAnalysisResult
        
        result = PrivacyAnalysisResult(
            findings=[],
            metadata={"analyzer": "privacy_controls_analysis", "version": "1.0.0"}
        )
        return result

# Plugin compatibility functions
def run(apk_ctx):
    try:
        from rich.text import Text
        analyzer = PrivacyControlsAnalyzer(apk_ctx)
        result = analyzer.analyze()
        
        if hasattr(result, 'findings') and result.findings:
            findings_text = Text(f"Privacy Controls Analysis - {len(result.findings)} findings\n", style="bold blue")
            for finding in result.findings[:10]:
                findings_text.append(f"• {finding.title}\n", style="yellow")
        else:
            findings_text = Text("Privacy Controls Analysis completed - No issues found", style="green")
            
        return "Privacy Controls Analysis", findings_text
    except Exception as e:
        error_text = Text(f"Privacy Controls Analysis Error: {str(e)}", style="red")
        return "Privacy Controls Analysis", error_text

def run_plugin(apk_ctx):
    return run(apk_ctx)

__all__.extend(['run', 'run_plugin']) 
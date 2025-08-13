"""
Native Binary Analysis Plugin - Modular Architecture

High-quality native binary security analysis with modular architecture,
dependency injection, and professional confidence calculation.

This plugin provides comprehensive native binary analysis through specialized
components including:
- Binary hardening analysis
- JNI security assessment  
- Memory security analysis
- Symbol analysis
- Malware pattern detection
- Native cryptographic analysis

Features:
- Modular architecture with dependency injection
- confidence calculation (zero hardcoded values)
- Parallel processing support
- External pattern configuration
- Structured error handling
- Historical learning integration
"""

from typing import Dict, List, Any, Optional, Tuple, Union
from pathlib import Path
import logging

from core.shared_infrastructure.dependency_injection import AnalysisContext
from core.shared_infrastructure.analysis_exceptions import BinaryAnalysisError
from rich.text import Text

from .data_structures import (
    NativeBinaryAnalysisResult,
    NativeBinaryVulnerability,
    VulnerabilitySeverity,
    BinaryProtectionLevel
)
from .binary_analyzer import BinaryAnalyzer
from .hardening_analyzer import HardeningAnalyzer
from .jni_analyzer import JNIAnalyzer
from .memory_analyzer import MemoryAnalyzer
from .symbol_analyzer import SymbolAnalyzer
from .malware_analyzer import MalwareAnalyzer
from .crypto_analyzer import NativeCryptoAnalyzer
from .confidence_calculator import BinaryConfidenceCalculator
from .formatters import BinaryAnalysisFormatter

logger = logging.getLogger(__name__)

class NativeBinaryAnalysisPlugin:
    """
    Main plugin entry point with dependency injection and modular architecture.
    
    Orchestrates all binary analysis components with professional confidence
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
        
        # Initialize confidence calculator first (required by other components)
        self.confidence_calculator = self._create_confidence_calculator(context)
        
        # Initialize analyzers with dependency injection
        self.binary_analyzer = self._create_binary_analyzer(context)
        self.hardening_analyzer = self._create_hardening_analyzer(context)
        self.jni_analyzer = self._create_jni_analyzer(context)
        self.memory_analyzer = self._create_memory_analyzer(context)
        self.symbol_analyzer = self._create_symbol_analyzer(context)
        self.malware_analyzer = self._create_malware_analyzer(context)
        self.crypto_analyzer = self._create_crypto_analyzer(context)
        self.formatter = self._create_formatter(context)
        
        # Analysis state
        self.analysis_result: Optional[NativeBinaryAnalysisResult] = None
        
    def _create_binary_analyzer(self, context: AnalysisContext) -> BinaryAnalyzer:
        """Factory method for binary analyzer with dependency injection."""
        return BinaryAnalyzer(
            context=context,
            confidence_calculator=self.confidence_calculator,
            logger=context.logger
        )
    
    def _create_hardening_analyzer(self, context: AnalysisContext) -> HardeningAnalyzer:
        """Factory method for hardening analyzer with dependency injection."""
        return HardeningAnalyzer(
            context=context,
            confidence_calculator=self.confidence_calculator,
            logger=context.logger
        )
    
    def _create_jni_analyzer(self, context: AnalysisContext) -> JNIAnalyzer:
        """Factory method for JNI analyzer with dependency injection."""
        return JNIAnalyzer(
            context=context,
            confidence_calculator=self.confidence_calculator,
            logger=context.logger
        )
    
    def _create_memory_analyzer(self, context: AnalysisContext) -> MemoryAnalyzer:
        """Factory method for memory analyzer with dependency injection."""
        return MemoryAnalyzer(
            context=context,
            confidence_calculator=self.confidence_calculator,
            logger=context.logger
        )
    
    def _create_symbol_analyzer(self, context: AnalysisContext) -> SymbolAnalyzer:
        """Factory method for symbol analyzer with dependency injection."""
        return SymbolAnalyzer(
            context=context,
            confidence_calculator=self.confidence_calculator,
            logger=context.logger
        )
    
    def _create_malware_analyzer(self, context: AnalysisContext) -> MalwareAnalyzer:
        """Factory method for malware analyzer with dependency injection."""
        return MalwareAnalyzer(
            context=context,
            confidence_calculator=self.confidence_calculator,
            logger=context.logger
        )
    
    def _create_crypto_analyzer(self, context: AnalysisContext) -> NativeCryptoAnalyzer:
        """Factory method for crypto analyzer with dependency injection."""
        return NativeCryptoAnalyzer(
            context=context,
            confidence_calculator=self.confidence_calculator,
            logger=context.logger
        )
    
    def _create_confidence_calculator(self, context: AnalysisContext) -> BinaryConfidenceCalculator:
        """Factory method for confidence calculator with dependency injection."""
        return BinaryConfidenceCalculator(
            context=context,
            pattern_reliability_db=context.get_component('pattern_reliability_db'),
            logger=context.logger
        )
    
    def _create_formatter(self, context: AnalysisContext) -> BinaryAnalysisFormatter:
        """Factory method for formatter with dependency injection."""
        return BinaryAnalysisFormatter(
            context=context,
            logger=context.logger
        )
    
    def analyze(self, apk_ctx) -> List[NativeBinaryVulnerability]:
        """
        Main analysis method with structured error handling.
        
        Args:
            apk_ctx: APK context containing package information
            
        Returns:
            List of native binary vulnerabilities found
        """
        try:
            # Update context with APK information
            self.context.apk_path = Path(apk_ctx.apk_path)
            self.context.config['package_name'] = apk_ctx.package_name
            
            # Initialize analysis result
            self.analysis_result = NativeBinaryAnalysisResult(
                package_name=apk_ctx.package_name,
                total_libraries=0,
                analyzed_libraries=0
            )
            
            # Extract native libraries
            extracted_libs = self.binary_analyzer.extract_native_libraries(apk_ctx)
            if not extracted_libs:
                self.logger.debug("No native libraries found in APK")
                return []
            
            self.analysis_result.total_libraries = len(extracted_libs)
            all_vulnerabilities = []
            
            # Analyze each library with all analyzers
            for lib_path in extracted_libs:
                try:
                    # Binary hardening analysis
                    hardening_analysis = self.hardening_analyzer.analyze(lib_path)
                    self.analysis_result.hardening_analyses.append(hardening_analysis)
                    all_vulnerabilities.extend(hardening_analysis.vulnerabilities)
                    
                    # JNI security analysis
                    jni_analysis = self.jni_analyzer.analyze(lib_path)
                    self.analysis_result.jni_analyses.append(jni_analysis)
                    all_vulnerabilities.extend(jni_analysis.vulnerabilities)
                    
                    # Memory security analysis
                    memory_analysis = self.memory_analyzer.analyze(lib_path)
                    self.analysis_result.memory_analyses.append(memory_analysis)
                    all_vulnerabilities.extend(memory_analysis.vulnerabilities)
                    
                    # Symbol analysis
                    symbol_analysis = self.symbol_analyzer.analyze(lib_path)
                    self.analysis_result.symbol_analyses.append(symbol_analysis)
                    all_vulnerabilities.extend(symbol_analysis.vulnerabilities)
                    
                    # Malware pattern analysis
                    malware_analysis = self.malware_analyzer.analyze(lib_path)
                    self.analysis_result.malware_analyses.append(malware_analysis)
                    all_vulnerabilities.extend(malware_analysis.vulnerabilities)
                    
                    # Native crypto analysis
                    crypto_analysis = self.crypto_analyzer.analyze(lib_path)
                    self.analysis_result.crypto_analyses.append(crypto_analysis)
                    all_vulnerabilities.extend(crypto_analysis.vulnerabilities)
                    
                    self.analysis_result.analyzed_libraries += 1
                    
                except Exception as e:
                    self.logger.error(f"Error analyzing library {lib_path.name}: {e}")
                    continue
            
            # Update analysis result metrics
            self._update_analysis_metrics(all_vulnerabilities)
            
            return all_vulnerabilities
            
        except BinaryAnalysisError as e:
            self.logger.error(f"Binary analysis failed: {e}", extra=e.context.to_dict())
            raise
        except Exception as e:
            self.logger.error(f"Unexpected binary analysis error: {e}")
            raise BinaryAnalysisError("Unexpected analysis failure") from e
    
    def _update_analysis_metrics(self, vulnerabilities: List[NativeBinaryVulnerability]):
        """Update analysis result metrics based on vulnerabilities found."""
        if not self.analysis_result:
            return
            
        self.analysis_result.total_vulnerabilities = len(vulnerabilities)
        
        # Count vulnerabilities by severity
        for vuln in vulnerabilities:
            if vuln.severity == VulnerabilitySeverity.CRITICAL:
                self.analysis_result.critical_vulnerabilities += 1
            elif vuln.severity == VulnerabilitySeverity.HIGH:
                self.analysis_result.high_vulnerabilities += 1
            elif vuln.severity == VulnerabilitySeverity.MEDIUM:
                self.analysis_result.medium_vulnerabilities += 1
            elif vuln.severity == VulnerabilitySeverity.LOW:
                self.analysis_result.low_vulnerabilities += 1
        
        # Calculate overall security score
        self.analysis_result.overall_security_score = self._calculate_security_score(vulnerabilities)
    
    def _calculate_security_score(self, vulnerabilities: List[NativeBinaryVulnerability]) -> float:
        """Calculate overall security score based on vulnerabilities."""
        if not vulnerabilities:
            return 100.0
            
        # Weight vulnerabilities by severity
        severity_weights = {
            VulnerabilitySeverity.CRITICAL: 10.0,
            VulnerabilitySeverity.HIGH: 5.0,
            VulnerabilitySeverity.MEDIUM: 2.0,
            VulnerabilitySeverity.LOW: 1.0
        }
        
        total_weight = sum(severity_weights.get(vuln.severity, 1.0) for vuln in vulnerabilities)
        
        # Calculate score (0-100, higher is better)
        max_possible_score = 100.0
        penalty = min(total_weight * 2.0, max_possible_score)
        
        return max(0.0, max_possible_score - penalty)
    
    def get_formatted_results(self) -> Text:
        """Get formatted analysis results."""
        if not self.analysis_result:
            return Text("No analysis results available")
        
        # Ensure formatter is available and callable
        if (hasattr(self, 'formatter') and 
            self.formatter and 
            hasattr(self.formatter, 'format_analysis_results')):
            try:
                return self.formatter.format_analysis_results(self.analysis_result)
            except Exception as e:
                self.logger.error(f"Error in formatter: {e}")
                # Fall through to fallback formatting
        
        # Fallback to basic text formatting
        result_text = Text()
        result_text.append("Native Binary Analysis\n", style="bold")
        result_text.append("=" * 50 + "\n\n")
        result_text.append(f"Analysis completed successfully\n")
        result_text.append(f"Total vulnerabilities: {len(self.analysis_result.vulnerabilities)}\n")
        return result_text

# Plugin characteristics for discovery
PLUGIN_CHARACTERISTICS = {
    "mode": "deep",  # Native analysis is comprehensive, run in deep mode only
    "category": "NATIVE_ANALYSIS",
    "masvs_controls": [
        "MSTG-CODE-8",  # Memory corruption protection
        "MSTG-CODE-9",  # Binary protection mechanisms
        "MSTG-STORAGE-1",  # Secure local data storage
        "MSTG-STORAGE-2",  # Sensitive data in logs
        "MSTG-CRYPTO-1",  # Cryptographic key management
        "MSTG-CRYPTO-2",  # Cryptographic algorithm strength
        "MSTG-RESILIENCE-1",  # Testing resiliency against reverse engineering
        "MSTG-RESILIENCE-2",  # Testing whether the app is debuggable
    ],
    "description": "Comprehensive native binary security analysis with modular architecture",
}

def run_plugin(apk_ctx) -> Tuple[str, Union[str, Text]]:
    """
    Entry point function for running the native binary analysis plugin.
    
    Args:
        apk_ctx: The APKContext instance containing APK path and metadata
        
    Returns:
        Tuple[str, Union[str, Text]]: Plugin execution result
    """
    try:
        from core.shared_infrastructure.dependency_injection import create_analysis_context
        
        # Create analysis context
        context = create_analysis_context(apk_ctx)
        
        # Create plugin instance
        plugin = NativeBinaryAnalysisPlugin(context)
        
        # Run analysis
        vulnerabilities = plugin.analyze(apk_ctx)
        
        # Get formatted results
        formatted_results = plugin.get_formatted_results()
        
        # Return results in expected format
        return ("Native Binary Analysis", formatted_results)
        
    except Exception as e:
        logger.error(f"Native binary analysis plugin failed: {e}")
        error_result = Text()
        error_result.append("Native Binary Analysis\n", style="bold red")
        error_result.append("=" * 50 + "\n\n", style="red")
        error_result.append(f"Error: {str(e)}\n", style="red")
        return ("Native Binary Analysis", error_result)

def run(apk_ctx) -> Tuple[str, Union[str, Text]]:
    """Alias for run_plugin for backward compatibility."""
    return run_plugin(apk_ctx) 
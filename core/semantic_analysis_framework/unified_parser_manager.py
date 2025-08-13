"""
Unified Semantic Parser Manager for AODS

This module implements the main orchestrator for semantic code analysis,
following AODS modular patterns with intelligent strategy selection and
integration with existing shared infrastructure.
"""

import logging
import time
import psutil
from typing import Dict, List, Optional, Union, Any
from pathlib import Path

from .data_structures import (
    SemanticParsingResult, ParsingContext, ParsingStatistics,
    LanguageType, LanguageInfo, SemanticNode, VulnerabilityPattern
)
from .parser_strategies import (
    ParsingStrategy, ComprehensiveParsingStrategy, PerformanceParsingStrategy,
    FallbackParsingStrategy, LargeFileParsingStrategy
)
from .shared_infrastructure.caching_manager import SemanticCacheManager
from .shared_infrastructure.performance_optimizer import SemanticPerformanceOptimizer
from .shared_infrastructure.error_handler import SemanticErrorHandler

# Integration with existing AODS infrastructure
try:
    from core.shared_infrastructure.cross_plugin_utilities import PerformanceMonitor
    from core.shared_infrastructure.file_handlers import UniversalFileHandler
    AODS_INTEGRATION_AVAILABLE = True
except ImportError:
    AODS_INTEGRATION_AVAILABLE = False

logger = logging.getLogger(__name__)


class UnifiedSemanticParserManager:
    """
    Unified semantic parser manager following AODS modular patterns.
    
    This class orchestrates the entire semantic analysis process using
    intelligent strategy selection, performance optimization, and
    integration with existing AODS shared infrastructure.
    
    Key Features:
    - Strategy pattern with multiple parsing approaches
    - Intelligent strategy selection based on code characteristics
    - Integration with AODS shared infrastructure
    - Comprehensive error handling and fallback mechanisms
    - Performance monitoring and optimization
    """
    
    def __init__(self, 
                 default_strategy: str = 'auto',
                 enable_caching: bool = True,
                 enable_optimization: bool = True,
                 max_file_size_mb: int = 100,
                 timeout_seconds: int = 300):
        """
        Initialize the unified semantic parser manager.
        
        Args:
            default_strategy: Default parsing strategy ('auto' for intelligent selection)
            enable_caching: Whether to enable intelligent caching
            enable_optimization: Whether to enable performance optimization
            max_file_size_mb: Maximum file size to process (MB)
            timeout_seconds: Timeout for parsing operations
        """
        self.default_strategy = default_strategy
        self.max_file_size_mb = max_file_size_mb
        self.timeout_seconds = timeout_seconds
        
        # Initialize parsing strategies
        self.strategies: Dict[str, ParsingStrategy] = {
            'comprehensive': ComprehensiveParsingStrategy(),
            'performance_optimized': PerformanceParsingStrategy(),
            'fallback': FallbackParsingStrategy(),
            'large_file': LargeFileParsingStrategy()
        }
        
        # Initialize shared infrastructure components
        self.cache_manager = SemanticCacheManager() if enable_caching else None
        self.performance_optimizer = SemanticPerformanceOptimizer() if enable_optimization else None
        self.error_handler = SemanticErrorHandler()
        
        # Integration with existing AODS infrastructure
        self.aods_integration = AODS_INTEGRATION_AVAILABLE
        if self.aods_integration:
            self.performance_monitor = PerformanceMonitor()
            self.file_handler = UniversalFileHandler()
            logger.info("AODS infrastructure integration enabled")
        else:
            logger.warning("AODS infrastructure not available, using standalone mode")
        
        # Statistics tracking
        self.total_files_processed = 0
        self.total_processing_time = 0.0
        self.strategy_usage_stats = {strategy: 0 for strategy in self.strategies.keys()}
        
        logger.info(f"UnifiedSemanticParserManager initialized with {len(self.strategies)} strategies")
    
    def parse_code(self, 
                   source_code: str, 
                   language: Union[str, LanguageType],
                   file_path: Optional[str] = None,
                   strategy: Optional[str] = None,
                   context: Optional[ParsingContext] = None) -> SemanticParsingResult:
        """
        Parse source code using intelligent strategy selection.
        
        Args:
            source_code: Source code to analyze
            language: Programming language
            file_path: Optional file path for context
            strategy: Optional specific strategy to use
            context: Optional parsing context
            
        Returns:
            Semantic parsing result with analysis findings
        """
        start_time = time.time()
        
        try:
            # Validate inputs
            if not source_code or not source_code.strip():
                return self._create_error_result("Empty source code provided", start_time)
            
            # Prepare language info
            if isinstance(language, str):
                try:
                    language = LanguageType(language.lower())
                except ValueError:
                    language = LanguageType.UNKNOWN
            
            # Create or use provided context
            if context is None:
                context = self._create_default_context(source_code, language, file_path)
            
            # Check cache if available
            if self.cache_manager:
                cached_result = self.cache_manager.get_cached_result(source_code, language)
                if cached_result:
                    logger.debug("Retrieved result from cache")
                    return cached_result
            
            # Select optimal parsing strategy
            selected_strategy = strategy or self._select_optimal_strategy(source_code, language, context)
            
            # Validate strategy
            if selected_strategy not in self.strategies:
                logger.warning(f"Unknown strategy '{selected_strategy}', falling back to 'fallback'")
                selected_strategy = 'fallback'
            
            # Update strategy usage statistics
            self.strategy_usage_stats[selected_strategy] += 1
            
            # Perform parsing with selected strategy
            logger.debug(f"Parsing with strategy: {selected_strategy}")
            result = self._parse_with_strategy(source_code, language, context, selected_strategy)
            
            # Cache result if successful and caching is enabled
            if result.success and self.cache_manager:
                self.cache_manager.cache_result(source_code, language, result)
            
            # Update statistics
            self._update_statistics(start_time, result)
            
            return result
            
        except Exception as e:
            logger.error(f"Parsing failed with error: {e}")
            return self._handle_parsing_error(e, source_code, language, start_time)
    
    def parse_file(self, 
                   file_path: Union[str, Path],
                   language: Optional[Union[str, LanguageType]] = None,
                   strategy: Optional[str] = None) -> SemanticParsingResult:
        """
        Parse a source code file.
        
        Args:
            file_path: Path to the source file
            language: Programming language (auto-detected if not provided)
            strategy: Optional specific strategy to use
            
        Returns:
            Semantic parsing result with analysis findings
        """
        start_time = time.time()
        file_path = Path(file_path)
        
        try:
            # Validate file
            if not file_path.exists():
                return self._create_error_result(f"File not found: {file_path}", start_time)
            
            # Check file size
            file_size_mb = file_path.stat().st_size / (1024 * 1024)
            if file_size_mb > self.max_file_size_mb:
                logger.warning(f"Large file detected: {file_size_mb:.1f}MB")
                strategy = strategy or 'large_file'
            
            # Read file content
            if self.aods_integration and self.file_handler:
                source_code = self.file_handler.read_file_safe(str(file_path))
            else:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    source_code = f.read()
            
            # Auto-detect language if not provided
            if language is None:
                language = self._detect_language(file_path, source_code)
            
            # Parse the code
            return self.parse_code(
                source_code=source_code,
                language=language,
                file_path=str(file_path),
                strategy=strategy
            )
            
        except Exception as e:
            logger.error(f"File parsing failed for {file_path}: {e}")
            return self._handle_parsing_error(e, "", LanguageType.UNKNOWN, start_time)
    
    def _select_optimal_strategy(self, 
                                source_code: str, 
                                language: LanguageType, 
                                context: ParsingContext) -> str:
        """
        Intelligently select the optimal parsing strategy based on code characteristics.
        
        Args:
            source_code: Source code to analyze
            language: Programming language
            context: Parsing context
            
        Returns:
            Selected strategy name
        """
        if self.default_strategy != 'auto':
            return self.default_strategy
        
        # Analyze code characteristics
        code_length = len(source_code)
        line_count = source_code.count('\n')
        
        # Strategy selection logic
        if code_length > 1_000_000 or line_count > 10_000:  # Large files
            return 'large_file'
        elif context.optimization_level == 'fast':  # Performance-focused
            return 'performance_optimized'
        elif context.optimization_level == 'comprehensive':  # Accuracy-focused
            return 'comprehensive'
        elif language == LanguageType.SMALI:  # Complex bytecode
            return 'comprehensive'
        elif language == LanguageType.JAVASCRIPT:  # Dynamic language
            return 'performance_optimized'
        else:  # Default balanced approach
            return 'comprehensive'
    
    def _parse_with_strategy(self, 
                           source_code: str, 
                           language: LanguageType, 
                           context: ParsingContext, 
                           strategy_name: str) -> SemanticParsingResult:
        """
        Parse code using the specified strategy with error handling.
        
        Args:
            source_code: Source code to parse
            language: Programming language
            context: Parsing context
            strategy_name: Strategy to use
            
        Returns:
            Parsing result
        """
        strategy = self.strategies[strategy_name]
        
        try:
            # Apply performance optimization if available
            if self.performance_optimizer:
                self.performance_optimizer.prepare_for_parsing(source_code, language)
            
            # Perform parsing
            result = strategy.parse(source_code, language, context)
            
            # Post-process result
            if result.success:
                result = self._post_process_result(result, strategy_name)
            
            return result
            
        except Exception as e:
            logger.warning(f"Strategy '{strategy_name}' failed: {e}")
            
            # Try fallback strategy if not already using it
            if strategy_name != 'fallback':
                logger.info("Attempting fallback strategy")
                return self._parse_with_strategy(source_code, language, context, 'fallback')
            else:
                # Fallback strategy failed, create error result
                return self._create_error_result(f"All parsing strategies failed: {e}", time.time())
    
    def _post_process_result(self, 
                           result: SemanticParsingResult, 
                           strategy_name: str) -> SemanticParsingResult:
        """
        Post-process parsing results to enhance analysis.
        
        Args:
            result: Raw parsing result
            strategy_name: Strategy that was used
            
        Returns:
            Enhanced parsing result
        """
        # Add strategy metadata
        result.metadata['strategy_used'] = strategy_name
        result.metadata['parser_version'] = "1.0.0"
        
        # Enhance vulnerability analysis if needed
        if result.vulnerabilities:
            result = self._enhance_vulnerabilities(result)
        
        # Calculate confidence scores
        result = self._calculate_confidence_scores(result)
        
        return result
    
    def _enhance_vulnerabilities(self, result: SemanticParsingResult) -> SemanticParsingResult:
        """
        Enhance vulnerability patterns with additional analysis.
        
        Args:
            result: Parsing result with vulnerabilities
            
        Returns:
            Enhanced parsing result
        """
        # Implementation would enhance vulnerability patterns
        # with additional context, confidence scores, etc.
        for vuln in result.vulnerabilities:
            if not vuln.confidence:
                vuln.confidence = 0.8  # Default confidence
        
        return result
    
    def _calculate_confidence_scores(self, result: SemanticParsingResult) -> SemanticParsingResult:
        """
        Calculate confidence scores for parsing results.
        
        Args:
            result: Parsing result
            
        Returns:
            Result with updated confidence scores
        """
        if result.vulnerabilities:
            total_confidence = sum(v.confidence for v in result.vulnerabilities)
            result.statistics.confidence_average = total_confidence / len(result.vulnerabilities)
        
        return result
    
    def _create_default_context(self, 
                               source_code: str, 
                               language: LanguageType, 
                               file_path: Optional[str]) -> ParsingContext:
        """Create a default parsing context."""
        language_info = LanguageInfo(language=language)
        
        return ParsingContext(
            file_path=file_path or "<string>",
            language_info=language_info,
            timeout_seconds=self.timeout_seconds,
            use_shared_infrastructure=self.aods_integration
        )
    
    def _detect_language(self, file_path: Path, source_code: str) -> LanguageType:
        """
        Detect programming language from file extension and content.
        
        Args:
            file_path: Path to the file
            source_code: Source code content
            
        Returns:
            Detected language type
        """
        extension = file_path.suffix.lower()
        
        extension_map = {
            '.java': LanguageType.JAVA,
            '.kt': LanguageType.KOTLIN,
            '.js': LanguageType.JAVASCRIPT,
            '.smali': LanguageType.SMALI,
            '.xml': LanguageType.XML
        }
        
        return extension_map.get(extension, LanguageType.UNKNOWN)
    
    def _create_error_result(self, error_message: str, start_time: float) -> SemanticParsingResult:
        """Create an error result for failed parsing."""
        end_time = time.time()
        
        statistics = ParsingStatistics(
            start_time=start_time,
            end_time=end_time,
            errors=[error_message]
        )
        
        context = ParsingContext(
            file_path="<error>",
            language_info=LanguageInfo(language=LanguageType.UNKNOWN)
        )
        
        return SemanticParsingResult(
            success=False,
            context=context,
            statistics=statistics,
            error_message=error_message
        )
    
    def _handle_parsing_error(self, 
                            error: Exception, 
                            source_code: str, 
                            language: LanguageType, 
                            start_time: float) -> SemanticParsingResult:
        """Handle parsing errors with comprehensive error reporting."""
        error_message = self.error_handler.format_error(error, source_code, language)
        return self._create_error_result(error_message, start_time)
    
    def _update_statistics(self, start_time: float, result: SemanticParsingResult):
        """Update global statistics tracking."""
        self.total_files_processed += 1
        self.total_processing_time += time.time() - start_time
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get comprehensive statistics about parsing operations.
        
        Returns:
            Dictionary containing parsing statistics
        """
        return {
            'total_files_processed': self.total_files_processed,
            'total_processing_time': self.total_processing_time,
            'average_processing_time': (
                self.total_processing_time / max(1, self.total_files_processed)
            ),
            'strategy_usage': self.strategy_usage_stats.copy(),
            'cache_enabled': self.cache_manager is not None,
            'optimization_enabled': self.performance_optimizer is not None,
            'aods_integration': self.aods_integration
        }
    
    def clear_cache(self):
        """Clear the parsing cache."""
        if self.cache_manager:
            self.cache_manager.clear_cache()
            logger.info("Parsing cache cleared")
    
    def __repr__(self) -> str:
        return (f"UnifiedSemanticParserManager("
                f"strategies={len(self.strategies)}, "
                f"processed={self.total_files_processed}, "
                f"integration={self.aods_integration})") 
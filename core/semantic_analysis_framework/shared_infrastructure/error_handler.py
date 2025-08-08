"""
Semantic Error Handler for AODS

This module provides comprehensive error handling and recovery mechanisms
for the semantic analysis framework, following AODS error handling patterns.
"""

import logging
import traceback
from typing import Optional, Dict, Any, List
from ..data_structures import LanguageType

logger = logging.getLogger(__name__)


class SemanticErrorHandler:
    """
    Comprehensive error handler for semantic analysis operations.
    
    This class provides standardized error handling, logging, and recovery
    mechanisms for the semantic analysis framework.
    """
    
    def __init__(self):
        """Initialize the semantic error handler."""
        self.error_counts = {
            'parsing_errors': 0,
            'language_errors': 0,
            'memory_errors': 0,
            'timeout_errors': 0,
            'unknown_errors': 0
        }
        
        self.error_history: List[Dict[str, Any]] = []
        self.max_history_size = 100
    
    def format_error(self, 
                    error: Exception, 
                    source_code: str, 
                    language: LanguageType,
                    context: Optional[Dict[str, Any]] = None) -> str:
        """
        Format an error with comprehensive context information.
        
        Args:
            error: The exception that occurred
            source_code: Source code being processed when error occurred
            language: Programming language
            context: Optional additional context
            
        Returns:
            Formatted error message with context
        """
        error_type = type(error).__name__
        error_message = str(error)
        
        # Categorize error
        category = self._categorize_error(error)
        self.error_counts[category] += 1
        
        # Build comprehensive error message
        formatted_message = f"[{error_type}] {error_message}"
        
        # Add context information
        if context:
            formatted_message += f" | Context: {context}"
        
        # Add source code snippet if available
        if source_code and len(source_code) < 200:
            formatted_message += f" | Source: {source_code[:100]}..."
        elif source_code:
            formatted_message += f" | Source size: {len(source_code)} characters"
        
        # Add language information
        formatted_message += f" | Language: {language.value}"
        
        # Log the error
        logger.error(formatted_message)
        
        # Store in error history
        self._store_error_history(error, source_code, language, context, category)
        
        return formatted_message
    
    def _categorize_error(self, error: Exception) -> str:
        """Categorize an error by type."""
        error_type = type(error).__name__
        
        if 'parse' in error_type.lower() or 'syntax' in error_type.lower():
            return 'parsing_errors'
        elif 'memory' in error_type.lower():
            return 'memory_errors'
        elif 'timeout' in error_type.lower():
            return 'timeout_errors'
        elif 'language' in str(error).lower():
            return 'language_errors'
        else:
            return 'unknown_errors'
    
    def _store_error_history(self, 
                           error: Exception, 
                           source_code: str, 
                           language: LanguageType,
                           context: Optional[Dict[str, Any]],
                           category: str):
        """Store error in history for analysis."""
        error_record = {
            'error_type': type(error).__name__,
            'error_message': str(error),
            'language': language.value,
            'source_size': len(source_code),
            'context': context,
            'category': category,
            'traceback': traceback.format_exc(),
            'timestamp': logging.Formatter().formatTime(logging.LogRecord(
                name='', level=0, pathname='', lineno=0, msg='', args=(), exc_info=None
            ))
        }
        
        self.error_history.append(error_record)
        
        # Maintain history size limit
        if len(self.error_history) > self.max_history_size:
            self.error_history.pop(0)
    
    def get_error_statistics(self) -> Dict[str, Any]:
        """Get comprehensive error statistics."""
        total_errors = sum(self.error_counts.values())
        
        return {
            'total_errors': total_errors,
            'error_counts': self.error_counts.copy(),
            'error_rates': {
                category: count / max(1, total_errors)
                for category, count in self.error_counts.items()
            },
            'recent_errors': len(self.error_history),
            'most_common_error': max(self.error_counts.items(), key=lambda x: x[1])[0] if total_errors > 0 else None
        }
    
    def get_recent_errors(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent errors for analysis."""
        return self.error_history[-limit:] if self.error_history else []
    
    def clear_error_history(self):
        """Clear error history and reset counters."""
        self.error_history.clear()
        self.error_counts = {key: 0 for key in self.error_counts} 
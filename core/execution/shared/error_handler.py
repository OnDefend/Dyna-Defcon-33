#!/usr/bin/env python3
"""
Error Handler

Unified error handling for all execution strategies.
"""

import logging
import traceback
from typing import Any, Dict, Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)

@dataclass
class ErrorContext:
    """Context information for an error."""
    operation: str
    plugin_name: Optional[str] = None
    error_type: str = ""
    error_message: str = ""
    traceback: str = ""

class ErrorHandler:
    """Unified error handling for execution strategies."""
    
    def __init__(self):
        """Initialize error handler."""
        self.logger = logging.getLogger(__name__)
        self.error_count = 0
        self.error_history = []
        
        self.logger.info("Error handler initialized")
    
    def handle_error(self, error: Exception, context: ErrorContext) -> Dict[str, Any]:
        """Handle an error and return formatted error information."""
        self.error_count += 1
        
        error_info = {
            'operation': context.operation,
            'plugin_name': context.plugin_name,
            'error_type': type(error).__name__,
            'error_message': str(error),
            'traceback': traceback.format_exc()
        }
        
        self.error_history.append(error_info)
        
        # Log the error
        if context.plugin_name:
            self.logger.error(f"Error in {context.operation} for plugin {context.plugin_name}: {error}")
        else:
            self.logger.error(f"Error in {context.operation}: {error}")
        
        return error_info
    
    def get_error_statistics(self) -> Dict[str, Any]:
        """Get error statistics."""
        return {
            'total_errors': self.error_count,
            'recent_errors': len(self.error_history[-10:]),
            'error_types': {}
        }

def create_error_handler() -> ErrorHandler:
    """Factory function to create error handler."""
    return ErrorHandler() 
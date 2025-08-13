#!/usr/bin/env python3
"""
Edge Case Integration Patterns for AODS Security Analyzers

This module provides integration patterns and utilities for existing security analyzers
to seamlessly integrate with the comprehensive edge case management system.

Key Features:
- Drop-in integration for existing analyzers
- Standardized error handling patterns
- Automatic recovery mechanisms
- Performance optimization
- User notification integration

"""

import functools
import logging
import time
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

from core.edge_case_management_system import (
    EdgeCaseManager,
    EdgeCaseType,
    EdgeCaseSeverity,
    InputValidator,
    ResourceManager,
    edge_case_handler,
    with_timeout,
    resource_monitoring,
    get_edge_case_manager
)

# Import base security analyzer
try:
    from core.base_security_analyzer import BaseSecurityAnalyzer
    BASE_ANALYZER_AVAILABLE = True
except ImportError:
    BASE_ANALYZER_AVAILABLE = False

class EdgeCaseIntegratedAnalyzer(ABC):
    """
    Base class for security analyzers with integrated edge case management.
    
    This class provides standardized edge case handling for all security analyzers
    in the AODS framework, ensuring consistent error handling and user experience.
    """
    
    def __init__(self, *args, **kwargs):
        """Initialize with edge case management integration."""
        super().__init__(*args, **kwargs)
        self.edge_case_manager = get_edge_case_manager()
        self.input_validator = InputValidator()
        self.resource_manager = ResourceManager()
        self.logger = logging.getLogger(self.__class__.__name__)
        
        # Register cleanup handler for this analyzer
        self.resource_manager.register_cleanup_handler(self._cleanup_resources)
        
        # Analysis state tracking
        self.analysis_state = {
            'started': False,
            'completed': False,
            'failed': False,
            'error_count': 0,
            'warnings_count': 0,
            'files_processed': 0,
            'files_failed': 0
        }
    
    def _cleanup_resources(self):
        """Clean up analyzer-specific resources."""
        try:
            # Clear any cached data
            if hasattr(self, 'findings'):
                self.findings.clear()
            
            # Reset analysis state
            self.analysis_state.update({
                'started': False,
                'completed': False,
                'failed': False
            })
            
            self.logger.debug(f"Resources cleaned up for {self.__class__.__name__}")
        except Exception as e:
            self.logger.error(f"Error during resource cleanup: {e}")
    
    def safe_file_read(self, file_path: Union[str, Path]) -> Tuple[Optional[str], bool]:
        """
        Safely read file content with comprehensive edge case handling.
        
        Args:
            file_path: Path to file to read
            
        Returns:
            Tuple of (content, success_flag)
        """
        try:
            # Validate file path first
            is_valid, validation_message = self.input_validator.validate_file_path(file_path)
            if not is_valid:
                self.edge_case_manager.handle_edge_case(
                    EdgeCaseType.INVALID_INPUT,
                    context={
                        'file_path': str(file_path),
                        'validation_error': validation_message,
                        'operation_type': 'file_read'
                    }
                )
                return None, False
            
            # Attempt to read file
            path_obj = Path(file_path)
            
            # Check file size before reading
            file_size = path_obj.stat().st_size
            if file_size > 50 * 1024 * 1024:  # 50MB limit
                self.edge_case_manager.handle_edge_case(
                    EdgeCaseType.RESOURCE_EXHAUSTED,
                    context={
                        'file_path': str(file_path),
                        'file_size': file_size,
                        'operation_type': 'file_read'
                    }
                )
                return None, False
            
            # Try multiple encodings
            encodings = ['utf-8', 'utf-16', 'latin-1', 'cp1252']
            
            for encoding in encodings:
                try:
                    with open(path_obj, 'r', encoding=encoding, errors='replace') as f:
                        content = f.read()
                    
                    # Success
                    self.analysis_state['files_processed'] += 1
                    return content, True
                    
                except UnicodeDecodeError:
                    continue
                except Exception as e:
                    self.logger.debug(f"Error reading with {encoding}: {e}")
                    continue
            
            # All encodings failed
            self.edge_case_manager.handle_edge_case(
                EdgeCaseType.PARSING_ERROR,
                context={
                    'file_path': str(file_path),
                    'attempted_encodings': encodings,
                    'operation_type': 'file_read'
                }
            )
            self.analysis_state['files_failed'] += 1
            return None, False
            
        except FileNotFoundError as e:
            self.edge_case_manager.handle_edge_case(
                EdgeCaseType.FILE_NOT_FOUND,
                error=e,
                context={
                    'file_path': str(file_path),
                    'operation_type': 'file_read'
                }
            )
            self.analysis_state['files_failed'] += 1
            return None, False
            
        except PermissionError as e:
            self.edge_case_manager.handle_edge_case(
                EdgeCaseType.PERMISSION_DENIED,
                error=e,
                context={
                    'file_path': str(file_path),
                    'operation_type': 'file_read'
                }
            )
            self.analysis_state['files_failed'] += 1
            return None, False
            
        except Exception as e:
            self.edge_case_manager.handle_edge_case(
                EdgeCaseType.UNKNOWN_ERROR,
                error=e,
                context={
                    'file_path': str(file_path),
                    'operation_type': 'file_read'
                }
            )
            self.analysis_state['files_failed'] += 1
            return None, False
    
    def safe_command_execution(self, command: List[str], timeout: int = 30) -> Tuple[bool, str, str]:
        """
        Safely execute command with edge case handling.
        
        Args:
            command: Command to execute as list
            timeout: Timeout in seconds
            
        Returns:
            Tuple of (success, stdout, stderr)
        """
        try:
            import subprocess
            
            # Validate command
            if not command or not isinstance(command, list):
                self.edge_case_manager.handle_edge_case(
                    EdgeCaseType.INVALID_INPUT,
                    context={
                        'command': str(command),
                        'operation_type': 'command_execution'
                    }
                )
                return False, "", "Invalid command format"
            
            # Execute with timeout
            try:
                result = subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    check=False
                )
                
                return True, result.stdout, result.stderr
                
            except subprocess.TimeoutExpired as e:
                self.edge_case_manager.handle_edge_case(
                    EdgeCaseType.TIMEOUT_EXCEEDED,
                    error=e,
                    context={
                        'command': ' '.join(command),
                        'timeout': timeout,
                        'operation_type': 'command_execution'
                    }
                )
                return False, "", f"Command timed out after {timeout} seconds"
                
            except subprocess.CalledProcessError as e:
                # Command failed but this might be expected
                return False, e.stdout if e.stdout else "", e.stderr if e.stderr else str(e)
                
        except Exception as e:
            self.edge_case_manager.handle_edge_case(
                EdgeCaseType.UNKNOWN_ERROR,
                error=e,
                context={
                    'command': ' '.join(command),
                    'operation_type': 'command_execution'
                }
            )
            return False, "", str(e)
    
    def safe_network_operation(self, operation: Callable, *args, **kwargs) -> Tuple[bool, Any]:
        """
        Safely perform network operation with edge case handling.
        
        Args:
            operation: Network operation function
            *args: Arguments for operation
            **kwargs: Keyword arguments for operation
            
        Returns:
            Tuple of (success, result)
        """
        try:
            # Check network availability
            import socket
            
            try:
                socket.create_connection(("8.8.8.8", 53), timeout=3)
                network_available = True
            except (socket.timeout, socket.error):
                network_available = False
            
            if not network_available:
                self.edge_case_manager.handle_edge_case(
                    EdgeCaseType.NETWORK_UNAVAILABLE,
                    context={
                        'operation': operation.__name__,
                        'operation_type': 'network_operation'
                    }
                )
                return False, None
            
            # Perform operation
            result = operation(*args, **kwargs)
            return True, result
            
        except Exception as e:
            self.edge_case_manager.handle_edge_case(
                EdgeCaseType.NETWORK_UNAVAILABLE,
                error=e,
                context={
                    'operation': operation.__name__,
                    'operation_type': 'network_operation'
                }
            )
            return False, None
    
    def safe_analysis_with_fallback(self, primary_analysis: Callable, 
                                  fallback_analysis: Callable = None,
                                  *args, **kwargs) -> Any:
        """
        Perform analysis with fallback mechanism.
        
        Args:
            primary_analysis: Primary analysis function
            fallback_analysis: Fallback analysis function
            *args: Arguments for analysis
            **kwargs: Keyword arguments for analysis
            
        Returns:
            Analysis result
        """
        try:
            # Try primary analysis
            return primary_analysis(*args, **kwargs)
            
        except Exception as e:
            self.logger.warning(f"Primary analysis failed: {e}")
            self.analysis_state['error_count'] += 1
            
            # Try fallback analysis if available
            if fallback_analysis:
                try:
                    self.logger.info("Attempting fallback analysis...")
                    return fallback_analysis(*args, **kwargs)
                except Exception as fallback_error:
                    self.logger.error(f"Fallback analysis also failed: {fallback_error}")
                    self.analysis_state['error_count'] += 1
            
            # Handle edge case
            self.edge_case_manager.handle_edge_case(
                EdgeCaseType.UNKNOWN_ERROR,
                error=e,
                context={
                    'primary_analysis': primary_analysis.__name__,
                    'fallback_available': fallback_analysis is not None,
                    'operation_type': 'analysis_with_fallback'
                }
            )
            
            # Return empty result or raise depending on analyzer needs
            return None
    
    def validate_analysis_input(self, **kwargs) -> bool:
        """
        Validate analysis input parameters.
        
        Args:
            **kwargs: Analysis parameters to validate
            
        Returns:
            True if valid, False otherwise
        """
        try:
            is_valid, validation_message = self.input_validator.validate_analysis_parameters(kwargs)
            if not is_valid:
                self.edge_case_manager.handle_edge_case(
                    EdgeCaseType.INVALID_INPUT,
                    context={
                        'validation_error': validation_message,
                        'parameters': str(kwargs)[:500],  # Truncate for logging
                        'operation_type': 'input_validation'
                    }
                )
                return False
            
            return True
            
        except Exception as e:
            self.edge_case_manager.handle_edge_case(
                EdgeCaseType.UNKNOWN_ERROR,
                error=e,
                context={
                    'operation_type': 'input_validation'
                }
            )
            return False
    
    def get_analysis_summary(self) -> Dict[str, Any]:
        """
        Get summary of analysis with edge case information.
        
        Returns:
            Dictionary containing analysis summary
        """
        edge_case_metrics = self.edge_case_manager.get_metrics()
        
        return {
            'analysis_state': self.analysis_state.copy(),
            'edge_cases': {
                'total_handled': edge_case_metrics.total_cases,
                'by_type': {k.value: v for k, v in edge_case_metrics.by_type.items()},
                'by_severity': {k.value: v for k, v in edge_case_metrics.by_severity.items()},
                'recovery_success_rate': (
                    edge_case_metrics.recovery_successes / edge_case_metrics.recovery_attempts
                    if edge_case_metrics.recovery_attempts > 0 else 0.0
                ),
                'user_notifications': edge_case_metrics.user_notifications,
                'performance_impact_ms': edge_case_metrics.performance_impact
            },
            'resource_usage': self.resource_manager.check_resource_availability()
        }

def integrate_edge_case_handling(analyzer_class: type) -> type:
    """
    Class decorator to integrate edge case handling into existing analyzers.
    
    Args:
        analyzer_class: Analyzer class to integrate
        
    Returns:
        Enhanced analyzer class with edge case handling
    """
    
    class EdgeCaseIntegratedClass(analyzer_class):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.edge_case_manager = get_edge_case_manager()
            self.input_validator = InputValidator()
            self.resource_manager = ResourceManager()
            
            # Wrap existing methods with edge case handling
            self._wrap_methods_with_edge_case_handling()
        
        def _wrap_methods_with_edge_case_handling(self):
            """Wrap existing methods with edge case handling."""
            # Common methods to wrap
            methods_to_wrap = [
                'analyze', 'analyze_file', 'analyze_content', 'run_analysis',
                'process_file', 'extract_data', 'parse_file'
            ]
            
            for method_name in methods_to_wrap:
                if hasattr(self, method_name):
                    original_method = getattr(self, method_name)
                    wrapped_method = self._wrap_with_edge_case_handling(original_method)
                    setattr(self, method_name, wrapped_method)
        
        def _wrap_with_edge_case_handling(self, method: Callable) -> Callable:
            """Wrap a method with edge case handling."""
            @functools.wraps(method)
            def wrapper(*args, **kwargs):
                try:
                    # Check resources before analysis
                    resources = self.resource_manager.check_resource_availability()
                    if (resources.get('memory', {}).get('critical', False) or
                        resources.get('disk', {}).get('critical', False)):
                        self.edge_case_manager.handle_edge_case(
                            EdgeCaseType.RESOURCE_EXHAUSTED,
                            context={
                                'method': method.__name__,
                                'resource_status': resources,
                                'operation_type': 'analysis_method'
                            }
                        )
                    
                    # Perform analysis
                    with resource_monitoring():
                        result = method(*args, **kwargs)
                    
                    return result
                    
                except Exception as e:
                    # Handle edge case
                    self.edge_case_manager.handle_edge_case(
                        EdgeCaseType.UNKNOWN_ERROR,
                        error=e,
                        context={
                            'method': method.__name__,
                            'args': str(args)[:200],
                            'kwargs': str(kwargs)[:200],
                            'operation_type': 'analysis_method'
                        }
                    )
                    
                    # Return appropriate fallback result
                    if hasattr(self, 'findings'):
                        return self.findings  # Return current findings
                    else:
                        return []  # Return empty list as fallback
            
            return wrapper
    
    return EdgeCaseIntegratedClass

def create_resilient_analyzer(base_class: type, timeout: int = 300) -> type:
    """
    Create a resilient analyzer class with comprehensive edge case handling.
    
    Args:
        base_class: Base analyzer class
        timeout: Default timeout for analysis operations
        
    Returns:
        Resilient analyzer class
    """
    
    class ResilientAnalyzer(base_class):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.edge_case_manager = get_edge_case_manager()
            self.input_validator = InputValidator()
            self.resource_manager = ResourceManager()
            self.analysis_timeout = timeout
            
            # Enhanced logging
            self.logger = logging.getLogger(f"{self.__class__.__name__}.Resilient")
            
            # Performance tracking
            self.performance_metrics = {
                'total_analysis_time': 0.0,
                'files_processed': 0,
                'errors_recovered': 0,
                'fallbacks_used': 0
            }
        
        @with_timeout(timeout)
        def analyze_with_resilience(self, *args, **kwargs):
            """
            Perform analysis with comprehensive resilience features.
            
            Args:
                *args: Analysis arguments
                **kwargs: Analysis keyword arguments
                
            Returns:
                Analysis results with resilience handling
            """
            start_time = time.time()
            
            try:
                # Validate input
                if not self._validate_input(*args, **kwargs):
                    return self._create_fallback_result("Input validation failed")
                
                # Check resources
                if not self._check_resources():
                    return self._create_fallback_result("Insufficient resources")
                
                # Perform analysis with resource monitoring
                with resource_monitoring():
                    if hasattr(super(), 'analyze'):
                        result = super().analyze(*args, **kwargs)
                    else:
                        result = self._perform_fallback_analysis(*args, **kwargs)
                
                # Update performance metrics
                self.performance_metrics['total_analysis_time'] += time.time() - start_time
                self.performance_metrics['files_processed'] += 1
                
                return result
                
            except Exception as e:
                # Handle edge case and provide fallback
                self.edge_case_manager.handle_edge_case(
                    EdgeCaseType.UNKNOWN_ERROR,
                    error=e,
                    context={
                        'analyzer': self.__class__.__name__,
                        'operation_type': 'resilient_analysis'
                    }
                )
                
                self.performance_metrics['errors_recovered'] += 1
                return self._create_fallback_result(f"Analysis failed: {str(e)}")
        
        def _validate_input(self, *args, **kwargs) -> bool:
            """Validate input parameters."""
            try:
                # Basic validation
                if not args and not kwargs:
                    return False
                
                # Validate APK path if provided
                if 'apk_path' in kwargs:
                    is_valid, _ = self.input_validator.validate_apk_file(kwargs['apk_path'])
                    return is_valid
                
                return True
                
            except Exception:
                return False
        
        def _check_resources(self) -> bool:
            """Check if sufficient resources are available."""
            try:
                resources = self.resource_manager.check_resource_availability()
                
                # Check for critical resource issues
                if resources.get('memory', {}).get('critical', False):
                    return False
                
                if resources.get('disk', {}).get('critical', False):
                    return False
                
                return True
                
            except Exception:
                return True  # Assume resources are available if check fails
        
        def _perform_fallback_analysis(self, *args, **kwargs):
            """Perform fallback analysis when primary method is unavailable."""
            self.performance_metrics['fallbacks_used'] += 1
            
            # Basic fallback analysis
            return {
                'findings': [],
                'status': 'completed_with_fallback',
                'message': 'Primary analysis method unavailable, used fallback'
            }
        
        def _create_fallback_result(self, reason: str):
            """Create fallback result when analysis fails."""
            return {
                'findings': [],
                'status': 'failed',
                'message': reason,
                'fallback_used': True
            }
        
        def get_resilience_metrics(self) -> Dict[str, Any]:
            """Get resilience metrics."""
            return {
                'performance_metrics': self.performance_metrics.copy(),
                'edge_case_summary': self.edge_case_manager.get_metrics().__dict__,
                'resource_status': self.resource_manager.check_resource_availability()
            }
    
    return ResilientAnalyzer

# Utility functions for easy integration
def make_resilient(func: Callable, timeout: int = 300) -> Callable:
    """
    Make a function resilient with edge case handling.
    
    Args:
        func: Function to make resilient
        timeout: Timeout for function execution
        
    Returns:
        Resilient function
    """
    edge_case_manager = get_edge_case_manager()
    
    @functools.wraps(func)
    @with_timeout(timeout)
    def resilient_wrapper(*args, **kwargs):
        try:
            with resource_monitoring():
                return func(*args, **kwargs)
        except Exception as e:
            edge_case_manager.handle_edge_case(
                EdgeCaseType.UNKNOWN_ERROR,
                error=e,
                context={
                    'function': func.__name__,
                    'operation_type': 'resilient_function'
                }
            )
            # Return None or appropriate fallback
            return None
    
    return resilient_wrapper

def batch_process_with_resilience(items: List[Any], 
                                 processor: Callable,
                                 batch_size: int = 10,
                                 timeout_per_item: int = 30) -> List[Any]:
    """
    Process items in batches with resilience handling.
    
    Args:
        items: List of items to process
        processor: Function to process each item
        batch_size: Number of items per batch
        timeout_per_item: Timeout per item processing
        
    Returns:
        List of processed results
    """
    edge_case_manager = get_edge_case_manager()
    results = []
    
    # Process in batches
    for i in range(0, len(items), batch_size):
        batch = items[i:i + batch_size]
        
        try:
            with resource_monitoring():
                batch_results = []
                
                for item in batch:
                    try:
                        # Process with timeout
                        @with_timeout(timeout_per_item)
                        def process_item():
                            return processor(item)
                        
                        result = process_item()
                        batch_results.append(result)
                        
                    except Exception as e:
                        edge_case_manager.handle_edge_case(
                            EdgeCaseType.TIMEOUT_EXCEEDED if isinstance(e, TimeoutError) else EdgeCaseType.UNKNOWN_ERROR,
                            error=e,
                            context={
                                'item': str(item)[:100],
                                'batch_index': i // batch_size,
                                'operation_type': 'batch_processing'
                            }
                        )
                        batch_results.append(None)  # Placeholder for failed item
                
                results.extend(batch_results)
                
        except Exception as e:
            edge_case_manager.handle_edge_case(
                EdgeCaseType.RESOURCE_EXHAUSTED,
                error=e,
                context={
                    'batch_index': i // batch_size,
                    'batch_size': len(batch),
                    'operation_type': 'batch_processing'
                }
            )
            # Add placeholders for failed batch
            results.extend([None] * len(batch))
    
    return results

if __name__ == "__main__":
    # Example usage
    print("Edge Case Integration System - Example Usage")
    
    # Example of integrating an existing analyzer
    class ExampleAnalyzer:
        def __init__(self):
            self.findings = []
        
        def analyze(self, file_path):
            # Simulate analysis
            print(f"Analyzing {file_path}")
            return {"findings": self.findings}
    
    # Create resilient version
    ResilientExampleAnalyzer = create_resilient_analyzer(ExampleAnalyzer)
    
    # Test resilient analyzer
    analyzer = ResilientExampleAnalyzer()
    result = analyzer.analyze_with_resilience(file_path="test.apk")
    print(f"Analysis result: {result}")
    print(f"Resilience metrics: {analyzer.get_resilience_metrics()}") 
 
 
 
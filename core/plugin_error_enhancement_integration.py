#!/usr/bin/env python3
"""
Surgical Plugin Enhancement Integration

This module provides minimal-impact enhancement of existing plugins with
the enhanced error handling framework, following AODS project principles:
- No code duplication
- Surgical, precise modifications
- Maximum impact with minimal changes
- Compatibility with existing plugin manager
- Enhance rather than replace existing functionality
"""

import logging
import functools
import inspect
from typing import Any, Callable, Optional, Dict, List
from core.enhanced_error_handling_framework import EnhancedErrorHandler, global_error_tracker

class PluginEnhancementManager:
    """
    Manages surgical enhancement of existing plugins without code duplication.
    Integrates with existing plugin execution patterns.
    """
    
    def __init__(self):
        self.enhanced_plugins: Dict[str, EnhancedErrorHandler] = {}
        self.logger = logging.getLogger("aods.plugin_enhancement")
    
    def enhance_plugin_class(self, plugin_class: type, plugin_name: str = None) -> type:
        """
        Surgically enhance an existing plugin class with error handling.
        Preserves all existing functionality while adding framework benefits.
        """
        if plugin_name is None:
            plugin_name = getattr(plugin_class, 'plugin_name', plugin_class.__name__.lower())
        
        # Create error handler for this plugin
        error_handler = EnhancedErrorHandler(plugin_name)
        global_error_tracker.register_handler(error_handler)
        self.enhanced_plugins[plugin_name] = error_handler
        
        # Store original methods to avoid duplication
        original_init = plugin_class.__init__
        original_run = getattr(plugin_class, 'run', None)
        
        def enhanced_init(self, *args, **kwargs):
            """Enhanced initialization that adds error handler without duplication."""
            # Call original initialization
            original_init(self, *args, **kwargs)
            # Add error handler to instance
            self._error_handler = error_handler
            self.logger.debug(f"Enhanced error handling enabled for {plugin_name}")
        
        def enhanced_run(self, apk_ctx, *args, **kwargs):
            """Enhanced run method with comprehensive error handling."""
            if original_run is None:
                self.logger.error(f"Plugin {plugin_name} has no run method")
                return plugin_name, "Error: No run method found"
            
            # Use enhanced error context for execution
            with self._error_handler.error_context("plugin_execution", apk_ctx):
                return original_run(self, apk_ctx, *args, **kwargs)
        
        # Surgically modify the class
        plugin_class.__init__ = enhanced_init
        if original_run is not None:
            plugin_class.run = enhanced_run
        
        return plugin_class

    def create_method_enhancer(self, operation_name: str):
        """
        Create a decorator for enhancing specific plugin methods.
        Follows existing patterns without code duplication.
        """
        def enhancer(func: Callable) -> Callable:
            @functools.wraps(func)
            def wrapper(self, *args, **kwargs):
                # Get error handler from instance (added by enhance_plugin_class)
                error_handler = getattr(self, '_error_handler', None)
                if error_handler is None:
                    # Fallback to original function if no enhancement
                    return func(self, *args, **kwargs)
                
                # Extract apk_ctx for context
                apk_ctx = None
                if args and hasattr(args[0], 'apk_path'):
                    apk_ctx = args[0]
                
                # Execute with enhanced error handling
                with error_handler.error_context(operation_name, apk_ctx):
                    return func(self, *args, **kwargs)
            
            return wrapper
        return enhancer

# Global enhancement manager instance
plugin_enhancement_manager = PluginEnhancementManager()

# Convenience decorators for common operations
enhance_analysis = plugin_enhancement_manager.create_method_enhancer("analysis")
enhance_parsing = plugin_enhancement_manager.create_method_enhancer("parsing") 
enhance_compilation = plugin_enhancement_manager.create_method_enhancer("compilation")
enhance_external_tool = plugin_enhancement_manager.create_method_enhancer("external_tool")

def surgical_plugin_enhancement(plugin_name: str = None):
    """
    Class decorator for minimal-impact plugin enhancement.
    Preserves existing functionality while adding error handling benefits.
    """
    def decorator(plugin_class: type) -> type:
        return plugin_enhancement_manager.enhance_plugin_class(plugin_class, plugin_name)
    return decorator

class CriticalPluginIdentifier:
    """
    Identifies plugins that would benefit most from enhanced error handling.
    Follows project principle of demonstrable improvements.
    """
    
    @staticmethod
    def analyze_plugin_priority(plugin_path: str) -> Dict[str, Any]:
        """Analyze plugin to determine enhancement priority."""
        try:
            with open(plugin_path, 'r') as f:
                content = f.read()
            
            # Count error handling patterns
            generic_exceptions = content.count('except Exception')
            specific_exceptions = len([line for line in content.split('\n') 
                                     if 'except ' in line and 'Exception' not in line])
            file_operations = content.count('open(') + content.count('with open')
            external_calls = content.count('subprocess.') + content.count('run(')
            
            # Calculate priority score
            priority_score = (generic_exceptions * 3 + 
                            file_operations * 2 + 
                            external_calls * 2 - 
                            specific_exceptions)
            
            return {
                'plugin_path': plugin_path,
                'priority_score': priority_score,
                'generic_exceptions': generic_exceptions,
                'file_operations': file_operations,
                'external_calls': external_calls,
                'enhancement_needed': priority_score > 5
            }
        except Exception as e:
            return {'plugin_path': plugin_path, 'error': str(e), 'priority_score': 0}
    
    @staticmethod
    def get_critical_plugins() -> List[str]:
        """Get list of plugins that need immediate enhancement."""
        import os
        import glob
        
        critical_plugins = []
        plugin_files = glob.glob('plugins/*/__init__.py')
        
        for plugin_file in plugin_files:
            analysis = CriticalPluginIdentifier.analyze_plugin_priority(plugin_file)
            if analysis.get('enhancement_needed', False):
                plugin_name = os.path.dirname(plugin_file).split('/')[-1]
                critical_plugins.append(plugin_name)
        
        return critical_plugins

def apply_surgical_enhancements():
    """
    Apply surgical enhancements to critical plugins without code duplication.
    Follows project methodology of surgical, demonstrable improvements.
    """
    logger = logging.getLogger("aods.surgical_enhancement")
    
    # Identify critical plugins first
    critical_plugins = CriticalPluginIdentifier.get_critical_plugins()
    logger.info(f"Identified {len(critical_plugins)} plugins for enhancement")
    
    enhancement_summary = {
        'total_candidates': len(critical_plugins),
        'enhanced_successfully': 0,
        'errors': []
    }
    
    for plugin_name in critical_plugins[:5]:  # Start with top 5 most critical
        try:
            # Dynamic import and enhancement
            plugin_module = __import__(f'plugins.{plugin_name}', fromlist=[''])
            
            # Look for plugin class or run function
            plugin_classes = [getattr(plugin_module, name) for name in dir(plugin_module) 
                            if (isinstance(getattr(plugin_module, name), type) and 
                                'plugin' in name.lower())]
            
            if plugin_classes:
                # Enhance the main plugin class
                enhanced_class = plugin_enhancement_manager.enhance_plugin_class(
                    plugin_classes[0], plugin_name
                )
                logger.info(f"✅ Enhanced plugin: {plugin_name}")
                enhancement_summary['enhanced_successfully'] += 1
            else:
                logger.debug(f"⏭️  No plugin class found in {plugin_name}")
                
        except Exception as e:
            error_msg = f"Failed to enhance {plugin_name}: {e}"
            enhancement_summary['errors'].append(error_msg)
            logger.warning(error_msg)
    
    return enhancement_summary

# Integration with existing plugin manager patterns
class PluginManagerIntegration:
    """
    Integration hooks for existing plugin manager without modifying core architecture.
    Follows principle of enhancing rather than replacing existing systems.
    """
    
    @staticmethod
    def wrap_plugin_execution(original_execute_func: Callable) -> Callable:
        """
        Wrap existing plugin execution with enhanced error handling.
        Preserves all existing behavior while adding framework benefits.
        """
        @functools.wraps(original_execute_func)
        def enhanced_execute(self, plugin, apk_ctx, *args, **kwargs):
            plugin_name = getattr(plugin, 'name', str(plugin))
            
            # Check if plugin has enhanced error handling
            if hasattr(plugin, '_error_handler'):
                # Plugin already enhanced, use original execution
                return original_execute_func(self, plugin, apk_ctx, *args, **kwargs)
            else:
                # Add basic enhancement for non-enhanced plugins
                error_handler = EnhancedErrorHandler(plugin_name)
                with error_handler.error_context("plugin_execution", apk_ctx):
                    return original_execute_func(self, plugin, apk_ctx, *args, **kwargs)
        
        return enhanced_execute 
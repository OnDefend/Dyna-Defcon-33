"""
Enhanced Plugin Manager with Robust Error Handling
Addresses timeout issues and initialization problems identified in Phase 1
"""

import time
import logging
import threading
import traceback
from typing import Dict, List, Optional, Any
from pathlib import Path
from contextlib import contextmanager

logger = logging.getLogger(__name__)

class PluginTimeoutError(Exception):
    """Custom exception for plugin timeouts."""
    pass

class EnhancedPluginManager:
    """Enhanced plugin manager with robust timeout and error handling."""
    
    def __init__(self, default_timeout: int = 120):
        self.default_timeout = default_timeout
        self.active_plugins = {}
        self.plugin_statistics = {}
        self.timeout_recoveries = 0
        
    @contextmanager
    def plugin_timeout(self, timeout_seconds: int = None):
        """Context manager for plugin execution with timeout."""
        timeout = timeout_seconds or self.default_timeout
        
        def timeout_handler():
            time.sleep(timeout)
            logger.warning(f"Plugin execution exceeded {timeout} seconds")
            raise PluginTimeoutError(f"Plugin timed out after {timeout} seconds")
        
        timer = threading.Timer(timeout, timeout_handler)
        timer.start()
        
        try:
            yield
        finally:
            timer.cancel()
    
    def execute_plugin_safely(self, plugin_name: str, plugin_function: callable, 
                             *args, timeout: int = None, **kwargs) -> Dict[str, Any]:
        """Execute a plugin with comprehensive error handling and timeout management."""
        
        start_time = time.time()
        execution_timeout = timeout or self.default_timeout
        
        logger.info(f"🔌 Executing plugin: {plugin_name} (timeout: {execution_timeout}s)")
        
        result = {
            "plugin_name": plugin_name,
            "status": "pending",
            "start_time": start_time,
            "execution_time": 0,
            "timeout_used": execution_timeout,
            "error": None,
            "findings": [],
            "metadata": {}
        }
        
        try:
            with self.plugin_timeout(execution_timeout):
                # Execute the plugin function
                plugin_result = plugin_function(*args, **kwargs)
                
                # Process the result
                if plugin_result:
                    if isinstance(plugin_result, dict):
                        result["findings"] = plugin_result.get("findings", [])
                        result["metadata"] = plugin_result.get("metadata", {})
                    elif isinstance(plugin_result, list):
                        result["findings"] = plugin_result
                    else:
                        result["findings"] = [plugin_result]
                
                result["status"] = "completed"
                execution_time = time.time() - start_time
                result["execution_time"] = execution_time
                
                logger.info(f"✅ Plugin {plugin_name} completed in {execution_time:.2f}s")
                
        except PluginTimeoutError as e:
            result["status"] = "timeout"
            result["error"] = str(e)
            result["execution_time"] = time.time() - start_time
            self.timeout_recoveries += 1
            
            logger.error(f"⏱️ Plugin {plugin_name} timed out after {execution_timeout}s")
            
        except Exception as e:
            result["status"] = "error"
            result["error"] = str(e)
            result["execution_time"] = time.time() - start_time
            
            logger.error(f"❌ Plugin {plugin_name} failed: {e}")
            logger.debug(f"Plugin {plugin_name} traceback: {traceback.format_exc()}")
            
        # Update statistics
        self.plugin_statistics[plugin_name] = result
        
        return result
    
    def execute_plugin_with_retry(self, plugin_name: str, plugin_function: callable,
                                 max_retries: int = 2, *args, **kwargs) -> Dict[str, Any]:
        """Execute plugin with retry logic for transient failures."""
        
        for attempt in range(max_retries + 1):
            if attempt > 0:
                logger.info(f"🔄 Retrying plugin {plugin_name} (attempt {attempt + 1})")
                time.sleep(2 ** attempt)  # Exponential backoff
            
            result = self.execute_plugin_safely(plugin_name, plugin_function, *args, **kwargs)
            
            if result["status"] == "completed":
                return result
            elif result["status"] == "timeout" and attempt < max_retries:
                # Increase timeout for retry
                kwargs["timeout"] = kwargs.get("timeout", self.default_timeout) * 1.5
                continue
            elif result["status"] == "error" and "import" in str(result["error"]).lower():
                # Don't retry import errors
                break
        
        return result
    
    def get_plugin_statistics(self) -> Dict[str, Any]:
        """Get comprehensive plugin execution statistics."""
        
        total_plugins = len(self.plugin_statistics)
        completed_plugins = sum(1 for p in self.plugin_statistics.values() if p["status"] == "completed")
        timeout_plugins = sum(1 for p in self.plugin_statistics.values() if p["status"] == "timeout")
        error_plugins = sum(1 for p in self.plugin_statistics.values() if p["status"] == "error")
        
        avg_execution_time = 0
        if total_plugins > 0:
            total_time = sum(p["execution_time"] for p in self.plugin_statistics.values())
            avg_execution_time = total_time / total_plugins
        
        return {
            "total_plugins": total_plugins,
            "completed_plugins": completed_plugins,
            "timeout_plugins": timeout_plugins,
            "error_plugins": error_plugins,
            "success_rate": completed_plugins / max(total_plugins, 1),
            "avg_execution_time": avg_execution_time,
            "timeout_recoveries": self.timeout_recoveries
        }

# Global enhanced plugin manager instance
enhanced_plugin_manager = EnhancedPluginManager()

def execute_plugin_robust(plugin_name: str, plugin_function: callable, 
                         *args, **kwargs) -> Dict[str, Any]:
    """Global function for robust plugin execution."""
    return enhanced_plugin_manager.execute_plugin_with_retry(
        plugin_name, plugin_function, *args, **kwargs
    ) 
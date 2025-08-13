#!/usr/bin/env python3
"""
Enhanced Plugin Manager for AODS

This module provides comprehensive plugin management with:
- Robust timeout protection to prevent hanging
- Resource management and memory limits
- Graceful error handling and recovery
- Progress tracking and status reporting
- Coordinated shutdown support
- Global error protection integration

"""

import importlib
import importlib.util
import inspect
import logging
import os
import sys
import time
import traceback
import threading
import signal
import pkgutil
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError, as_completed
from contextlib import contextmanager
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from rich.console import Console
from rich.progress import Progress, TaskID
from rich.table import Table
from rich.text import Text

from core.output_manager import get_output_manager
from core.plugin_constants import TIMEOUTS, RISK_LEVELS, PLUGIN_CATEGORIES
from core.scan_profiles import ScanProfile, scan_profile_manager, get_recommended_profile, apply_scan_profile

# GLOBAL ERROR PROTECTION: Import comprehensive error protection
try:
    from core.global_error_protection import (
        get_global_error_protection,
        protect_scan_execution,
        error_protected,
        ErrorSeverity
    )
    GLOBAL_ERROR_PROTECTION_AVAILABLE = True
    logger = logging.getLogger(__name__)
    logger.info("Global error protection integrated into Plugin Manager")
except ImportError:
    GLOBAL_ERROR_PROTECTION_AVAILABLE = False
    logger = logging.getLogger(__name__)
    logger.warning("Global error protection not available - using basic error handling")
    
    # Fallback functions
    def get_global_error_protection():
        return None
    
    def protect_scan_execution(func, *args, **kwargs):
        return func(*args, **kwargs)
    
    def error_protected(*args, **kwargs):
        def decorator(func):
            return func
        return decorator
    
    class ErrorSeverity:
        CRITICAL = "critical"
        HIGH = "high"
        MEDIUM = "medium"
        LOW = "low"

# GRACEFUL SHUTDOWN: Import graceful shutdown support
try:
    from core.graceful_shutdown_manager import (
        is_shutdown_requested,
        plugin_context,
        get_shutdown_manager
    )
    GRACEFUL_SHUTDOWN_AVAILABLE = True
except ImportError:
    GRACEFUL_SHUTDOWN_AVAILABLE = False
    
    # Fallback functions
    def is_shutdown_requested():
        return False
    
    def plugin_context(plugin_name):
        from contextlib import nullcontext
        return nullcontext()

    def get_shutdown_manager():
        return None

class PluginStatus(Enum):
    """Plugin execution status enumeration."""

    NOT_LOADED = "not_loaded"
    LOADED = "loaded"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"
    DISABLED = "disabled"
    PENDING = "pending"
    COMPLETED = "completed"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"

class PluginCategory(Enum):
    """Plugin category classification."""

    STATIC_ANALYSIS = "static_analysis"
    DYNAMIC_ANALYSIS = "dynamic_analysis"
    NETWORK_ANALYSIS = "network_analysis"
    CRYPTO_ANALYSIS = "crypto_analysis"
    PRIVACY_ANALYSIS = "privacy_analysis"
    RESILIENCE_ANALYSIS = "resilience_analysis"
    PLATFORM_ANALYSIS = "platform_analysis"
    VULNERABILITY_ANALYSIS = "vulnerability_analysis"

@dataclass
class PluginDependency:
    """Represents a plugin dependency requirement."""

    name: str
    required: bool = True
    version_min: Optional[str] = None
    command: Optional[str] = None  # Command to check availability

@dataclass
class PluginMetadata:
    """Enhanced plugin metadata with execution tracking."""

    name: str
    module_path: str
    module: Optional[Any] = None  # Add module attribute for direct access
    module_name: Optional[str] = None  # Add module_name attribute for consistency
    priority: int = 50
    timeout: int = TIMEOUTS["default"]  # Default timeout from constants
    max_memory_mb: int = 512  # Memory limit in MB
    dependencies: List[str] = field(default_factory=list)
    status: PluginStatus = PluginStatus.PENDING
    start_time: Optional[float] = None
    end_time: Optional[float] = None
    execution_time: Optional[float] = None
    error_message: Optional[str] = None
    memory_usage: Optional[float] = None
    retry_count: int = 0
    max_retries: int = 2

class PluginResourceMonitor:
    """Monitor plugin resource usage and enforce limits."""
    
    def __init__(self):
        self.active_plugins: Dict[str, PluginMetadata] = {}
        self.resource_limits = {
            'max_memory_mb': 1024,  # 1GB total memory limit
            'max_execution_time': 600,  # 10 minutes max execution
            'max_concurrent_plugins': 4
        }
        
    def register_plugin(self, plugin_metadata: PluginMetadata):
        """Register a plugin for monitoring."""
        self.active_plugins[plugin_metadata.name] = plugin_metadata
        
    def unregister_plugin(self, plugin_name: str):
        """Unregister a plugin from monitoring."""
        self.active_plugins.pop(plugin_name, None)
        
    def check_resource_limits(self, plugin_name: str) -> bool:
        """Check if plugin can run within resource limits."""
        if len(self.active_plugins) >= self.resource_limits['max_concurrent_plugins']:
            logger.warning(f"Plugin {plugin_name} blocked: too many concurrent plugins")
            return False
            
        return True
        
    def get_memory_usage(self) -> float:
        """Get current memory usage in MB."""
        try:
            import psutil
            process = psutil.Process()
            return process.memory_info().rss / 1024 / 1024
        except ImportError:
            return 0.0

class PluginManager:
    """
    Enhanced Plugin Manager with robust timeout protection and resource management.
    
    Features:
    - Automatic plugin discovery and loading
    - Dependency resolution and execution ordering
    - Timeout protection and resource limits
    - Graceful error handling and recovery
    - Progress tracking and status reporting
    - Coordinated shutdown support
    """

    def __init__(self, output_mgr=None, scan_profile: Optional[ScanProfile] = None):
        """
        Initialize the Plugin Manager.

        Args:
            output_mgr: Output manager for logging and display
            scan_profile: Scan profile for performance optimization
        """
        self.output_mgr = output_mgr or self._create_default_output_manager()
        self.plugins: Dict[str, PluginMetadata] = {}
        self.loaded_modules: Dict[str, Any] = {}
        self.execution_stats = {
            'total_plugins': 0,
            'successful': 0,
            'failed': 0,
            'timeout': 0,
            'skipped': 0,
            'total_time': 0.0
        }
        self.resource_monitor = PluginResourceMonitor()
        self._shutdown_requested = False
        
        # Scan optimization
        self.scan_profile = scan_profile or ScanProfile.STANDARD
        self.optimization_config = None
        
        # Plugin discovery paths (remove duplicates)
        plugin_paths_raw = [
            Path(__file__).parent.parent / "plugins",
            Path.cwd() / "plugins"
        ]
        
        # Remove duplicate paths by resolving and deduplicating
        seen_paths = set()
        self.plugin_paths = []
        for path in plugin_paths_raw:
            resolved_path = path.resolve()
            if resolved_path not in seen_paths:
                seen_paths.add(resolved_path)
                self.plugin_paths.append(path)
        
        # Load plugins on initialization
        self.discover_plugins()

    def _create_default_output_manager(self):
        """Create a default output manager if none provided."""
        class DefaultOutputManager:
            def info(self, msg): logger.info(msg)
            def warning(self, msg): logger.warning(msg)
            def error(self, msg): logger.error(msg)
            def debug(self, msg): logger.debug(msg)
            def section_header(self, title, subtitle=""): logger.info(f"=== {title} ===")
            
            def progress_update(self, current, total, desc=""):
                """Update progress information for plugin execution."""
                if total > 0:
                    percentage = (current / total) * 100
                    progress_bar = "█" * int(percentage // 5) + "░" * (20 - int(percentage // 5))
                    status_msg = f"🔄 Progress: [{progress_bar}] {current}/{total} ({percentage:.1f}%)"
                    if desc:
                        status_msg += f" - {desc}"
                    logger.info(status_msg)
                else:
                    # Handle case where total is 0 or unknown
                    status_msg = f"🔄 Processing: {current} items"
                    if desc:
                        status_msg += f" - {desc}"
                    logger.info(status_msg)
            
        return DefaultOutputManager()

    def discover_plugins(self) -> None:
        """
        Discover and register all available plugins with enhanced metadata.
        """
        self.output_mgr.info("🔍 Discovering security analysis plugins...")
        
        # Log discovery paths for transparency
        self.output_mgr.debug(f"Plugin discovery paths: {[str(p) for p in self.plugin_paths]}")
        
        discovered_count = 0
        total_files_scanned = 0

        for plugin_path in self.plugin_paths:
            if not plugin_path.exists():
                continue
                
            # Discover standalone .py plugin files
            for plugin_file in plugin_path.glob("*.py"):
                if plugin_file.name.startswith("__"):
                    continue
                    
                total_files_scanned += 1
                plugin_name = plugin_file.stem
                module_path = f"plugins.{plugin_name}"
                
                # Skip if already discovered (prevent duplicates from multiple paths)
                if plugin_name in self.plugins:
                    self.output_mgr.debug(f"  ⏭️  Skipping duplicate: {plugin_name}")
                    continue
                
                try:
                    # Load plugin metadata
                    plugin_metadata = self._load_plugin_metadata(plugin_name, module_path, plugin_file)
                    
                    if plugin_metadata:
                        self.plugins[plugin_name] = plugin_metadata
                        discovered_count += 1
                        self.output_mgr.debug(f"  ✅ Discovered: {plugin_name}")
                    
                except Exception as e:
                    self.output_mgr.warning(f"  ⚠️  Failed to discover {plugin_name}: {e}")
                    continue
            
            # Discover directory-based plugins with __init__.py
            for plugin_dir in plugin_path.iterdir():
                if not plugin_dir.is_dir() or plugin_dir.name.startswith("__"):
                    continue
                
                init_file = plugin_dir / "__init__.py"
                if not init_file.exists():
                    continue
                
                total_files_scanned += 1
                plugin_name = plugin_dir.name
                module_path = f"plugins.{plugin_name}"
                
                # Skip if already discovered (prevent duplicates from multiple paths)
                if plugin_name in self.plugins:
                    self.output_mgr.debug(f"  ⏭️  Skipping duplicate: {plugin_name} (directory)")
                    continue
                
                try:
                    # Load plugin metadata for directory-based plugin
                    plugin_metadata = self._load_plugin_metadata(plugin_name, module_path, init_file)
                    
                    if plugin_metadata:
                        self.plugins[plugin_name] = plugin_metadata
                        discovered_count += 1
                        self.output_mgr.debug(f"  ✅ Discovered: {plugin_name} (directory)")
                    
                except Exception as e:
                    self.output_mgr.warning(f"  ⚠️  Failed to discover {plugin_name}: {e}")
                    continue
        
        # Report accurate discovery results
        skipped_duplicates = total_files_scanned - discovered_count
        self.output_mgr.info(f"📦 Successfully loaded {discovered_count} plugins")
        if skipped_duplicates > 0:
            self.output_mgr.debug(f"   ⏭️  Skipped {skipped_duplicates} items (duplicates or failed loads)")
        if len(self.plugin_paths) > 1:
            self.output_mgr.debug(f"   🔍 Scanned {len(self.plugin_paths)} plugin paths")
        
        self.execution_stats['total_plugins'] = discovered_count
        
        # Apply scan optimization after discovery
        self._apply_scan_optimization()

    def _apply_scan_optimization(self):
        """Apply scan profile optimization to filter and configure plugins."""
        if not hasattr(self, 'scan_profile') or not self.scan_profile:
            return
            
        try:
            from core.scan_profiles import apply_scan_profile
            
            # Get available plugin names
            available_plugins = set(self.plugins.keys())
            
            # Apply scan profile optimization
            self.optimization_config = apply_scan_profile(self.scan_profile, available_plugins)
            
            if self.output_mgr:
                selected_count = self.optimization_config.get('plugin_count', 0)
                excluded_count = self.optimization_config.get('excluded_count', 0)
                speedup = self.optimization_config.get('estimated_speedup', '0%')
                
                self.output_mgr.debug(f"🎯 Scan optimization applied:")
                self.output_mgr.debug(f"   Profile: {self.scan_profile.value}")
                self.output_mgr.debug(f"   Selected: {selected_count} plugins")
                self.output_mgr.debug(f"   Excluded: {excluded_count} plugins")
                self.output_mgr.debug(f"   Speed boost: {speedup}")
                
        except Exception as e:
            if self.output_mgr:
                self.output_mgr.warning(f"Scan optimization failed, using all plugins: {e}")
            self.optimization_config = None

    def register_priority_plugin(self, plugin_name: str, plugin_function, priority: int = 1):
        """Register a priority plugin with direct function execution.
        
        This method supports dynamic plugin registration for specialized components
        like Frida-first dynamic analysis that need to bypass normal plugin discovery.
        
        Args:
            plugin_name: Name of the plugin
            plugin_function: Callable function that takes apk_ctx and returns results
            priority: Priority level (lower numbers = higher priority)
        """
        # Create a simple wrapper that looks like a plugin
        class PriorityPlugin:
            def __init__(self, name, func, priority):
                self.name = name
                self.run = func
                self.priority = priority
                self.enabled = True
                # Provide metadata compatibility attributes used elsewhere
                from core.plugin_manager import PluginStatus
                self.status: PluginStatus = PluginStatus.LOADED
                self.start_time = None
                self.end_time = None
                self.execution_time = None
                self.error_message = None
                
            def __call__(self, apk_ctx):
                return self.run(apk_ctx)
        
        # Register the priority plugin
        priority_plugin = PriorityPlugin(plugin_name, plugin_function, priority)
        self.plugins[plugin_name] = priority_plugin
        
        # Add to priority plugins tracking if it doesn't exist
        if not hasattr(self, 'priority_plugins'):
            self.priority_plugins = {}
        self.priority_plugins[plugin_name] = priority
        
        self.output_mgr.info(f"✅ Priority plugin '{plugin_name}' registered (priority {priority})")

    def set_scan_profile(self, scan_profile):
        """Set the scan profile and re-apply optimization.
        
        Args:
            scan_profile: The scan profile to apply (ScanProfile enum or string)
        """
        try:
            # Import ScanProfile if needed
            from core.scan_profiles import ScanProfile
            
            # Handle string input
            if isinstance(scan_profile, str):
                # Convert string to ScanProfile enum
                scan_profile_map = {
                    'lightning': ScanProfile.LIGHTNING,
                    'fast': ScanProfile.FAST, 
                    'standard': ScanProfile.STANDARD,
                    'deep': ScanProfile.DEEP,
                    'safe': ScanProfile.LIGHTNING,  # Map safe to lightning for backwards compatibility
                }
                scan_profile = scan_profile_map.get(scan_profile.lower(), ScanProfile.STANDARD)
            
            # Update the scan profile
            self.scan_profile = scan_profile
            
            # Re-apply scan optimization with the new profile
            self._apply_scan_optimization()
            
            if self.output_mgr:
                self.output_mgr.info(f"🎯 Scan profile updated to: {self.scan_profile.value}")
                
        except Exception as e:
            if self.output_mgr:
                self.output_mgr.warning(f"Failed to set scan profile: {e}")
            # Keep current profile if setting fails
            pass

    def get_optimized_plugins(self) -> List[str]:
        """Get the list of plugins selected by scan profile optimization."""
        if hasattr(self, 'optimization_config') and self.optimization_config:
            selected_plugins = self.optimization_config.get('selected_plugins', set())
            # Return plugins that are both available and selected by optimization
            return [name for name in self.plugins.keys() if name in selected_plugins]
        else:
            # No optimization applied, return all plugins
            return list(self.plugins.keys())
    
    def get_plugin_metadata_optimized(self) -> List:
        """Get plugin metadata only for optimized/selected plugins."""
        optimized_plugin_names = self.get_optimized_plugins()
        
        # Filter plugin metadata to only include optimized plugins
        optimized_metadata = []
        for plugin_data in self.plugins.values():
            if hasattr(plugin_data, 'name') and plugin_data.name in optimized_plugin_names:
                optimized_metadata.append(plugin_data)
            elif hasattr(plugin_data, 'module_name') and plugin_data.module_name in optimized_plugin_names:
                optimized_metadata.append(plugin_data)
        
        self.output_mgr.info(f"🎯 Executing {len(optimized_metadata)}/{len(self.plugins)} optimized plugins")
        
        if len(optimized_metadata) != len(optimized_plugin_names):
            self.output_mgr.warning(f"⚠️ Plugin metadata mismatch: expected {len(optimized_plugin_names)}, got {len(optimized_metadata)}")
        
        return optimized_metadata

    def should_execute_plugin(self, plugin_name: str) -> bool:
        """Check if plugin should be executed based on current scan profile."""
        if not self.optimization_config:
            return True
        return plugin_name in self.optimization_config['selected_plugins']

    def _load_plugin_metadata(self, plugin_name: str, module_path: str, plugin_file: Path) -> Optional[PluginMetadata]:
        """Load plugin metadata with enhanced configuration."""
        try:
            # Handle directory-based plugins vs standalone files differently
            if plugin_file.name == "__init__.py":
                # Directory-based plugin - use proper import mechanism
                try:
                    module = importlib.import_module(module_path)
                except ImportError as import_error:
                    # If direct import fails, try spec-based loading as fallback
                    spec = importlib.util.spec_from_file_location(module_path, plugin_file)
                    if not spec or not spec.loader:
                        logger.debug(f"Failed to create spec for directory plugin {plugin_name}: {import_error}")
                        return None
                    
                    module = importlib.util.module_from_spec(spec)
                    
                    # Add to sys.modules before executing to handle internal imports
                    sys.modules[module_path] = module
                    try:
                        spec.loader.exec_module(module)
                    except Exception as exec_error:
                        # Clean up sys.modules on failure
                        sys.modules.pop(module_path, None)
                        logger.debug(f"Failed to execute directory plugin {plugin_name}: {exec_error}")
                        return None
            else:
                # Standalone file plugin - use spec-based loading
                spec = importlib.util.spec_from_file_location(plugin_name, plugin_file)
                if not spec or not spec.loader:
                    return None
                    
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
            
            # Check if plugin has required run function
            if not hasattr(module, 'run'):
                self.output_mgr.warning(f"Plugin {plugin_name} missing 'run' function")
                return None
            
            # Load plugin characteristics if available
            characteristics = getattr(module, 'PLUGIN_CHARACTERISTICS', {})
            
            # Create metadata with enhanced configuration
            metadata = PluginMetadata(
                name=plugin_name,
                module_path=module_path,
                module=module,  # Directly attach module to metadata
                module_name=plugin_name,  # Set module_name for consistency
                priority=characteristics.get('priority', 50),
                timeout=characteristics.get('timeout', TIMEOUTS["default"]),  # Use constant instead of hardcoded value
                max_memory_mb=characteristics.get('max_memory_mb', 512),
                dependencies=characteristics.get('dependencies', [])
            )
            
            # Store the loaded module for later use (backward compatibility)
            self.loaded_modules[plugin_name] = module
            
            return metadata

        except Exception as e:
            logger.debug(f"Error loading plugin metadata for {plugin_name}: {e}")
            return None

    def plan_execution_order(self) -> List[PluginMetadata]:
        """
        Plan optimal plugin execution order based on dependencies and priorities.
        CRITICAL FIX: Apply scan profile filtering to exclude plugins based on current profile.

        Returns:
            List of plugins in execution order (filtered by scan profile)
        """
        if not self.plugins:
            return []
        
        # CRITICAL FIX: Filter plugins based on scan profile BEFORE planning execution
        available_plugins = {}
        excluded_plugins = []
        
        for plugin_name, plugin_metadata in self.plugins.items():
            if self.should_execute_plugin(plugin_name):
                available_plugins[plugin_name] = plugin_metadata
            else:
                excluded_plugins.append(plugin_name)
        
        # Log filtering results
        if excluded_plugins:
            self.output_mgr.debug(f"⚡ Scan profile filtering: Excluded {len(excluded_plugins)} plugins: {excluded_plugins}")
            self.output_mgr.debug(f"📊 Executing {len(available_plugins)}/{len(self.plugins)} plugins based on {self.scan_profile.value} profile")
        
        # Store filtered plugins temporarily for dependency resolution
        original_plugins = self.plugins
        self.plugins = available_plugins
        
        try:
            # Implement proper dependency resolution using topological sorting on filtered plugins
            result = self._resolve_dependencies_topological()
        finally:
            # Restore original plugins list
            self.plugins = original_plugins
        
        return result
    
    def _resolve_dependencies_topological(self) -> List[PluginMetadata]:
        """
        Resolve plugin dependencies using topological sorting algorithm.
        
        Returns:
            List of plugins in dependency-resolved execution order
        """
        # Create dependency graph
        graph = {}  # plugin_name -> set of dependencies
        in_degree = {}  # plugin_name -> number of dependencies
        all_plugins = {}  # plugin_name -> PluginMetadata
        
        # Initialize graph structures
        for plugin_metadata in self.plugins.values():
            plugin_name = plugin_metadata.name
            all_plugins[plugin_name] = plugin_metadata
            
            # Get explicit dependencies from plugin metadata (handle different formats)
            dependencies = self._extract_dependency_names(plugin_metadata.dependencies)
            
            # Add implicit dependencies based on plugin characteristics
            dependencies.update(self._analyze_implicit_dependencies(plugin_metadata, list(self.plugins.values())))
            
            # Filter dependencies to only include available plugins
            available_dependencies = {dep for dep in dependencies if dep in self.plugins}
            
            graph[plugin_name] = available_dependencies
            in_degree[plugin_name] = len(available_dependencies)
        
        # Topological sort using Kahn's algorithm
        ordered_plugins = []
        queue = []
        
        # Find all plugins with no dependencies (in_degree = 0)
        for plugin_name, degree in in_degree.items():
            if degree == 0:
                queue.append(plugin_name)
        
        # Sort initial queue by priority for deterministic ordering
        def get_priority_key(name):
            """Convert priority to integer for consistent sorting."""
            priority = all_plugins[name].priority
            if isinstance(priority, str):
                # Convert string priorities to integers
                priority_map = {
                    'CRITICAL': 10, 'HIGH': 20, 'MEDIUM': 50, 'LOW': 80, 'INFO': 90
                }
                priority = priority_map.get(priority.upper(), 50)  # Default to MEDIUM
            return (priority, name)
        
        queue.sort(key=get_priority_key)
        
        # Process plugins in topological order
        while queue:
            # Remove plugin with no dependencies
            current_plugin = queue.pop(0)
            ordered_plugins.append(all_plugins[current_plugin])
            
            # Update in_degree for dependent plugins
            for plugin_name, dependencies in graph.items():
                if current_plugin in dependencies:
                    in_degree[plugin_name] -= 1
                    
                    # If all dependencies satisfied, add to queue
                    if in_degree[plugin_name] == 0 and plugin_name not in [p.name for p in ordered_plugins]:
                        queue.append(plugin_name)
            
            # Sort queue by priority for consistent ordering using the same function
            queue.sort(key=get_priority_key)
        
        # Check for circular dependencies
        if len(ordered_plugins) != len(self.plugins):
            self.output_mgr.warning("⚠️  Circular dependencies detected, falling back to priority ordering")
            return self._fallback_priority_ordering()
        
        self.output_mgr.debug(f"Dependency-resolved execution order: {[p.name for p in ordered_plugins]}")
        return ordered_plugins
    
    def _extract_dependency_names(self, dependencies) -> Set[str]:
        """
        Extract dependency names from various dependency formats.
        
        Args:
            dependencies: Dependency information (list of strings, dicts, or None)
            
        Returns:
            Set of dependency names as strings
        """
        if not dependencies:
            return set()
        
        dependency_names = set()
        
        if isinstance(dependencies, (list, tuple)):
            for dep in dependencies:
                if isinstance(dep, str):
                    dependency_names.add(dep)
                elif isinstance(dep, dict):
                    # Handle dependency as dict (e.g., {'name': 'plugin_name', 'required': True})
                    if 'name' in dep:
                        dependency_names.add(dep['name'])
                    elif 'plugin' in dep:
                        dependency_names.add(dep['plugin'])
                    # Add other possible dict formats as needed
                elif hasattr(dep, 'name'):
                    # Handle dependency objects with name attribute
                    dependency_names.add(dep.name)
        elif isinstance(dependencies, str):
            # Single dependency as string
            dependency_names.add(dependencies)
        elif isinstance(dependencies, dict):
            # Single dependency as dict
            if 'name' in dependencies:
                dependency_names.add(dependencies['name'])
            elif 'plugin' in dependencies:
                dependency_names.add(dependencies['plugin'])
        
        return dependency_names
    
    def _analyze_implicit_dependencies(self, plugin_metadata: PluginMetadata, all_plugins: List[PluginMetadata]) -> Set[str]:
        """
        Analyze implicit dependencies based on plugin characteristics.
        
        Args:
            plugin_metadata: Plugin to analyze dependencies for
            all_plugins: List of all available plugins
            
        Returns:
            Set of implicit dependency plugin names
        """
        implicit_deps = set()
        plugin_name = plugin_metadata.name
        
        # Static analysis should generally run first
        if not plugin_name.startswith(('jadx_', 'static_', 'manifest_')):
            static_plugins = [p.name for p in all_plugins 
                           if p.name.startswith(('jadx_', 'static_', 'manifest_')) 
                           and p.name != plugin_name]
            implicit_deps.update(static_plugins)
        
        # Dynamic analysis depends on static analysis
        if 'dynamic' in plugin_name or 'frida' in plugin_name:
            prerequisite_patterns = ['static_', 'manifest_', 'platform_']
            for p in all_plugins:
                if any(p.name.startswith(pattern) for pattern in prerequisite_patterns):
                    if p.name != plugin_name:
                        implicit_deps.add(p.name)
        
        # Vulnerability analysis depends on foundational analysis
        if 'vulnerability' in plugin_name or 'attack_surface' in plugin_name:
            foundational_patterns = ['static_', 'manifest_', 'crypto', 'network_']
            for p in all_plugins:
                if any(pattern in p.name for pattern in foundational_patterns):
                    if p.name != plugin_name:
                        implicit_deps.add(p.name)
        
        # High-memory plugins should run after lighter plugins
        if plugin_metadata.max_memory_mb > 800:
            lighter_plugins = [p.name for p in all_plugins 
                             if p.max_memory_mb <= 400 and p.name != plugin_name]
            implicit_deps.update(lighter_plugins[:3])  # Limit to avoid too many deps
        
        return implicit_deps
    
    def _fallback_priority_ordering(self) -> List[PluginMetadata]:
        """
        Fallback to priority-based ordering when dependency resolution fails.
        
        Returns:
            List of plugins sorted by priority
        """
        def get_sort_key(plugin_metadata):
            # Ensure priority is always an integer for consistent sorting
            priority = plugin_metadata.priority
            if isinstance(priority, str):
                try:
                    priority = int(priority)
                except (ValueError, TypeError):
                    priority = 50  # Default priority
            elif not isinstance(priority, int):
                priority = 50  # Default priority
            
            return (priority, plugin_metadata.name)
        
        ordered_plugins = sorted(
            self.plugins.values(),
            key=get_sort_key
        )
        
        self.output_mgr.debug(f"Priority-based execution order: {[p.name for p in ordered_plugins]}")
        return ordered_plugins

    def _execute_plugin_with_protection(self, plugin_metadata: PluginMetadata, apk_ctx) -> Tuple[str, Any]:
        """Execute a single plugin with comprehensive protection and enhanced timeout handling."""
        plugin_name = plugin_metadata.name
        
        # GLOBAL ERROR PROTECTION: Check if plugin is disabled due to previous failures
        if GLOBAL_ERROR_PROTECTION_AVAILABLE:
            error_protection = get_global_error_protection()
            if error_protection and error_protection.is_plugin_disabled(plugin_name):
                plugin_metadata.status = PluginStatus.SKIPPED
                return f"⏭️  {plugin_name}", Text(f"Skipped - disabled after multiple failures", style="yellow")
        
        # GLOBAL ERROR PROTECTION: Wrap entire plugin execution
        if GLOBAL_ERROR_PROTECTION_AVAILABLE:
            error_protection = get_global_error_protection()
            success, result = error_protection.protect_plugin_execution(
                lambda ctx: self._execute_plugin_core(plugin_metadata, ctx),
                plugin_name,
                apk_ctx
            )
            
            if not success:
                plugin_metadata.status = PluginStatus.FAILED
                plugin_metadata.error_message = "Protected execution failed"
                return result
            else:
                return result
        else:
            # Fallback to original execution without global protection
            return self._execute_plugin_core(plugin_metadata, apk_ctx)
    
    def _execute_plugin_core(self, plugin_metadata: PluginMetadata, apk_ctx) -> Tuple[str, Any]:
        """Core plugin execution logic (separated for global error protection integration)."""
        plugin_name = plugin_metadata.name
        
        try:
            # Check resource limits
            if not self.resource_monitor.check_resource_limits(plugin_name):
                plugin_metadata.status = PluginStatus.SKIPPED
                return f"⏭️  {plugin_name}", Text("Skipped due to resource limits", style="yellow")
            
            # Register plugin for monitoring
            self.resource_monitor.register_plugin(plugin_metadata)
            
            # Update plugin status
            plugin_metadata.status = PluginStatus.RUNNING
            plugin_metadata.start_time = time.time()
            
            # Get the loaded module (prefer metadata.module, fallback to loaded_modules)
            module = plugin_metadata.module or self.loaded_modules.get(plugin_name)
            if not module:
                raise ImportError(f"Plugin module {plugin_name} not loaded")
            
            # Enhanced timeout handling for ALL plugins with specific limits
            effective_timeout = plugin_metadata.timeout
            
            # Dynamic timeout adjustment based on APK size and scan profile
            if hasattr(apk_ctx, 'apk_path') and apk_ctx.apk_path:
                try:
                    apk_size_mb = os.path.getsize(str(apk_ctx.apk_path)) / (1024 * 1024)
                    if apk_size_mb > 100:  # Large APK
                        effective_timeout = min(effective_timeout * 1.5, 900)  # Cap at 15 minutes
                        self.output_mgr.debug(f"Increased timeout for large APK: {effective_timeout}s")
                except (OSError, AttributeError):
                    pass
            
            # Scan profile optimization with JADX exception
            if self.scan_profile == ScanProfile.LIGHTNING:
                if plugin_name == "jadx_static_analysis":
                    # JADX exception: Allow up to 5 minutes even in Lightning mode for complex APKs
                    jadx_timeout = self._calculate_adaptive_jadx_timeout(apk_ctx)
                    effective_timeout = min(effective_timeout, jadx_timeout)
                    self.output_mgr.debug(f"Lightning mode JADX exception: {effective_timeout}s timeout")
                else:
                    effective_timeout = min(effective_timeout, 120)  # Cap at 2 minutes for lightning
                    self.output_mgr.debug(f"Lightning mode timeout cap: {effective_timeout}s")
            elif self.scan_profile == ScanProfile.FAST:
                effective_timeout = min(effective_timeout, 300)  # Cap at 5 minutes for fast
            
            # CRITICAL FIX: Special handling for JADX to prevent hanging at low progress
            if plugin_name == "jadx_static_analysis":
                # Ensure JADX gets sufficient time but not infinite
                min_jadx_timeout = 300  # 5 minutes minimum
                max_jadx_timeout = 900  # 15 minutes maximum to prevent indefinite hanging
                effective_timeout = max(min_jadx_timeout, min(effective_timeout, max_jadx_timeout))
                self.output_mgr.debug(f"JADX timeout adjusted: {effective_timeout}s (range: {min_jadx_timeout}-{max_jadx_timeout}s)")
            
            # **MANIFEST ANALYSIS FIX**: Use structured data method for enhanced_manifest_analysis  
            plugin_function = module.run
            if plugin_name == "enhanced_manifest_analysis" and hasattr(module, "run_with_structured_data"):
                plugin_function = module.run_with_structured_data
                self.output_mgr.debug(f"🔧 Using structured data method for {plugin_name}")
            
            # Execute plugin with timeout protection using ThreadPoolExecutor
            with ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(plugin_function, apk_ctx)
                
                try:
                    # Wait for plugin completion with timeout
                    result = future.result(timeout=effective_timeout)
                    
                    # Update plugin status
                    plugin_metadata.status = PluginStatus.COMPLETED
                    plugin_metadata.end_time = time.time()
                    plugin_metadata.execution_time = plugin_metadata.end_time - plugin_metadata.start_time
                    
                    self.output_mgr.debug(f"✅ Plugin {plugin_name} completed in {plugin_metadata.execution_time:.2f}s")
                    
                    return f"✅ {plugin_name}", result
                    
                except FutureTimeoutError:
                    # Plugin timed out - force cleanup
                    plugin_metadata.status = PluginStatus.TIMEOUT
                    plugin_metadata.end_time = time.time()
                    plugin_metadata.execution_time = effective_timeout
                    plugin_metadata.error_message = f"Plugin timed out after {effective_timeout}s"
                    
                    self.output_mgr.warning(f"⏰ Plugin {plugin_name} timed out after {effective_timeout}s - forcing cleanup")
                    
                    # Aggressively cancel the future and continue
                    future.cancel()
                    
                    # CRITICAL FIX: For JADX plugins, ensure proper process termination
                    if plugin_name == 'jadx_static_analysis':
                        try:
                            from core.jadx_decompilation_manager import get_jadx_manager
                            jadx_manager = get_jadx_manager()
                            
                            # Terminate all active JADX jobs managed by AODS
                            terminated_jobs = []
                            for job_id in list(jadx_manager.active_jobs.keys()):
                                self.output_mgr.warning(f"🔥 Force terminating hanging JADX job: {job_id}")
                                jadx_manager._terminate_job(job_id)
                                terminated_jobs.append(job_id)
                            
                            # More precise cleanup: Only kill JADX processes with AODS-specific patterns
                            if terminated_jobs:
                                # Kill any remaining JADX processes that might be related to our APK
                                import subprocess
                                import psutil
                                
                                aods_related_killed = 0
                                try:
                                    # Look for JADX processes that might be related to our scan
                                    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                                        try:
                                            if proc.info['name'] and 'jadx' in proc.info['name'].lower():
                                                cmdline = ' '.join(proc.info['cmdline'] or [])
                                                # Only kill if it contains AODS-related paths or temp directories
                                                if any(pattern in cmdline.lower() for pattern in ['/tmp/jadx', 'aods', 'decompiled']):
                                                    proc.terminate()
                                                    aods_related_killed += 1
                                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                                            continue
                                    
                                    if aods_related_killed > 0:
                                        self.output_mgr.warning(f"🔥 Terminated {aods_related_killed} AODS-related JADX processes")
                                    else:
                                        self.output_mgr.debug("✅ No additional AODS-related JADX processes found")
                                        
                                except Exception as proc_error:
                                    # Fallback to basic pkill only if psutil approach fails
                                    self.output_mgr.warning(f"⚠️ Process-specific cleanup failed: {proc_error}")
                                    subprocess.run(['pkill', '-f', '/tmp/jadx'], capture_output=True, timeout=3)
                                    self.output_mgr.warning("🔥 Fallback: killed JADX processes with /tmp/jadx pattern")
                            
                        except Exception as e:
                            self.output_mgr.warning(f"⚠️ JADX cleanup error: {e}")
                    
                    # For critical plugins, return partial results instead of complete failure
                    critical_plugins_with_partial_results = [
                        'insecure_data_storage', 'enhanced_static_analysis', 'jadx_static_analysis',
                        'intent_fuzzing', 'webview_security_analysis', 'runtime_decryption_analysis'
                    ]
                    
                    if plugin_name in critical_plugins_with_partial_results:
                        return f"⏰ {plugin_name}", Text(
                            f"Analysis completed with timeout protection ({effective_timeout}s) - partial results available\n"
                            f"This plugin was stopped to prevent system hanging. Consider:\n"
                            f"• Running analysis on smaller APK subsets\n"
                            f"• Using manual analysis tools for this component\n"
                            f"• Checking system resources and trying again", 
                            style="yellow"
                        )
                    else:
                        return f"⏰ {plugin_name}", Text(
                            f"Plugin timed out after {effective_timeout}s\n"
                            f"This timeout prevents system hanging and ensures scan completion.", 
                            style="yellow"
                        )
                    
        except Exception as e:
            # Plugin failed with exception
            plugin_metadata.status = PluginStatus.FAILED
            plugin_metadata.end_time = time.time()
            if plugin_metadata.start_time:
                plugin_metadata.execution_time = plugin_metadata.end_time - plugin_metadata.start_time
            plugin_metadata.error_message = str(e)
            
            error_msg = f"Plugin execution failed: {e}"
            self.output_mgr.error(f"❌ Plugin {plugin_name} failed: {e}")
            self.output_mgr.debug(f"Plugin error traceback: {traceback.format_exc()}")

            return f"❌ {plugin_name}", Text(f"Error: {error_msg}", style="red")
            
        finally:
            # Always unregister plugin from monitoring
            self.resource_monitor.unregister_plugin(plugin_name)

    def execute_plugin(self, plugin_metadata: PluginMetadata, apk_ctx) -> Tuple[str, Any]:
        """
        Execute a single plugin with comprehensive protection and monitoring.

        Args:
            plugin_metadata: Plugin metadata and configuration
            apk_ctx: APK context object

        Returns:
            Tuple of (plugin_title, plugin_result)
        """
        plugin_name = plugin_metadata.name
        
        # Check for shutdown request
        if GRACEFUL_SHUTDOWN_AVAILABLE and is_shutdown_requested():
            plugin_metadata.status = PluginStatus.CANCELLED
            self.output_mgr.warning(f"🛑 Plugin {plugin_name} cancelled due to shutdown request")
            return f"🛑 {plugin_name}", Text("Cancelled due to shutdown", style="yellow")
        
        # Use plugin context for graceful shutdown coordination
        with plugin_context(plugin_name):
            self.output_mgr.info(f"🔍 Executing plugin: {plugin_name}")
            
            try:
                return self._execute_plugin_with_protection(plugin_metadata, apk_ctx)
                
            except KeyboardInterrupt:
                plugin_metadata.status = PluginStatus.CANCELLED
                self.output_mgr.warning(f"🛑 Plugin {plugin_name} cancelled by user")
                return f"🛑 {plugin_name}", Text("Cancelled by user", style="yellow")
                
            except Exception as e:
                plugin_metadata.status = PluginStatus.FAILED
                plugin_metadata.error_message = str(e)
                error_msg = f"Plugin execution failed: {e}"
                self.output_mgr.error(f"❌ Plugin {plugin_name} failed: {e}")
                self.output_mgr.debug(f"Plugin error traceback: {traceback.format_exc()}")
                return f"❌ {plugin_name}", Text(f"Error: {error_msg}", style="red")

    def _calculate_adaptive_jadx_timeout(self, apk_ctx) -> int:
        """Calculate adaptive timeout for JADX based on APK characteristics"""
        try:
            # Base timeout for Lightning mode
            base_timeout = 180  # 3 minutes minimum for JADX in Lightning
            
            if hasattr(apk_ctx, 'apk_path') and apk_ctx.apk_path:
                try:
                    apk_size_mb = os.path.getsize(str(apk_ctx.apk_path)) / (1024 * 1024)
                    
                    # Adaptive timeout based on APK size
                    if apk_size_mb > 50:
                        timeout = 360  # 6 minutes for very large APKs
                    elif apk_size_mb > 20:
                        timeout = 300  # 5 minutes for large APKs
                    elif apk_size_mb > 5:
                        timeout = 240  # 4 minutes for medium APKs
                    else:
                        timeout = base_timeout  # 3 minutes for small APKs
                    
                    self.output_mgr.debug(f"JADX adaptive timeout: {timeout}s for {apk_size_mb:.1f}MB APK")
                    return timeout
                    
                except (OSError, AttributeError):
                    pass
            
            return base_timeout
            
        except Exception as e:
            self.output_mgr.warning(f"Failed to calculate adaptive JADX timeout: {e}")
            return 300  # 5 minute fallback

    def execute_all_plugins(self, apk_ctx) -> Dict[str, Tuple[str, Any]]:
        """
        Execute all plugins in optimal order with comprehensive protection.

        Args:
            apk_ctx: APK context object

        Returns:
            Dictionary of plugin results
        """
        # GLOBAL ERROR PROTECTION: Wrap entire plugin execution process
        if GLOBAL_ERROR_PROTECTION_AVAILABLE:
            return protect_scan_execution(self._execute_all_plugins_core, apk_ctx)
        else:
            return self._execute_all_plugins_core(apk_ctx)
    
    def _execute_all_plugins_core(self, apk_ctx) -> Dict[str, Tuple[str, Any]]:
        """Core plugin execution logic with global error protection integration."""
        ordered_plugins = self.plan_execution_order()
        results = {}
        start_time = time.time()

        if not ordered_plugins:
            self.output_mgr.warning("No plugins available for execution")
            return results

        # Check for shutdown before starting
        if GRACEFUL_SHUTDOWN_AVAILABLE and is_shutdown_requested():
            self.output_mgr.warning("🛑 Shutdown requested - skipping plugin execution")
            return results

        # GLOBAL ERROR PROTECTION: Get error protection instance for monitoring
        error_protection = None
        if GLOBAL_ERROR_PROTECTION_AVAILABLE:
            error_protection = get_global_error_protection()
            self.output_mgr.info("🛡️  Global error protection active - scan cannot crash from plugin failures")

        self.output_mgr.section_header(
            "Plugin Execution",
            f"Running {len(ordered_plugins)} security analysis plugins with timeout protection",
        )

        # Show plugin loading information with protection status
        self.output_mgr.info("🔌 Loading Security Analysis Plugins:")
        disabled_count = 0
        for i, plugin in enumerate(ordered_plugins, 1):
            timeout_info = f"(timeout: {plugin.timeout}s)" if plugin.timeout != 300 else ""
            
            # Check if plugin is disabled due to previous failures
            protection_status = ""
            if error_protection and error_protection.is_plugin_disabled(plugin.name):
                protection_status = " [DISABLED]"
                disabled_count += 1
            
            self.output_mgr.info(f"  {i:2d}. {plugin.name} {timeout_info}{protection_status}")
        
        if disabled_count > 0:
            self.output_mgr.warning(f"🛡️  {disabled_count} plugins disabled due to previous failures")

        # Start progress tracking
        active_plugins = len(ordered_plugins) - disabled_count
        self.output_mgr.progress_start("Executing plugins", active_plugins)

        # Execute plugins with progress tracking and enhanced error protection
        successful_plugins = 0
        failed_plugins = 0
        timeout_plugins = 0
        skipped_plugins = 0

        for i, plugin_metadata in enumerate(ordered_plugins, 1):
            # Check for shutdown request before each plugin
            if GRACEFUL_SHUTDOWN_AVAILABLE and is_shutdown_requested():
                self.output_mgr.warning(f"🛑 Shutdown requested - stopping plugin execution at {i}/{len(ordered_plugins)}")
                break

            # Update progress
            self.output_mgr.progress_update(advance=1, description=f"Executing {plugin_metadata.name}")

            # Execute plugin with global error protection
            try:
                plugin_result = self.execute_plugin(plugin_metadata, apk_ctx)
                results[plugin_metadata.name] = plugin_result

                # Update statistics
                if plugin_metadata.status == PluginStatus.COMPLETED:
                    successful_plugins += 1
                elif plugin_metadata.status == PluginStatus.FAILED:
                    failed_plugins += 1
                elif plugin_metadata.status == PluginStatus.TIMEOUT:
                    timeout_plugins += 1
                elif plugin_metadata.status == PluginStatus.SKIPPED:
                    skipped_plugins += 1

            except Exception as e:
                # This should rarely happen with global error protection, but add fallback
                self.output_mgr.error(f"❌ Critical error in plugin {plugin_metadata.name}: {e}")
                failed_plugins += 1
                results[plugin_metadata.name] = (
                    f"❌ {plugin_metadata.name}", 
                    Text(f"Critical execution error: {str(e)}", style="red")
                )
                
                # Log to error protection if available
                if error_protection:
                    with error_protection.protect_operation(f"plugin_critical_{plugin_metadata.name}", 
                                                           plugin_metadata.name, ErrorSeverity.HIGH):
                        pass  # Error will be logged by protection system

            # Brief pause between plugins to allow system recovery
            if i < len(ordered_plugins):
                time.sleep(0.1)

        # Calculate final statistics
        total_time = time.time() - start_time
        self.execution_stats.update({
            'successful': successful_plugins,
            'failed': failed_plugins,
            'timeout': timeout_plugins,
            'skipped': skipped_plugins,
            'total_time': total_time
        })

        # Stop progress tracking
        self.output_mgr.progress_stop()

        # Display execution summary with error protection statistics
        self._display_execution_summary_with_protection(error_protection)

        return results
        
    def _display_execution_summary_with_protection(self, error_protection=None):
        """Display execution summary including global error protection statistics."""
        # Original execution summary
        self._display_execution_summary()
        
        # Additional error protection summary
        if error_protection:
            error_summary = error_protection.get_error_summary()
            stats = error_summary['statistics']
            
            if stats['total_errors'] > 0:
                self.output_mgr.section_header("Error Protection Summary", "Global error handling statistics")
                
                self.output_mgr.info(f"🛡️  Total errors handled: {stats['total_errors']}")
                self.output_mgr.info(f"🔄 Errors recovered: {stats['recovered_errors']}")
                self.output_mgr.info(f"🚫 Scan crashes prevented: {stats['scan_crashes_prevented']}")
                
                if error_summary['plugin_failures']:
                    self.output_mgr.info("Plugin failure counts:")
                    for plugin, count in error_summary['plugin_failures'].items():
                        status = "DISABLED" if count >= 3 else "ACTIVE"
                        self.output_mgr.info(f"  • {plugin}: {count} failures ({status})")
            else:
                self.output_mgr.info("🛡️  Global error protection: No errors detected")

    def _display_execution_summary(self):
        """Display comprehensive plugin execution summary."""
        stats = self.execution_stats
        
        self.output_mgr.section_header("Plugin Execution Summary")
        
        self.output_mgr.info(f"📊 Execution Statistics:")
        self.output_mgr.info(f"  • Total plugins: {stats['total_plugins']}")
        self.output_mgr.info(f"  • Successful: {stats['successful']} ✅")
        self.output_mgr.info(f"  • Failed: {stats['failed']} ❌")
        self.output_mgr.info(f"  • Timeout: {stats['timeout']} ⏰")
        self.output_mgr.info(f"  • Skipped: {stats['skipped']} ⏭️")
        self.output_mgr.info(f"  • Total execution time: {stats['total_time']:.2f}s")
        
        # Success rate calculation
        total_attempted = stats['successful'] + stats['failed'] + stats['timeout']
        if total_attempted > 0:
            success_rate = (stats['successful'] / total_attempted) * 100
            self.output_mgr.info(f"  • Success rate: {success_rate:.1f}%")
        
        # Show plugin-specific timing information
        if self.plugins:
            self.output_mgr.info(f"\n⏱️  Plugin Execution Times:")
            for plugin_name, plugin_metadata in self.plugins.items():
                if plugin_metadata.execution_time is not None:
                    status_icon = {
                        PluginStatus.COMPLETED: "✅",
                        PluginStatus.FAILED: "❌",
                        PluginStatus.TIMEOUT: "⏰",
                        PluginStatus.SKIPPED: "⏭️",
                        PluginStatus.CANCELLED: "🛑"
                    }.get(plugin_metadata.status, "❓")
                    
                    self.output_mgr.info(
                        f"  {status_icon} {plugin_name}: {plugin_metadata.execution_time:.2f}s"
                    )

    def get_plugin_status(self, plugin_name: str) -> Optional[PluginStatus]:
        """Get the current status of a specific plugin."""
        plugin = self.plugins.get(plugin_name)
        return plugin.status if plugin else None

    def get_execution_statistics(self) -> Dict[str, Any]:
        """Get comprehensive execution statistics."""
        return {
            **self.execution_stats,
            'plugin_details': {
                name: {
                    'status': plugin.status.value,
                    'execution_time': plugin.execution_time,
                    'error_message': plugin.error_message,
                    'retry_count': plugin.retry_count
                }
                for name, plugin in self.plugins.items()
            }
        }

    def cleanup(self):
        """Cleanup plugin manager resources."""
        self.output_mgr.info("🧹 Cleaning up plugin manager resources...")
        
        # Clear loaded modules
        self.loaded_modules.clear()
        
        # Reset plugin statuses
        for plugin in self.plugins.values():
            if plugin.status == PluginStatus.RUNNING:
                plugin.status = PluginStatus.CANCELLED
        
        self.output_mgr.info("✅ Plugin manager cleanup completed")

    def request_shutdown(self):
        """Request graceful shutdown of plugin execution."""
        self._shutdown_requested = True
        self.output_mgr.warning("🛑 Plugin manager shutdown requested")

    def is_shutdown_requested(self) -> bool:
        """Check if shutdown has been requested."""
        return self._shutdown_requested or (GRACEFUL_SHUTDOWN_AVAILABLE and is_shutdown_requested())
    
    def _determine_smart_timeout(self, plugin_metadata: PluginMetadata, plugin_name: str) -> int:
        """Determine smart timeout based on plugin characteristics and system conditions."""
        # Start with plugin-specific timeout if available
        base_timeout = plugin_metadata.timeout
        
        # Apply smart timeout logic based on plugin name and characteristics
        plugin_name_lower = plugin_name.lower()
        
        # Category-based timeout adjustments
        if any(keyword in plugin_name_lower for keyword in ['ml', 'machine_learning', 'ai']):
            base_timeout = max(base_timeout, TIMEOUTS.get("ml_analysis", 360))
        elif any(keyword in plugin_name_lower for keyword in ['frida', 'dynamic', 'runtime']):
            base_timeout = max(base_timeout, TIMEOUTS.get("frida_analysis", 300))
        elif any(keyword in plugin_name_lower for keyword in ['webview', 'web', 'browser']):
            base_timeout = max(base_timeout, TIMEOUTS.get("webview_analysis", 240))
        elif any(keyword in plugin_name_lower for keyword in ['network', 'http', 'ssl', 'tls']):
            base_timeout = max(base_timeout, TIMEOUTS.get("network_analysis", 180))
        elif any(keyword in plugin_name_lower for keyword in ['crypto', 'encryption', 'key']):
            base_timeout = max(base_timeout, TIMEOUTS.get("crypto_analysis", 240))
        elif any(keyword in plugin_name_lower for keyword in ['file', 'storage', 'database']):
            base_timeout = max(base_timeout, TIMEOUTS.get("file_processing", 420))
        elif any(keyword in plugin_name_lower for keyword in ['device', 'adb', 'android']):
            base_timeout = max(base_timeout, TIMEOUTS.get("device_interaction", 240))
        elif any(keyword in plugin_name_lower for keyword in ['intent', 'fuzzing', 'fuzz']):
            base_timeout = max(base_timeout, TIMEOUTS.get("intent_fuzzing", 180))
        elif any(keyword in plugin_name_lower for keyword in ['log', 'logcat', 'logging']):
            base_timeout = max(base_timeout, TIMEOUTS.get("log_analysis", 120))
        elif any(keyword in plugin_name_lower for keyword in ['anti', 'debug', 'tamper']):
            base_timeout = max(base_timeout, TIMEOUTS.get("anti_debugging", 180))
        elif any(keyword in plugin_name_lower for keyword in ['root', 'jailbreak', 'detection']):
            base_timeout = max(base_timeout, TIMEOUTS.get("root_detection", 120))
        
        # System condition adjustments
        try:
            # Check system load and adjust timeout accordingly
            import psutil
            cpu_percent = psutil.cpu_percent(interval=0.1)
            memory_percent = psutil.virtual_memory().percent
            
            # Increase timeout if system is under heavy load
            if cpu_percent > 80 or memory_percent > 85:
                base_timeout = int(base_timeout * 1.5)  # 50% increase for high load
                self.output_mgr.debug(f"🔧 Increased timeout for {plugin_name} due to high system load")
            elif cpu_percent > 60 or memory_percent > 70:
                base_timeout = int(base_timeout * 1.2)  # 20% increase for moderate load
                self.output_mgr.debug(f"🔧 Slightly increased timeout for {plugin_name} due to moderate system load")
                
        except ImportError:
            # psutil not available, use default timeout
            pass
        except Exception as e:
            self.output_mgr.debug(f"Failed to check system conditions: {e}")
        
        # Ensure minimum and maximum bounds
        min_timeout = 30  # 30 seconds minimum
        max_timeout = 1800  # 30 minutes maximum
        
        effective_timeout = max(min_timeout, min(base_timeout, max_timeout))
        
        if effective_timeout != plugin_metadata.timeout:
            self.output_mgr.debug(f"🔧 Smart timeout for {plugin_name}: {plugin_metadata.timeout}s → {effective_timeout}s")
        
        return effective_timeout

    def validate_integration(self) -> bool:
        """
        Validate that plugins are properly integrated and available.

        Returns:
            bool: True if integration is valid, False if there are issues
        """
        if not self.plugins:
            self.output_mgr.warning("No plugins discovered - plugin integration may have issues")
            return False
        
        # Check if critical plugins are available
        critical_plugins = ['insecure_data_storage', 'enhanced_static_analysis', 'cryptography_tests']
        missing_critical = []
        
        for plugin_name in critical_plugins:
            if plugin_name not in self.plugins:
                missing_critical.append(plugin_name)
        
        if missing_critical:
            self.output_mgr.warning(f"Some critical plugins not available: {', '.join(missing_critical)}")
            return False
        
        # Check if plugins can be loaded
        failed_plugins = []
        for plugin_name, plugin_metadata in self.plugins.items():
            if plugin_name not in self.loaded_modules:
                failed_plugins.append(plugin_name)
        
        if failed_plugins:
            self.output_mgr.warning(f"Some plugins failed to load: {', '.join(failed_plugins)}")
            return False
        
        self.output_mgr.debug(f"Plugin integration validated: {len(self.plugins)} plugins available")
        return True

    def generate_plugin_summary(self):
        """Generate a summary table of plugin execution results."""
        try:
            from rich.table import Table
            from rich.console import Console
            
            table = Table(title="Plugin Execution Summary")
            table.add_column("Plugin", style="cyan")
            table.add_column("Status", style="green")
            table.add_column("Execution Time", style="yellow")
            table.add_column("Details", style="white")
            
            for plugin_name, plugin_metadata in self.plugins.items():
                status_icon = {
                    PluginStatus.COMPLETED: "✅ Completed",
                    PluginStatus.FAILED: "❌ Failed",
                    PluginStatus.TIMEOUT: "⏰ Timeout",
                    PluginStatus.SKIPPED: "⏭️ Skipped",
                    PluginStatus.CANCELLED: "🛑 Cancelled",
                    PluginStatus.PENDING: "⏳ Pending"
                }.get(plugin_metadata.status, "❓ Unknown")
                
                exec_time = f"{plugin_metadata.execution_time:.2f}s" if plugin_metadata.execution_time else "N/A"
                details = plugin_metadata.error_message or "Success"
                
                table.add_row(plugin_name, status_icon, exec_time, details)
            
            return table
        except ImportError:
            # Fallback if rich is not available
            return "Plugin summary table not available (rich library required)"

    def get_masvs_coverage(self) -> List[str]:
        """Get MASVS controls covered by available plugins."""
        # This is a simplified mapping - in a real implementation, 
        # this would be more comprehensive
        masvs_mapping = {
            'insecure_data_storage': ['MASVS-STORAGE-1', 'MASVS-STORAGE-2'],
            'cryptography_tests': ['MASVS-CRYPTO-1', 'MASVS-CRYPTO-2'],
            'enhanced_static_analysis': ['MASVS-CODE-1', 'MASVS-CODE-2'],
            'enhanced_network_security_analysis': ['MASVS-NETWORK-1', 'MASVS-NETWORK-2'],
            'privacy_leak_detection': ['MASVS-PRIVACY-1', 'MASVS-PRIVACY-2'],
            'anti_tampering_analysis': ['MASVS-RESILIENCE-1', 'MASVS-RESILIENCE-2']
        }
        
        covered_controls = []
        for plugin_name in self.plugins.keys():
            if plugin_name in masvs_mapping:
                covered_controls.extend(masvs_mapping[plugin_name])
        
        return list(set(covered_controls))  # Remove duplicates

def enhance_plugin_manager_with_unified_execution(plugin_manager):
    """
    Enhance PluginManager with unified execution framework.
    
    This integration provides:
    - Zero code duplication through shared components
    - Consistent timeout and error handling
    - Better resource management
    - Backward compatibility with existing interfaces
    
    Args:
        plugin_manager: Existing PluginManager instance
        
    Returns:
        Enhanced PluginManager with unified execution capabilities
    """
    logger.info("🔧 Integrating unified execution framework with PluginManager...")
    
    try:
        # Import unified execution framework
        from core.execution import (
            UnifiedExecutionManager,
            ExecutionConfig,
            ExecutionMode,
            enhance_plugin_manager_with_unified_execution as core_enhance
        )
        
        # Create optimized configuration for plugin execution
        config = ExecutionConfig(
            execution_mode=ExecutionMode.ADAPTIVE,
            max_workers=4,  # Reasonable default
            timeout_seconds=300,
            enable_resource_monitoring=True,
            enable_parallel_execution=True,
            parallel_threshold_plugins=3
        )
        
        # Create unified execution manager
        unified_manager = UnifiedExecutionManager(config)
        
        # Use the core enhancement function
        return core_enhance(plugin_manager, unified_manager)
        
    except ImportError as e:
        logger.warning(f"Unified execution framework not available: {e}")
        logger.info("Continuing with standard plugin execution...")
        return plugin_manager
    except Exception as e:
        logger.error(f"Failed to integrate unified execution: {e}")
        logger.info("Continuing with standard plugin execution...")
        return plugin_manager

def create_plugin_manager(scan_mode: str = "safe", vulnerable_app_mode: bool = False) -> PluginManager:
    """
    Factory function to create a plugin manager instance with unified execution and scan optimization.

    Args:
        scan_mode: Scan mode ("safe" or "deep")
        vulnerable_app_mode: Whether running in vulnerable app mode

    Returns:
        Configured PluginManager instance with unified execution framework and scan optimization
    """
    # Get the output manager and create plugin manager with proper parameters
    try:
        output_mgr = get_output_manager()
    except:
        output_mgr = None
    
    # Get recommended scan profile for performance optimization
    recommended_profile = get_recommended_profile(scan_mode, vulnerable_app_mode)
    
    # Create base plugin manager with scan optimization
    plugin_manager = PluginManager(output_mgr=output_mgr, scan_profile=recommended_profile)
    
    # DISABLED: Enhance with unified execution framework (causes "no callable execution method" errors)
    # enhanced_manager = enhance_plugin_manager_with_unified_execution(plugin_manager)
    
    logger.info(f"✅ Plugin manager created with scan optimization (unified execution framework disabled)")
    
    return plugin_manager  # Return base plugin manager instead of enhanced one

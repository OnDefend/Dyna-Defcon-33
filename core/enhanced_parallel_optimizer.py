#!/usr/bin/env python3
"""
Enhanced Parallel Execution Optimizer

This module provides advanced parallel execution optimizations on top of the
existing unified execution framework, adding:

- Intelligent plugin dependency management
- Lightning mode specific optimizations  
- Advanced resource allocation and scheduling
- Real-time performance monitoring and adjustment
- Smart plugin ordering and batching
"""

import logging
import threading
import time
import psutil
from collections import defaultdict, deque
from typing import Dict, List, Set, Optional, Any, Tuple
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, Future, as_completed

from core.execution import UnifiedExecutionManager, ExecutionConfig, ExecutionMode

logger = logging.getLogger(__name__)

@dataclass
class PluginDependency:
    """Represents a plugin dependency relationship."""
    plugin_name: str
    depends_on: List[str] = field(default_factory=list)
    provides: List[str] = field(default_factory=list)
    priority: int = 0  # Higher number = higher priority
    execution_weight: float = 1.0  # Resource requirement multiplier
    lightning_optimized: bool = False

@dataclass
class ExecutionBatch:
    """Represents a batch of plugins that can execute in parallel."""
    batch_id: int
    plugins: List[Any]
    dependencies_met: bool = True
    estimated_time: float = 0.0
    resource_requirement: float = 0.0

@dataclass
class ResourceAllocation:
    """Represents resource allocation for parallel execution."""
    cpu_workers: int
    memory_limit_mb: float
    io_threads: int
    network_threads: int
    lightning_priority_slots: int = 0

class EnhancedParallelOptimizer:
    """
    Enhanced parallel execution optimizer providing intelligent dependency
    management and resource optimization.
    """
    
    def __init__(self, base_manager: Optional[UnifiedExecutionManager] = None):
        """Initialize the enhanced parallel optimizer."""
        self.base_manager = base_manager or UnifiedExecutionManager()
        self.logger = logging.getLogger(__name__)
        
        # Dependency management
        self.dependency_graph: Dict[str, PluginDependency] = {}
        self.execution_order: List[ExecutionBatch] = []
        
        # Resource monitoring
        self.resource_monitor = RealTimeResourceMonitor()
        self.resource_allocator = IntelligentResourceAllocator()
        
        # Performance tracking
        self.performance_tracker = PerformanceTracker()
        
        # Lightning mode optimization
        self.lightning_optimizer = LightningModeOptimizer()
        
        # Thread safety
        self._optimization_lock = threading.RLock()
        
        self.logger.info("Enhanced Parallel Optimizer initialized")
    
    def optimize_execution(self, plugins: List[Any], apk_ctx: Any, 
                         lightning_mode: bool = False,
                         context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Optimize parallel execution with dependency management and resource allocation.
        
        Args:
            plugins: List of plugins to execute
            apk_ctx: APK context for analysis
            lightning_mode: Whether to use Lightning mode optimizations
            context: Additional execution context
            
        Returns:
            Optimized execution results
        """
        start_time = time.time()
        context = context or {}
        
        self.logger.info(f"Starting enhanced parallel optimization for {len(plugins)} plugins "
                        f"(Lightning mode: {lightning_mode})")
        
        with self._optimization_lock:
            try:
                # Step 1: Build dependency graph
                self._build_dependency_graph(plugins, lightning_mode)
                
                # Step 2: Create execution batches with dependency resolution
                execution_batches = self._create_execution_batches(plugins)
                
                # Step 3: Optimize resource allocation
                resource_allocation = self._optimize_resource_allocation(
                    execution_batches, lightning_mode
                )
                
                # Step 4: Execute with optimizations
                results = self._execute_optimized_batches(
                    execution_batches, apk_ctx, resource_allocation, lightning_mode
                )
                
                # Step 5: Update performance tracking
                execution_time = time.time() - start_time
                self._update_performance_tracking(plugins, execution_time, results, lightning_mode)
                
                # Compile final results
                final_results = {
                    'execution_results': results,
                    'optimization_stats': {
                        'total_plugins': len(plugins),
                        'execution_batches': len(execution_batches),
                        'total_time': execution_time,
                        'lightning_mode': lightning_mode,
                        'resource_allocation': resource_allocation,
                        'dependency_optimizations': len(self.dependency_graph),
                        'performance_improvement': self._calculate_performance_improvement(execution_time, len(plugins))
                    }
                }
                
                self.logger.info(f"Enhanced parallel optimization completed in {execution_time:.2f}s")
                return final_results
                
            except Exception as e:
                self.logger.error(f"Enhanced parallel optimization failed: {e}")
                # Fallback to base manager
                fallback_result = self.base_manager.execute(plugins, apk_ctx)
                return {
                    'execution_results': fallback_result.results,
                    'optimization_stats': {'fallback_used': True, 'error': str(e)}
                }
    
    def _build_dependency_graph(self, plugins: List[Any], lightning_mode: bool):
        """Build intelligent dependency graph for plugins."""
        self.dependency_graph.clear()
        
        for plugin in plugins:
            plugin_name = self._get_plugin_name(plugin)
            
            # Create dependency info
            dependency = PluginDependency(
                plugin_name=plugin_name,
                depends_on=self._analyze_plugin_dependencies(plugin),
                provides=self._analyze_plugin_outputs(plugin),
                priority=self._calculate_plugin_priority(plugin, lightning_mode),
                execution_weight=self._estimate_plugin_weight(plugin),
                lightning_optimized=self._is_lightning_optimized(plugin)
            )
            
            self.dependency_graph[plugin_name] = dependency
        
        self.logger.debug(f"Built dependency graph with {len(self.dependency_graph)} plugins")
    
    def _analyze_plugin_dependencies(self, plugin: Any) -> List[str]:
        """Analyze what dependencies a plugin has."""
        plugin_name = self._get_plugin_name(plugin).lower()
        dependencies = []
        
        # Known dependency patterns
        dependency_rules = {
            # Static analysis plugins that depend on JADX
            'enhanced_static_analysis': ['jadx_static_analysis'],
            'advanced_pattern_integration': ['jadx_static_analysis'],
            'code_quality_injection_analysis': ['jadx_static_analysis'],
            
            # Plugins that depend on manifest analysis
            'authentication_security_analysis': ['enhanced_manifest_analysis'],
            'privacy_controls_analysis': ['enhanced_manifest_analysis'],
            'network_cleartext_traffic': ['enhanced_manifest_analysis'],
            
            # Certificate-dependent plugins
            'advanced_ssl_tls_analyzer': ['apk_signing_certificate_analyzer'],
            
            # Dynamic analysis dependencies
            'frida_dynamic_analysis': ['enhanced_root_detection_bypass_analyzer'],
            'token_replay_analysis': ['network_communication_tests'],
        }
        
        for pattern, deps in dependency_rules.items():
            if pattern in plugin_name:
                dependencies.extend(deps)
        
        return dependencies
    
    def _analyze_plugin_outputs(self, plugin: Any) -> List[str]:
        """Analyze what outputs a plugin provides for other plugins."""
        plugin_name = self._get_plugin_name(plugin).lower()
        provides = []
        
        # Known output patterns
        output_rules = {
            'jadx_static_analysis': ['decompiled_sources', 'static_analysis_results'],
            'enhanced_manifest_analysis': ['manifest_data', 'permissions_analysis'],
            'apk_signing_certificate_analyzer': ['certificate_info', 'signing_data'],
            'enhanced_root_detection_bypass_analyzer': ['root_detection_patterns'],
            'network_communication_tests': ['network_baseline', 'communication_patterns'],
            'enhanced_static_analysis': ['vulnerability_patterns', 'security_findings'],
        }
        
        for pattern, outputs in output_rules.items():
            if pattern in plugin_name:
                provides.extend(outputs)
        
        return provides
    
    def _calculate_plugin_priority(self, plugin: Any, lightning_mode: bool) -> int:
        """Calculate plugin execution priority."""
        plugin_name = self._get_plugin_name(plugin).lower()
        base_priority = 0
        
        # Lightning mode priorities
        if lightning_mode:
            lightning_priority_plugins = {
                'enhanced_static_analysis': 10,
                'cryptography_tests': 9,
                'insecure_data_storage': 8,
                'enhanced_data_storage_analyzer': 7,
                'authentication_security_analysis': 6
            }
            
            for pattern, priority in lightning_priority_plugins.items():
                if pattern in plugin_name:
                    base_priority = max(base_priority, priority)
        
        # General priorities
        general_priorities = {
            'jadx_static_analysis': 15,  # Foundation for many other plugins
            'enhanced_manifest_analysis': 12,  # Provides core APK info
            'apk_signing_certificate_analyzer': 10,  # Certificate info needed early
            'enhanced_static_analysis': 8,  # Core static analysis
            'network_communication_tests': 6,  # Network baseline
        }
        
        for pattern, priority in general_priorities.items():
            if pattern in plugin_name:
                base_priority = max(base_priority, priority)
        
        return base_priority
    
    def _estimate_plugin_weight(self, plugin: Any) -> float:
        """Estimate computational weight of plugin."""
        plugin_name = self._get_plugin_name(plugin).lower()
        
        # Resource-intensive plugins
        heavy_plugins = {
            'jadx_static_analysis': 3.0,
            'advanced_pattern_integration': 2.5,
            'frida_dynamic_analysis': 2.0,
            'enhanced_static_analysis': 1.8,
            'library_vulnerability_scanner': 1.5,
        }
        
        # Lightweight plugins
        light_plugins = {
            'enhanced_manifest_analysis': 0.3,
            'apk_signing_certificate_analyzer': 0.4,
            'network_cleartext_traffic': 0.5,
            'cryptography_tests': 0.6,
        }
        
        # Check heavy plugins first
        for pattern, weight in heavy_plugins.items():
            if pattern in plugin_name:
                return weight
        
        # Check light plugins
        for pattern, weight in light_plugins.items():
            if pattern in plugin_name:
                return weight
        
        # Default weight
        return 1.0
    
    def _is_lightning_optimized(self, plugin: Any) -> bool:
        """Check if plugin is optimized for Lightning mode."""
        plugin_name = self._get_plugin_name(plugin).lower()
        
        lightning_optimized = {
            'enhanced_static_analysis', 'cryptography_tests', 'insecure_data_storage',
            'enhanced_data_storage_analyzer', 'authentication_security_analysis',
            'enhanced_manifest_analysis', 'network_cleartext_traffic'
        }
        
        return any(pattern in plugin_name for pattern in lightning_optimized)
    
    def _create_execution_batches(self, plugins: List[Any]) -> List[ExecutionBatch]:
        """Create execution batches respecting dependencies."""
        batches = []
        remaining_plugins = set(self._get_plugin_name(p) for p in plugins)
        completed_plugins = set()
        batch_id = 0
        
        while remaining_plugins:
            current_batch_plugins = []
            batch_weight = 0.0
            
            # Find plugins whose dependencies are satisfied
            for plugin_name in list(remaining_plugins):
                dependency = self.dependency_graph.get(plugin_name)
                if not dependency:
                    continue
                
                # Check if all dependencies are satisfied
                dependencies_met = all(dep in completed_plugins for dep in dependency.depends_on)
                
                if dependencies_met:
                    # Find the actual plugin object
                    plugin_obj = next((p for p in plugins if self._get_plugin_name(p) == plugin_name), None)
                    if plugin_obj:
                        current_batch_plugins.append(plugin_obj)
                        batch_weight += dependency.execution_weight
                        remaining_plugins.remove(plugin_name)
            
            if not current_batch_plugins:
                # Dependency deadlock - add remaining plugins anyway
                self.logger.warning("Dependency deadlock detected, adding remaining plugins")
                for plugin_name in remaining_plugins:
                    plugin_obj = next((p for p in plugins if self._get_plugin_name(p) == plugin_name), None)
                    if plugin_obj:
                        current_batch_plugins.append(plugin_obj)
                remaining_plugins.clear()
            
            # Create batch
            batch = ExecutionBatch(
                batch_id=batch_id,
                plugins=current_batch_plugins,
                dependencies_met=True,
                estimated_time=self._estimate_batch_time(current_batch_plugins),
                resource_requirement=batch_weight
            )
            
            batches.append(batch)
            
            # Mark plugins as completed for next iteration
            completed_plugins.update(self._get_plugin_name(p) for p in current_batch_plugins)
            batch_id += 1
        
        self.logger.info(f"Created {len(batches)} execution batches")
        return batches
    
    def _optimize_resource_allocation(self, batches: List[ExecutionBatch], 
                                    lightning_mode: bool) -> ResourceAllocation:
        """Optimize resource allocation for execution batches."""
        
        # Get current system resources
        system_resources = self.resource_monitor.get_current_resources()
        
        # Calculate optimal allocation
        total_plugins = sum(len(batch.plugins) for batch in batches)
        max_concurrent_plugins = max(len(batch.plugins) for batch in batches) if batches else 1
        
        # Base resource allocation
        cpu_workers = min(
            system_resources['cpu_cores'],
            max_concurrent_plugins,
            8  # Cap at 8 workers for stability
        )
        
        # Lightning mode gets priority
        if lightning_mode:
            memory_limit_mb = min(system_resources['available_memory_mb'] * 0.8, 4096)  # Up to 4GB
            lightning_priority_slots = max(cpu_workers // 2, 2)  # Reserve slots for Lightning
        else:
            memory_limit_mb = min(system_resources['available_memory_mb'] * 0.6, 2048)  # Up to 2GB
            lightning_priority_slots = 0
        
        # I/O and network optimization
        io_threads = min(cpu_workers, 4)
        network_threads = min(cpu_workers // 2, 2)
        
        allocation = ResourceAllocation(
            cpu_workers=cpu_workers,
            memory_limit_mb=memory_limit_mb,
            io_threads=io_threads,
            network_threads=network_threads,
            lightning_priority_slots=lightning_priority_slots
        )
        
        self.logger.info(f"Optimized resource allocation: {cpu_workers} workers, "
                        f"{memory_limit_mb:.0f}MB memory, Lightning slots: {lightning_priority_slots}")
        
        return allocation
    
    def _execute_optimized_batches(self, batches: List[ExecutionBatch], apk_ctx: Any,
                                 allocation: ResourceAllocation, lightning_mode: bool) -> Dict[str, Any]:
        """Execute batches with optimized resource allocation."""
        
        all_results = {}
        total_start_time = time.time()
        
        for i, batch in enumerate(batches):
            batch_start_time = time.time()
            
            self.logger.info(f"Executing batch {i+1}/{len(batches)} with {len(batch.plugins)} plugins")
            
            # Lightning mode optimization
            if lightning_mode and allocation.lightning_priority_slots > 0:
                # Prioritize Lightning plugins
                lightning_plugins = [p for p in batch.plugins if self._is_lightning_optimized(p)]
                regular_plugins = [p for p in batch.plugins if not self._is_lightning_optimized(p)]
                
                if lightning_plugins:
                    # Execute Lightning plugins with priority
                    lightning_results = self._execute_plugin_batch(
                        lightning_plugins, apk_ctx, allocation.lightning_priority_slots
                    )
                    all_results.update(lightning_results)
                
                if regular_plugins:
                    # Execute remaining plugins
                    remaining_workers = max(allocation.cpu_workers - allocation.lightning_priority_slots, 1)
                    regular_results = self._execute_plugin_batch(
                        regular_plugins, apk_ctx, remaining_workers
                    )
                    all_results.update(regular_results)
            else:
                # Standard parallel execution
                batch_results = self._execute_plugin_batch(batch.plugins, apk_ctx, allocation.cpu_workers)
                all_results.update(batch_results)
            
            batch_time = time.time() - batch_start_time
            self.logger.debug(f"Batch {i+1} completed in {batch_time:.2f}s")
        
        total_time = time.time() - total_start_time
        self.logger.info(f"All batches completed in {total_time:.2f}s")
        
        return all_results
    
    def _execute_plugin_batch(self, plugins: List[Any], apk_ctx: Any, max_workers: int) -> Dict[str, Any]:
        """Execute a batch of plugins in parallel."""
        if not plugins:
            return {}
        
        results = {}
        
        with ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="EnhancedParallel") as executor:
            # Submit all plugins
            future_to_plugin = {}
            for plugin in plugins:
                future = executor.submit(self._execute_single_plugin, plugin, apk_ctx)
                future_to_plugin[future] = plugin
            
            # Collect results
            for future in as_completed(future_to_plugin):
                plugin = future_to_plugin[future]
                plugin_name = self._get_plugin_name(plugin)
                
                try:
                    result = future.result()
                    results[plugin_name] = result
                except Exception as e:
                    self.logger.error(f"Plugin {plugin_name} failed: {e}")
                    results[plugin_name] = f"❌ Error: {e}"
        
        return results
    
    def _execute_single_plugin(self, plugin: Any, apk_ctx: Any) -> Any:
        """Execute a single plugin with resource monitoring."""
        plugin_name = self._get_plugin_name(plugin)
        start_time = time.time()
        
        try:
            # Use the base manager's plugin executor
            result = self.base_manager.plugin_executor.execute_plugin(plugin, apk_ctx)
            
            execution_time = time.time() - start_time
            self.performance_tracker.record_execution(plugin_name, execution_time, True)
            
            return result.result if hasattr(result, 'result') else result
            
        except Exception as e:
            execution_time = time.time() - start_time
            self.performance_tracker.record_execution(plugin_name, execution_time, False)
            raise
    
    def _get_plugin_name(self, plugin: Any) -> str:
        """Get plugin name from plugin object."""
        if hasattr(plugin, '__name__'):
            return plugin.__name__
        elif hasattr(plugin, 'name'):
            return plugin.name
        elif hasattr(plugin, '__class__'):
            return plugin.__class__.__name__
        else:
            return str(plugin)
    
    def _estimate_batch_time(self, plugins: List[Any]) -> float:
        """Estimate execution time for a batch of plugins."""
        total_weight = sum(
            self.dependency_graph.get(self._get_plugin_name(p), PluginDependency("")).execution_weight
            for p in plugins
        )
        # Rough estimate: 1.0 weight = 1 second, with parallel efficiency
        return total_weight * 0.8  # 20% efficiency gain from parallelization
    
    def _update_performance_tracking(self, plugins: List[Any], execution_time: float, 
                                   results: Dict[str, Any], lightning_mode: bool):
        """Update performance tracking data."""
        self.performance_tracker.record_full_execution(
            len(plugins), execution_time, len(results), lightning_mode
        )
    
    def _calculate_performance_improvement(self, execution_time: float, plugin_count: int) -> float:
        """Calculate performance improvement over sequential execution."""
        # Rough estimate: sequential would take plugin_count * 2 seconds
        estimated_sequential_time = plugin_count * 2.0
        improvement = max(0, (estimated_sequential_time - execution_time) / estimated_sequential_time * 100)
        return improvement

class RealTimeResourceMonitor:
    """Real-time system resource monitoring."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def get_current_resources(self) -> Dict[str, Any]:
        """Get current system resource status."""
        try:
            cpu_percent = psutil.cpu_percent(interval=0.1)
            memory = psutil.virtual_memory()
            
            return {
                'cpu_cores': psutil.cpu_count(),
                'cpu_percent': cpu_percent,
                'available_memory_mb': memory.available / (1024 * 1024),
                'memory_percent': memory.percent,
                'disk_io': psutil.disk_io_counters() is not None
            }
        except Exception as e:
            self.logger.warning(f"Resource monitoring failed: {e}")
            return {
                'cpu_cores': 4,
                'cpu_percent': 50.0,
                'available_memory_mb': 2048,
                'memory_percent': 50.0,
                'disk_io': True
            }

class IntelligentResourceAllocator:
    """Intelligent resource allocation for optimal performance."""
    
    def __init__(self):
        self.allocation_history = []
    
    def allocate_resources(self, requirements: Dict[str, float]) -> Dict[str, int]:
        """Allocate resources based on requirements."""
        # This would contain sophisticated resource allocation logic
        return {
            'cpu_workers': min(requirements.get('cpu', 4), 8),
            'memory_mb': min(requirements.get('memory', 1024), 4096),
            'io_threads': min(requirements.get('io', 2), 4)
        }

class LightningModeOptimizer:
    """Specialized optimizer for Lightning mode scans."""
    
    def __init__(self):
        self.lightning_patterns = set()
        self.optimization_cache = {}
    
    def optimize_for_lightning(self, plugins: List[Any]) -> List[Any]:
        """Optimize plugin order and configuration for Lightning mode."""
        # Sort plugins by Lightning optimization and priority
        lightning_plugins = [p for p in plugins if self._is_lightning_optimized(p)]
        regular_plugins = [p for p in plugins if not self._is_lightning_optimized(p)]
        
        # Lightning plugins go first
        return lightning_plugins + regular_plugins
    
    def _is_lightning_optimized(self, plugin: Any) -> bool:
        """Check if plugin is Lightning optimized."""
        plugin_name = str(plugin).lower()
        lightning_patterns = {
            'enhanced_static_analysis', 'cryptography_tests', 'insecure_data_storage'
        }
        return any(pattern in plugin_name for pattern in lightning_patterns)

class PerformanceTracker:
    """Track and analyze execution performance."""
    
    def __init__(self):
        self.execution_history = []
        self.plugin_performance = defaultdict(list)
    
    def record_execution(self, plugin_name: str, execution_time: float, success: bool):
        """Record individual plugin execution."""
        self.plugin_performance[plugin_name].append({
            'time': execution_time,
            'success': success,
            'timestamp': time.time()
        })
    
    def record_full_execution(self, plugin_count: int, total_time: float, 
                            successful_plugins: int, lightning_mode: bool):
        """Record full execution statistics."""
        self.execution_history.append({
            'plugin_count': plugin_count,
            'total_time': total_time,
            'successful_plugins': successful_plugins,
            'lightning_mode': lightning_mode,
            'timestamp': time.time()
        })
    
    def get_performance_stats(self) -> Dict[str, Any]:
        """Get comprehensive performance statistics."""
        if not self.execution_history:
            return {}
        
        recent_executions = self.execution_history[-10:]  # Last 10 executions
        avg_time = sum(e['total_time'] for e in recent_executions) / len(recent_executions)
        avg_success_rate = sum(e['successful_plugins'] / e['plugin_count'] for e in recent_executions) / len(recent_executions)
        
        return {
            'average_execution_time': avg_time,
            'average_success_rate': avg_success_rate,
            'total_executions': len(self.execution_history),
            'lightning_mode_executions': sum(1 for e in self.execution_history if e['lightning_mode'])
        }

# Factory function for easy usage
def create_enhanced_parallel_optimizer(config: Optional[ExecutionConfig] = None) -> EnhancedParallelOptimizer:
    """Create enhanced parallel optimizer with optional configuration."""
    if config:
        base_manager = UnifiedExecutionManager(config)
    else:
        base_manager = UnifiedExecutionManager()
    
    return EnhancedParallelOptimizer(base_manager)

# Convenience function for direct optimization
def optimize_parallel_execution(plugins: List[Any], apk_ctx: Any, 
                               lightning_mode: bool = False) -> Dict[str, Any]:
    """Convenience function for optimized parallel execution."""
    optimizer = create_enhanced_parallel_optimizer()
    return optimizer.optimize_execution(plugins, apk_ctx, lightning_mode) 
"""
Enhanced Parallel Execution Optimizer

This module provides advanced parallel execution optimizations on top of the
existing unified execution framework, adding:

- Intelligent plugin dependency management
- Lightning mode specific optimizations  
- Advanced resource allocation and scheduling
- Real-time performance monitoring and adjustment
- Smart plugin ordering and batching
"""

import logging
import threading
import time
import psutil
from collections import defaultdict, deque
from typing import Dict, List, Set, Optional, Any, Tuple
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, Future, as_completed

from core.execution import UnifiedExecutionManager, ExecutionConfig, ExecutionMode

logger = logging.getLogger(__name__)

@dataclass
class PluginDependency:
    """Represents a plugin dependency relationship."""
    plugin_name: str
    depends_on: List[str] = field(default_factory=list)
    provides: List[str] = field(default_factory=list)
    priority: int = 0  # Higher number = higher priority
    execution_weight: float = 1.0  # Resource requirement multiplier
    lightning_optimized: bool = False

@dataclass
class ExecutionBatch:
    """Represents a batch of plugins that can execute in parallel."""
    batch_id: int
    plugins: List[Any]
    dependencies_met: bool = True
    estimated_time: float = 0.0
    resource_requirement: float = 0.0

@dataclass
class ResourceAllocation:
    """Represents resource allocation for parallel execution."""
    cpu_workers: int
    memory_limit_mb: float
    io_threads: int
    network_threads: int
    lightning_priority_slots: int = 0

class EnhancedParallelOptimizer:
    """
    Enhanced parallel execution optimizer providing intelligent dependency
    management and resource optimization.
    """
    
    def __init__(self, base_manager: Optional[UnifiedExecutionManager] = None):
        """Initialize the enhanced parallel optimizer."""
        self.base_manager = base_manager or UnifiedExecutionManager()
        self.logger = logging.getLogger(__name__)
        
        # Dependency management
        self.dependency_graph: Dict[str, PluginDependency] = {}
        self.execution_order: List[ExecutionBatch] = []
        
        # Resource monitoring
        self.resource_monitor = RealTimeResourceMonitor()
        self.resource_allocator = IntelligentResourceAllocator()
        
        # Performance tracking
        self.performance_tracker = PerformanceTracker()
        
        # Lightning mode optimization
        self.lightning_optimizer = LightningModeOptimizer()
        
        # Thread safety
        self._optimization_lock = threading.RLock()
        
        self.logger.info("Enhanced Parallel Optimizer initialized")
    
    def optimize_execution(self, plugins: List[Any], apk_ctx: Any, 
                         lightning_mode: bool = False,
                         context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Optimize parallel execution with dependency management and resource allocation.
        
        Args:
            plugins: List of plugins to execute
            apk_ctx: APK context for analysis
            lightning_mode: Whether to use Lightning mode optimizations
            context: Additional execution context
            
        Returns:
            Optimized execution results
        """
        start_time = time.time()
        context = context or {}
        
        self.logger.info(f"Starting enhanced parallel optimization for {len(plugins)} plugins "
                        f"(Lightning mode: {lightning_mode})")
        
        with self._optimization_lock:
            try:
                # Step 1: Build dependency graph
                self._build_dependency_graph(plugins, lightning_mode)
                
                # Step 2: Create execution batches with dependency resolution
                execution_batches = self._create_execution_batches(plugins)
                
                # Step 3: Optimize resource allocation
                resource_allocation = self._optimize_resource_allocation(
                    execution_batches, lightning_mode
                )
                
                # Step 4: Execute with optimizations
                results = self._execute_optimized_batches(
                    execution_batches, apk_ctx, resource_allocation, lightning_mode
                )
                
                # Step 5: Update performance tracking
                execution_time = time.time() - start_time
                self._update_performance_tracking(plugins, execution_time, results, lightning_mode)
                
                # Compile final results
                final_results = {
                    'execution_results': results,
                    'optimization_stats': {
                        'total_plugins': len(plugins),
                        'execution_batches': len(execution_batches),
                        'total_time': execution_time,
                        'lightning_mode': lightning_mode,
                        'resource_allocation': resource_allocation,
                        'dependency_optimizations': len(self.dependency_graph),
                        'performance_improvement': self._calculate_performance_improvement(execution_time, len(plugins))
                    }
                }
                
                self.logger.info(f"Enhanced parallel optimization completed in {execution_time:.2f}s")
                return final_results
                
            except Exception as e:
                self.logger.error(f"Enhanced parallel optimization failed: {e}")
                # Fallback to base manager
                fallback_result = self.base_manager.execute(plugins, apk_ctx)
                return {
                    'execution_results': fallback_result.results,
                    'optimization_stats': {'fallback_used': True, 'error': str(e)}
                }
    
    def _build_dependency_graph(self, plugins: List[Any], lightning_mode: bool):
        """Build intelligent dependency graph for plugins."""
        self.dependency_graph.clear()
        
        for plugin in plugins:
            plugin_name = self._get_plugin_name(plugin)
            
            # Create dependency info
            dependency = PluginDependency(
                plugin_name=plugin_name,
                depends_on=self._analyze_plugin_dependencies(plugin),
                provides=self._analyze_plugin_outputs(plugin),
                priority=self._calculate_plugin_priority(plugin, lightning_mode),
                execution_weight=self._estimate_plugin_weight(plugin),
                lightning_optimized=self._is_lightning_optimized(plugin)
            )
            
            self.dependency_graph[plugin_name] = dependency
        
        self.logger.debug(f"Built dependency graph with {len(self.dependency_graph)} plugins")
    
    def _analyze_plugin_dependencies(self, plugin: Any) -> List[str]:
        """Analyze what dependencies a plugin has."""
        plugin_name = self._get_plugin_name(plugin).lower()
        dependencies = []
        
        # Known dependency patterns
        dependency_rules = {
            # Static analysis plugins that depend on JADX
            'enhanced_static_analysis': ['jadx_static_analysis'],
            'advanced_pattern_integration': ['jadx_static_analysis'],
            'code_quality_injection_analysis': ['jadx_static_analysis'],
            
            # Plugins that depend on manifest analysis
            'authentication_security_analysis': ['enhanced_manifest_analysis'],
            'privacy_controls_analysis': ['enhanced_manifest_analysis'],
            'network_cleartext_traffic': ['enhanced_manifest_analysis'],
            
            # Certificate-dependent plugins
            'advanced_ssl_tls_analyzer': ['apk_signing_certificate_analyzer'],
            
            # Dynamic analysis dependencies
            'frida_dynamic_analysis': ['enhanced_root_detection_bypass_analyzer'],
            'token_replay_analysis': ['network_communication_tests'],
        }
        
        for pattern, deps in dependency_rules.items():
            if pattern in plugin_name:
                dependencies.extend(deps)
        
        return dependencies
    
    def _analyze_plugin_outputs(self, plugin: Any) -> List[str]:
        """Analyze what outputs a plugin provides for other plugins."""
        plugin_name = self._get_plugin_name(plugin).lower()
        provides = []
        
        # Known output patterns
        output_rules = {
            'jadx_static_analysis': ['decompiled_sources', 'static_analysis_results'],
            'enhanced_manifest_analysis': ['manifest_data', 'permissions_analysis'],
            'apk_signing_certificate_analyzer': ['certificate_info', 'signing_data'],
            'enhanced_root_detection_bypass_analyzer': ['root_detection_patterns'],
            'network_communication_tests': ['network_baseline', 'communication_patterns'],
            'enhanced_static_analysis': ['vulnerability_patterns', 'security_findings'],
        }
        
        for pattern, outputs in output_rules.items():
            if pattern in plugin_name:
                provides.extend(outputs)
        
        return provides
    
    def _calculate_plugin_priority(self, plugin: Any, lightning_mode: bool) -> int:
        """Calculate plugin execution priority."""
        plugin_name = self._get_plugin_name(plugin).lower()
        base_priority = 0
        
        # Lightning mode priorities
        if lightning_mode:
            lightning_priority_plugins = {
                'enhanced_static_analysis': 10,
                'cryptography_tests': 9,
                'insecure_data_storage': 8,
                'enhanced_data_storage_analyzer': 7,
                'authentication_security_analysis': 6
            }
            
            for pattern, priority in lightning_priority_plugins.items():
                if pattern in plugin_name:
                    base_priority = max(base_priority, priority)
        
        # General priorities
        general_priorities = {
            'jadx_static_analysis': 15,  # Foundation for many other plugins
            'enhanced_manifest_analysis': 12,  # Provides core APK info
            'apk_signing_certificate_analyzer': 10,  # Certificate info needed early
            'enhanced_static_analysis': 8,  # Core static analysis
            'network_communication_tests': 6,  # Network baseline
        }
        
        for pattern, priority in general_priorities.items():
            if pattern in plugin_name:
                base_priority = max(base_priority, priority)
        
        return base_priority
    
    def _estimate_plugin_weight(self, plugin: Any) -> float:
        """Estimate computational weight of plugin."""
        plugin_name = self._get_plugin_name(plugin).lower()
        
        # Resource-intensive plugins
        heavy_plugins = {
            'jadx_static_analysis': 3.0,
            'advanced_pattern_integration': 2.5,
            'frida_dynamic_analysis': 2.0,
            'enhanced_static_analysis': 1.8,
            'library_vulnerability_scanner': 1.5,
        }
        
        # Lightweight plugins
        light_plugins = {
            'enhanced_manifest_analysis': 0.3,
            'apk_signing_certificate_analyzer': 0.4,
            'network_cleartext_traffic': 0.5,
            'cryptography_tests': 0.6,
        }
        
        # Check heavy plugins first
        for pattern, weight in heavy_plugins.items():
            if pattern in plugin_name:
                return weight
        
        # Check light plugins
        for pattern, weight in light_plugins.items():
            if pattern in plugin_name:
                return weight
        
        # Default weight
        return 1.0
    
    def _is_lightning_optimized(self, plugin: Any) -> bool:
        """Check if plugin is optimized for Lightning mode."""
        plugin_name = self._get_plugin_name(plugin).lower()
        
        lightning_optimized = {
            'enhanced_static_analysis', 'cryptography_tests', 'insecure_data_storage',
            'enhanced_data_storage_analyzer', 'authentication_security_analysis',
            'enhanced_manifest_analysis', 'network_cleartext_traffic'
        }
        
        return any(pattern in plugin_name for pattern in lightning_optimized)
    
    def _create_execution_batches(self, plugins: List[Any]) -> List[ExecutionBatch]:
        """Create execution batches respecting dependencies."""
        batches = []
        remaining_plugins = set(self._get_plugin_name(p) for p in plugins)
        completed_plugins = set()
        batch_id = 0
        
        while remaining_plugins:
            current_batch_plugins = []
            batch_weight = 0.0
            
            # Find plugins whose dependencies are satisfied
            for plugin_name in list(remaining_plugins):
                dependency = self.dependency_graph.get(plugin_name)
                if not dependency:
                    continue
                
                # Check if all dependencies are satisfied
                dependencies_met = all(dep in completed_plugins for dep in dependency.depends_on)
                
                if dependencies_met:
                    # Find the actual plugin object
                    plugin_obj = next((p for p in plugins if self._get_plugin_name(p) == plugin_name), None)
                    if plugin_obj:
                        current_batch_plugins.append(plugin_obj)
                        batch_weight += dependency.execution_weight
                        remaining_plugins.remove(plugin_name)
            
            if not current_batch_plugins:
                # Dependency deadlock - add remaining plugins anyway
                self.logger.warning("Dependency deadlock detected, adding remaining plugins")
                for plugin_name in remaining_plugins:
                    plugin_obj = next((p for p in plugins if self._get_plugin_name(p) == plugin_name), None)
                    if plugin_obj:
                        current_batch_plugins.append(plugin_obj)
                remaining_plugins.clear()
            
            # Create batch
            batch = ExecutionBatch(
                batch_id=batch_id,
                plugins=current_batch_plugins,
                dependencies_met=True,
                estimated_time=self._estimate_batch_time(current_batch_plugins),
                resource_requirement=batch_weight
            )
            
            batches.append(batch)
            
            # Mark plugins as completed for next iteration
            completed_plugins.update(self._get_plugin_name(p) for p in current_batch_plugins)
            batch_id += 1
        
        self.logger.info(f"Created {len(batches)} execution batches")
        return batches
    
    def _optimize_resource_allocation(self, batches: List[ExecutionBatch], 
                                    lightning_mode: bool) -> ResourceAllocation:
        """Optimize resource allocation for execution batches."""
        
        # Get current system resources
        system_resources = self.resource_monitor.get_current_resources()
        
        # Calculate optimal allocation
        total_plugins = sum(len(batch.plugins) for batch in batches)
        max_concurrent_plugins = max(len(batch.plugins) for batch in batches) if batches else 1
        
        # Base resource allocation
        cpu_workers = min(
            system_resources['cpu_cores'],
            max_concurrent_plugins,
            8  # Cap at 8 workers for stability
        )
        
        # Lightning mode gets priority
        if lightning_mode:
            memory_limit_mb = min(system_resources['available_memory_mb'] * 0.8, 4096)  # Up to 4GB
            lightning_priority_slots = max(cpu_workers // 2, 2)  # Reserve slots for Lightning
        else:
            memory_limit_mb = min(system_resources['available_memory_mb'] * 0.6, 2048)  # Up to 2GB
            lightning_priority_slots = 0
        
        # I/O and network optimization
        io_threads = min(cpu_workers, 4)
        network_threads = min(cpu_workers // 2, 2)
        
        allocation = ResourceAllocation(
            cpu_workers=cpu_workers,
            memory_limit_mb=memory_limit_mb,
            io_threads=io_threads,
            network_threads=network_threads,
            lightning_priority_slots=lightning_priority_slots
        )
        
        self.logger.info(f"Optimized resource allocation: {cpu_workers} workers, "
                        f"{memory_limit_mb:.0f}MB memory, Lightning slots: {lightning_priority_slots}")
        
        return allocation
    
    def _execute_optimized_batches(self, batches: List[ExecutionBatch], apk_ctx: Any,
                                 allocation: ResourceAllocation, lightning_mode: bool) -> Dict[str, Any]:
        """Execute batches with optimized resource allocation."""
        
        all_results = {}
        total_start_time = time.time()
        
        for i, batch in enumerate(batches):
            batch_start_time = time.time()
            
            self.logger.info(f"Executing batch {i+1}/{len(batches)} with {len(batch.plugins)} plugins")
            
            # Lightning mode optimization
            if lightning_mode and allocation.lightning_priority_slots > 0:
                # Prioritize Lightning plugins
                lightning_plugins = [p for p in batch.plugins if self._is_lightning_optimized(p)]
                regular_plugins = [p for p in batch.plugins if not self._is_lightning_optimized(p)]
                
                if lightning_plugins:
                    # Execute Lightning plugins with priority
                    lightning_results = self._execute_plugin_batch(
                        lightning_plugins, apk_ctx, allocation.lightning_priority_slots
                    )
                    all_results.update(lightning_results)
                
                if regular_plugins:
                    # Execute remaining plugins
                    remaining_workers = max(allocation.cpu_workers - allocation.lightning_priority_slots, 1)
                    regular_results = self._execute_plugin_batch(
                        regular_plugins, apk_ctx, remaining_workers
                    )
                    all_results.update(regular_results)
            else:
                # Standard parallel execution
                batch_results = self._execute_plugin_batch(batch.plugins, apk_ctx, allocation.cpu_workers)
                all_results.update(batch_results)
            
            batch_time = time.time() - batch_start_time
            self.logger.debug(f"Batch {i+1} completed in {batch_time:.2f}s")
        
        total_time = time.time() - total_start_time
        self.logger.info(f"All batches completed in {total_time:.2f}s")
        
        return all_results
    
    def _execute_plugin_batch(self, plugins: List[Any], apk_ctx: Any, max_workers: int) -> Dict[str, Any]:
        """Execute a batch of plugins in parallel."""
        if not plugins:
            return {}
        
        results = {}
        
        with ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="EnhancedParallel") as executor:
            # Submit all plugins
            future_to_plugin = {}
            for plugin in plugins:
                future = executor.submit(self._execute_single_plugin, plugin, apk_ctx)
                future_to_plugin[future] = plugin
            
            # Collect results
            for future in as_completed(future_to_plugin):
                plugin = future_to_plugin[future]
                plugin_name = self._get_plugin_name(plugin)
                
                try:
                    result = future.result()
                    results[plugin_name] = result
                except Exception as e:
                    self.logger.error(f"Plugin {plugin_name} failed: {e}")
                    results[plugin_name] = f"❌ Error: {e}"
        
        return results
    
    def _execute_single_plugin(self, plugin: Any, apk_ctx: Any) -> Any:
        """Execute a single plugin with resource monitoring."""
        plugin_name = self._get_plugin_name(plugin)
        start_time = time.time()
        
        try:
            # Use the base manager's plugin executor
            result = self.base_manager.plugin_executor.execute_plugin(plugin, apk_ctx)
            
            execution_time = time.time() - start_time
            self.performance_tracker.record_execution(plugin_name, execution_time, True)
            
            return result.result if hasattr(result, 'result') else result
            
        except Exception as e:
            execution_time = time.time() - start_time
            self.performance_tracker.record_execution(plugin_name, execution_time, False)
            raise
    
    def _get_plugin_name(self, plugin: Any) -> str:
        """Get plugin name from plugin object."""
        if hasattr(plugin, '__name__'):
            return plugin.__name__
        elif hasattr(plugin, 'name'):
            return plugin.name
        elif hasattr(plugin, '__class__'):
            return plugin.__class__.__name__
        else:
            return str(plugin)
    
    def _estimate_batch_time(self, plugins: List[Any]) -> float:
        """Estimate execution time for a batch of plugins."""
        total_weight = sum(
            self.dependency_graph.get(self._get_plugin_name(p), PluginDependency("")).execution_weight
            for p in plugins
        )
        # Rough estimate: 1.0 weight = 1 second, with parallel efficiency
        return total_weight * 0.8  # 20% efficiency gain from parallelization
    
    def _update_performance_tracking(self, plugins: List[Any], execution_time: float, 
                                   results: Dict[str, Any], lightning_mode: bool):
        """Update performance tracking data."""
        self.performance_tracker.record_full_execution(
            len(plugins), execution_time, len(results), lightning_mode
        )
    
    def _calculate_performance_improvement(self, execution_time: float, plugin_count: int) -> float:
        """Calculate performance improvement over sequential execution."""
        # Rough estimate: sequential would take plugin_count * 2 seconds
        estimated_sequential_time = plugin_count * 2.0
        improvement = max(0, (estimated_sequential_time - execution_time) / estimated_sequential_time * 100)
        return improvement

class RealTimeResourceMonitor:
    """Real-time system resource monitoring."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def get_current_resources(self) -> Dict[str, Any]:
        """Get current system resource status."""
        try:
            cpu_percent = psutil.cpu_percent(interval=0.1)
            memory = psutil.virtual_memory()
            
            return {
                'cpu_cores': psutil.cpu_count(),
                'cpu_percent': cpu_percent,
                'available_memory_mb': memory.available / (1024 * 1024),
                'memory_percent': memory.percent,
                'disk_io': psutil.disk_io_counters() is not None
            }
        except Exception as e:
            self.logger.warning(f"Resource monitoring failed: {e}")
            return {
                'cpu_cores': 4,
                'cpu_percent': 50.0,
                'available_memory_mb': 2048,
                'memory_percent': 50.0,
                'disk_io': True
            }

class IntelligentResourceAllocator:
    """Intelligent resource allocation for optimal performance."""
    
    def __init__(self):
        self.allocation_history = []
    
    def allocate_resources(self, requirements: Dict[str, float]) -> Dict[str, int]:
        """Allocate resources based on requirements."""
        # This would contain sophisticated resource allocation logic
        return {
            'cpu_workers': min(requirements.get('cpu', 4), 8),
            'memory_mb': min(requirements.get('memory', 1024), 4096),
            'io_threads': min(requirements.get('io', 2), 4)
        }

class LightningModeOptimizer:
    """Specialized optimizer for Lightning mode scans."""
    
    def __init__(self):
        self.lightning_patterns = set()
        self.optimization_cache = {}
    
    def optimize_for_lightning(self, plugins: List[Any]) -> List[Any]:
        """Optimize plugin order and configuration for Lightning mode."""
        # Sort plugins by Lightning optimization and priority
        lightning_plugins = [p for p in plugins if self._is_lightning_optimized(p)]
        regular_plugins = [p for p in plugins if not self._is_lightning_optimized(p)]
        
        # Lightning plugins go first
        return lightning_plugins + regular_plugins
    
    def _is_lightning_optimized(self, plugin: Any) -> bool:
        """Check if plugin is Lightning optimized."""
        plugin_name = str(plugin).lower()
        lightning_patterns = {
            'enhanced_static_analysis', 'cryptography_tests', 'insecure_data_storage'
        }
        return any(pattern in plugin_name for pattern in lightning_patterns)

class PerformanceTracker:
    """Track and analyze execution performance."""
    
    def __init__(self):
        self.execution_history = []
        self.plugin_performance = defaultdict(list)
    
    def record_execution(self, plugin_name: str, execution_time: float, success: bool):
        """Record individual plugin execution."""
        self.plugin_performance[plugin_name].append({
            'time': execution_time,
            'success': success,
            'timestamp': time.time()
        })
    
    def record_full_execution(self, plugin_count: int, total_time: float, 
                            successful_plugins: int, lightning_mode: bool):
        """Record full execution statistics."""
        self.execution_history.append({
            'plugin_count': plugin_count,
            'total_time': total_time,
            'successful_plugins': successful_plugins,
            'lightning_mode': lightning_mode,
            'timestamp': time.time()
        })
    
    def get_performance_stats(self) -> Dict[str, Any]:
        """Get comprehensive performance statistics."""
        if not self.execution_history:
            return {}
        
        recent_executions = self.execution_history[-10:]  # Last 10 executions
        avg_time = sum(e['total_time'] for e in recent_executions) / len(recent_executions)
        avg_success_rate = sum(e['successful_plugins'] / e['plugin_count'] for e in recent_executions) / len(recent_executions)
        
        return {
            'average_execution_time': avg_time,
            'average_success_rate': avg_success_rate,
            'total_executions': len(self.execution_history),
            'lightning_mode_executions': sum(1 for e in self.execution_history if e['lightning_mode'])
        }

# Factory function for easy usage
def create_enhanced_parallel_optimizer(config: Optional[ExecutionConfig] = None) -> EnhancedParallelOptimizer:
    """Create enhanced parallel optimizer with optional configuration."""
    if config:
        base_manager = UnifiedExecutionManager(config)
    else:
        base_manager = UnifiedExecutionManager()
    
    return EnhancedParallelOptimizer(base_manager)

# Convenience function for direct optimization
def optimize_parallel_execution(plugins: List[Any], apk_ctx: Any, 
                               lightning_mode: bool = False) -> Dict[str, Any]:
    """Convenience function for optimized parallel execution."""
    optimizer = create_enhanced_parallel_optimizer()
    return optimizer.optimize_execution(plugins, apk_ctx, lightning_mode) 
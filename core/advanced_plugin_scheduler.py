#!/usr/bin/env python3
"""
Advanced Plugin Scheduler for AODS

This module implements advanced parallel optimizations for plugin execution
scheduling and resource management in the AODS security testing framework.

Provides plugin-specific optimizations through:
- Affinity-based worker pools
- Dynamic resource allocation
- Plugin profiling and learning
- Smart batching and pipeline optimization
"""

import logging
import threading
import time
from collections import defaultdict
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple, Union

import psutil
from rich.console import Console
from rich.table import Table
from rich.text import Text

from core.optimized_apk_processor import MemoryMetrics, MemoryMonitor
from core.output_manager import get_output_manager
from core.plugin_manager import PluginCategory, PluginMetadata, PluginStatus

logger = logging.getLogger(__name__)

class PluginAffinityType(Enum):
    """Plugin affinity classification for optimized scheduling."""

    CPU_INTENSIVE = "cpu_intensive"  # JADX, static analysis
    IO_INTENSIVE = "io_intensive"  # File scanning, APK parsing
    MEMORY_INTENSIVE = "memory_intensive"  # Large data processing
    NETWORK_INTENSIVE = "network_intensive"  # MITM, external services
    DEVICE_DEPENDENT = "device_dependent"  # ADB, Frida operations
    CRYPTO_HEAVY = "crypto_heavy"  # Encryption analysis
    PARALLEL_FRIENDLY = "parallel_friendly"  # Can run multiple instances

class PluginResourceProfile(Enum):
    """Resource consumption profiles for plugins."""

    LIGHTWEIGHT = "lightweight"  # <50MB RAM, <30s, minimal CPU
    MODERATE = "moderate"  # <200MB RAM, <60s, moderate CPU
    HEAVY = "heavy"  # <500MB RAM, <120s, high CPU
    ENTERPRISE = "enterprise"  # >500MB RAM, >120s, very high CPU

@dataclass
class PluginOptimizationProfile:
    """Optimization profile for individual plugins."""

    plugin_name: str
    affinity_type: PluginAffinityType
    resource_profile: PluginResourceProfile
    optimal_batch_size: int = 1
    can_run_parallel_instances: bool = False
    preferred_worker_pool: Optional[str] = None
    cpu_cores_preferred: int = 1
    memory_mb_preferred: int = 100
    execution_time_history: List[float] = field(default_factory=list)
    success_rate: float = 1.0
    optimization_hints: Dict[str, Any] = field(default_factory=dict)

@dataclass
class WorkerPool:
    """Specialized worker pool for specific plugin types."""

    name: str
    affinity_type: PluginAffinityType
    max_workers: int
    current_workers: int = 0
    executor: Optional[ThreadPoolExecutor] = None
    active_plugins: Set[str] = field(default_factory=set)
    completed_tasks: int = 0
    failed_tasks: int = 0
    total_execution_time: float = 0.0

@dataclass
class SchedulingMetrics:
    """Comprehensive scheduling performance metrics."""

    total_plugins_scheduled: int = 0
    optimization_efficiency: float = 0.0
    worker_pool_utilization: Dict[str, float] = field(default_factory=dict)
    affinity_based_speedup: float = 0.0
    resource_optimization_ratio: float = 0.0
    plugin_specific_improvements: Dict[str, float] = field(default_factory=dict)
    total_scheduling_time: float = 0.0

class AdvancedPluginScheduler:
    """
    Advanced plugin scheduler with intelligent optimization capabilities.

    Provides plugin-specific optimizations through:
    - Affinity-based worker pools
    - Dynamic resource allocation
    - Plugin profiling and learning
    - Smart batching and pipeline optimization
    """

    def __init__(self, max_total_workers: int = 8, enable_profiling: bool = True):
        """
        Initialize the advanced plugin scheduler.

        Args:
            max_total_workers: Maximum total workers across all pools
            enable_profiling: Enable plugin profiling for performance learning
        """
        self.max_total_workers = max_total_workers
        self.enable_profiling = enable_profiling

        # Core components
        self.console = Console()
        self.output_mgr = get_output_manager()
        self.memory_monitor = MemoryMonitor()

        # Plugin optimization profiles
        self.plugin_profiles: Dict[str, PluginOptimizationProfile] = {}
        self.worker_pools: Dict[str, WorkerPool] = {}
        self.scheduling_metrics = SchedulingMetrics()

        # Thread safety
        self._profiles_lock = threading.Lock()
        self._pools_lock = threading.Lock()
        self._metrics_lock = threading.Lock()

        # Initialize default profiles and worker pools
        self._initialize_default_profiles()
        self._create_worker_pools()

        logger.info(
            "Advanced Plugin Scheduler initialized with plugin-specific optimizations"
        )

    def _initialize_default_profiles(self):
        """Initialize default optimization profiles for known plugins."""

        # Static Analysis Plugins (CPU-intensive)
        static_plugins = [
            "jadx_static_analysis",
            "enhanced_static_analysis",
            "manifest_analysis",
            "native_binary_analysis",
            "enhanced_manifest_analysis",
        ]
        for plugin in static_plugins:
            self.plugin_profiles[plugin] = PluginOptimizationProfile(
                plugin_name=plugin,
                affinity_type=PluginAffinityType.CPU_INTENSIVE,
                resource_profile=PluginResourceProfile.MODERATE,
                cpu_cores_preferred=2,
                memory_mb_preferred=300,
                preferred_worker_pool="cpu_intensive",
            )

        # Network Analysis Plugins (Network-intensive)
        network_plugins = [
            "mitmproxy_network_analysis",
            "external_service_analysis",
            "network_communication_tests",
            "token_replay_analysis",
        ]
        for plugin in network_plugins:
            self.plugin_profiles[plugin] = PluginOptimizationProfile(
                plugin_name=plugin,
                affinity_type=PluginAffinityType.NETWORK_INTENSIVE,
                resource_profile=PluginResourceProfile.HEAVY,
                cpu_cores_preferred=1,
                memory_mb_preferred=200,
                preferred_worker_pool="network_intensive",
            )

        # Dynamic Analysis Plugins (Device-dependent)
        dynamic_plugins = [
            "advanced_dynamic_analysis",
            "frida_dynamic_analysis",
            "intent_fuzzing",
            "webview_security_analysis",
            "injuredandroid_dynamic_exploitation",
            "dynamic_analysis_enhancement_plugin",  # NEW: Enhanced dynamic analysis capabilities
        ]
        for plugin in dynamic_plugins:
            self.plugin_profiles[plugin] = PluginOptimizationProfile(
                plugin_name=plugin,
                affinity_type=PluginAffinityType.DEVICE_DEPENDENT,
                resource_profile=PluginResourceProfile.MODERATE,
                cpu_cores_preferred=1,
                memory_mb_preferred=150,
                preferred_worker_pool="device_dependent",
            )

        # Cryptography Plugins (Crypto-heavy)
        crypto_plugins = [
            "advanced_cryptography_tests",
            "runtime_decryption_analysis",
            "cryptography_tests",
            "injuredandroid_encoding_vulnerabilities",
        ]
        for plugin in crypto_plugins:
            self.plugin_profiles[plugin] = PluginOptimizationProfile(
                plugin_name=plugin,
                affinity_type=PluginAffinityType.CRYPTO_HEAVY,
                resource_profile=PluginResourceProfile.MODERATE,
                cpu_cores_preferred=2,
                memory_mb_preferred=250,
                preferred_worker_pool="crypto_heavy",
            )

        # Data Processing Plugins (Memory-intensive)
        data_plugins = [
            "apk2url_extraction",
            "enhanced_encoding_cloud_analysis",
            "advanced_vulnerability_detection",
            "insecure_data_storage",
        ]
        for plugin in data_plugins:
            self.plugin_profiles[plugin] = PluginOptimizationProfile(
                plugin_name=plugin,
                affinity_type=PluginAffinityType.MEMORY_INTENSIVE,
                resource_profile=PluginResourceProfile.HEAVY,
                optimal_batch_size=2,
                cpu_cores_preferred=1,
                memory_mb_preferred=400,
                preferred_worker_pool="memory_intensive",
            )

        # Lightweight Plugins (Parallel-friendly)
        lightweight_plugins = [
            "privacy_leak_detection",
                            "network_cleartext_traffic_analyzer",
            "improper_platform_usage",
            "traversal_vulnerabilities",
            "attack_surface_analysis",
        ]
        for plugin in lightweight_plugins:
            self.plugin_profiles[plugin] = PluginOptimizationProfile(
                plugin_name=plugin,
                affinity_type=PluginAffinityType.PARALLEL_FRIENDLY,
                resource_profile=PluginResourceProfile.LIGHTWEIGHT,
                optimal_batch_size=4,
                can_run_parallel_instances=True,
                cpu_cores_preferred=1,
                memory_mb_preferred=50,
                preferred_worker_pool="parallel_friendly",
            )

    def _create_worker_pools(self):
        """Create specialized worker pools based on affinity types."""

        # Calculate optimal worker distribution
        system_cores = psutil.cpu_count()
        memory_gb = psutil.virtual_memory().total / (1024**3)

        # Distribute workers based on system resources and plugin characteristics
        pool_configs = {
            "cpu_intensive": min(system_cores // 2, 4),  # CPU-bound tasks
            "memory_intensive": min(memory_gb // 2, 3),  # Memory-bound tasks
            "network_intensive": min(4, system_cores // 3),  # Network I/O
            "device_dependent": 2,  # ADB/device operations (limited concurrency)
            "crypto_heavy": min(system_cores // 2, 3),  # Crypto operations
            "parallel_friendly": min(system_cores, 6),  # Lightweight tasks
        }

        # Ensure we don't exceed total worker limit
        total_allocated = sum(pool_configs.values())
        if total_allocated > self.max_total_workers:
            scale_factor = self.max_total_workers / total_allocated
            for pool_name in pool_configs:
                pool_configs[pool_name] = max(
                    1, int(pool_configs[pool_name] * scale_factor)
                )

        # Create worker pools
        for affinity_name, max_workers in pool_configs.items():
            affinity_type = PluginAffinityType(affinity_name)
            self.worker_pools[affinity_name] = WorkerPool(
                name=affinity_name,
                affinity_type=affinity_type,
                max_workers=max_workers,
                executor=ThreadPoolExecutor(
                    max_workers=max_workers, thread_name_prefix=f"pool-{affinity_name}"
                ),
            )

        logger.info(
            f"Created {len(self.worker_pools)} specialized worker pools: {pool_configs}"
        )

    def get_plugin_profile(self, plugin: PluginMetadata) -> PluginOptimizationProfile:
        """Get or create optimization profile for a plugin."""

        with self._profiles_lock:
            if plugin.module_name in self.plugin_profiles:
                return self.plugin_profiles[plugin.module_name]

            # Create profile based on plugin characteristics
            profile = self._analyze_plugin_characteristics(plugin)
            self.plugin_profiles[plugin.module_name] = profile
            return profile

    def _analyze_plugin_characteristics(
        self, plugin: PluginMetadata
    ) -> PluginOptimizationProfile:
        """Analyze plugin characteristics to create optimization profile."""

        # Determine affinity type based on plugin metadata
        affinity = self._determine_plugin_affinity(plugin)

        # Determine resource profile based on execution time and category
        if plugin.execution_time_estimate <= 30:
            resource_profile = PluginResourceProfile.LIGHTWEIGHT
        elif plugin.execution_time_estimate <= 90:
            resource_profile = PluginResourceProfile.MODERATE
        elif plugin.execution_time_estimate <= 180:
            resource_profile = PluginResourceProfile.HEAVY
        else:
            resource_profile = PluginResourceProfile.ENTERPRISE

        # Calculate optimal settings
        cpu_cores = 2 if affinity == PluginAffinityType.CPU_INTENSIVE else 1
        memory_mb = plugin.execution_time_estimate * 3  # Rough estimation
        batch_size = 4 if affinity == PluginAffinityType.PARALLEL_FRIENDLY else 1

        return PluginOptimizationProfile(
            plugin_name=plugin.module_name,
            affinity_type=affinity,
            resource_profile=resource_profile,
            optimal_batch_size=batch_size,
            can_run_parallel_instances=(
                affinity == PluginAffinityType.PARALLEL_FRIENDLY
            ),
            preferred_worker_pool=affinity.value,
            cpu_cores_preferred=cpu_cores,
            memory_mb_preferred=min(memory_mb, 500),
        )

    def _determine_plugin_affinity(self, plugin: PluginMetadata) -> PluginAffinityType:
        """Determine plugin affinity type based on characteristics."""

        name_lower = plugin.module_name.lower()
        description_lower = plugin.description.lower() if plugin.description else ""

        # Check description first for test cases (handles mock plugins)
        if "cpu_intensive" in description_lower or "cpu_intensive" in name_lower:
            return PluginAffinityType.CPU_INTENSIVE
        elif (
            "network_intensive" in description_lower
            or "network_intensive" in name_lower
        ):
            return PluginAffinityType.NETWORK_INTENSIVE
        elif (
            "device_dependent" in description_lower or "device_dependent" in name_lower
        ):
            return PluginAffinityType.DEVICE_DEPENDENT
        elif "crypto_heavy" in description_lower or "crypto_heavy" in name_lower:
            return PluginAffinityType.CRYPTO_HEAVY
        elif (
            "memory_intensive" in description_lower or "memory_intensive" in name_lower
        ):
            return PluginAffinityType.MEMORY_INTENSIVE
        elif (
            "parallel_friendly" in description_lower
            or "parallel_friendly" in name_lower
        ):
            return PluginAffinityType.PARALLEL_FRIENDLY

        # Network-intensive plugins (real plugin names)
        elif any(
            keyword in name_lower
            for keyword in ["network", "mitm", "external", "token_replay"]
        ):
            return PluginAffinityType.NETWORK_INTENSIVE

        # Device-dependent plugins
        elif (
            any(
                keyword in name_lower
                for keyword in ["dynamic", "frida", "intent", "webview"]
            )
            or plugin.requires_device
        ):
            return PluginAffinityType.DEVICE_DEPENDENT

        # CPU-intensive plugins
        elif any(
            keyword in name_lower
            for keyword in ["jadx", "static", "native", "manifest"]
        ):
            return PluginAffinityType.CPU_INTENSIVE

        # Crypto-heavy plugins
        elif any(
            keyword in name_lower
            for keyword in ["crypto", "encryption", "decryption", "encoding"]
        ):
            return PluginAffinityType.CRYPTO_HEAVY

        # Memory-intensive plugins
        elif any(
            keyword in name_lower
            for keyword in ["apk2url", "vulnerability", "storage", "extraction"]
        ):
            return PluginAffinityType.MEMORY_INTENSIVE

        # Default to parallel-friendly for lightweight plugins
        else:
            return PluginAffinityType.PARALLEL_FRIENDLY

    def schedule_plugins_optimized(
        self, plugins: List[PluginMetadata], apk_ctx, execution_callback: callable
    ) -> Dict[str, Tuple[str, Any]]:
        """
        Schedule plugins with advanced optimizations.

        Args:
            plugins: List of plugins to schedule
            apk_ctx: APK context object
            execution_callback: Function to execute individual plugins

        Returns:
            Dictionary of plugin results
        """
        start_time = time.time()

        with self._metrics_lock:
            self.scheduling_metrics.total_plugins_scheduled = len(plugins)

        # Group plugins by affinity type
        plugin_groups = self._group_plugins_by_affinity(plugins)

        # Create optimized execution plan
        execution_plan = self._create_optimized_execution_plan(plugin_groups)

        # Execute with specialized pools
        results = self._execute_optimized_plan(
            execution_plan, apk_ctx, execution_callback
        )

        # Update metrics
        total_time = time.time() - start_time
        with self._metrics_lock:
            self.scheduling_metrics.total_scheduling_time = total_time
            self._calculate_optimization_metrics()

        return results

    def _group_plugins_by_affinity(
        self, plugins: List[PluginMetadata]
    ) -> Dict[PluginAffinityType, List[PluginMetadata]]:
        """Group plugins by their affinity types for optimized scheduling."""

        groups = defaultdict(list)

        for plugin in plugins:
            profile = self.get_plugin_profile(plugin)
            groups[profile.affinity_type].append(plugin)

        # Log grouping information
        self.output_mgr.verbose("Plugin Affinity Grouping:")
        for affinity_type, plugin_list in groups.items():
            self.output_mgr.verbose(
                f"  {affinity_type.value}: {len(plugin_list)} plugins"
            )

        return dict(groups)

    def _create_optimized_execution_plan(
        self, plugin_groups: Dict[PluginAffinityType, List[PluginMetadata]]
    ) -> List[Tuple[str, List[PluginMetadata]]]:
        """Create optimized execution plan based on plugin groups."""

        execution_plan = []

        # Priority order for execution (dependencies considered)
        execution_order = [
            PluginAffinityType.CPU_INTENSIVE,  # Static analysis first
            PluginAffinityType.PARALLEL_FRIENDLY,  # Lightweight plugins in parallel
            PluginAffinityType.MEMORY_INTENSIVE,  # Memory-heavy plugins
            PluginAffinityType.CRYPTO_HEAVY,  # Crypto analysis
            PluginAffinityType.NETWORK_INTENSIVE,  # Network operations
            PluginAffinityType.DEVICE_DEPENDENT,  # Device operations last
        ]

        for affinity_type in execution_order:
            if affinity_type in plugin_groups:
                plugins = plugin_groups[affinity_type]

                # Group into optimal batches
                batches = self._create_optimal_batches(plugins, affinity_type)

                for batch in batches:
                    pool_name = affinity_type.value
                    execution_plan.append((pool_name, batch))

        return execution_plan

    def _create_optimal_batches(
        self, plugins: List[PluginMetadata], affinity_type: PluginAffinityType
    ) -> List[List[PluginMetadata]]:
        """Create optimal batches for plugins of the same affinity type."""

        if not plugins:
            return []

        # Get optimal batch size for this affinity type
        sample_profile = self.get_plugin_profile(plugins[0])
        batch_size = sample_profile.optimal_batch_size

        # For parallel-friendly plugins, use larger batches
        if affinity_type == PluginAffinityType.PARALLEL_FRIENDLY:
            batch_size = min(
                len(plugins), self.worker_pools[affinity_type.value].max_workers
            )

        # Create batches
        batches = []
        for i in range(0, len(plugins), batch_size):
            batch = plugins[i : i + batch_size]
            batches.append(batch)

        return batches

    def _execute_optimized_plan(
        self,
        execution_plan: List[Tuple[str, List[PluginMetadata]]],
        apk_ctx,
        execution_callback: callable,
    ) -> Dict[str, Tuple[str, Any]]:
        """Execute the optimized execution plan."""

        results = {}

        for pool_name, plugin_batch in execution_plan:
            pool = self.worker_pools[pool_name]

            self.output_mgr.info(
                f"Executing {len(plugin_batch)} plugins with {pool_name} pool"
            )

            # Execute batch with specialized pool
            batch_results = self._execute_plugin_batch(
                pool, plugin_batch, apk_ctx, execution_callback
            )
            results.update(batch_results)

        return results

    def _execute_plugin_batch(
        self,
        pool: WorkerPool,
        plugins: List[PluginMetadata],
        apk_ctx,
        execution_callback: callable,
    ) -> Dict[str, Tuple[str, Any]]:
        """Execute a batch of plugins using a specialized worker pool."""

        results = {}

        # Submit plugins to the specialized pool
        futures = {}
        for plugin in plugins:
            profile = self.get_plugin_profile(plugin)

            # Track execution start
            start_time = time.time()

            # Submit to appropriate pool
            future = pool.executor.submit(execution_callback, plugin, apk_ctx)
            futures[future] = (plugin, start_time, profile)

            with self._pools_lock:
                pool.active_plugins.add(plugin.module_name)

        # Collect results
        for future in futures:
            plugin, start_time, profile = futures[future]

            try:
                result = future.result()
                execution_time = time.time() - start_time

                # Update plugin profile with execution time
                with self._profiles_lock:
                    profile.execution_time_history.append(execution_time)
                    if len(profile.execution_time_history) > 10:
                        profile.execution_time_history.pop(0)  # Keep last 10 executions

                # Update pool statistics
                with self._pools_lock:
                    pool.completed_tasks += 1
                    pool.total_execution_time += execution_time
                    pool.active_plugins.discard(plugin.module_name)

                results[plugin.module_name] = result

            except Exception as e:
                # Handle plugin failure
                with self._pools_lock:
                    pool.failed_tasks += 1
                    pool.active_plugins.discard(plugin.module_name)

                # Update success rate
                with self._profiles_lock:
                    if profile.success_rate > 0.1:  # Don't let it go to 0
                        profile.success_rate *= 0.9

                logger.error(
                    f"Plugin {plugin.module_name} failed in {pool.name} pool: {e}"
                )
                results[plugin.module_name] = (f"❌ {plugin.name}", f"Error: {e}")

        return results

    def _calculate_optimization_metrics(self):
        """Calculate optimization performance metrics."""

        # Calculate worker pool utilization
        for pool_name, pool in self.worker_pools.items():
            if pool.completed_tasks + pool.failed_tasks > 0:
                utilization = pool.completed_tasks / (
                    pool.completed_tasks + pool.failed_tasks
                )
                self.scheduling_metrics.worker_pool_utilization[pool_name] = utilization

        # Calculate average optimization efficiency
        total_utilization = sum(
            self.scheduling_metrics.worker_pool_utilization.values()
        )
        pool_count = len(self.scheduling_metrics.worker_pool_utilization)

        if pool_count > 0:
            self.scheduling_metrics.optimization_efficiency = (
                total_utilization / pool_count
            )

    def generate_optimization_report(self) -> Table:
        """Generate comprehensive optimization performance report."""

        table = Table(title="Advanced Plugin Scheduler - Optimization Report")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="green")
        table.add_column("Analysis", style="yellow")

        # Scheduling metrics
        table.add_row(
            "Total Plugins Scheduled",
            str(self.scheduling_metrics.total_plugins_scheduled),
            "✅ Complete",
        )

        table.add_row(
            "Optimization Efficiency",
            f"{self.scheduling_metrics.optimization_efficiency:.1%}",
            (
                "🚀 Excellent"
                if self.scheduling_metrics.optimization_efficiency > 0.8
                else (
                    "⚡ Good"
                    if self.scheduling_metrics.optimization_efficiency > 0.6
                    else "🔧 Needs tuning"
                )
            ),
        )

        table.add_row(
            "Total Scheduling Time",
            f"{self.scheduling_metrics.total_scheduling_time:.1f}s",
            "⚡ Optimized scheduling overhead",
        )

        # Worker pool performance
        for (
            pool_name,
            utilization,
        ) in self.scheduling_metrics.worker_pool_utilization.items():
            pool = self.worker_pools[pool_name]

            table.add_row(
                f"{pool_name.title()} Pool",
                f"Utilization: {utilization:.1%} | Completed: {pool.completed_tasks} | Failed: {pool.failed_tasks}",
                f"Workers: {pool.max_workers} | Avg Time: {pool.total_execution_time / max(pool.completed_tasks, 1):.1f}s",
            )

        # Plugin-specific improvements
        if self.scheduling_metrics.plugin_specific_improvements:
            for (
                plugin_name,
                improvement,
            ) in self.scheduling_metrics.plugin_specific_improvements.items():
                table.add_row(
                    f"Plugin: {plugin_name}",
                    f"{improvement:.1%} improvement",
                    "📈 Optimized execution",
                )

        return table

    def get_plugin_recommendations(self, plugin_name: str) -> Dict[str, Any]:
        """Get optimization recommendations for a specific plugin."""

        if plugin_name not in self.plugin_profiles:
            return {"error": "Plugin profile not found"}

        profile = self.plugin_profiles[plugin_name]
        recommendations = {}

        # Execution time analysis
        if profile.execution_time_history:
            avg_time = sum(profile.execution_time_history) / len(
                profile.execution_time_history
            )
            recommendations["average_execution_time"] = f"{avg_time:.1f}s"

            if len(profile.execution_time_history) > 1:
                trend = (
                    profile.execution_time_history[-1]
                    - profile.execution_time_history[0]
                )
                recommendations["performance_trend"] = (
                    "Improving"
                    if trend < 0
                    else "Stable" if abs(trend) < 0.1 else "Degrading"
                )

        # Success rate analysis
        recommendations["success_rate"] = f"{profile.success_rate:.1%}"

        # Resource optimization suggestions
        if profile.affinity_type == PluginAffinityType.CPU_INTENSIVE:
            recommendations["optimization_hint"] = (
                "Consider running during low CPU periods"
            )
        elif profile.affinity_type == PluginAffinityType.MEMORY_INTENSIVE:
            recommendations["optimization_hint"] = "Monitor memory usage closely"
        elif profile.affinity_type == PluginAffinityType.PARALLEL_FRIENDLY:
            recommendations["optimization_hint"] = "Can be batched with similar plugins"

        return recommendations

    def shutdown(self):
        """Shutdown all worker pools and cleanup resources."""

        self.output_mgr.verbose("Shutting down advanced plugin scheduler...")

        for pool_name, pool in self.worker_pools.items():
            if pool.executor:
                pool.executor.shutdown(wait=True)
                self.output_mgr.verbose(f"Shutdown {pool_name} pool")

        logger.info("Advanced Plugin Scheduler shutdown complete")

def create_advanced_scheduler(
    max_workers: int = 8, enable_profiling: bool = True
) -> AdvancedPluginScheduler:
    """
    Factory function to create an advanced plugin scheduler.

    Args:
        max_workers: Maximum total workers across all pools
        enable_profiling: Enable plugin profiling for performance learning

    Returns:
        Configured AdvancedPluginScheduler instance
    """
    return AdvancedPluginScheduler(
        max_total_workers=max_workers, enable_profiling=enable_profiling
    )

if __name__ == "__main__":
    # Example usage and testing
    scheduler = create_advanced_scheduler(max_workers=8)
    print(
        f"Advanced Plugin Scheduler created with {len(scheduler.worker_pools)} specialized pools"
    )

    # Display worker pool configuration
    for pool_name, pool in scheduler.worker_pools.items():
        print(f"  {pool_name}: {pool.max_workers} workers ({pool.affinity_type.value})")

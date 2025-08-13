"""
Parallel Processing Engine for AODS Phase 3
Optimize performance for large APKs and concurrent analysis
"""

import os
import time
import logging
import threading
import multiprocessing
from typing import Dict, List, Any, Optional, Callable, Tuple
from pathlib import Path
from dataclasses import dataclass
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed
from queue import Queue, Empty
import psutil
import json

logger = logging.getLogger(__name__)

@dataclass
class ProcessingTask:
    """Individual processing task for parallel execution."""
    task_id: str
    task_type: str
    plugin_name: str
    input_data: Any
    priority: int
    estimated_time: float
    memory_requirement: int
    created_at: str

@dataclass
class ProcessingResult:
    """Result of parallel processing task."""
    task_id: str
    status: str
    result_data: Any
    execution_time: float
    memory_used: int
    error_message: Optional[str]
    completed_at: str

class ResourceMonitor:
    """Monitor system resources for optimal parallel processing."""
    
    def __init__(self):
        self.cpu_count = multiprocessing.cpu_count()
        self.memory_total = psutil.virtual_memory().total
        self.monitoring_active = False
        self.resource_history = []
        
    def get_system_resources(self) -> Dict[str, Any]:
        """Get current system resource utilization."""
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        
        return {
            "cpu_percent": cpu_percent,
            "cpu_count": self.cpu_count,
            "memory_percent": memory.percent,
            "memory_available": memory.available,
            "memory_total": memory.total,
            "disk_percent": disk.percent,
            "disk_free": disk.free,
            "timestamp": datetime.now().isoformat()
        }
    
    def calculate_optimal_workers(self, task_type: str = "cpu_bound") -> int:
        """Calculate optimal number of worker processes/threads."""
        system_resources = self.get_system_resources()
        
        if task_type == "cpu_bound":
            # For CPU-bound tasks, use CPU count
            base_workers = self.cpu_count
            
            # Adjust based on current CPU usage
            if system_resources["cpu_percent"] > 80:
                workers = max(1, base_workers // 2)
            elif system_resources["cpu_percent"] > 50:
                workers = max(2, int(base_workers * 0.75))
            else:
                workers = base_workers
                
        elif task_type == "io_bound":
            # For I/O-bound tasks, can use more workers
            base_workers = self.cpu_count * 2
            
            # Adjust based on memory usage
            if system_resources["memory_percent"] > 80:
                workers = max(2, base_workers // 2)
            else:
                workers = base_workers
                
        else:  # mixed workload
            workers = max(2, self.cpu_count)
        
        logger.info(f"Optimal workers for {task_type}: {workers} "
                   f"(CPU: {system_resources['cpu_percent']:.1f}%, "
                   f"Memory: {system_resources['memory_percent']:.1f}%)")
        
        return workers
    
    def start_monitoring(self, interval: int = 30):
        """Start continuous resource monitoring."""
        self.monitoring_active = True
        
        def monitor_loop():
            while self.monitoring_active:
                resources = self.get_system_resources()
                self.resource_history.append(resources)
                
                # Keep only last hour of data
                if len(self.resource_history) > 120:  # 30s intervals = 120 for 1 hour
                    self.resource_history = self.resource_history[-120:]
                
                time.sleep(interval)
        
        monitor_thread = threading.Thread(target=monitor_loop, daemon=True)
        monitor_thread.start()
        logger.info("Resource monitoring started")
    
    def stop_monitoring(self):
        """Stop resource monitoring."""
        self.monitoring_active = False
        logger.info("Resource monitoring stopped")
    
    def get_resource_trends(self) -> Dict[str, Any]:
        """Get resource utilization trends."""
        if not self.resource_history:
            return {"message": "No monitoring data available"}
        
        recent_data = self.resource_history[-10:]  # Last 10 measurements
        
        avg_cpu = sum(d["cpu_percent"] for d in recent_data) / len(recent_data)
        avg_memory = sum(d["memory_percent"] for d in recent_data) / len(recent_data)
        
        return {
            "average_cpu_usage": avg_cpu,
            "average_memory_usage": avg_memory,
            "peak_cpu_usage": max(d["cpu_percent"] for d in recent_data),
            "peak_memory_usage": max(d["memory_percent"] for d in recent_data),
            "measurements_count": len(self.resource_history),
            "monitoring_duration": len(self.resource_history) * 30  # seconds
        }

class TaskQueue:
    """Priority-based task queue for parallel processing."""
    
    def __init__(self, max_size: int = 1000):
        self.queue = Queue(maxsize=max_size)
        self.priority_queues = {
            "high": Queue(),
            "medium": Queue(), 
            "low": Queue()
        }
        self.completed_tasks = {}
        self.failed_tasks = {}
        
    def add_task(self, task: ProcessingTask):
        """Add task to appropriate priority queue."""
        if task.priority >= 8:
            self.priority_queues["high"].put(task)
        elif task.priority >= 5:
            self.priority_queues["medium"].put(task)
        else:
            self.priority_queues["low"].put(task)
        
        logger.debug(f"Added task {task.task_id} to priority queue")
    
    def get_next_task(self, timeout: float = 1.0) -> Optional[ProcessingTask]:
        """Get next task from priority queues."""
        # Check high priority first
        for priority in ["high", "medium", "low"]:
            try:
                task = self.priority_queues[priority].get_nowait()
                return task
            except Empty:
                continue
        
        return None
    
    def mark_completed(self, task_id: str, result: ProcessingResult):
        """Mark task as completed."""
        self.completed_tasks[task_id] = result
        logger.debug(f"Task {task_id} marked as completed")
    
    def mark_failed(self, task_id: str, result: ProcessingResult):
        """Mark task as failed."""
        self.failed_tasks[task_id] = result
        logger.debug(f"Task {task_id} marked as failed")
    
    def get_queue_status(self) -> Dict[str, int]:
        """Get current queue status."""
        return {
            "high_priority": self.priority_queues["high"].qsize(),
            "medium_priority": self.priority_queues["medium"].qsize(),
            "low_priority": self.priority_queues["low"].qsize(),
            "completed": len(self.completed_tasks),
            "failed": len(self.failed_tasks)
        }

class ParallelProcessingEngine:
    """Main parallel processing engine for AODS optimization."""
    
    def __init__(self, base_dir: Path = None):
        self.base_dir = base_dir or Path(".")
        self.resource_monitor = ResourceMonitor()
        self.task_queue = TaskQueue()
        
        # Processing pools
        self.thread_pool = None
        self.process_pool = None
        
        # Configuration
        self.config = {
            "max_concurrent_tasks": 10,
            "task_timeout": 300,  # 5 minutes
            "memory_limit_mb": 2048,  # 2GB per task
            "auto_scaling": True,
            "resource_monitoring": True
        }
        
        # Statistics
        self.processing_stats = {
            "total_tasks": 0,
            "completed_tasks": 0,
            "failed_tasks": 0,
            "total_processing_time": 0,
            "average_task_time": 0,
            "peak_memory_usage": 0,
            "throughput_per_minute": 0
        }
        
        self.start_time = time.time()
        
    def initialize_engine(self) -> Dict[str, Any]:
        """Initialize the parallel processing engine."""
        logger.info("🚀 Initializing Parallel Processing Engine")
        
        # Start resource monitoring
        if self.config["resource_monitoring"]:
            self.resource_monitor.start_monitoring()
        
        # Calculate optimal worker counts
        cpu_workers = self.resource_monitor.calculate_optimal_workers("cpu_bound")
        io_workers = self.resource_monitor.calculate_optimal_workers("io_bound")
        
        # Initialize thread pool for I/O-bound tasks
        self.thread_pool = ThreadPoolExecutor(
            max_workers=io_workers,
            thread_name_prefix="AODS-Thread"
        )
        
        # Initialize process pool for CPU-bound tasks
        self.process_pool = ProcessPoolExecutor(
            max_workers=cpu_workers
        )
        
        initialization_result = {
            "status": "initialized",
            "thread_workers": io_workers,
            "process_workers": cpu_workers,
            "resource_monitoring": self.config["resource_monitoring"],
            "system_resources": self.resource_monitor.get_system_resources(),
            "configuration": self.config
        }
        
        logger.info(f"✅ Engine initialized: {io_workers} threads, {cpu_workers} processes")
        return initialization_result
    
    def process_apk_parallel(self, apk_path: str, plugins: List[str]) -> Dict[str, Any]:
        """Process APK with multiple plugins in parallel."""
        logger.info(f"🔄 Processing APK in parallel: {apk_path}")
        
        start_time = time.time()
        
        # Create tasks for each plugin
        tasks = []
        for i, plugin_name in enumerate(plugins):
            task = ProcessingTask(
                task_id=f"{Path(apk_path).stem}_{plugin_name}_{i}",
                task_type="plugin_analysis",
                plugin_name=plugin_name,
                input_data={"apk_path": apk_path, "plugin_config": {}},
                priority=7,  # High priority for main analysis
                estimated_time=60.0,  # 1 minute estimate
                memory_requirement=512,  # 512MB estimate
                created_at=datetime.now().isoformat()
            )
            tasks.append(task)
            self.task_queue.add_task(task)
        
        # Process tasks in parallel
        results = self._execute_parallel_tasks(tasks, task_type="io_bound")
        
        processing_time = time.time() - start_time
        
        # Aggregate results
        aggregated_results = {
            "apk_path": apk_path,
            "processing_time": processing_time,
            "plugins_processed": len(plugins),
            "successful_plugins": len([r for r in results if r.status == "completed"]),
            "failed_plugins": len([r for r in results if r.status == "failed"]),
            "plugin_results": {r.task_id: r.result_data for r in results if r.status == "completed"},
            "plugin_errors": {r.task_id: r.error_message for r in results if r.status == "failed"},
            "performance_metrics": {
                "total_time": processing_time,
                "average_plugin_time": sum(r.execution_time for r in results) / len(results),
                "parallel_efficiency": len(plugins) * 60 / processing_time if processing_time > 0 else 0,
                "memory_peak": max(r.memory_used for r in results) if results else 0
            }
        }
        
        self._update_statistics(results, processing_time)
        
        logger.info(f"✅ APK processing completed in {processing_time:.2f}s")
        logger.info(f"📊 Success rate: {aggregated_results['successful_plugins']}/{aggregated_results['plugins_processed']}")
        
        return aggregated_results
    
    def process_multiple_apks(self, apk_paths: List[str], plugins: List[str]) -> Dict[str, Any]:
        """Process multiple APKs concurrently."""
        logger.info(f"🔄 Processing {len(apk_paths)} APKs concurrently")
        
        start_time = time.time()
        
        # Create batched tasks to avoid overwhelming the system
        batch_size = min(self.config["max_concurrent_tasks"], len(apk_paths))
        batched_results = []
        
        for i in range(0, len(apk_paths), batch_size):
            batch = apk_paths[i:i + batch_size]
            logger.info(f"Processing batch {i//batch_size + 1}: {len(batch)} APKs")
            
            # Create futures for batch processing
            futures = []
            for apk_path in batch:
                future = self.thread_pool.submit(self.process_apk_parallel, apk_path, plugins)
                futures.append((apk_path, future))
            
            # Collect batch results
            batch_results = {}
            for apk_path, future in futures:
                try:
                    result = future.result(timeout=self.config["task_timeout"])
                    batch_results[apk_path] = result
                except Exception as e:
                    logger.error(f"Failed to process {apk_path}: {e}")
                    batch_results[apk_path] = {"status": "failed", "error": str(e)}
            
            batched_results.append(batch_results)
            
            # Brief pause between batches to prevent resource exhaustion
            if i + batch_size < len(apk_paths):
                time.sleep(2)
        
        total_time = time.time() - start_time
        
        # Aggregate all results
        all_results = {}
        for batch in batched_results:
            all_results.update(batch)
        
        successful_apks = len([r for r in all_results.values() if r.get("successful_plugins", 0) > 0])
        total_plugins_processed = sum(r.get("plugins_processed", 0) for r in all_results.values())
        
        final_results = {
            "total_apks": len(apk_paths),
            "successful_apks": successful_apks,
            "failed_apks": len(apk_paths) - successful_apks,
            "total_processing_time": total_time,
            "average_apk_time": total_time / len(apk_paths),
            "total_plugins_processed": total_plugins_processed,
            "throughput_apks_per_minute": len(apk_paths) / (total_time / 60) if total_time > 0 else 0,
            "batch_processing": True,
            "batch_size": batch_size,
            "individual_results": all_results,
            "resource_usage": self.resource_monitor.get_resource_trends()
        }
        
        logger.info(f"✅ Multiple APK processing completed in {total_time:.2f}s")
        logger.info(f"📊 Throughput: {final_results['throughput_apks_per_minute']:.1f} APKs/minute")
        
        return final_results
    
    def _execute_parallel_tasks(self, tasks: List[ProcessingTask], 
                               task_type: str = "io_bound") -> List[ProcessingResult]:
        """Execute tasks in parallel using appropriate executor."""
        
        executor = self.thread_pool if task_type == "io_bound" else self.process_pool
        
        # Submit all tasks
        futures = {}
        for task in tasks:
            future = executor.submit(self._execute_single_task, task)
            futures[future] = task
        
        # Collect results
        results = []
        for future in as_completed(futures, timeout=self.config["task_timeout"]):
            task = futures[future]
            try:
                result = future.result()
                results.append(result)
                
                if result.status == "completed":
                    self.task_queue.mark_completed(task.task_id, result)
                else:
                    self.task_queue.mark_failed(task.task_id, result)
                    
            except Exception as e:
                error_result = ProcessingResult(
                    task_id=task.task_id,
                    status="failed",
                    result_data=None,
                    execution_time=0,
                    memory_used=0,
                    error_message=str(e),
                    completed_at=datetime.now().isoformat()
                )
                results.append(error_result)
                self.task_queue.mark_failed(task.task_id, error_result)
                logger.error(f"Task {task.task_id} failed: {e}")
        
        return results
    
    def _execute_single_task(self, task: ProcessingTask) -> ProcessingResult:
        """Execute a single processing task."""
        start_time = time.time()
        start_memory = psutil.Process().memory_info().rss
        
        try:
            # Simulate plugin execution (in real implementation, this would call actual plugins)
            result_data = self._simulate_plugin_execution(task)
            
            execution_time = time.time() - start_time
            end_memory = psutil.Process().memory_info().rss
            memory_used = end_memory - start_memory
            
            return ProcessingResult(
                task_id=task.task_id,
                status="completed",
                result_data=result_data,
                execution_time=execution_time,
                memory_used=memory_used,
                error_message=None,
                completed_at=datetime.now().isoformat()
            )
            
        except Exception as e:
            execution_time = time.time() - start_time
            
            return ProcessingResult(
                task_id=task.task_id,
                status="failed",
                result_data=None,
                execution_time=execution_time,
                memory_used=0,
                error_message=str(e),
                completed_at=datetime.now().isoformat()
            )
    
    def _simulate_plugin_execution(self, task: ProcessingTask) -> Dict[str, Any]:
        """Simulate plugin execution for demonstration."""
        # Simulate processing time based on plugin type
        processing_times = {
            "static_analysis": 2.0,
            "dynamic_analysis": 5.0,
            "ml_analysis": 3.0,
            "network_analysis": 1.5,
            "crypto_analysis": 2.5
        }
        
        base_time = processing_times.get(task.plugin_name, 2.0)
        # Add some randomness
        actual_time = base_time * (0.8 + 0.4 * hash(task.task_id) % 100 / 100)
        
        time.sleep(actual_time)
        
        # Simulate findings
        findings_count = max(1, int(actual_time))
        
        return {
            "plugin_name": task.plugin_name,
            "findings_count": findings_count,
            "processing_time": actual_time,
            "status": "completed",
            "findings": [
                {
                    "id": f"finding_{i}",
                    "type": f"vulnerability_type_{i % 3}",
                    "severity": ["low", "medium", "high"][i % 3],
                    "confidence": 0.7 + (i % 3) * 0.1
                }
                for i in range(findings_count)
            ]
        }
    
    def _update_statistics(self, results: List[ProcessingResult], total_time: float):
        """Update processing statistics."""
        completed_count = len([r for r in results if r.status == "completed"])
        failed_count = len([r for r in results if r.status == "failed"])
        
        self.processing_stats["total_tasks"] += len(results)
        self.processing_stats["completed_tasks"] += completed_count
        self.processing_stats["failed_tasks"] += failed_count
        self.processing_stats["total_processing_time"] += total_time
        
        if self.processing_stats["total_tasks"] > 0:
            self.processing_stats["average_task_time"] = (
                self.processing_stats["total_processing_time"] / 
                self.processing_stats["total_tasks"]
            )
        
        # Update throughput
        elapsed_time = time.time() - self.start_time
        if elapsed_time > 0:
            self.processing_stats["throughput_per_minute"] = (
                self.processing_stats["completed_tasks"] / (elapsed_time / 60)
            )
        
        # Update peak memory
        if results:
            current_peak = max(r.memory_used for r in results if r.memory_used)
            self.processing_stats["peak_memory_usage"] = max(
                self.processing_stats["peak_memory_usage"], current_peak
            )
    
    def get_performance_metrics(self) -> Dict[str, Any]:
        """Get comprehensive performance metrics."""
        uptime = time.time() - self.start_time
        
        return {
            "engine_uptime": uptime,
            "processing_statistics": self.processing_stats,
            "queue_status": self.task_queue.get_queue_status(),
            "resource_trends": self.resource_monitor.get_resource_trends(),
            "current_resources": self.resource_monitor.get_system_resources(),
            "pool_status": {
                "thread_pool_active": self.thread_pool is not None,
                "process_pool_active": self.process_pool is not None
            },
            "configuration": self.config,
            "performance_indicators": {
                "success_rate": (
                    self.processing_stats["completed_tasks"] / 
                    max(self.processing_stats["total_tasks"], 1)
                ),
                "efficiency_score": min(1.0, self.processing_stats["throughput_per_minute"] / 10),
                "resource_utilization": "optimal" if uptime > 60 else "initializing"
            }
        }
    
    def shutdown_engine(self):
        """Gracefully shutdown the parallel processing engine."""
        logger.info("🔄 Shutting down Parallel Processing Engine")
        
        if self.thread_pool:
            self.thread_pool.shutdown(wait=True)
            
        if self.process_pool:
            self.process_pool.shutdown(wait=True)
            
        self.resource_monitor.stop_monitoring()
        
        logger.info("✅ Parallel Processing Engine shutdown completed")

# Global parallel processing engine
parallel_engine = ParallelProcessingEngine()

def optimize_apk_processing(apk_paths: List[str], plugins: List[str]) -> Dict[str, Any]:
    """Global function for optimized APK processing."""
    if not parallel_engine.thread_pool:
        parallel_engine.initialize_engine()
    
    if len(apk_paths) == 1:
        return parallel_engine.process_apk_parallel(apk_paths[0], plugins)
    else:
        return parallel_engine.process_multiple_apks(apk_paths, plugins) 
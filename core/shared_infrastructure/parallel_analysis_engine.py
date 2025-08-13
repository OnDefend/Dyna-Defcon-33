"""
AODS Parallel Processing Architecture

Provides enterprise-grade parallel processing capabilities for large-scale APK analysis
with async/threading coordination, task scheduling, and resource management.

Features:
- Thread pool and async execution coordination
- Intelligent task distribution and load balancing
- Resource monitoring and throttling
- Progress tracking and cancellation support
- Memory and CPU resource management
- Failure isolation and recovery
"""

import asyncio
import threading
import time
import logging
import multiprocessing
from abc import ABC, abstractmethod
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed, Future
from typing import Dict, List, Any, Optional, Callable, Union, TypeVar, Generic, Awaitable
from dataclasses import dataclass, field
from pathlib import Path
import psutil
import queue
from contextlib import contextmanager
import signal
import weakref

from .analysis_exceptions import ParallelProcessingError, ErrorContext, ContextualLogger

T = TypeVar('T')
R = TypeVar('R')

logger = logging.getLogger(__name__)

@dataclass
class TaskMetrics:
    """Metrics for task execution monitoring."""
    task_id: str
    start_time: float = field(default_factory=time.time)
    end_time: Optional[float] = None
    duration: Optional[float] = None
    memory_usage_mb: float = 0.0
    cpu_usage_percent: float = 0.0
    status: str = "pending"  # pending, running, completed, failed, cancelled
    error: Optional[str] = None
    
    def mark_started(self):
        """Mark task as started."""
        self.start_time = time.time()
        self.status = "running"
    
    def mark_completed(self):
        """Mark task as completed."""
        self.end_time = time.time()
        self.duration = self.end_time - self.start_time
        self.status = "completed"
    
    def mark_failed(self, error: str):
        """Mark task as failed."""
        self.end_time = time.time()
        self.duration = self.end_time - self.start_time if self.start_time else 0
        self.status = "failed"
        self.error = error

@dataclass
class ResourceLimits:
    """Resource limits for parallel processing."""
    max_threads: int = multiprocessing.cpu_count()
    max_processes: int = min(4, multiprocessing.cpu_count())
    max_memory_mb: int = 2048
    max_cpu_percent: float = 80.0
    task_timeout_seconds: int = 300
    queue_size_limit: int = 1000
    
    def __post_init__(self):
        """Validate resource limits."""
        available_memory = psutil.virtual_memory().total / (1024 * 1024)
        if self.max_memory_mb > available_memory * 0.8:
            self.max_memory_mb = int(available_memory * 0.8)
            logger.warning(f"Adjusted max memory to {self.max_memory_mb}MB")

class AnalysisTask(Generic[T]):
    """
    Represents an analysis task that can be executed in parallel.
    
    Provides task metadata, execution context, and result handling
    for comprehensive task management.
    """
    
    def __init__(self, 
                 task_id: str,
                 operation: Callable[..., T],
                 args: tuple = (),
                 kwargs: dict = None,
                 priority: int = 0,
                 timeout: Optional[int] = None,
                 dependencies: List[str] = None):
        """
        Initialize analysis task.
        
        Args:
            task_id: Unique identifier for the task
            operation: The operation to execute
            args: Positional arguments for the operation
            kwargs: Keyword arguments for the operation
            priority: Task priority (higher = more important)
            timeout: Task timeout in seconds
            dependencies: List of task IDs this task depends on
        """
        self.task_id = task_id
        self.operation = operation
        self.args = args
        self.kwargs = kwargs or {}
        self.priority = priority
        self.timeout = timeout
        self.dependencies = dependencies or []
        self.metrics = TaskMetrics(task_id)
        self.result: Optional[T] = None
        self.future: Optional[Future] = None
        self.cancelled = False
        
        # Task state management
        self._completed_event = threading.Event()
        self._lock = threading.Lock()
    
    def execute(self) -> T:
        """Execute the task with metrics tracking."""
        with self._lock:
            if self.cancelled:
                raise ParallelProcessingError(f"Task {self.task_id} was cancelled")
            
            self.metrics.mark_started()
        
        try:
            # Monitor resource usage during execution
            process = psutil.Process()
            initial_memory = process.memory_info().rss / (1024 * 1024)
            
            # Execute the operation
            result = self.operation(*self.args, **self.kwargs)
            
            # Update metrics
            final_memory = process.memory_info().rss / (1024 * 1024)
            self.metrics.memory_usage_mb = final_memory - initial_memory
            self.metrics.cpu_usage_percent = process.cpu_percent()
            
            with self._lock:
                self.result = result
                self.metrics.mark_completed()
                self._completed_event.set()
            
            return result
            
        except Exception as e:
            with self._lock:
                self.metrics.mark_failed(str(e))
                self._completed_event.set()
            raise
    
    def cancel(self):
        """Cancel the task."""
        with self._lock:
            self.cancelled = True
            if self.future:
                self.future.cancel()
            self._completed_event.set()
    
    def wait(self, timeout: Optional[float] = None) -> bool:
        """Wait for task completion."""
        return self._completed_event.wait(timeout)
    
    def is_completed(self) -> bool:
        """Check if task is completed."""
        return self._completed_event.is_set()
    
    def __lt__(self, other):
        """Compare tasks by priority for priority queue."""
        return self.priority > other.priority  # Higher priority first

class TaskScheduler:
    """
    Intelligent task scheduler with dependency resolution and load balancing.
    
    Manages task dependencies, resource allocation, and execution ordering
    for optimal parallel processing performance.
    """
    
    def __init__(self, resource_limits: ResourceLimits):
        """
        Initialize task scheduler.
        
        Args:
            resource_limits: Resource limits for task execution
        """
        self.resource_limits = resource_limits
        self.task_queue = queue.PriorityQueue(maxsize=resource_limits.queue_size_limit)
        self.completed_tasks: Dict[str, AnalysisTask] = {}
        self.running_tasks: Dict[str, AnalysisTask] = {}
        self.waiting_tasks: Dict[str, AnalysisTask] = {}
        self.task_metrics: Dict[str, TaskMetrics] = {}
        
        self._lock = threading.Lock()
        self._shutdown = False
        self.logger = ContextualLogger("task_scheduler")
    
    def schedule_task(self, task: AnalysisTask) -> bool:
        """
        Schedule a task for execution.
        
        Args:
            task: The task to schedule
            
        Returns:
            True if task was scheduled, False if queue is full
        """
        if self._shutdown:
            raise ParallelProcessingError("Task scheduler is shutting down")
        
        try:
            # Check dependencies
            if task.dependencies:
                unresolved_deps = [dep for dep in task.dependencies 
                                 if dep not in self.completed_tasks]
                if unresolved_deps:
                    self.logger.debug(f"Task {task.task_id} waiting for dependencies: {unresolved_deps}")
                    with self._lock:
                        self.waiting_tasks[task.task_id] = task
                    return True
            
            # Add to priority queue
            self.task_queue.put((task.priority, time.time(), task), block=False)
            self.logger.debug(f"Scheduled task {task.task_id} with priority {task.priority}")
            return True
            
        except queue.Full:
            self.logger.warning(f"Task queue full, cannot schedule task {task.task_id}")
            return False
    
    def get_next_task(self, timeout: Optional[float] = None) -> Optional[AnalysisTask]:
        """
        Get the next task ready for execution.
        
        Args:
            timeout: Timeout for waiting for a task
            
        Returns:
            Next available task or None if timeout
        """
        try:
            _, _, task = self.task_queue.get(timeout=timeout)
            
            with self._lock:
                self.running_tasks[task.task_id] = task
                self.task_metrics[task.task_id] = task.metrics
            
            return task
            
        except queue.Empty:
            return None
    
    def complete_task(self, task: AnalysisTask):
        """
        Mark a task as completed and check for dependent tasks.
        
        Args:
            task: The completed task
        """
        with self._lock:
            # Move from running to completed
            if task.task_id in self.running_tasks:
                del self.running_tasks[task.task_id]
            self.completed_tasks[task.task_id] = task
            
            # Check for waiting tasks that can now run
            ready_tasks = []
            for waiting_task in list(self.waiting_tasks.values()):
                unresolved_deps = [dep for dep in waiting_task.dependencies 
                                 if dep not in self.completed_tasks]
                if not unresolved_deps:
                    ready_tasks.append(waiting_task)
                    del self.waiting_tasks[waiting_task.task_id]
            
            # Schedule ready tasks
            for ready_task in ready_tasks:
                try:
                    self.task_queue.put((ready_task.priority, time.time(), ready_task), block=False)
                    self.logger.debug(f"Scheduled dependent task {ready_task.task_id}")
                except queue.Full:
                    # Put back in waiting if queue is full
                    self.waiting_tasks[ready_task.task_id] = ready_task
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get scheduler metrics."""
        with self._lock:
            return {
                'queued_tasks': self.task_queue.qsize(),
                'running_tasks': len(self.running_tasks),
                'completed_tasks': len(self.completed_tasks),
                'waiting_tasks': len(self.waiting_tasks),
                'total_memory_usage': sum(m.memory_usage_mb for m in self.task_metrics.values()),
                'average_cpu_usage': sum(m.cpu_usage_percent for m in self.task_metrics.values()) / 
                                   len(self.task_metrics) if self.task_metrics else 0
            }
    
    def shutdown(self):
        """Shutdown the scheduler."""
        self._shutdown = True
        
        # Cancel all waiting and running tasks
        with self._lock:
            for task in list(self.waiting_tasks.values()):
                task.cancel()
            for task in list(self.running_tasks.values()):
                task.cancel()

class ResourceManager:
    """
    Manages system resources for parallel processing.
    
    Monitors CPU, memory, and other resources to ensure optimal
    performance without system overload.
    """
    
    def __init__(self, resource_limits: ResourceLimits):
        """
        Initialize resource manager.
        
        Args:
            resource_limits: Resource limits to enforce
        """
        self.resource_limits = resource_limits
        self.monitoring_active = False
        self._monitor_thread: Optional[threading.Thread] = None
        self._shutdown_event = threading.Event()
        self.logger = ContextualLogger("resource_manager")
        
        # Resource metrics
        self.current_memory_mb = 0.0
        self.current_cpu_percent = 0.0
        self.active_threads = 0
        self.active_processes = 0
    
    def start_monitoring(self):
        """Start resource monitoring."""
        if self.monitoring_active:
            return
        
        self.monitoring_active = True
        self._monitor_thread = threading.Thread(target=self._monitor_resources, daemon=True)
        self._monitor_thread.start()
        self.logger.info("Started resource monitoring")
    
    def stop_monitoring(self):
        """Stop resource monitoring."""
        if not self.monitoring_active:
            return
        
        self.monitoring_active = False
        self._shutdown_event.set()
        if self._monitor_thread:
            self._monitor_thread.join(timeout=5.0)
        self.logger.info("Stopped resource monitoring")
    
    def _monitor_resources(self):
        """Monitor system resources in background thread."""
        while self.monitoring_active and not self._shutdown_event.is_set():
            try:
                # Get current resource usage
                process = psutil.Process()
                self.current_memory_mb = process.memory_info().rss / (1024 * 1024)
                self.current_cpu_percent = process.cpu_percent(interval=1.0)
                
                # Log warnings if limits are exceeded
                if self.current_memory_mb > self.resource_limits.max_memory_mb:
                    self.logger.warning(f"Memory usage ({self.current_memory_mb:.1f}MB) exceeds limit ({self.resource_limits.max_memory_mb}MB)")
                
                if self.current_cpu_percent > self.resource_limits.max_cpu_percent:
                    self.logger.warning(f"CPU usage ({self.current_cpu_percent:.1f}%) exceeds limit ({self.resource_limits.max_cpu_percent}%)")
                
            except Exception as e:
                self.logger.error(f"Error monitoring resources: {e}")
            
            # Wait for next check or shutdown
            self._shutdown_event.wait(timeout=5.0)
    
    def can_execute_task(self) -> bool:
        """Check if resources allow task execution."""
        memory_ok = self.current_memory_mb < self.resource_limits.max_memory_mb
        cpu_ok = self.current_cpu_percent < self.resource_limits.max_cpu_percent
        threads_ok = self.active_threads < self.resource_limits.max_threads
        
        return memory_ok and cpu_ok and threads_ok
    
    def acquire_thread_slot(self) -> bool:
        """Acquire a thread slot if available."""
        if self.active_threads < self.resource_limits.max_threads:
            self.active_threads += 1
            return True
        return False
    
    def release_thread_slot(self):
        """Release a thread slot."""
        if self.active_threads > 0:
            self.active_threads -= 1
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get resource metrics."""
        return {
            'memory_usage_mb': self.current_memory_mb,
            'memory_limit_mb': self.resource_limits.max_memory_mb,
            'cpu_usage_percent': self.current_cpu_percent,
            'cpu_limit_percent': self.resource_limits.max_cpu_percent,
            'active_threads': self.active_threads,
            'max_threads': self.resource_limits.max_threads,
            'memory_utilization': self.current_memory_mb / self.resource_limits.max_memory_mb,
            'cpu_utilization': self.current_cpu_percent / self.resource_limits.max_cpu_percent
        }

class ParallelAnalysisEngine:
    """
    Main parallel analysis engine for AODS framework.
    
    Coordinates thread pools, task scheduling, resource management,
    and provides high-level interface for parallel APK analysis.
    """
    
    def __init__(self, resource_limits: Optional[ResourceLimits] = None):
        """
        Initialize parallel analysis engine.
        
        Args:
            resource_limits: Optional custom resource limits
        """
        self.resource_limits = resource_limits or ResourceLimits()
        self.scheduler = TaskScheduler(self.resource_limits)
        self.resource_manager = ResourceManager(self.resource_limits)
        self.thread_executor = ThreadPoolExecutor(max_workers=self.resource_limits.max_threads)
        self.process_executor = ProcessPoolExecutor(max_workers=self.resource_limits.max_processes)
        
        # Engine state
        self.running = False
        self.worker_threads: List[threading.Thread] = []
        self._shutdown_event = threading.Event()
        self.logger = ContextualLogger("parallel_engine")
        
        # Metrics and monitoring
        self.processed_tasks = 0
        self.failed_tasks = 0
        self.total_processing_time = 0.0
    
    def start(self):
        """Start the parallel processing engine."""
        if self.running:
            return
        
        self.running = True
        self.resource_manager.start_monitoring()
        
        # Start worker threads
        for i in range(self.resource_limits.max_threads // 2):  # Conservative thread count
            worker = threading.Thread(target=self._worker_loop, args=(f"worker-{i}",), daemon=True)
            worker.start()
            self.worker_threads.append(worker)
        
        self.logger.info(f"Started parallel analysis engine with {len(self.worker_threads)} workers")
    
    def stop(self):
        """Stop the parallel processing engine."""
        if not self.running:
            return
        
        self.running = False
        self._shutdown_event.set()
        
        # Shutdown components
        self.scheduler.shutdown()
        self.resource_manager.stop_monitoring()
        
        # Wait for workers to finish
        for worker in self.worker_threads:
            worker.join(timeout=10.0)
        
        # Shutdown executors
        self.thread_executor.shutdown(wait=True)
        self.process_executor.shutdown(wait=True)
        
        self.logger.info("Stopped parallel analysis engine")
    
    def _worker_loop(self, worker_id: str):
        """Main worker loop for processing tasks."""
        worker_logger = ContextualLogger(f"worker.{worker_id}")
        
        while self.running and not self._shutdown_event.is_set():
            try:
                # Check resource availability
                if not self.resource_manager.can_execute_task():
                    worker_logger.debug("Waiting for resources")
                    time.sleep(1.0)
                    continue
                
                # Get next task
                task = self.scheduler.get_next_task(timeout=1.0)
                if not task:
                    continue
                
                # Acquire thread slot
                if not self.resource_manager.acquire_thread_slot():
                    # Put task back in queue
                    self.scheduler.schedule_task(task)
                    continue
                
                try:
                    # Execute task
                    worker_logger.debug(f"Executing task {task.task_id}")
                    task.execute()
                    
                    # Update metrics
                    self.processed_tasks += 1
                    if task.metrics.duration:
                        self.total_processing_time += task.metrics.duration
                    
                    worker_logger.debug(f"Completed task {task.task_id} in {task.metrics.duration:.2f}s")
                    
                except Exception as e:
                    self.failed_tasks += 1
                    worker_logger.error(f"Task {task.task_id} failed: {e}")
                
                finally:
                    # Release resources and mark task complete
                    self.resource_manager.release_thread_slot()
                    self.scheduler.complete_task(task)
                
            except Exception as e:
                worker_logger.error(f"Error in worker loop: {e}")
                time.sleep(1.0)
    
    def submit_task(self, task: AnalysisTask) -> bool:
        """
        Submit a task for parallel execution.
        
        Args:
            task: The task to execute
            
        Returns:
            True if task was submitted successfully
        """
        if not self.running:
            raise ParallelProcessingError("Engine is not running")
        
        return self.scheduler.schedule_task(task)
    
    def create_task(self, 
                   task_id: str,
                   operation: Callable[..., T],
                   *args,
                   priority: int = 0,
                   timeout: Optional[int] = None,
                   dependencies: List[str] = None,
                   **kwargs) -> AnalysisTask[T]:
        """
        Create and submit an analysis task.
        
        Args:
            task_id: Unique identifier for the task
            operation: The operation to execute
            *args: Positional arguments for the operation
            priority: Task priority
            timeout: Task timeout in seconds
            dependencies: List of task IDs this task depends on
            **kwargs: Keyword arguments for the operation
            
        Returns:
            Created analysis task
        """
        task = AnalysisTask(
            task_id=task_id,
            operation=operation,
            args=args,
            kwargs=kwargs,
            priority=priority,
            timeout=timeout,
            dependencies=dependencies
        )
        
        if not self.submit_task(task):
            raise ParallelProcessingError(f"Failed to submit task {task_id}")
        
        return task
    
    async def execute_async(self, 
                          operations: List[Callable],
                          max_concurrent: Optional[int] = None) -> List[Any]:
        """
        Execute multiple operations asynchronously.
        
        Args:
            operations: List of operations to execute
            max_concurrent: Maximum concurrent operations
            
        Returns:
            List of results in order
        """
        max_concurrent = max_concurrent or self.resource_limits.max_threads
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def execute_with_semaphore(op):
            async with semaphore:
                loop = asyncio.get_event_loop()
                return await loop.run_in_executor(self.thread_executor, op)
        
        tasks = [execute_with_semaphore(op) for op in operations]
        return await asyncio.gather(*tasks)
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get comprehensive engine metrics."""
        scheduler_metrics = self.scheduler.get_metrics()
        resource_metrics = self.resource_manager.get_metrics()
        
        engine_metrics = {
            'processed_tasks': self.processed_tasks,
            'failed_tasks': self.failed_tasks,
            'success_rate': (self.processed_tasks / (self.processed_tasks + self.failed_tasks)) 
                          if (self.processed_tasks + self.failed_tasks) > 0 else 0.0,
            'total_processing_time': self.total_processing_time,
            'average_task_time': (self.total_processing_time / self.processed_tasks) 
                                if self.processed_tasks > 0 else 0.0,
            'worker_threads': len(self.worker_threads),
            'engine_running': self.running
        }
        
        return {
            'engine': engine_metrics,
            'scheduler': scheduler_metrics,
            'resources': resource_metrics
        }
    
    @contextmanager
    def analysis_session(self):
        """Context manager for analysis session with automatic start/stop."""
        if not self.running:
            self.start()
            should_stop = True
        else:
            should_stop = False
        
        try:
            yield self
        finally:
            if should_stop:
                self.stop()

# Global parallel analysis engine instance
_parallel_engine: Optional[ParallelAnalysisEngine] = None

def get_parallel_engine(resource_limits: Optional[ResourceLimits] = None) -> ParallelAnalysisEngine:
    """Get or create global parallel analysis engine."""
    global _parallel_engine
    
    if _parallel_engine is None:
        _parallel_engine = ParallelAnalysisEngine(resource_limits)
    
    return _parallel_engine

def parallel_execute(operations: List[Callable], 
                    max_workers: Optional[int] = None) -> List[Any]:
    """
    Execute operations in parallel using the global engine.
    
    Args:
        operations: List of operations to execute
        max_workers: Maximum concurrent workers
        
    Returns:
        List of results in order
    """
    engine = get_parallel_engine()
    
    with engine.analysis_session():
        # Create tasks for all operations
        tasks = []
        for i, operation in enumerate(operations):
            task = engine.create_task(
                task_id=f"parallel_op_{i}",
                operation=operation,
                priority=0
            )
            tasks.append(task)
        
        # Wait for all tasks to complete
        results = []
        for task in tasks:
            task.wait(timeout=300)  # 5 minute timeout
            if task.metrics.status == "completed":
                results.append(task.result)
            else:
                results.append(None)
        
        return results 
#!/usr/bin/env python3
"""
Unified Parallel Framework - Core Execution Engine

Central execution engine consolidating all parallel execution approaches:
- Plugin-level parallel execution with dependency management
- Process-level execution with inter-process communication
- Task-level execution with resource management
- Enhanced error handling and monitoring

Consolidates capabilities from:
- parallel_analysis_engine.py (plugin coordination)
- parallel_execution_manager.py (process management)
- enhanced_parallel_execution.py (robust execution)
"""

import asyncio
import logging
import multiprocessing as mp
import os
import signal
import threading
import time
from abc import ABC, abstractmethod
from concurrent.futures import Future, ThreadPoolExecutor, ProcessPoolExecutor, as_completed
from dataclasses import dataclass, field
from enum import Enum
from queue import PriorityQueue, Queue
from typing import Any, Dict, List, Optional, Set, Tuple, Union, Callable

import psutil
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.progress import Progress, TaskID
from rich.table import Table
from rich.text import Text

class ExecutionMode(Enum):
    """Unified execution modes for different parallel approaches."""
    SEQUENTIAL = "sequential"                    # Sequential execution
    THREAD_BASED = "thread_based"               # Thread-based parallel execution
    PROCESS_BASED = "process_based"             # Process-based parallel execution
    HYBRID = "hybrid"                           # Hybrid thread+process execution
    PLUGIN_OPTIMIZED = "plugin_optimized"      # Optimized for plugin execution
    ANALYSIS_SEPARATED = "analysis_separated"   # Separate static/dynamic processes
    ADAPTIVE = "adaptive"                       # Adaptive based on system resources

class ExecutionLevel(Enum):
    """Level of parallel execution granularity."""
    TASK = "task"                    # Individual task execution
    PLUGIN = "plugin"                # Plugin-level execution
    ANALYSIS_TYPE = "analysis_type"  # Analysis type separation (static/dynamic)
    PROCESS = "process"              # Full process separation

class ResourceLevel(Enum):
    """System resource utilization levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class ExecutionTask:
    """Unified task representation for all execution types."""
    task_id: str
    task_type: str
    priority: int
    dependencies: Set[str] = field(default_factory=set)
    estimated_time_seconds: float = 10.0
    memory_requirement_mb: float = 100.0
    cpu_intensive: bool = False
    io_intensive: bool = False
    payload: Dict[str, Any] = field(default_factory=dict)
    
    # Execution tracking
    start_time: Optional[float] = None
    end_time: Optional[float] = None
    result: Optional[Any] = None
    error: Optional[str] = None
    worker_id: Optional[str] = None
    
    def __lt__(self, other):
        return self.priority < other.priority
    
    @property
    def execution_time(self) -> Optional[float]:
        if self.start_time and self.end_time:
            return self.end_time - self.start_time
        return None
    
    @property
    def is_completed(self) -> bool:
        return self.end_time is not None
    
    @property
    def is_successful(self) -> bool:
        return self.is_completed and self.error is None

@dataclass
class ExecutionMetrics:
    """Comprehensive execution metrics for monitoring."""
    total_tasks: int = 0
    completed_tasks: int = 0
    failed_tasks: int = 0
    running_tasks: int = 0
    pending_tasks: int = 0
    
    total_execution_time: float = 0.0
    average_task_time: float = 0.0
    parallel_efficiency: float = 1.0
    
    memory_peak_mb: float = 0.0
    cpu_peak_percent: float = 0.0
    
    workers_used: int = 0
    workers_max: int = 0
    
    cache_hits: int = 0
    cache_misses: int = 0
    
    @property
    def success_rate(self) -> float:
        if self.total_tasks == 0:
            return 0.0
        return self.completed_tasks / self.total_tasks
    
    @property
    def completion_rate(self) -> float:
        if self.total_tasks == 0:
            return 0.0
        return (self.completed_tasks + self.failed_tasks) / self.total_tasks

class DependencyGraph:
    """Manages task dependencies for parallel execution scheduling."""
    
    def __init__(self):
        self.graph: Dict[str, Set[str]] = {}
        self.reverse_graph: Dict[str, Set[str]] = {}
        self.completed: Set[str] = set()
        self._lock = threading.RLock()
    
    def add_task(self, task_id: str, dependencies: Set[str] = None):
        """Add a task with its dependencies."""
        with self._lock:
            if dependencies is None:
                dependencies = set()
            
            self.graph[task_id] = dependencies.copy()
            
            if task_id not in self.reverse_graph:
                self.reverse_graph[task_id] = set()
            
            for dep in dependencies:
                if dep not in self.reverse_graph:
                    self.reverse_graph[dep] = set()
                self.reverse_graph[dep].add(task_id)
    
    def get_ready_tasks(self) -> List[str]:
        """Get tasks that are ready to execute (all dependencies satisfied)."""
        with self._lock:
            ready = []
            for task_id, dependencies in self.graph.items():
                if task_id not in self.completed:
                    if dependencies.issubset(self.completed):
                        ready.append(task_id)
            return ready
    
    def mark_completed(self, task_id: str):
        """Mark a task as completed."""
        with self._lock:
            self.completed.add(task_id)
    
    def get_dependents(self, task_id: str) -> Set[str]:
        """Get tasks that depend on the given task."""
        with self._lock:
            return self.reverse_graph.get(task_id, set()).copy()
    
    def has_circular_dependencies(self) -> bool:
        """Check for circular dependencies in the graph."""
        with self._lock:
            visited = set()
            rec_stack = set()
            
            def has_cycle(node):
                visited.add(node)
                rec_stack.add(node)
                
                for neighbor in self.graph.get(node, set()):
                    if neighbor not in visited:
                        if has_cycle(neighbor):
                            return True
                    elif neighbor in rec_stack:
                        return True
                
                rec_stack.remove(node)
                return False
            
            for node in self.graph:
                if node not in visited:
                    if has_cycle(node):
                        return True
            
            return False

class ExecutionContext:
    """Context for execution providing shared resources and state."""
    
    def __init__(self, execution_id: str, config: Dict[str, Any] = None):
        self.execution_id = execution_id
        self.config = config or {}
        self.shared_data = {}
        self.metrics = ExecutionMetrics()
        self.start_time = time.time()
        self.end_time: Optional[float] = None
        
        # Communication channels
        self.task_queue = PriorityQueue()
        self.result_queue = Queue()
        self.status_updates = Queue()
        
        # Synchronization
        self._lock = threading.RLock()
        self._shutdown_event = threading.Event()
        
        # Resource monitoring
        self.resource_monitor = None
        self.console = Console()
    
    def set_shared_data(self, key: str, value: Any):
        """Set shared data accessible to all execution components."""
        with self._lock:
            self.shared_data[key] = value
    
    def get_shared_data(self, key: str, default: Any = None) -> Any:
        """Get shared data."""
        with self._lock:
            return self.shared_data.get(key, default)
    
    def signal_shutdown(self):
        """Signal shutdown to all execution components."""
        self._shutdown_event.set()
    
    def is_shutdown_requested(self) -> bool:
        """Check if shutdown has been requested."""
        return self._shutdown_event.is_set()
    
    def update_metrics(self, **kwargs):
        """Update execution metrics."""
        with self._lock:
            for key, value in kwargs.items():
                if hasattr(self.metrics, key):
                    setattr(self.metrics, key, value)
    
    def finalize(self):
        """Finalize execution context."""
        self.end_time = time.time()
        if self.start_time:
            self.metrics.total_execution_time = self.end_time - self.start_time

class ExecutionEngine(ABC):
    """Abstract base class for execution engines."""
    
    def __init__(self, max_workers: int = 4, engine_config: Dict[str, Any] = None):
        self.max_workers = max_workers
        self.config = engine_config or {}
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        
        # Auto-optimize worker count based on system resources
        self._optimize_worker_count()
        
        # Execution tracking
        self.active_tasks: Dict[str, ExecutionTask] = {}
        self.dependency_graph = DependencyGraph()
        self._task_lock = threading.RLock()
        
        # Performance tracking
        self.execution_history: List[ExecutionTask] = []
        self.performance_cache: Dict[str, Dict[str, float]] = {}
        
        self.logger.info(f"{self.__class__.__name__} initialized with {self.max_workers} workers")
    
    def _optimize_worker_count(self):
        """Optimize worker count based on system capabilities."""
        try:
            cpu_count = os.cpu_count() or 4
            memory_gb = psutil.virtual_memory().total / (1024**3)
            
            # Base optimization on CPU and memory
            if self.max_workers == 4:  # Default value
                # Use 75% of CPU cores, but consider memory
                optimal_workers = max(2, int(cpu_count * 0.75))
                
                # Memory-based constraints
                if memory_gb < 4:
                    optimal_workers = min(optimal_workers, 2)
                elif memory_gb < 8:
                    optimal_workers = min(optimal_workers, 4)
                
                self.max_workers = optimal_workers
                self.logger.info(f"Optimized worker count: {self.max_workers} "
                               f"(CPU: {cpu_count}, Memory: {memory_gb:.1f}GB)")
        
        except Exception as e:
            self.logger.warning(f"Failed to optimize worker count: {e}")
    
    @abstractmethod
    def execute_tasks(self, tasks: List[ExecutionTask], context: ExecutionContext) -> Dict[str, Any]:
        """Execute tasks using this engine's approach."""
        pass
    
    @abstractmethod
    def get_execution_mode(self) -> ExecutionMode:
        """Get the execution mode this engine implements."""
        pass
    
    @abstractmethod
    def is_suitable_for(self, tasks: List[ExecutionTask], context: ExecutionContext) -> float:
        """Return suitability score (0.0-1.0) for executing given tasks."""
        pass
    
    def add_task(self, task: ExecutionTask):
        """Add a task to the execution queue."""
        with self._task_lock:
            self.active_tasks[task.task_id] = task
            self.dependency_graph.add_task(task.task_id, task.dependencies)
    
    def get_ready_tasks(self) -> List[ExecutionTask]:
        """Get tasks ready for execution."""
        ready_ids = self.dependency_graph.get_ready_tasks()
        return [self.active_tasks[task_id] for task_id in ready_ids 
                if task_id in self.active_tasks and not self.active_tasks[task_id].is_completed]
    
    def mark_task_completed(self, task_id: str, result: Any = None, error: str = None):
        """Mark a task as completed."""
        with self._task_lock:
            if task_id in self.active_tasks:
                task = self.active_tasks[task_id]
                task.end_time = time.time()
                task.result = result
                task.error = error
                
                self.dependency_graph.mark_completed(task_id)
                self.execution_history.append(task)
                
                # Update performance cache
                if task.execution_time:
                    task_type = task.task_type
                    if task_type not in self.performance_cache:
                        self.performance_cache[task_type] = {
                            'avg_time': 0.0,
                            'total_executions': 0,
                            'success_rate': 0.0
                        }
                    
                    cache = self.performance_cache[task_type]
                    cache['total_executions'] += 1
                    cache['avg_time'] = (
                        (cache['avg_time'] * (cache['total_executions'] - 1) + task.execution_time) /
                        cache['total_executions']
                    )
                    
                    if not error:
                        cache['success_rate'] = (
                            (cache['success_rate'] * (cache['total_executions'] - 1) + 1.0) /
                            cache['total_executions']
                        )
    
    def get_performance_metrics(self) -> Dict[str, Any]:
        """Get comprehensive performance metrics."""
        completed_tasks = [t for t in self.execution_history if t.is_completed]
        successful_tasks = [t for t in completed_tasks if t.is_successful]
        
        if not completed_tasks:
            return {
                'total_tasks': 0,
                'success_rate': 0.0,
                'average_execution_time': 0.0,
                'engine_type': self.__class__.__name__
            }
        
        avg_time = sum(t.execution_time for t in completed_tasks if t.execution_time) / len(completed_tasks)
        
        return {
            'total_tasks': len(completed_tasks),
            'successful_tasks': len(successful_tasks),
            'success_rate': len(successful_tasks) / len(completed_tasks),
            'average_execution_time': avg_time,
            'task_type_performance': self.performance_cache.copy(),
            'engine_type': self.__class__.__name__,
            'execution_mode': self.get_execution_mode().value
        }
    
    def cleanup(self):
        """Cleanup engine resources."""
        pass

class ThreadBasedEngine(ExecutionEngine):
    """Thread-based parallel execution engine."""
    
    def get_execution_mode(self) -> ExecutionMode:
        return ExecutionMode.THREAD_BASED
    
    def is_suitable_for(self, tasks: List[ExecutionTask], context: ExecutionContext) -> float:
        """High suitability for I/O intensive tasks, plugin execution."""
        io_intensive_count = sum(1 for task in tasks if task.io_intensive)
        cpu_intensive_count = sum(1 for task in tasks if task.cpu_intensive)
        
        # Threads are better for I/O intensive tasks
        if io_intensive_count > cpu_intensive_count:
            return 0.9
        elif cpu_intensive_count > len(tasks) * 0.7:
            return 0.3  # Less suitable for CPU-heavy tasks
        else:
            return 0.7  # Good general purpose
    
    def execute_tasks(self, tasks: List[ExecutionTask], context: ExecutionContext) -> Dict[str, Any]:
        """Execute tasks using thread-based parallelism."""
        self.logger.info(f"Executing {len(tasks)} tasks with thread-based engine")
        
        # Add tasks to dependency graph
        for task in tasks:
            self.add_task(task)
        
        results = {}
        completed_count = 0
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            active_futures: Dict[Future, ExecutionTask] = {}
            
            while completed_count < len(tasks) and not context.is_shutdown_requested():
                # Submit ready tasks
                ready_tasks = self.get_ready_tasks()
                
                for task in ready_tasks:
                    if len(active_futures) < self.max_workers:
                        future = executor.submit(self._execute_single_task, task, context)
                        active_futures[future] = task
                        task.start_time = time.time()
                
                # Process completed futures
                if active_futures:
                    completed_futures = as_completed(active_futures, timeout=1.0)
                    
                    try:
                        for future in completed_futures:
                            task = active_futures[future]
                            
                            try:
                                result = future.result()
                                self.mark_task_completed(task.task_id, result)
                                results[task.task_id] = result
                            except Exception as e:
                                self.mark_task_completed(task.task_id, error=str(e))
                                results[task.task_id] = {"error": str(e)}
                            
                            del active_futures[future]
                            completed_count += 1
                            break  # Process one at a time
                    
                    except TimeoutError:
                        continue  # Check for new ready tasks
                
                # Prevent busy waiting
                time.sleep(0.01)
        
        self.logger.info(f"Thread-based execution completed: {completed_count}/{len(tasks)} tasks")
        return results
    
    def _execute_single_task(self, task: ExecutionTask, context: ExecutionContext) -> Any:
        """Execute a single task with error handling."""
        try:
            task_function = task.payload.get('function')
            task_args = task.payload.get('args', ())
            task_kwargs = task.payload.get('kwargs', {})
            
            if task_function:
                return task_function(*task_args, **task_kwargs)
            else:
                raise ValueError(f"No function provided for task {task.task_id}")
        
        except Exception as e:
            self.logger.error(f"Task {task.task_id} failed: {e}")
            raise

class ProcessBasedEngine(ExecutionEngine):
    """Process-based parallel execution engine."""
    
    def get_execution_mode(self) -> ExecutionMode:
        return ExecutionMode.PROCESS_BASED
    
    def is_suitable_for(self, tasks: List[ExecutionTask], context: ExecutionContext) -> float:
        """High suitability for CPU intensive tasks, isolated execution."""
        cpu_intensive_count = sum(1 for task in tasks if task.cpu_intensive)
        memory_heavy_count = sum(1 for task in tasks if task.memory_requirement_mb > 500)
        
        # Processes are better for CPU-intensive tasks
        if cpu_intensive_count > len(tasks) * 0.5:
            return 0.9
        elif memory_heavy_count > 0:
            return 0.8  # Good for memory isolation
        else:
            return 0.5  # Moderate for other tasks
    
    def execute_tasks(self, tasks: List[ExecutionTask], context: ExecutionContext) -> Dict[str, Any]:
        """Execute tasks using process-based parallelism."""
        self.logger.info(f"Executing {len(tasks)} tasks with process-based engine")
        
        # Add tasks to dependency graph
        for task in tasks:
            self.add_task(task)
        
        results = {}
        completed_count = 0
        
        with ProcessPoolExecutor(max_workers=self.max_workers) as executor:
            active_futures: Dict[Future, ExecutionTask] = {}
            
            while completed_count < len(tasks) and not context.is_shutdown_requested():
                # Submit ready tasks
                ready_tasks = self.get_ready_tasks()
                
                for task in ready_tasks:
                    if len(active_futures) < self.max_workers:
                        future = executor.submit(self._execute_single_task_process, task, context)
                        active_futures[future] = task
                        task.start_time = time.time()
                
                # Process completed futures
                if active_futures:
                    completed_futures = as_completed(active_futures, timeout=1.0)
                    
                    try:
                        for future in completed_futures:
                            task = active_futures[future]
                            
                            try:
                                result = future.result()
                                self.mark_task_completed(task.task_id, result)
                                results[task.task_id] = result
                            except Exception as e:
                                self.mark_task_completed(task.task_id, error=str(e))
                                results[task.task_id] = {"error": str(e)}
                            
                            del active_futures[future]
                            completed_count += 1
                            break
                    
                    except TimeoutError:
                        continue
                
                time.sleep(0.01)
        
        self.logger.info(f"Process-based execution completed: {completed_count}/{len(tasks)} tasks")
        return results
    
    def _execute_single_task_process(self, task: ExecutionTask, context: ExecutionContext) -> Any:
        """Execute a single task in a separate process."""
        try:
            task_function = task.payload.get('function')
            task_args = task.payload.get('args', ())
            task_kwargs = task.payload.get('kwargs', {})
            
            if task_function:
                return task_function(*task_args, **task_kwargs)
            else:
                raise ValueError(f"No function provided for task {task.task_id}")
        
        except Exception as e:
            raise

class HybridEngine(ExecutionEngine):
    """Hybrid thread+process execution engine."""
    
    def __init__(self, max_workers: int = 4, engine_config: Dict[str, Any] = None):
        super().__init__(max_workers, engine_config)
        
        # Create sub-engines
        thread_workers = max(2, self.max_workers // 2)
        process_workers = max(1, self.max_workers // 2)
        
        self.thread_engine = ThreadBasedEngine(thread_workers, engine_config)
        self.process_engine = ProcessBasedEngine(process_workers, engine_config)
    
    def get_execution_mode(self) -> ExecutionMode:
        return ExecutionMode.HYBRID
    
    def is_suitable_for(self, tasks: List[ExecutionTask], context: ExecutionContext) -> float:
        """Suitable for mixed workloads."""
        cpu_intensive_count = sum(1 for task in tasks if task.cpu_intensive)
        io_intensive_count = sum(1 for task in tasks if task.io_intensive)
        
        # Good for mixed workloads
        if abs(cpu_intensive_count - io_intensive_count) < len(tasks) * 0.3:
            return 0.9
        else:
            return 0.6
    
    def execute_tasks(self, tasks: List[ExecutionTask], context: ExecutionContext) -> Dict[str, Any]:
        """Execute tasks using hybrid approach."""
        self.logger.info(f"Executing {len(tasks)} tasks with hybrid engine")
        
        # Categorize tasks
        cpu_tasks = [task for task in tasks if task.cpu_intensive]
        io_tasks = [task for task in tasks if task.io_intensive]
        other_tasks = [task for task in tasks if not task.cpu_intensive and not task.io_intensive]
        
        # Distribute other tasks based on estimated execution time
        for task in other_tasks:
            if task.estimated_time_seconds > 30:
                cpu_tasks.append(task)  # Long tasks to processes
            else:
                io_tasks.append(task)   # Short tasks to threads
        
        results = {}
        
        # Execute in parallel using both engines
        thread_future = None
        process_future = None
        
        if io_tasks:
            thread_future = asyncio.get_event_loop().run_in_executor(
                None, self.thread_engine.execute_tasks, io_tasks, context
            )
        
        if cpu_tasks:
            process_future = asyncio.get_event_loop().run_in_executor(
                None, self.process_engine.execute_tasks, cpu_tasks, context
            )
        
        # Collect results
        if thread_future:
            thread_results = asyncio.get_event_loop().run_until_complete(thread_future)
            results.update(thread_results)
        
        if process_future:
            process_results = asyncio.get_event_loop().run_until_complete(process_future)
            results.update(process_results)
        
        self.logger.info(f"Hybrid execution completed: {len(results)} results")
        return results
    
    def cleanup(self):
        """Cleanup both engines."""
        self.thread_engine.cleanup()
        self.process_engine.cleanup()

def create_execution_engine(execution_mode: ExecutionMode, 
                          max_workers: int = 4, 
                          config: Dict[str, Any] = None) -> ExecutionEngine:
    """Factory function to create execution engines."""
    engine_config = config or {}
    
    if execution_mode == ExecutionMode.THREAD_BASED:
        return ThreadBasedEngine(max_workers, engine_config)
    elif execution_mode == ExecutionMode.PROCESS_BASED:
        return ProcessBasedEngine(max_workers, engine_config)
    elif execution_mode == ExecutionMode.HYBRID:
        return HybridEngine(max_workers, engine_config)
    else:
        # Default to thread-based for unknown modes
        return ThreadBasedEngine(max_workers, engine_config)

# Utility functions for task creation
def create_plugin_task(plugin_name: str, plugin_function: Callable, 
                      args: Tuple = (), kwargs: Dict = None, 
                      priority: int = 100) -> ExecutionTask:
    """Create a task for plugin execution."""
    return ExecutionTask(
        task_id=f"plugin_{plugin_name}",
        task_type="plugin",
        priority=priority,
        io_intensive=True,  # Most plugins are I/O intensive
        payload={
            'function': plugin_function,
            'args': args,
            'kwargs': kwargs or {}
        }
    )

def create_analysis_task(analysis_type: str, analysis_function: Callable,
                        args: Tuple = (), kwargs: Dict = None,
                        cpu_intensive: bool = True) -> ExecutionTask:
    """Create a task for analysis execution."""
    return ExecutionTask(
        task_id=f"analysis_{analysis_type}",
        task_type="analysis",
        priority=50,
        cpu_intensive=cpu_intensive,
        memory_requirement_mb=200,
        estimated_time_seconds=60,
        payload={
            'function': analysis_function,
            'args': args,
            'kwargs': kwargs or {}
        }
    ) 
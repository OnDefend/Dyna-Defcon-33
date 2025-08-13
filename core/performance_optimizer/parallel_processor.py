#!/usr/bin/env python3
"""
Performance Optimizer - Parallel Processor

parallel processing framework with intelligent workload distribution,
resource management, and comprehensive performance monitoring.
"""

import logging
import time
import threading
from typing import Dict, List, Any, Optional, Callable, Union
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed, Future
import multiprocessing
import queue
import psutil

from .data_structures import ParallelMetrics, ParallelMode, PerformanceMetrics

class ParallelProcessor:
    """
    parallel processing system for AODS performance optimization
    
    Features:
    - Adaptive parallel processing (thread/process-based)
    - Intelligent workload distribution and load balancing
    - Resource-aware worker management
    - Comprehensive performance monitoring and metrics
    - Dynamic scaling based on system resources
    - Error handling and fault tolerance
    """
    
    def __init__(self, max_workers: Optional[int] = None, mode: ParallelMode = ParallelMode.ADAPTIVE):
        self.mode = mode
        self.logger = logging.getLogger(__name__)
        
        # Determine optimal worker count
        self.max_workers = self._determine_optimal_workers(max_workers)
        
        # Initialize executors
        self.thread_executor = None
        self.process_executor = None
        
        # Metrics and monitoring
        self.metrics = ParallelMetrics()
        self.performance_history = []
        self.lock = threading.RLock()
        
        # Workload management
        self.active_tasks = {}
        self.task_queue = queue.Queue()
        
        # Initialize parallel processing
        self._initialize_executors()
        
        self.logger.info(f"Parallel processor initialized with {self.max_workers} workers ({mode.value} mode)")
    
    def _determine_optimal_workers(self, max_workers: Optional[int]) -> int:
        """Determine optimal number of workers based on system resources."""
        try:
            cpu_count = multiprocessing.cpu_count()
            
            if max_workers is not None:
                return min(max_workers, cpu_count * 2)
            
            # Adaptive worker calculation based on system resources
            memory_gb = psutil.virtual_memory().total / (1024**3)
            
            # Conservative approach: don't oversubscribe
            if memory_gb < 4:
                optimal_workers = max(1, cpu_count // 2)
            elif memory_gb < 8:
                optimal_workers = cpu_count
            else:
                optimal_workers = min(cpu_count * 2, 12)  # Cap at 12 workers
            
            self.logger.info(f"Determined optimal worker count: {optimal_workers} (CPU: {cpu_count}, RAM: {memory_gb:.1f}GB)")
            return optimal_workers
            
        except Exception as e:
            self.logger.error(f"Error determining optimal workers: {e}")
            return 4  # Safe default
    
    def _initialize_executors(self):
        """Initialize thread and process executors based on mode."""
        try:
            if self.mode in [ParallelMode.THREAD_BASED, ParallelMode.ADAPTIVE]:
                self.thread_executor = ThreadPoolExecutor(
                    max_workers=self.max_workers,
                    thread_name_prefix="aods_thread"
                )
                self.logger.debug("Thread executor initialized")
            
            if self.mode in [ParallelMode.PROCESS_BASED, ParallelMode.HYBRID, ParallelMode.ADAPTIVE]:
                # Use fewer workers for process-based execution due to higher overhead
                process_workers = max(1, self.max_workers // 2)
                self.process_executor = ProcessPoolExecutor(
                    max_workers=process_workers
                )
                self.logger.debug(f"Process executor initialized with {process_workers} workers")
                
        except Exception as e:
            self.logger.error(f"Error initializing executors: {e}")
            # Fallback to thread-based execution
            self.thread_executor = ThreadPoolExecutor(max_workers=2)
    
    def process_parallel(self, items: List[Any], processor_func: Callable, 
                        chunk_size: Optional[int] = None, timeout: Optional[float] = None) -> List[Any]:
        """
        Process items in parallel with intelligent chunking and load balancing.
        """
        if not items:
            return []
        
        start_time = time.time()
        
        with self.lock:
            self.metrics.tasks_pending = len(items)
            self.metrics.workers_total = self.max_workers
        
        try:
            # Determine optimal processing strategy
            processing_strategy = self._determine_processing_strategy(items, processor_func)
            
            # Choose executor based on strategy
            executor = self._select_executor(processing_strategy)
            
            if executor is None:
                self.logger.warning("No executor available - falling back to sequential processing")
                return self._process_sequential(items, processor_func)
            
            # Determine optimal chunk size
            optimal_chunk_size = chunk_size or self._calculate_optimal_chunk_size(len(items))
            
            # Create chunks for parallel processing
            chunks = self._create_chunks(items, optimal_chunk_size)
            
            self.logger.info(f"Processing {len(items)} items in {len(chunks)} chunks using {processing_strategy}")
            
            # Submit tasks to executor
            future_to_chunk = {}
            for i, chunk in enumerate(chunks):
                future = executor.submit(self._process_chunk, chunk, processor_func, i)
                future_to_chunk[future] = (i, chunk)
                
                # Track active task
                task_id = f"chunk_{i}"
                self.active_tasks[task_id] = {
                    'future': future,
                    'start_time': time.time(),
                    'chunk_size': len(chunk)
                }
            
            # Collect results with timeout handling
            results = []
            completed_tasks = 0
            
            for future in as_completed(future_to_chunk.keys(), timeout=timeout):
                chunk_index, chunk = future_to_chunk[future]
                task_id = f"chunk_{chunk_index}"
                
                try:
                    chunk_results = future.result()
                    results.extend(chunk_results)
                    completed_tasks += 1
                    
                    # Update metrics
                    with self.lock:
                        self.metrics.tasks_completed += len(chunk)
                        self.metrics.tasks_pending = max(0, self.metrics.tasks_pending - len(chunk))
                    
                    # Clean up task tracking
                    if task_id in self.active_tasks:
                        task_duration = time.time() - self.active_tasks[task_id]['start_time']
                        self._update_task_metrics(task_duration, len(chunk))
                        del self.active_tasks[task_id]
                    
                except Exception as e:
                    self.logger.error(f"Chunk {chunk_index} processing failed: {e}")
                    # Process failed chunk sequentially as fallback
                    try:
                        fallback_results = self._process_chunk(chunk, processor_func, chunk_index)
                        results.extend(fallback_results)
                        completed_tasks += 1
                    except Exception as fallback_error:
                        self.logger.error(f"Fallback processing failed for chunk {chunk_index}: {fallback_error}")
            
            # Calculate final metrics
            total_duration = time.time() - start_time
            self._calculate_parallel_efficiency(total_duration, len(items), completed_tasks)
            
            self.logger.info(f"Parallel processing complete: {len(items)} items in {total_duration:.2f}s")
            
            return results
            
        except Exception as e:
            self.logger.error(f"Parallel processing failed: {e}")
            # Fallback to sequential processing
            return self._process_sequential(items, processor_func)
    
    def _determine_processing_strategy(self, items: List[Any], processor_func: Callable) -> str:
        """Determine optimal processing strategy based on workload characteristics."""
        try:
            item_count = len(items)
            
            # For small workloads, use sequential processing
            if item_count < 10:
                return "sequential"
            
            # For CPU-intensive tasks, prefer process-based execution
            if hasattr(processor_func, '__name__') and any(
                keyword in processor_func.__name__.lower() 
                for keyword in ['cpu', 'compute', 'calculate', 'analyze']
            ):
                if self.process_executor and item_count > 50:
                    return "process_based"
            
            # For I/O-intensive tasks or moderate workloads, use thread-based
            if self.thread_executor:
                return "thread_based"
            
            # Fallback
            return "sequential"
            
        except Exception as e:
            self.logger.error(f"Error determining processing strategy: {e}")
            return "thread_based"
    
    def _select_executor(self, strategy: str):
        """Select appropriate executor based on strategy."""
        if strategy == "process_based" and self.process_executor:
            return self.process_executor
        elif strategy == "thread_based" and self.thread_executor:
            return self.thread_executor
        elif self.thread_executor:
            return self.thread_executor
        else:
            return None
    
    def _calculate_optimal_chunk_size(self, total_items: int) -> int:
        """Calculate optimal chunk size for parallel processing."""
        try:
            # Base chunk size on number of workers and total items
            base_chunk_size = max(1, total_items // (self.max_workers * 2))
            
            # Adjust based on item count
            if total_items < 100:
                chunk_size = max(1, total_items // self.max_workers)
            elif total_items < 1000:
                chunk_size = base_chunk_size
            else:
                # For large datasets, use larger chunks to reduce overhead
                chunk_size = min(base_chunk_size * 2, total_items // self.max_workers)
            
            self.logger.debug(f"Calculated optimal chunk size: {chunk_size} for {total_items} items")
            return chunk_size
            
        except Exception as e:
            self.logger.error(f"Error calculating chunk size: {e}")
            return max(1, total_items // self.max_workers)
    
    def _create_chunks(self, items: List[Any], chunk_size: int) -> List[List[Any]]:
        """Create chunks from items list for parallel processing."""
        chunks = []
        for i in range(0, len(items), chunk_size):
            chunk = items[i:i + chunk_size]
            chunks.append(chunk)
        return chunks
    
    def _process_chunk(self, chunk: List[Any], processor_func: Callable, chunk_index: int) -> List[Any]:
        """Process a single chunk of items."""
        try:
            chunk_start_time = time.time()
            results = []
            
            for item in chunk:
                try:
                    result = processor_func(item)
                    results.append(result)
                except Exception as e:
                    self.logger.error(f"Error processing item in chunk {chunk_index}: {e}")
                    # Continue processing other items in chunk
                    results.append(None)  # Or some error indicator
            
            chunk_duration = time.time() - chunk_start_time
            self.logger.debug(f"Chunk {chunk_index} processed: {len(results)} items in {chunk_duration:.2f}s")
            
            return results
            
        except Exception as e:
            self.logger.error(f"Chunk {chunk_index} processing failed: {e}")
            raise
    
    def _process_sequential(self, items: List[Any], processor_func: Callable) -> List[Any]:
        """Fallback sequential processing."""
        self.logger.info(f"Processing {len(items)} items sequentially")
        
        results = []
        for i, item in enumerate(items):
            try:
                result = processor_func(item)
                results.append(result)
            except Exception as e:
                self.logger.error(f"Sequential processing error at item {i}: {e}")
                results.append(None)
        
        return results
    
    def _update_task_metrics(self, task_duration: float, items_processed: int):
        """Update task performance metrics."""
        with self.lock:
            # Update average task duration
            total_completed = self.metrics.tasks_completed
            if total_completed > 0:
                current_avg = self.metrics.average_task_duration_ms
                new_duration_ms = task_duration * 1000
                self.metrics.average_task_duration_ms = (
                    (current_avg * (total_completed - items_processed) + new_duration_ms) / 
                    total_completed
                )
            
            # Update worker utilization
            active_workers = len(self.active_tasks)
            self.metrics.workers_active = active_workers
            self.metrics.utilization_percentage = (
                active_workers / self.metrics.workers_total * 100
                if self.metrics.workers_total > 0 else 0
            )
    
    def _calculate_parallel_efficiency(self, total_duration: float, total_items: int, completed_chunks: int):
        """Calculate parallel processing efficiency metrics."""
        with self.lock:
            try:
                # Estimate sequential processing time
                if self.metrics.average_task_duration_ms > 0:
                    estimated_sequential_time = (
                        total_items * self.metrics.average_task_duration_ms / 1000
                    )
                    
                    # Calculate speedup factor
                    self.metrics.speedup_factor = (
                        estimated_sequential_time / total_duration 
                        if total_duration > 0 else 1.0
                    )
                    
                    # Calculate efficiency percentage
                    theoretical_speedup = min(self.max_workers, total_items)
                    self.metrics.efficiency_percentage = (
                        self.metrics.speedup_factor / theoretical_speedup * 100
                        if theoretical_speedup > 0 else 0
                    )
                
                # Calculate overhead
                if total_items > 0:
                    items_per_second = total_items / total_duration if total_duration > 0 else 0
                    theoretical_items_per_second = items_per_second * self.max_workers
                    
                    if theoretical_items_per_second > 0:
                        self.metrics.overhead_percentage = max(0, 
                            (1 - items_per_second / theoretical_items_per_second) * 100
                        )
                
                # Update parallel effectiveness
                self.metrics.parallel_effectiveness = min(100.0, 
                    (self.metrics.efficiency_percentage + 
                     (100 - self.metrics.overhead_percentage)) / 2
                )
                
            except Exception as e:
                self.logger.error(f"Error calculating parallel efficiency: {e}")
    
    def get_performance_report(self) -> Dict[str, Any]:
        """Generate comprehensive parallel processing performance report."""
        with self.lock:
            try:
                return {
                    'configuration': {
                        'max_workers': self.max_workers,
                        'processing_mode': self.mode.value,
                        'thread_executor_available': self.thread_executor is not None,
                        'process_executor_available': self.process_executor is not None
                    },
                    'current_status': {
                        'workers_active': self.metrics.workers_active,
                        'workers_total': self.metrics.workers_total,
                        'utilization_percentage': self.metrics.utilization_percentage,
                        'tasks_pending': self.metrics.tasks_pending,
                        'active_tasks': len(self.active_tasks)
                    },
                    'performance_metrics': {
                        'speedup_factor': self.metrics.speedup_factor,
                        'efficiency_percentage': self.metrics.efficiency_percentage,
                        'overhead_percentage': self.metrics.overhead_percentage,
                        'parallel_effectiveness': self.metrics.parallel_effectiveness,
                        'average_task_duration_ms': self.metrics.average_task_duration_ms
                    },
                    'statistics': {
                        'tasks_completed': self.metrics.tasks_completed,
                        'load_balance_efficiency': self.metrics.load_balance_efficiency,
                        'resource_contention': self.metrics.resource_contention
                    },
                    'recommendations': self._generate_performance_recommendations()
                }
                
            except Exception as e:
                self.logger.error(f"Error generating performance report: {e}")
                return {}
    
    def _generate_performance_recommendations(self) -> List[str]:
        """Generate performance optimization recommendations."""
        recommendations = []
        
        try:
            if self.metrics.efficiency_percentage < 50:
                recommendations.append("Low parallel efficiency - consider reducing worker count or optimizing task distribution")
            
            if self.metrics.overhead_percentage > 30:
                recommendations.append("High overhead detected - consider increasing chunk size or reducing parallelization")
            
            if self.metrics.utilization_percentage < 30:
                recommendations.append("Low worker utilization - consider reducing worker count")
            elif self.metrics.utilization_percentage > 90:
                recommendations.append("High worker utilization - consider increasing worker count if resources allow")
            
            if self.metrics.speedup_factor < 1.5:
                recommendations.append("Poor speedup factor - parallel processing may not be beneficial for this workload")
            
            if not recommendations:
                recommendations.append("Parallel processing performance is within optimal parameters")
                
        except Exception as e:
            self.logger.error(f"Error generating recommendations: {e}")
            recommendations.append("Unable to generate recommendations due to error")
        
        return recommendations
    
    def shutdown(self):
        """Shutdown executors and clean up resources."""
        try:
            if self.thread_executor:
                self.thread_executor.shutdown(wait=True)
                self.logger.info("Thread executor shutdown complete")
            
            if self.process_executor:
                self.process_executor.shutdown(wait=True)
                self.logger.info("Process executor shutdown complete")
                
        except Exception as e:
            self.logger.error(f"Error during executor shutdown: {e}")
    
    def __del__(self):
        """Cleanup on object deletion."""
        self.shutdown() 
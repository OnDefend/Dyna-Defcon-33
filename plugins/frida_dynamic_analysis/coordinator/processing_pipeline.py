#!/usr/bin/env python3
"""
Real-Time Processing Pipeline

Advanced real-time processing pipeline for streaming hook data,
vulnerability detection, and evidence collection coordination.

Author: AODS Team
Date: January 2025
"""

import logging
import time
import threading
import queue
from typing import Dict, List, Optional, Any, Callable, Generator
from dataclasses import dataclass, field
from enum import Enum
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import deque
import statistics


class PipelineStage(Enum):
    """Stages of the processing pipeline."""
    INPUT = "input"
    FILTERING = "filtering"
    ANALYSIS = "analysis"
    DETECTION = "detection"
    CORRELATION = "correlation"
    EVIDENCE = "evidence"
    OUTPUT = "output"


class ProcessingMode(Enum):
    """Processing modes for the pipeline."""
    REAL_TIME = "real_time"
    BATCH = "batch"
    HYBRID = "hybrid"


@dataclass
class PipelineMetrics:
    """Metrics for pipeline performance."""
    events_processed: int = 0
    events_filtered: int = 0
    vulnerabilities_detected: int = 0
    processing_latency: float = 0.0
    throughput_rate: float = 0.0
    stage_latencies: Dict[str, float] = field(default_factory=dict)
    error_count: int = 0
    backlog_size: int = 0


@dataclass
class ProcessingResult:
    """Result from pipeline processing."""
    event_id: str
    original_event: Dict[str, Any]
    processed_data: Dict[str, Any]
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    evidence: Optional[Dict[str, Any]] = None
    processing_time: float = 0.0
    stage_times: Dict[str, float] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)


class RealTimeProcessingPipeline:
    """
    Advanced real-time processing pipeline for streaming hook data,
    vulnerability detection, and evidence collection coordination.
    """
    
    def __init__(self, detector=None, collector=None, mode: ProcessingMode = ProcessingMode.REAL_TIME):
        """Initialize real-time processing pipeline."""
        self.logger = logging.getLogger(__name__)
        
        # Core components
        self.detector = detector
        self.collector = collector
        self.processing_mode = mode
        
        # Pipeline state
        self.pipeline_active = False
        self.processing_threads: List[threading.Thread] = []
        self.input_queue = queue.Queue(maxsize=10000)
        self.output_queue = queue.Queue(maxsize=5000)
        self.shutdown_event = threading.Event()
        
        # Processing stages
        self.stage_queues: Dict[PipelineStage, queue.Queue] = {}
        self.stage_processors: Dict[PipelineStage, Callable] = {}
        self.stage_threads: Dict[PipelineStage, threading.Thread] = {}
        
        # Metrics and monitoring
        self.metrics = PipelineMetrics()
        self.metrics_lock = threading.Lock()
        self.processing_history = deque(maxlen=1000)  # Keep last 1000 processing times
        
        # Configuration
        self.max_workers = 4
        self.batch_size = 10
        self.processing_timeout = 30
        self.metrics_update_interval = 1.0
        
        # Event handlers
        self.event_handlers: Dict[str, List[Callable]] = {}
        self.result_handlers: List[Callable] = []
        
        # Initialize pipeline stages
        self._initialize_pipeline_stages()
        
        self.logger.info(f"⚡ RealTimeProcessingPipeline initialized in {mode.value} mode")
    
    def _initialize_pipeline_stages(self):
        """Initialize pipeline stages and their queues."""
        stages = list(PipelineStage)
        
        for stage in stages:
            self.stage_queues[stage] = queue.Queue(maxsize=1000)
            
        # Register stage processors
        self.stage_processors = {
            PipelineStage.INPUT: self._process_input_stage,
            PipelineStage.FILTERING: self._process_filtering_stage,
            PipelineStage.ANALYSIS: self._process_analysis_stage,
            PipelineStage.DETECTION: self._process_detection_stage,
            PipelineStage.CORRELATION: self._process_correlation_stage,
            PipelineStage.EVIDENCE: self._process_evidence_stage,
            PipelineStage.OUTPUT: self._process_output_stage
        }
        
        self.logger.debug(f"📋 Initialized {len(stages)} pipeline stages")
    
    def start_processing(self):
        """Start the real-time processing pipeline."""
        if self.pipeline_active:
            self.logger.warning("⚠️ Processing pipeline already active")
            return
        
        self.pipeline_active = True
        self.shutdown_event.clear()
        
        # Start stage processors
        self._start_stage_processors()
        
        # Start metrics monitoring
        self._start_metrics_monitoring()
        
        # Start main processing loop
        main_thread = threading.Thread(target=self._main_processing_loop, daemon=True)
        main_thread.start()
        self.processing_threads.append(main_thread)
        
        self.logger.info("🚀 Real-time processing pipeline started")
    
    def stop_processing(self):
        """Stop the processing pipeline gracefully."""
        if not self.pipeline_active:
            return
        
        self.logger.info("🛑 Stopping processing pipeline")
        
        self.pipeline_active = False
        self.shutdown_event.set()
        
        # Wait for threads to complete
        for thread in self.processing_threads:
            if thread.is_alive():
                thread.join(timeout=5.0)
        
        # Stop stage processors
        for thread in self.stage_threads.values():
            if thread.is_alive():
                thread.join(timeout=3.0)
        
        self.logger.info("✅ Processing pipeline stopped")
    
    def _start_stage_processors(self):
        """Start individual stage processing threads."""
        for stage, processor in self.stage_processors.items():
            thread = threading.Thread(
                target=self._stage_processor_loop,
                args=(stage, processor),
                daemon=True,
                name=f"Stage-{stage.value}"
            )
            thread.start()
            self.stage_threads[stage] = thread
        
        self.logger.debug(f"🔧 Started {len(self.stage_processors)} stage processors")
    
    def _start_metrics_monitoring(self):
        """Start metrics monitoring thread."""
        metrics_thread = threading.Thread(target=self._metrics_monitoring_loop, daemon=True)
        metrics_thread.start()
        self.processing_threads.append(metrics_thread)
        
        self.logger.debug("📊 Metrics monitoring started")
    
    def _main_processing_loop(self):
        """Main processing loop for the pipeline."""
        while self.pipeline_active and not self.shutdown_event.is_set():
            try:
                # Get events from input queue
                try:
                    event_data = self.input_queue.get(timeout=1.0)
                    if event_data is None:  # Shutdown signal
                        break
                    
                    # Process event through pipeline
                    self._process_event_through_pipeline(event_data)
                    
                except queue.Empty:
                    continue
                
            except Exception as e:
                self.logger.error(f"❌ Main processing loop error: {e}")
                with self.metrics_lock:
                    self.metrics.error_count += 1
    
    def _stage_processor_loop(self, stage: PipelineStage, processor: Callable):
        """Processing loop for individual pipeline stages."""
        while self.pipeline_active and not self.shutdown_event.is_set():
            try:
                # Get item from stage queue
                try:
                    stage_input = self.stage_queues[stage].get(timeout=1.0)
                    if stage_input is None:  # Shutdown signal
                        break
                    
                    # Process through stage
                    stage_start_time = time.time()
                    stage_output = processor(stage_input)
                    stage_duration = time.time() - stage_start_time
                    
                    # Update stage metrics
                    with self.metrics_lock:
                        self.metrics.stage_latencies[stage.value] = stage_duration
                    
                    # Pass to next stage if output exists
                    if stage_output and stage != PipelineStage.OUTPUT:
                        next_stage = self._get_next_stage(stage)
                        if next_stage and next_stage in self.stage_queues:
                            self.stage_queues[next_stage].put(stage_output)
                    
                except queue.Empty:
                    continue
                
            except Exception as e:
                self.logger.debug(f"Stage {stage.value} processing error: {e}")
                with self.metrics_lock:
                    self.metrics.error_count += 1
    
    def _metrics_monitoring_loop(self):
        """Metrics monitoring and calculation loop."""
        while self.pipeline_active and not self.shutdown_event.is_set():
            try:
                time.sleep(self.metrics_update_interval)
                self._update_pipeline_metrics()
                
            except Exception as e:
                self.logger.debug(f"Metrics monitoring error: {e}")
    
    def _process_event_through_pipeline(self, event_data: Dict[str, Any]):
        """Process an event through the entire pipeline."""
        event_id = event_data.get('event_id', f"event_{int(time.time() * 1000)}")
        processing_start_time = time.time()
        
        # Create processing result
        result = ProcessingResult(
            event_id=event_id,
            original_event=event_data,
            processed_data={}
        )
        
        try:
            # Start pipeline by putting event in input stage
            self.stage_queues[PipelineStage.INPUT].put({
                'result': result,
                'start_time': processing_start_time
            })
            
        except Exception as e:
            self.logger.error(f"❌ Failed to process event {event_id}: {e}")
            with self.metrics_lock:
                self.metrics.error_count += 1
    
    def _process_input_stage(self, stage_input: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Process input stage - event ingestion and initial processing."""
        result = stage_input['result']
        
        try:
            # Extract and normalize event data
            event_data = result.original_event
            
            # Add metadata
            result.processed_data = {
                'event_type': event_data.get('type', 'unknown'),
                'timestamp': event_data.get('timestamp', time.time()),
                'source': event_data.get('source', 'unknown'),
                'payload': event_data.get('payload', {}),
                'metadata': {
                    'processing_start': stage_input['start_time'],
                    'input_stage_time': time.time()
                }
            }
            
            with self.metrics_lock:
                self.metrics.events_processed += 1
            
            return stage_input
            
        except Exception as e:
            result.errors.append(f"Input stage error: {e}")
            return None
    
    def _process_filtering_stage(self, stage_input: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Process filtering stage - filter relevant events."""
        result = stage_input['result']
        
        try:
            event_type = result.processed_data.get('event_type', '')
            payload = result.processed_data.get('payload', {})
            
            # Filter criteria
            should_process = True
            
            # Skip certain event types
            skip_types = ['heartbeat', 'debug', 'trace']
            if event_type.lower() in skip_types:
                should_process = False
            
            # Skip events without meaningful payload
            if not payload or len(payload) == 0:
                should_process = False
            
            if not should_process:
                with self.metrics_lock:
                    self.metrics.events_filtered += 1
                return None
            
            # Add filtering metadata
            result.processed_data['filtering'] = {
                'passed': True,
                'criteria_met': ['has_payload', 'relevant_type'],
                'filter_time': time.time()
            }
            
            return stage_input
            
        except Exception as e:
            result.errors.append(f"Filtering stage error: {e}")
            return None
    
    def _process_analysis_stage(self, stage_input: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Process analysis stage - detailed event analysis."""
        result = stage_input['result']
        
        try:
            payload = result.processed_data.get('payload', {})
            event_type = result.processed_data.get('event_type', '')
            
            # Perform detailed analysis
            analysis_data = {
                'event_classification': self._classify_event(event_type, payload),
                'risk_indicators': self._extract_risk_indicators(payload),
                'api_calls': self._extract_api_calls(payload),
                'data_flows': self._extract_data_flows(payload),
                'analysis_time': time.time()
            }
            
            result.processed_data['analysis'] = analysis_data
            
            return stage_input
            
        except Exception as e:
            result.errors.append(f"Analysis stage error: {e}")
            return stage_input  # Continue processing even with analysis errors
    
    def _process_detection_stage(self, stage_input: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Process detection stage - vulnerability detection."""
        result = stage_input['result']
        
        try:
            # Use detector if available
            if self.detector and hasattr(self.detector, 'analyze_hook_data'):
                hook_data = result.processed_data.get('payload', {})
                
                # Detect vulnerabilities
                detected_vulnerabilities = self.detector.analyze_hook_data(hook_data)
                
                if detected_vulnerabilities:
                    # Convert to dictionaries if needed
                    vuln_list = []
                    for vuln in detected_vulnerabilities:
                        if hasattr(vuln, 'to_dict'):
                            vuln_list.append(vuln.to_dict())
                        elif isinstance(vuln, dict):
                            vuln_list.append(vuln)
                    
                    result.vulnerabilities.extend(vuln_list)
                    
                    with self.metrics_lock:
                        self.metrics.vulnerabilities_detected += len(vuln_list)
            
            # Add detection metadata
            result.processed_data['detection'] = {
                'vulnerabilities_found': len(result.vulnerabilities),
                'detector_used': self.detector is not None,
                'detection_time': time.time()
            }
            
            return stage_input
            
        except Exception as e:
            result.errors.append(f"Detection stage error: {e}")
            return stage_input
    
    def _process_correlation_stage(self, stage_input: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Process correlation stage - correlate with other events."""
        result = stage_input['result']
        
        try:
            # Correlate with recent events
            correlation_data = {
                'related_events': self._find_related_events(result),
                'event_sequence': self._determine_event_sequence(result),
                'attack_patterns': self._detect_attack_patterns(result),
                'correlation_time': time.time()
            }
            
            result.processed_data['correlation'] = correlation_data
            
            return stage_input
            
        except Exception as e:
            result.errors.append(f"Correlation stage error: {e}")
            return stage_input
    
    def _process_evidence_stage(self, stage_input: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Process evidence stage - collect evidence."""
        result = stage_input['result']
        
        try:
            # Use evidence collector if available
            if self.collector and hasattr(self.collector, 'generate_runtime_evidence'):
                evidence_package = self.collector.generate_runtime_evidence(result.processed_data)
                
                if evidence_package:
                    if hasattr(evidence_package, 'to_dict'):
                        result.evidence = evidence_package.to_dict()
                    else:
                        result.evidence = evidence_package
            
            # Add evidence metadata
            result.processed_data['evidence'] = {
                'evidence_collected': result.evidence is not None,
                'collector_used': self.collector is not None,
                'evidence_time': time.time()
            }
            
            return stage_input
            
        except Exception as e:
            result.errors.append(f"Evidence stage error: {e}")
            return stage_input
    
    def _process_output_stage(self, stage_input: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Process output stage - finalize and output results."""
        result = stage_input['result']
        
        try:
            # Calculate total processing time
            start_time = stage_input['start_time']
            result.processing_time = time.time() - start_time
            
            # Update processing history
            self.processing_history.append(result.processing_time)
            
            # Execute result handlers
            for handler in self.result_handlers:
                try:
                    handler(result)
                except Exception as e:
                    self.logger.debug(f"Result handler error: {e}")
            
            # Put in output queue
            self.output_queue.put(result)
            
            # Update metrics
            with self.metrics_lock:
                if self.processing_history:
                    self.metrics.processing_latency = statistics.mean(self.processing_history)
            
            return None  # End of pipeline
            
        except Exception as e:
            result.errors.append(f"Output stage error: {e}")
            return None
    
    def _classify_event(self, event_type: str, payload: Dict[str, Any]) -> str:
        """Classify event based on type and payload."""
        if 'crypto' in event_type.lower() or 'cipher' in str(payload).lower():
            return 'cryptographic'
        elif 'network' in event_type.lower() or 'http' in str(payload).lower():
            return 'network'
        elif 'storage' in event_type.lower() or 'file' in str(payload).lower():
            return 'storage'
        elif 'auth' in event_type.lower() or 'login' in str(payload).lower():
            return 'authentication'
        else:
            return 'general'
    
    def _extract_risk_indicators(self, payload: Dict[str, Any]) -> List[str]:
        """Extract risk indicators from payload."""
        indicators = []
        payload_str = str(payload).lower()
        
        risk_keywords = [
            'password', 'token', 'secret', 'key', 'credential',
            'admin', 'root', 'bypass', 'exploit', 'vulnerable'
        ]
        
        for keyword in risk_keywords:
            if keyword in payload_str:
                indicators.append(keyword)
        
        return indicators
    
    def _extract_api_calls(self, payload: Dict[str, Any]) -> List[str]:
        """Extract API calls from payload."""
        api_calls = []
        
        # Look for API call patterns
        api_patterns = [
            'api_call', 'method_name', 'function_call', 'class_method'
        ]
        
        for pattern in api_patterns:
            if pattern in payload:
                api_calls.append(str(payload[pattern]))
        
        return api_calls
    
    def _extract_data_flows(self, payload: Dict[str, Any]) -> List[str]:
        """Extract data flow information from payload."""
        data_flows = []
        
        # Look for data flow indicators
        flow_indicators = ['input', 'output', 'parameter', 'return_value']
        
        for indicator in flow_indicators:
            if indicator in payload:
                data_flows.append(f"{indicator}: {payload[indicator]}")
        
        return data_flows
    
    def _find_related_events(self, result: ProcessingResult) -> List[str]:
        """Find events related to the current event."""
        # Simple correlation based on timing and event type
        related = []
        
        current_time = result.processed_data.get('timestamp', time.time())
        event_type = result.processed_data.get('event_type', '')
        
        # Look for events within 10 seconds with similar types
        # This is a simplified implementation
        related.append(f"Similar {event_type} events in timeframe")
        
        return related
    
    def _determine_event_sequence(self, result: ProcessingResult) -> str:
        """Determine event sequence pattern."""
        # Simplified sequence determination
        event_type = result.processed_data.get('event_type', '')
        
        if event_type in ['crypto_vulnerability', 'network_vulnerability']:
            return 'security_event_sequence'
        else:
            return 'normal_event_sequence'
    
    def _detect_attack_patterns(self, result: ProcessingResult) -> List[str]:
        """Detect potential attack patterns."""
        patterns = []
        
        vulnerabilities = result.vulnerabilities
        if vulnerabilities:
            for vuln in vulnerabilities:
                vuln_type = vuln.get('vulnerability_type', '')
                if 'injection' in vuln_type.lower():
                    patterns.append('injection_attack_pattern')
                elif 'bypass' in vuln_type.lower():
                    patterns.append('bypass_attack_pattern')
        
        return patterns
    
    def _get_next_stage(self, current_stage: PipelineStage) -> Optional[PipelineStage]:
        """Get the next stage in the pipeline."""
        stages = list(PipelineStage)
        current_index = stages.index(current_stage)
        
        if current_index < len(stages) - 1:
            return stages[current_index + 1]
        
        return None
    
    def _update_pipeline_metrics(self):
        """Update pipeline performance metrics."""
        with self.metrics_lock:
            # Calculate throughput
            if self.processing_history:
                recent_times = list(self.processing_history)[-100:]  # Last 100 events
                if recent_times:
                    avg_time = statistics.mean(recent_times)
                    self.metrics.throughput_rate = 1.0 / avg_time if avg_time > 0 else 0.0
            
            # Update backlog size
            self.metrics.backlog_size = self.input_queue.qsize()
    
    def process_event(self, event_data: Dict[str, Any]) -> bool:
        """Process a single event through the pipeline."""
        if not self.pipeline_active:
            return False
        
        try:
            # Add event ID if not present
            if 'event_id' not in event_data:
                event_data['event_id'] = f"event_{int(time.time() * 1000)}"
            
            self.input_queue.put(event_data, timeout=1.0)
            return True
            
        except queue.Full:
            self.logger.warning("⚠️ Processing pipeline input queue full")
            return False
        except Exception as e:
            self.logger.error(f"❌ Failed to process event: {e}")
            return False
    
    def process_recent_events(self, max_events: int = 100) -> int:
        """Process recent events from hook engine."""
        # This would typically be called by the coordinator
        # to process events from the hook engine
        
        events_processed = 0
        
        # Mock implementation - in real scenario would get events from hook engine
        for i in range(min(max_events, 10)):  # Process up to 10 mock events
            mock_event = {
                'event_id': f"recent_event_{i}_{int(time.time())}",
                'type': 'runtime_event',
                'timestamp': time.time(),
                'payload': {'mock_data': f'recent_event_{i}'},
                'source': 'hook_engine'
            }
            
            if self.process_event(mock_event):
                events_processed += 1
        
        return events_processed
    
    def process_scenario_events(self) -> int:
        """Process events generated by scenario execution."""
        # Mock implementation for scenario events
        scenario_events = [
            {
                'event_id': f"scenario_event_{int(time.time())}",
                'type': 'scenario_execution',
                'timestamp': time.time(),
                'payload': {'scenario': 'crypto_test', 'result': 'completed'},
                'source': 'scenario_engine'
            }
        ]
        
        events_processed = 0
        for event in scenario_events:
            if self.process_event(event):
                events_processed += 1
        
        return events_processed
    
    def get_processed_results(self, max_results: int = 100) -> List[ProcessingResult]:
        """Get processed results from output queue."""
        results = []
        
        try:
            while len(results) < max_results:
                try:
                    result = self.output_queue.get_nowait()
                    results.append(result)
                except queue.Empty:
                    break
                    
        except Exception as e:
            self.logger.debug(f"Error getting results: {e}")
        
        return results
    
    def register_result_handler(self, handler: Callable[[ProcessingResult], None]):
        """Register a handler for processing results."""
        self.result_handlers.append(handler)
        self.logger.debug("📋 Result handler registered")
    
    def get_pipeline_metrics(self) -> Dict[str, Any]:
        """Get current pipeline metrics."""
        with self.metrics_lock:
            return {
                "events_processed": self.metrics.events_processed,
                "events_filtered": self.metrics.events_filtered,
                "vulnerabilities_detected": self.metrics.vulnerabilities_detected,
                "processing_latency": self.metrics.processing_latency,
                "throughput_rate": self.metrics.throughput_rate,
                "error_count": self.metrics.error_count,
                "backlog_size": self.metrics.backlog_size,
                "stage_latencies": dict(self.metrics.stage_latencies),
                "pipeline_active": self.pipeline_active
            }
    
    def get_pipeline_status(self) -> Dict[str, Any]:
        """Get comprehensive pipeline status."""
        metrics = self.get_pipeline_metrics()
        
        return {
            "status": "active" if self.pipeline_active else "inactive",
            "processing_mode": self.processing_mode.value,
            "stages_active": len([t for t in self.stage_threads.values() if t.is_alive()]),
            "total_stages": len(self.stage_threads),
            "metrics": metrics,
            "queue_sizes": {
                "input": self.input_queue.qsize(),
                "output": self.output_queue.qsize()
            }
        }


# Convenience functions
def create_processing_pipeline(detector=None, collector=None, 
                             mode: ProcessingMode = ProcessingMode.REAL_TIME) -> RealTimeProcessingPipeline:
    """Create real-time processing pipeline."""
    return RealTimeProcessingPipeline(detector=detector, collector=collector, mode=mode)


if __name__ == "__main__":
    # Demo usage
    print("⚡ Real-Time Processing Pipeline Demo")
    print("=" * 40)
    
    # Create pipeline
    pipeline = RealTimeProcessingPipeline()
    
    print("✅ RealTimeProcessingPipeline initialized")
    print("🎯 Pipeline stages:")
    stages = list(PipelineStage)
    for i, stage in enumerate(stages, 1):
        print(f"   {i}. {stage.value}")
    
    print("\n📊 Processing modes:")
    modes = list(ProcessingMode)
    for mode in modes:
        print(f"   • {mode.value}")
    
    print("\n✅ Pipeline ready for real-time processing!")
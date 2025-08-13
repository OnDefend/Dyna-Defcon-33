#!/usr/bin/env python3
"""
Data Synchronization Manager

Advanced data synchronization manager for coordinating data flow
between hooks, detection, automation, and evidence collection components.

Author: AODS Team
Date: January 2025
"""

import logging
import time
import threading
from typing import Dict, List, Optional, Any, Callable, Set
from dataclasses import dataclass, field
from enum import Enum
import json
import hashlib
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor
import queue


class SyncStatus(Enum):
    """Synchronization status for components."""
    OUT_OF_SYNC = "out_of_sync"
    SYNCING = "syncing"
    SYNCHRONIZED = "synchronized"
    ERROR = "error"


class DataType(Enum):
    """Types of data being synchronized."""
    RUNTIME_EVENTS = "runtime_events"
    VULNERABILITIES = "vulnerabilities"
    EVIDENCE_PACKAGES = "evidence_packages"
    AUTOMATION_METRICS = "automation_metrics"
    SCENARIO_RESULTS = "scenario_results"
    COMPONENT_STATE = "component_state"


@dataclass
class SyncPoint:
    """Represents a synchronization point."""
    sync_id: str
    timestamp: float
    data_type: DataType
    component_id: str
    data_hash: str
    data_size: int
    checksum: str = ""


@dataclass
class ComponentSyncState:
    """Synchronization state for a component."""
    component_id: str
    last_sync_time: float = 0.0
    sync_status: SyncStatus = SyncStatus.OUT_OF_SYNC
    pending_syncs: int = 0
    sync_points: List[SyncPoint] = field(default_factory=list)
    error_count: int = 0
    data_version: int = 0


@dataclass
class SyncMetrics:
    """Metrics for synchronization performance."""
    total_syncs: int = 0
    successful_syncs: int = 0
    failed_syncs: int = 0
    avg_sync_time: float = 0.0
    data_transferred: int = 0
    sync_conflicts: int = 0
    last_full_sync: float = 0.0


class DataSynchronizationManager:
    """
    Advanced data synchronization manager for coordinating data flow
    between hooks, detection, automation, and evidence collection components.
    """
    
    def __init__(self, components: Dict[str, Any] = None):
        """Initialize data synchronization manager."""
        self.logger = logging.getLogger(__name__)
        
        # Component registry
        self.components = components or {}
        self.component_states: Dict[str, ComponentSyncState] = {}
        
        # Synchronization state
        self.sync_active = False
        self.sync_threads: List[threading.Thread] = []
        self.shutdown_event = threading.Event()
        
        # Data caches
        self.data_cache: Dict[DataType, Dict[str, Any]] = defaultdict(dict)
        self.sync_history: deque = deque(maxlen=1000)
        self.pending_syncs: queue.Queue = queue.Queue(maxsize=5000)
        
        # Synchronization configuration
        self.sync_interval = 2.0  # seconds
        self.full_sync_interval = 30.0  # seconds
        self.max_sync_workers = 3
        self.sync_timeout = 10.0  # seconds
        self.conflict_resolution = "latest_wins"
        
        # Metrics and monitoring
        self.metrics = SyncMetrics()
        self.metrics_lock = threading.Lock()
        
        # Event handlers
        self.sync_handlers: Dict[DataType, List[Callable]] = defaultdict(list)
        self.conflict_handlers: List[Callable] = []
        
        # Thread pool for sync operations
        self.sync_executor = ThreadPoolExecutor(max_workers=self.max_sync_workers)
        
        self.logger.info("🔄 DataSynchronizationManager initialized")
    
    def register_component(self, component_id: str, component: Any):
        """Register a component for synchronization."""
        self.components[component_id] = component
        self.component_states[component_id] = ComponentSyncState(component_id=component_id)
        
        self.logger.info(f"📋 Registered component for sync: {component_id}")
    
    def register_sync_handler(self, data_type: DataType, handler: Callable):
        """Register handler for specific data type synchronization."""
        self.sync_handlers[data_type].append(handler)
        self.logger.debug(f"📋 Registered sync handler for: {data_type.value}")
    
    def register_conflict_handler(self, handler: Callable):
        """Register handler for synchronization conflicts."""
        self.conflict_handlers.append(handler)
        self.logger.debug("📋 Conflict handler registered")
    
    def start_synchronization(self):
        """Start data synchronization processes."""
        if self.sync_active:
            self.logger.warning("⚠️ Synchronization already active")
            return
        
        self.sync_active = True
        self.shutdown_event.clear()
        
        # Start synchronization threads
        self._start_sync_threads()
        
        # Start metrics monitoring
        self._start_metrics_monitoring()
        
        self.logger.info("🚀 Data synchronization started")
    
    def stop_synchronization(self):
        """Stop data synchronization gracefully."""
        if not self.sync_active:
            return
        
        self.logger.info("🛑 Stopping data synchronization")
        
        self.sync_active = False
        self.shutdown_event.set()
        
        # Wait for threads
        for thread in self.sync_threads:
            if thread.is_alive():
                thread.join(timeout=5.0)
        
        # Shutdown executor
        self.sync_executor.shutdown(wait=True)
        
        self.logger.info("✅ Data synchronization stopped")
    
    def _start_sync_threads(self):
        """Start synchronization threads."""
        # Main synchronization loop
        main_sync_thread = threading.Thread(target=self._main_sync_loop, daemon=True)
        main_sync_thread.start()
        self.sync_threads.append(main_sync_thread)
        
        # Sync processor thread
        sync_processor_thread = threading.Thread(target=self._sync_processor_loop, daemon=True)
        sync_processor_thread.start()
        self.sync_threads.append(sync_processor_thread)
        
        # Full sync thread
        full_sync_thread = threading.Thread(target=self._full_sync_loop, daemon=True)
        full_sync_thread.start()
        self.sync_threads.append(full_sync_thread)
        
        self.logger.debug(f"🔧 Started {len(self.sync_threads)} synchronization threads")
    
    def _start_metrics_monitoring(self):
        """Start metrics monitoring thread."""
        metrics_thread = threading.Thread(target=self._metrics_monitoring_loop, daemon=True)
        metrics_thread.start()
        self.sync_threads.append(metrics_thread)
        
        self.logger.debug("📊 Metrics monitoring started")
    
    def _main_sync_loop(self):
        """Main synchronization loop."""
        while self.sync_active and not self.shutdown_event.is_set():
            try:
                # Schedule synchronization for each component
                for component_id in self.components:
                    self._schedule_component_sync(component_id)
                
                time.sleep(self.sync_interval)
                
            except Exception as e:
                self.logger.error(f"❌ Main sync loop error: {e}")
    
    def _sync_processor_loop(self):
        """Process pending synchronizations."""
        while self.sync_active and not self.shutdown_event.is_set():
            try:
                # Get pending sync request
                try:
                    sync_request = self.pending_syncs.get(timeout=1.0)
                    if sync_request is None:  # Shutdown signal
                        break
                    
                    # Process sync request
                    self._process_sync_request(sync_request)
                    
                except queue.Empty:
                    continue
                
            except Exception as e:
                self.logger.error(f"❌ Sync processor error: {e}")
    
    def _full_sync_loop(self):
        """Perform full synchronization periodically."""
        while self.sync_active and not self.shutdown_event.is_set():
            try:
                time.sleep(self.full_sync_interval)
                
                if self.sync_active:
                    self._perform_full_synchronization()
                
            except Exception as e:
                self.logger.error(f"❌ Full sync loop error: {e}")
    
    def _metrics_monitoring_loop(self):
        """Monitor synchronization metrics."""
        while self.sync_active and not self.shutdown_event.is_set():
            try:
                time.sleep(5.0)  # Update metrics every 5 seconds
                self._update_sync_metrics()
                
            except Exception as e:
                self.logger.debug(f"Metrics monitoring error: {e}")
    
    def _schedule_component_sync(self, component_id: str):
        """Schedule synchronization for a component."""
        if component_id not in self.component_states:
            return
        
        component_state = self.component_states[component_id]
        current_time = time.time()
        
        # Check if sync is needed
        if current_time - component_state.last_sync_time >= self.sync_interval:
            sync_request = {
                'component_id': component_id,
                'sync_type': 'incremental',
                'timestamp': current_time,
                'data_types': list(DataType)
            }
            
            try:
                self.pending_syncs.put_nowait(sync_request)
                component_state.pending_syncs += 1
            except queue.Full:
                self.logger.warning(f"⚠️ Sync queue full for component: {component_id}")
    
    def _process_sync_request(self, sync_request: Dict[str, Any]):
        """Process a synchronization request."""
        component_id = sync_request['component_id']
        sync_type = sync_request['sync_type']
        data_types = sync_request['data_types']
        
        start_time = time.time()
        
        try:
            component = self.components.get(component_id)
            if not component:
                return
            
            component_state = self.component_states[component_id]
            component_state.sync_status = SyncStatus.SYNCING
            
            # Synchronize each data type
            sync_results = {}
            for data_type in data_types:
                sync_result = self._sync_data_type(component_id, component, data_type)
                sync_results[data_type.value] = sync_result
            
            # Update component state
            sync_duration = time.time() - start_time
            component_state.last_sync_time = time.time()
            component_state.pending_syncs = max(0, component_state.pending_syncs - 1)
            component_state.sync_status = SyncStatus.SYNCHRONIZED
            component_state.data_version += 1
            
            # Update metrics
            with self.metrics_lock:
                self.metrics.total_syncs += 1
                self.metrics.successful_syncs += 1
                self._update_avg_sync_time(sync_duration)
            
            # Execute sync handlers
            self._execute_sync_handlers(component_id, sync_results)
            
        except Exception as e:
            self.logger.error(f"❌ Sync failed for {component_id}: {e}")
            
            # Update error state
            if component_id in self.component_states:
                self.component_states[component_id].sync_status = SyncStatus.ERROR
                self.component_states[component_id].error_count += 1
            
            with self.metrics_lock:
                self.metrics.failed_syncs += 1
    
    def _sync_data_type(self, component_id: str, component: Any, data_type: DataType) -> Dict[str, Any]:
        """Synchronize a specific data type for a component."""
        sync_result = {
            'data_type': data_type.value,
            'success': False,
            'items_synced': 0,
            'conflicts_resolved': 0,
            'data_hash': None
        }
        
        try:
            # Extract data based on data type
            data = self._extract_component_data(component, data_type)
            
            if data:
                # Calculate data hash
                data_hash = self._calculate_data_hash(data)
                sync_result['data_hash'] = data_hash
                
                # Check for conflicts
                existing_data = self.data_cache[data_type].get(component_id)
                if existing_data:
                    conflicts = self._detect_conflicts(existing_data, data)
                    if conflicts:
                        resolved_data = self._resolve_conflicts(existing_data, data, conflicts)
                        data = resolved_data
                        sync_result['conflicts_resolved'] = len(conflicts)
                
                # Update cache
                self.data_cache[data_type][component_id] = data
                sync_result['items_synced'] = len(data) if isinstance(data, (list, dict)) else 1
                sync_result['success'] = True
                
                # Create sync point
                sync_point = SyncPoint(
                    sync_id=f"{component_id}_{data_type.value}_{int(time.time())}",
                    timestamp=time.time(),
                    data_type=data_type,
                    component_id=component_id,
                    data_hash=data_hash,
                    data_size=len(str(data)),
                    checksum=self._calculate_checksum(data)
                )
                
                self.component_states[component_id].sync_points.append(sync_point)
                
                # Keep only recent sync points
                self.component_states[component_id].sync_points = \
                    self.component_states[component_id].sync_points[-10:]
            
        except Exception as e:
            self.logger.debug(f"Data type sync error for {data_type.value}: {e}")
        
        return sync_result
    
    def _extract_component_data(self, component: Any, data_type: DataType) -> Any:
        """Extract data from component based on data type."""
        try:
            if data_type == DataType.RUNTIME_EVENTS:
                if hasattr(component, 'runtime_events'):
                    return getattr(component, 'runtime_events', [])
                
            elif data_type == DataType.VULNERABILITIES:
                if hasattr(component, 'detected_vulnerabilities'):
                    return getattr(component, 'detected_vulnerabilities', [])
                elif hasattr(component, 'vulnerabilities'):
                    return getattr(component, 'vulnerabilities', [])
                
            elif data_type == DataType.EVIDENCE_PACKAGES:
                if hasattr(component, 'evidence_packages'):
                    return getattr(component, 'evidence_packages', {})
                
            elif data_type == DataType.AUTOMATION_METRICS:
                if hasattr(component, 'get_automation_summary'):
                    return component.get_automation_summary()
                elif hasattr(component, 'metrics'):
                    return getattr(component, 'metrics', {})
                
            elif data_type == DataType.SCENARIO_RESULTS:
                if hasattr(component, 'get_scenario_summary'):
                    return component.get_scenario_summary()
                elif hasattr(component, 'completed_scenarios'):
                    return getattr(component, 'completed_scenarios', [])
                
            elif data_type == DataType.COMPONENT_STATE:
                # Extract basic component state
                state = {
                    'status': getattr(component, 'status', 'unknown'),
                    'last_update': time.time()
                }
                if hasattr(component, 'get_status'):
                    state.update(component.get_status())
                return state
            
        except Exception as e:
            self.logger.debug(f"Data extraction error for {data_type.value}: {e}")
        
        return None
    
    def _calculate_data_hash(self, data: Any) -> str:
        """Calculate hash for data."""
        try:
            data_str = json.dumps(data, sort_keys=True, default=str)
            return hashlib.md5(data_str.encode()).hexdigest()
        except Exception:
            return hashlib.md5(str(data).encode()).hexdigest()
    
    def _calculate_checksum(self, data: Any) -> str:
        """Calculate checksum for data integrity."""
        try:
            data_str = json.dumps(data, sort_keys=True, default=str)
            return hashlib.sha256(data_str.encode()).hexdigest()[:16]
        except Exception:
            return hashlib.sha256(str(data).encode()).hexdigest()[:16]
    
    def _detect_conflicts(self, existing_data: Any, new_data: Any) -> List[Dict[str, Any]]:
        """Detect conflicts between existing and new data."""
        conflicts = []
        
        try:
            existing_hash = self._calculate_data_hash(existing_data)
            new_hash = self._calculate_data_hash(new_data)
            
            if existing_hash != new_hash:
                conflicts.append({
                    'type': 'data_mismatch',
                    'existing_hash': existing_hash,
                    'new_hash': new_hash,
                    'existing_size': len(str(existing_data)),
                    'new_size': len(str(new_data))
                })
            
        except Exception as e:
            self.logger.debug(f"Conflict detection error: {e}")
        
        return conflicts
    
    def _resolve_conflicts(self, existing_data: Any, new_data: Any, conflicts: List[Dict[str, Any]]) -> Any:
        """Resolve synchronization conflicts."""
        try:
            # Execute conflict handlers
            for handler in self.conflict_handlers:
                try:
                    resolved = handler(existing_data, new_data, conflicts)
                    if resolved is not None:
                        return resolved
                except Exception as e:
                    self.logger.debug(f"Conflict handler error: {e}")
            
            # Default conflict resolution
            if self.conflict_resolution == "latest_wins":
                return new_data
            elif self.conflict_resolution == "merge":
                return self._merge_data(existing_data, new_data)
            else:
                return existing_data
                
        except Exception as e:
            self.logger.debug(f"Conflict resolution error: {e}")
            return new_data
    
    def _merge_data(self, existing_data: Any, new_data: Any) -> Any:
        """Merge existing and new data."""
        try:
            if isinstance(existing_data, dict) and isinstance(new_data, dict):
                merged = existing_data.copy()
                merged.update(new_data)
                return merged
            elif isinstance(existing_data, list) and isinstance(new_data, list):
                # Merge lists, avoiding duplicates
                merged = existing_data.copy()
                for item in new_data:
                    if item not in merged:
                        merged.append(item)
                return merged
            else:
                return new_data  # Can't merge, use new data
                
        except Exception:
            return new_data
    
    def _execute_sync_handlers(self, component_id: str, sync_results: Dict[str, Any]):
        """Execute registered sync handlers."""
        for data_type_str, sync_result in sync_results.items():
            try:
                data_type = DataType(data_type_str)
                if data_type in self.sync_handlers:
                    for handler in self.sync_handlers[data_type]:
                        try:
                            handler(component_id, sync_result)
                        except Exception as e:
                            self.logger.debug(f"Sync handler error: {e}")
            except ValueError:
                # Invalid data type
                continue
    
    def _perform_full_synchronization(self):
        """Perform full synchronization across all components."""
        self.logger.info("🔄 Performing full synchronization")
        
        start_time = time.time()
        
        try:
            # Force sync all components
            for component_id in self.components:
                sync_request = {
                    'component_id': component_id,
                    'sync_type': 'full',
                    'timestamp': time.time(),
                    'data_types': list(DataType)
                }
                
                self._process_sync_request(sync_request)
            
            # Update metrics
            with self.metrics_lock:
                self.metrics.last_full_sync = time.time()
            
            duration = time.time() - start_time
            self.logger.info(f"✅ Full synchronization completed in {duration:.2f}s")
            
        except Exception as e:
            self.logger.error(f"❌ Full synchronization failed: {e}")
    
    def _update_avg_sync_time(self, sync_duration: float):
        """Update average synchronization time."""
        # Simple exponential moving average
        alpha = 0.1
        if self.metrics.avg_sync_time == 0:
            self.metrics.avg_sync_time = sync_duration
        else:
            self.metrics.avg_sync_time = alpha * sync_duration + (1 - alpha) * self.metrics.avg_sync_time
    
    def _update_sync_metrics(self):
        """Update synchronization metrics."""
        with self.metrics_lock:
            # Calculate data transferred
            total_data = 0
            for data_type_cache in self.data_cache.values():
                for data in data_type_cache.values():
                    total_data += len(str(data))
            
            self.metrics.data_transferred = total_data
    
    def force_sync(self, component_id: str = None, data_type: DataType = None):
        """Force synchronization for specific component or data type."""
        if component_id and component_id in self.components:
            data_types = [data_type] if data_type else list(DataType)
            
            sync_request = {
                'component_id': component_id,
                'sync_type': 'forced',
                'timestamp': time.time(),
                'data_types': data_types
            }
            
            self.pending_syncs.put(sync_request)
            self.logger.info(f"🔄 Forced sync scheduled for {component_id}")
        else:
            # Force sync all components
            for comp_id in self.components:
                self.force_sync(comp_id, data_type)
    
    def get_sync_status(self) -> Dict[str, Any]:
        """Get comprehensive synchronization status."""
        component_statuses = {}
        for comp_id, state in self.component_states.items():
            component_statuses[comp_id] = {
                'sync_status': state.sync_status.value,
                'last_sync_time': state.last_sync_time,
                'pending_syncs': state.pending_syncs,
                'error_count': state.error_count,
                'data_version': state.data_version,
                'sync_points': len(state.sync_points)
            }
        
        return {
            'sync_active': self.sync_active,
            'total_components': len(self.components),
            'synchronized_components': len([s for s in self.component_states.values() 
                                          if s.sync_status == SyncStatus.SYNCHRONIZED]),
            'pending_syncs': self.pending_syncs.qsize(),
            'component_statuses': component_statuses,
            'metrics': {
                'total_syncs': self.metrics.total_syncs,
                'successful_syncs': self.metrics.successful_syncs,
                'failed_syncs': self.metrics.failed_syncs,
                'avg_sync_time': self.metrics.avg_sync_time,
                'data_transferred': self.metrics.data_transferred,
                'last_full_sync': self.metrics.last_full_sync
            }
        }
    
    def get_synchronized_data(self, data_type: DataType, component_id: str = None) -> Dict[str, Any]:
        """Get synchronized data by type and optionally by component."""
        if data_type not in self.data_cache:
            return {}
        
        if component_id:
            return self.data_cache[data_type].get(component_id, {})
        else:
            return dict(self.data_cache[data_type])
    
    def get_all_synchronized_data(self) -> Dict[str, Dict[str, Any]]:
        """Get all synchronized data."""
        all_data = {}
        for data_type, component_data in self.data_cache.items():
            all_data[data_type.value] = dict(component_data)
        return all_data


# Convenience functions
def create_data_sync_manager(components: Dict[str, Any] = None) -> DataSynchronizationManager:
    """Create data synchronization manager."""
    return DataSynchronizationManager(components=components)


if __name__ == "__main__":
    # Demo usage
    print("🔄 Data Synchronization Manager Demo")
    print("=" * 40)
    
    # Create sync manager
    sync_manager = DataSynchronizationManager()
    
    print("✅ DataSynchronizationManager initialized")
    print("🎯 Data types:")
    data_types = list(DataType)
    for i, data_type in enumerate(data_types, 1):
        print(f"   {i}. {data_type.value}")
    
    print("\n📊 Sync statuses:")
    statuses = list(SyncStatus)
    for status in statuses:
        print(f"   • {status.value}")
    
    print("\n✅ Synchronization manager ready!")
#!/usr/bin/env python3
"""
Hot Reload Manager for AODS Configuration

This module provides hot reload capabilities for configuration files,
allowing runtime updates without system restart.

Features:
- File system watching for configuration changes
- Automatic cache invalidation on changes
- Event-driven configuration updates
- Thread-safe reload operations
- Configurable reload policies
"""

import logging
import time
import threading
from typing import Dict, List, Optional, Any, Callable, Set
from pathlib import Path
from dataclasses import dataclass, field
from enum import Enum
import os
import hashlib

# Try to import watchdog for file monitoring
try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler, FileModifiedEvent, FileCreatedEvent, FileDeletedEvent
    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False
    Observer = None
    
    # Provide fallback base class when watchdog is not available
    class FileSystemEventHandler:
        """Fallback FileSystemEventHandler when watchdog is not available."""
        def __init__(self):
            self.logger = logging.getLogger(__name__)
            self.logger.warning("Watchdog library not available, file monitoring disabled")
        
        def on_modified(self, event):
            """Handle file modification events (fallback implementation)."""
            file_path = getattr(event, 'src_path', None)
            if file_path:
                self.logger.info(f"📝 File modified (fallback mode): {file_path}")
                # In fallback mode, attempt manual reload if file is being monitored
                try:
                    from pathlib import Path
                    path_obj = Path(file_path)
                    if hasattr(self.hot_reload_manager, 'reload_callbacks'):
                        normalized_path = str(path_obj.resolve())
                        if normalized_path in self.hot_reload_manager.reload_callbacks:
                            self.hot_reload_manager._trigger_reload_callbacks(normalized_path, 'modified')
                            self.logger.info(f"✅ Triggered manual reload for: {file_path}")
                except Exception as e:
                    self.logger.error(f"❌ Failed to handle file modification in fallback mode: {e}")
            else:
                self.logger.debug("File modified event received (fallback - no path available)")
        
        def on_created(self, event):
            """Handle file creation events (fallback implementation)."""
            file_path = getattr(event, 'src_path', None)
            if file_path:
                self.logger.info(f"📂 File created (fallback mode): {file_path}")
                # In fallback mode, check if newly created file should be monitored
                try:
                    from pathlib import Path
                    path_obj = Path(file_path)
                    if hasattr(self.hot_reload_manager, 'reload_callbacks'):
                        # Check if this file matches any watched patterns
                        if path_obj.suffix in ['.yaml', '.yml', '.json', '.conf', '.cfg', '.ini', '.toml']:
                            self.logger.info(f"🔍 New configuration file detected: {file_path}")
                            # Could potentially auto-register for monitoring
                except Exception as e:
                    self.logger.error(f"❌ Failed to handle file creation in fallback mode: {e}")
            else:
                self.logger.debug("File created event received (fallback - no path available)")
        
        def on_deleted(self, event):
            """Handle file deletion events (fallback implementation)."""
            file_path = getattr(event, 'src_path', None)
            if file_path:
                self.logger.warning(f"🗑️ File deleted (fallback mode): {file_path}")
                # In fallback mode, clean up any monitoring for deleted files
                try:
                    from pathlib import Path
                    path_obj = Path(file_path)
                    if hasattr(self.hot_reload_manager, 'reload_callbacks'):
                        normalized_path = str(path_obj.resolve())
                        if normalized_path in self.hot_reload_manager.reload_callbacks:
                            # Remove callbacks for deleted file
                            del self.hot_reload_manager.reload_callbacks[normalized_path]
                            self.logger.info(f"🧹 Cleaned up monitoring for deleted file: {file_path}")
                except Exception as e:
                    self.logger.error(f"❌ Failed to handle file deletion in fallback mode: {e}")
            else:
                self.logger.debug("File deleted event received (fallback - no path available)")

logger = logging.getLogger(__name__)

class ReloadPolicy(Enum):
    """Reload policy options."""
    IMMEDIATE = "immediate"  # Reload immediately on change
    DEBOUNCED = "debounced"  # Reload after debounce period
    MANUAL = "manual"  # Manual reload only
    SCHEDULED = "scheduled"  # Scheduled reload intervals

@dataclass
class ReloadEvent:
    """Configuration reload event."""
    file_path: Path
    event_type: str  # 'created', 'modified', 'deleted'
    timestamp: float
    config_type: str = ""
    reload_successful: bool = False
    error_message: str = ""

@dataclass
class ReloadConfig:
    """Configuration for hot reload behavior."""
    policy: ReloadPolicy = ReloadPolicy.DEBOUNCED
    debounce_seconds: float = 2.0
    watch_subdirectories: bool = True
    file_patterns: List[str] = field(default_factory=lambda: ['*.yaml', '*.yml', '*.json'])
    ignore_patterns: List[str] = field(default_factory=lambda: ['*.tmp', '*.swp', '*~'])
    max_reload_attempts: int = 3
    reload_timeout: float = 10.0

class ConfigFileHandler(FileSystemEventHandler):
    """File system event handler for configuration files."""
    
    def __init__(self, hot_reload_manager: 'HotReloadManager'):
        """Initialize file handler."""
        super().__init__()
        self.hot_reload_manager = hot_reload_manager
        self.logger = logging.getLogger(__name__)
    
    def on_modified(self, event):
        """Handle file modification events."""
        if not event.is_directory:
            self.hot_reload_manager._handle_file_event(event.src_path, 'modified')
    
    def on_created(self, event):
        """Handle file creation events."""
        if not event.is_directory:
            self.hot_reload_manager._handle_file_event(event.src_path, 'created')
    
    def on_deleted(self, event):
        """Handle file deletion events."""
        if not event.is_directory:
            self.hot_reload_manager._handle_file_event(event.src_path, 'deleted')

class HotReloadManager:
    """
    Hot reload manager for configuration files.
    
    Monitors configuration files for changes and automatically reloads
    them with configurable policies and debouncing.
    """
    
    def __init__(self, config: Optional[ReloadConfig] = None):
        """
        Initialize hot reload manager.
        
        Args:
            config: Reload configuration settings
        """
        self.config = config or ReloadConfig()
        self.logger = logging.getLogger(__name__)
        
        # Watched files and directories
        self.watched_files: Dict[str, Path] = {}  # normalized_path -> Path
        self.watched_directories: Dict[str, Path] = {}
        
        # File monitoring
        self.observer = None
        self.file_handler = None
        self.monitoring_active = False
        
        # Reload callbacks
        self.reload_callbacks: Dict[str, List[Callable]] = {}  # file_path -> callbacks
        
        # Debouncing
        self.pending_reloads: Dict[str, float] = {}  # file_path -> timestamp
        self.debounce_timer = None
        self.debounce_lock = threading.Lock()
        
        # File checksums for change detection
        self.file_checksums: Dict[str, str] = {}
        
        # Reload history
        self.reload_events: List[ReloadEvent] = []
        self.max_event_history = 100
        
        # Thread safety
        self.lock = threading.RLock()
        
        # Initialize watchdog if available
        if WATCHDOG_AVAILABLE:
            self._init_watchdog()
        else:
            self.logger.warning("Watchdog not available - hot reload will use polling")
        
        self.logger.info("Hot reload manager initialized")
    
    def watch_file(self, file_path: Path, callback: Optional[Callable] = None) -> bool:
        """
        Watch a configuration file for changes.
        
        Args:
            file_path: Path to file to watch
            callback: Optional callback function to call on reload
            
        Returns:
            True if file is being watched, False otherwise
        """
        with self.lock:
            normalized_path = str(file_path.resolve())
            
            if not file_path.exists():
                self.logger.warning(f"Cannot watch non-existent file: {file_path}")
                return False
            
            # Add to watched files
            self.watched_files[normalized_path] = file_path
            
            # Calculate initial checksum
            self.file_checksums[normalized_path] = self._calculate_file_checksum(file_path)
            
            # Add callback if provided
            if callback:
                self.add_reload_callback(file_path, callback)
            
            # Start monitoring if not already active
            if not self.monitoring_active:
                self._start_monitoring()
            
            self.logger.info(f"Watching file: {file_path}")
            return True
    
    def watch_directory(self, directory_path: Path, callback: Optional[Callable] = None) -> bool:
        """
        Watch a directory for configuration file changes.
        
        Args:
            directory_path: Path to directory to watch
            callback: Optional callback function to call on reload
            
        Returns:
            True if directory is being watched, False otherwise
        """
        with self.lock:
            normalized_path = str(directory_path.resolve())
            
            if not directory_path.exists() or not directory_path.is_dir():
                self.logger.warning(f"Cannot watch non-existent directory: {directory_path}")
                return False
            
            # Add to watched directories
            self.watched_directories[normalized_path] = directory_path
            
            # Add callback if provided
            if callback:
                self.add_reload_callback(directory_path, callback)
            
            # Start monitoring if not already active
            if not self.monitoring_active:
                self._start_monitoring()
            
            self.logger.info(f"Watching directory: {directory_path}")
            return True
    
    def unwatch_file(self, file_path: Path) -> bool:
        """
        Stop watching a file.
        
        Args:
            file_path: Path to file to stop watching
            
        Returns:
            True if file was being watched, False otherwise
        """
        with self.lock:
            normalized_path = str(file_path.resolve())
            
            if normalized_path in self.watched_files:
                del self.watched_files[normalized_path]
                if normalized_path in self.file_checksums:
                    del self.file_checksums[normalized_path]
                if normalized_path in self.reload_callbacks:
                    del self.reload_callbacks[normalized_path]
                if normalized_path in self.pending_reloads:
                    del self.pending_reloads[normalized_path]
                
                self.logger.info(f"Stopped watching file: {file_path}")
                return True
            
            return False
    
    def unwatch_directory(self, directory_path: Path) -> bool:
        """
        Stop watching a directory.
        
        Args:
            directory_path: Path to directory to stop watching
            
        Returns:
            True if directory was being watched, False otherwise
        """
        with self.lock:
            normalized_path = str(directory_path.resolve())
            
            if normalized_path in self.watched_directories:
                del self.watched_directories[normalized_path]
                if normalized_path in self.reload_callbacks:
                    del self.reload_callbacks[normalized_path]
                
                self.logger.info(f"Stopped watching directory: {directory_path}")
                return True
            
            return False
    
    def add_reload_callback(self, file_path: Path, callback: Callable) -> None:
        """
        Add callback for file reload events.
        
        Args:
            file_path: Path to file
            callback: Callback function to call on reload
        """
        with self.lock:
            normalized_path = str(file_path.resolve())
            
            if normalized_path not in self.reload_callbacks:
                self.reload_callbacks[normalized_path] = []
            
            self.reload_callbacks[normalized_path].append(callback)
    
    def remove_reload_callback(self, file_path: Path, callback: Callable) -> bool:
        """
        Remove reload callback.
        
        Args:
            file_path: Path to file
            callback: Callback function to remove
            
        Returns:
            True if callback was removed, False otherwise
        """
        with self.lock:
            normalized_path = str(file_path.resolve())
            
            if normalized_path in self.reload_callbacks:
                try:
                    self.reload_callbacks[normalized_path].remove(callback)
                    return True
                except ValueError:
                    pass
            
            return False
    
    def manual_reload(self, file_path: Path) -> bool:
        """
        Manually trigger reload of a file.
        
        Args:
            file_path: Path to file to reload
            
        Returns:
            True if reload was successful, False otherwise
        """
        return self._reload_file(file_path, 'manual')
    
    def reload_all(self) -> Dict[str, bool]:
        """
        Reload all watched files.
        
        Returns:
            Dictionary mapping file paths to reload success status
        """
        results = {}
        
        with self.lock:
            for file_path in self.watched_files.values():
                results[str(file_path)] = self._reload_file(file_path, 'manual')
        
        return results
    
    def get_reload_events(self, limit: Optional[int] = None) -> List[ReloadEvent]:
        """
        Get recent reload events.
        
        Args:
            limit: Maximum number of events to return
            
        Returns:
            List of recent reload events
        """
        with self.lock:
            events = self.reload_events.copy()
            if limit:
                events = events[-limit:]
            return events
    
    def clear_reload_history(self) -> None:
        """Clear reload event history."""
        with self.lock:
            self.reload_events.clear()
    
    def _init_watchdog(self) -> None:
        """Initialize watchdog observer."""
        if WATCHDOG_AVAILABLE:
            self.observer = Observer()
            self.file_handler = ConfigFileHandler(self)
        else:
            self.logger.warning("Watchdog not available for file monitoring")
    
    def _start_monitoring(self) -> None:
        """Start file monitoring."""
        if not WATCHDOG_AVAILABLE:
            self.logger.warning("Cannot start monitoring - watchdog not available")
            return
        
        if self.monitoring_active:
            return
        
        try:
            # Watch all directories
            for directory_path in self.watched_directories.values():
                self.observer.schedule(
                    self.file_handler,
                    str(directory_path),
                    recursive=self.config.watch_subdirectories
                )
            
            # Watch parent directories of individual files
            parent_dirs = set()
            for file_path in self.watched_files.values():
                parent_dirs.add(file_path.parent)
            
            for parent_dir in parent_dirs:
                if str(parent_dir.resolve()) not in self.watched_directories:
                    self.observer.schedule(
                        self.file_handler,
                        str(parent_dir),
                        recursive=False
                    )
            
            self.observer.start()
            self.monitoring_active = True
            self.logger.info("File monitoring started")
            
        except Exception as e:
            self.logger.error(f"Failed to start file monitoring: {e}")
    
    def _stop_monitoring(self) -> None:
        """Stop file monitoring."""
        if self.observer and self.monitoring_active:
            self.observer.stop()
            self.observer.join()
            self.monitoring_active = False
            self.logger.info("File monitoring stopped")
    
    def _handle_file_event(self, file_path: str, event_type: str) -> None:
        """Handle file system events."""
        file_path_obj = Path(file_path)
        normalized_path = str(file_path_obj.resolve())
        
        # Check if this is a file we're interested in
        if not self._should_handle_file(file_path_obj):
            return
        
        # Check if we're watching this file or its parent directory
        watching_file = normalized_path in self.watched_files
        watching_parent = any(
            str(file_path_obj).startswith(str(dir_path))
            for dir_path in self.watched_directories.values()
        )
        
        if not (watching_file or watching_parent):
            return
        
        # Check if file actually changed
        if event_type == 'modified' and not self._file_changed(file_path_obj):
            return
        
        self.logger.debug(f"File event: {event_type} - {file_path}")
        
        # Handle based on reload policy
        if self.config.policy == ReloadPolicy.IMMEDIATE:
            self._reload_file(file_path_obj, event_type)
        elif self.config.policy == ReloadPolicy.DEBOUNCED:
            self._schedule_debounced_reload(file_path_obj, event_type)
        # MANUAL and SCHEDULED policies don't auto-reload
    
    def _should_handle_file(self, file_path: Path) -> bool:
        """Check if file should be handled based on patterns."""
        file_name = file_path.name
        
        # Check ignore patterns
        for pattern in self.config.ignore_patterns:
            if file_path.match(pattern):
                return False
        
        # Check file patterns
        for pattern in self.config.file_patterns:
            if file_path.match(pattern):
                return True
        
        return False
    
    def _file_changed(self, file_path: Path) -> bool:
        """Check if file has actually changed using checksums."""
        normalized_path = str(file_path.resolve())
        
        try:
            current_checksum = self._calculate_file_checksum(file_path)
            previous_checksum = self.file_checksums.get(normalized_path)
            
            if current_checksum != previous_checksum:
                self.file_checksums[normalized_path] = current_checksum
                return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"Error checking file change: {e}")
            return True  # Assume changed if we can't check
    
    def _calculate_file_checksum(self, file_path: Path) -> str:
        """Calculate file checksum for change detection."""
        try:
            with open(file_path, 'rb') as f:
                return hashlib.md5(f.read()).hexdigest()
        except Exception as e:
            self.logger.error(f"Error calculating checksum for {file_path}: {e}")
            return ""
    
    def _schedule_debounced_reload(self, file_path: Path, event_type: str) -> None:
        """Schedule debounced reload."""
        normalized_path = str(file_path.resolve())
        
        with self.debounce_lock:
            # Update pending reload timestamp
            self.pending_reloads[normalized_path] = time.time()
            
            # Start debounce timer if not already running
            if self.debounce_timer is None or not self.debounce_timer.is_alive():
                self.debounce_timer = threading.Timer(
                    self.config.debounce_seconds,
                    self._process_debounced_reloads
                )
                self.debounce_timer.start()
    
    def _process_debounced_reloads(self) -> None:
        """Process pending debounced reloads."""
        with self.debounce_lock:
            current_time = time.time()
            ready_reloads = []
            
            # Find reloads that are ready
            for file_path, timestamp in self.pending_reloads.items():
                if current_time - timestamp >= self.config.debounce_seconds:
                    ready_reloads.append(file_path)
            
            # Remove ready reloads from pending
            for file_path in ready_reloads:
                del self.pending_reloads[file_path]
            
            # Process ready reloads
            for file_path in ready_reloads:
                self._reload_file(Path(file_path), 'debounced')
            
            # Schedule next debounce check if there are still pending reloads
            if self.pending_reloads:
                self.debounce_timer = threading.Timer(
                    self.config.debounce_seconds,
                    self._process_debounced_reloads
                )
                self.debounce_timer.start()
    
    def _reload_file(self, file_path: Path, event_type: str) -> bool:
        """Reload a configuration file."""
        normalized_path = str(file_path.resolve())
        
        # Create reload event
        reload_event = ReloadEvent(
            file_path=file_path,
            event_type=event_type,
            timestamp=time.time()
        )
        
        try:
            # Call reload callbacks
            callbacks = self.reload_callbacks.get(normalized_path, [])
            
            for callback in callbacks:
                try:
                    callback(file_path)
                except Exception as e:
                    self.logger.error(f"Error in reload callback: {e}")
                    reload_event.error_message = str(e)
                    reload_event.reload_successful = False
                    break
            else:
                reload_event.reload_successful = True
            
            # Update file checksum
            if file_path.exists():
                self.file_checksums[normalized_path] = self._calculate_file_checksum(file_path)
            
            self.logger.info(f"Reloaded configuration file: {file_path}")
            
        except Exception as e:
            self.logger.error(f"Failed to reload file {file_path}: {e}")
            reload_event.error_message = str(e)
            reload_event.reload_successful = False
        
        # Add to history
        with self.lock:
            self.reload_events.append(reload_event)
            if len(self.reload_events) > self.max_event_history:
                self.reload_events = self.reload_events[-self.max_event_history:]
        
        return reload_event.reload_successful
    
    def shutdown(self) -> None:
        """Shutdown hot reload manager."""
        self.logger.info("Shutting down hot reload manager")
        
        # Stop monitoring
        self._stop_monitoring()
        
        # Cancel debounce timer
        if self.debounce_timer and self.debounce_timer.is_alive():
            self.debounce_timer.cancel()
        
        # Clear state
        with self.lock:
            self.watched_files.clear()
            self.watched_directories.clear()
            self.reload_callbacks.clear()
            self.pending_reloads.clear()
            self.file_checksums.clear()
    
    def __del__(self):
        """Cleanup on destruction."""
        self.shutdown()

# Global hot reload manager instance
_hot_reload_manager = None

def get_hot_reload_manager() -> HotReloadManager:
    """Get global hot reload manager instance."""
    global _hot_reload_manager
    if _hot_reload_manager is None:
        _hot_reload_manager = HotReloadManager()
    return _hot_reload_manager

def watch_config_file(file_path: Path, callback: Optional[Callable] = None) -> bool:
    """Watch a configuration file for changes."""
    return get_hot_reload_manager().watch_file(file_path, callback)

def watch_config_directory(directory_path: Path, callback: Optional[Callable] = None) -> bool:
    """Watch a configuration directory for changes."""
    return get_hot_reload_manager().watch_directory(directory_path, callback)

def unwatch_config_file(file_path: Path) -> bool:
    """Stop watching a configuration file."""
    return get_hot_reload_manager().unwatch_file(file_path)

def manual_reload_config(file_path: Path) -> bool:
    """Manually reload a configuration file."""
    return get_hot_reload_manager().manual_reload(file_path) 
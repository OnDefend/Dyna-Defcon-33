#!/usr/bin/env python3
"""
Frida Resource Manager - Concurrent Testing Coordination

This module provides comprehensive resource management for concurrent Frida testing,
including file-based locking, dynamic port allocation, and session isolation to
prevent conflicts between multiple analysis sessions.
"""

import os
import time
import logging
import threading
import socket
from pathlib import Path
from typing import Dict, List, Optional, Set
from dataclasses import dataclass
from contextlib import contextmanager
import tempfile
import uuid

@dataclass
class FridaSession:
    """Represents an active Frida analysis session."""
    session_id: str
    package_name: str
    device_id: str
    frida_port: int
    adb_port: int
    pid: Optional[int] = None
    start_time: float = 0.0
    lock_file: Optional[str] = None
    status: str = "INITIALIZING"

@dataclass
class ResourceAllocation:
    """Resource allocation for a Frida session."""
    frida_port: int
    adb_forward_port: int
    temp_dir: Path
    lock_file: Path
    session_id: str

class PortManager:
    """Manages dynamic port allocation for concurrent sessions."""
    
    def __init__(self, start_port: int = 27042, end_port: int = 27100):
        self.start_port = start_port
        self.end_port = end_port
        self.allocated_ports: Set[int] = set()
        self.port_lock = threading.Lock()
        
    def allocate_port(self) -> Optional[int]:
        """Allocate an available port."""
        with self.port_lock:
            for port in range(self.start_port, self.end_port + 1):
                if port not in self.allocated_ports and self._is_port_available(port):
                    self.allocated_ports.add(port)
                    return port
        return None
    
    def release_port(self, port: int):
        """Release a previously allocated port."""
        with self.port_lock:
            self.allocated_ports.discard(port)
    
    def _is_port_available(self, port: int) -> bool:
        """Check if a port is available for use."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind(('localhost', port))
                return True
        except OSError:
            return False

class FridaResourceManager:
    """
    Comprehensive resource manager for concurrent Frida testing.
    
    Features:
    - File-based locking for system-wide coordination
    - Dynamic port allocation
    - Session isolation and tracking
    - Resource cleanup and recovery
    - Deadlock prevention
    """
    
    def __init__(self, base_temp_dir: str = "/tmp/frida_sessions"):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.base_temp_dir = Path(base_temp_dir)
        self.base_temp_dir.mkdir(exist_ok=True)
        
        # Resource managers
        self.port_manager = PortManager()
        self.active_sessions: Dict[str, FridaSession] = {}
        self.session_lock = threading.Lock()
        
        # Global coordination
        self.global_lock_file = self.base_temp_dir / "frida_global.lock"
        self.session_registry = self.base_temp_dir / "session_registry.txt"
        
        # Configuration
        self.max_concurrent_sessions = 3
        self.session_timeout = 300  # 5 minutes
        self.cleanup_interval = 60  # 1 minute
        
        # Start cleanup thread
        self._start_cleanup_thread()
        
        self.logger.info(f"🔧 Frida Resource Manager initialized (max sessions: {self.max_concurrent_sessions})")
    
    @contextmanager
    def acquire_session(self, package_name: str, device_id: str = "default"):
        """
        Context manager to acquire exclusive Frida session resources.
        
        Args:
            package_name: Target package name
            device_id: Target device identifier
            
        Yields:
            ResourceAllocation: Allocated resources for the session
        """
        session_id = self._generate_session_id(package_name)
        allocation = None
        
        try:
            # Acquire resources
            allocation = self._acquire_resources(session_id, package_name, device_id)
            
            if allocation is None:
                raise ResourceExhaustionError("No available resources for Frida session")
            
            # Register session
            session = FridaSession(
                session_id=session_id,
                package_name=package_name,
                device_id=device_id,
                frida_port=allocation.frida_port,
                adb_port=allocation.adb_forward_port,
                start_time=time.time(),
                lock_file=str(allocation.lock_file),
                status="ACTIVE"
            )
            
            with self.session_lock:
                self.active_sessions[session_id] = session
            
            self._register_session(session)
            
            self.logger.info(f"✅ Acquired Frida session: {session_id} (port: {allocation.frida_port})")
            
            yield allocation
            
        except Exception as e:
            self.logger.error(f"❌ Session acquisition failed: {e}")
            raise
            
        finally:
            # Always cleanup resources
            if allocation:
                self._release_resources(allocation)
            
            # Unregister session
            with self.session_lock:
                self.active_sessions.pop(session_id, None)
            
            self._unregister_session(session_id)
            
            self.logger.info(f"🧹 Released Frida session: {session_id}")
    
    def _acquire_resources(self, session_id: str, package_name: str, device_id: str) -> Optional[ResourceAllocation]:
        """Acquire all necessary resources for a Frida session."""
        
        # Check session limits
        if len(self.active_sessions) >= self.max_concurrent_sessions:
            self.logger.warning(f"⚠️ Maximum concurrent sessions reached ({self.max_concurrent_sessions})")
            return None
        
        # Allocate ports
        frida_port = self.port_manager.allocate_port()
        if frida_port is None:
            self.logger.warning("⚠️ No available ports for Frida session")
            return None
        
        adb_port = self.port_manager.allocate_port()
        if adb_port is None:
            self.port_manager.release_port(frida_port)
            self.logger.warning("⚠️ No available ADB forward port")
            return None
        
        # Create session directory
        session_dir = self.base_temp_dir / f"session_{session_id}"
        session_dir.mkdir(exist_ok=True)
        
        # Create lock file
        lock_file = session_dir / "session.lock"
        
        try:
            # Acquire file lock
            if not self._acquire_file_lock(lock_file, package_name):
                self.port_manager.release_port(frida_port)
                self.port_manager.release_port(adb_port)
                return None
            
            return ResourceAllocation(
                frida_port=frida_port,
                adb_forward_port=adb_port,
                temp_dir=session_dir,
                lock_file=lock_file,
                session_id=session_id
            )
            
        except Exception as e:
            self.logger.error(f"Resource acquisition failed: {e}")
            self.port_manager.release_port(frida_port)
            self.port_manager.release_port(adb_port)
            return None
    
    def _acquire_file_lock(self, lock_file: Path, package_name: str, timeout: int = 30) -> bool:
        """Acquire exclusive file lock for session coordination."""
        
        try:
            # Try to acquire lock with timeout
            start_time = time.time()
            while time.time() - start_time < timeout:
                try:
                    # Open lock file exclusively
                    fd = os.open(str(lock_file), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
                    
                    # Write lock info
                    lock_content = f"{package_name},{os.getpid()},{time.time()},{socket.gethostname()}\n"
                    os.write(fd, lock_content.encode())
                    os.close(fd)
                    
                    self.logger.debug(f"🔒 Acquired file lock: {lock_file}")
                    return True
                    
                except OSError as e:
                    if e.errno == 17:  # File exists
                        # Check if existing lock is stale
                        if self._is_stale_lock(lock_file):
                            self._remove_stale_lock(lock_file)
                            continue
                        
                        # Wait and retry
                        time.sleep(0.5)
                        continue
                    else:
                        raise
            
            self.logger.warning(f"⏰ Lock acquisition timeout: {lock_file}")
            return False
            
        except Exception as e:
            self.logger.error(f"Lock acquisition error: {e}")
            return False
    
    def _is_stale_lock(self, lock_file: Path) -> bool:
        """Check if a lock file is stale (process no longer exists)."""
        try:
            if not lock_file.exists():
                return True
            
            # Read lock info
            content = lock_file.read_text().strip()
            if not content:
                return True
            
            parts = content.split(',')
            if len(parts) < 4:
                return True
            
            pid = int(parts[1])
            timestamp = float(parts[2])
            
            # Check if process still exists
            try:
                os.kill(pid, 0)  # Signal 0 just checks if process exists
                
                # Check if lock is too old (stale timeout)
                if time.time() - timestamp > self.session_timeout:
                    self.logger.warning(f"🕰️ Stale lock detected (old): {lock_file}")
                    return True
                
                return False  # Process exists and lock is recent
                
            except OSError:
                # Process doesn't exist
                self.logger.warning(f"👻 Stale lock detected (dead process): {lock_file}")
                return True
            
        except Exception as e:
            self.logger.debug(f"Stale lock check error: {e}")
            return True  # Assume stale on error
    
    def _remove_stale_lock(self, lock_file: Path):
        """Remove a stale lock file."""
        try:
            lock_file.unlink(missing_ok=True)
            self.logger.debug(f"🧹 Removed stale lock: {lock_file}")
        except Exception as e:
            self.logger.debug(f"Stale lock removal error: {e}")
    
    def _release_resources(self, allocation: ResourceAllocation):
        """Release all resources for a session."""
        try:
            # Release ports
            self.port_manager.release_port(allocation.frida_port)
            self.port_manager.release_port(allocation.adb_forward_port)
            
            # Remove lock file
            allocation.lock_file.unlink(missing_ok=True)
            
            # Cleanup session directory
            if allocation.temp_dir.exists():
                import shutil
                shutil.rmtree(allocation.temp_dir, ignore_errors=True)
            
            self.logger.debug(f"🧹 Released resources for session: {allocation.session_id}")
            
        except Exception as e:
            self.logger.debug(f"Resource cleanup error: {e}")
    
    def _generate_session_id(self, package_name: str) -> str:
        """Generate unique session identifier."""
        timestamp = int(time.time() * 1000)
        unique_id = str(uuid.uuid4())[:8]
        safe_package = package_name.replace('.', '_')[:20]
        return f"{safe_package}_{timestamp}_{unique_id}"
    
    def _register_session(self, session: FridaSession):
        """Register session in global registry."""
        try:
            registry_line = f"{session.session_id},{session.package_name},{session.frida_port},{session.start_time},{os.getpid()}\n"
            
            with open(self.session_registry, 'a') as f:
                f.write(registry_line)
                
        except Exception as e:
            self.logger.debug(f"Session registration error: {e}")
    
    def _unregister_session(self, session_id: str):
        """Remove session from global registry."""
        try:
            if not self.session_registry.exists():
                return
            
            # Read existing registry
            lines = self.session_registry.read_text().splitlines()
            
            # Filter out the session
            filtered_lines = [line for line in lines if not line.startswith(session_id)]
            
            # Write back filtered registry
            self.session_registry.write_text('\n'.join(filtered_lines) + '\n' if filtered_lines else '')
            
        except Exception as e:
            self.logger.debug(f"Session unregistration error: {e}")
    
    def _start_cleanup_thread(self):
        """Start background cleanup thread for stale sessions."""
        def cleanup_loop():
            while True:
                try:
                    self._cleanup_stale_sessions()
                    time.sleep(self.cleanup_interval)
                except Exception as e:
                    self.logger.debug(f"Cleanup thread error: {e}")
                    time.sleep(5)
        
        cleanup_thread = threading.Thread(target=cleanup_loop, daemon=True)
        cleanup_thread.start()
        self.logger.debug("🧹 Started cleanup thread")
    
    def _cleanup_stale_sessions(self):
        """Clean up stale sessions and resources."""
        try:
            # Clean up stale lock files
            for lock_file in self.base_temp_dir.glob("*/session.lock"):
                if self._is_stale_lock(lock_file):
                    session_dir = lock_file.parent
                    self._remove_stale_lock(lock_file)
                    
                    # Remove entire session directory
                    if session_dir.exists():
                        import shutil
                        shutil.rmtree(session_dir, ignore_errors=True)
            
            # Clean up stale registry entries
            if self.session_registry.exists():
                lines = self.session_registry.read_text().splitlines()
                active_lines = []
                
                for line in lines:
                    if not line.strip():
                        continue
                    
                    parts = line.split(',')
                    if len(parts) >= 5:
                        start_time = float(parts[3])
                        pid = int(parts[4])
                        
                        # Check if session is still active
                        try:
                            os.kill(pid, 0)
                            if time.time() - start_time < self.session_timeout:
                                active_lines.append(line)
                        except OSError:
                            pass  # Process dead, don't keep entry
                
                # Write back active sessions only
                self.session_registry.write_text('\n'.join(active_lines) + '\n' if active_lines else '')
            
        except Exception as e:
            self.logger.debug(f"Stale session cleanup error: {e}")
    
    def get_active_sessions(self) -> List[FridaSession]:
        """Get list of currently active sessions."""
        with self.session_lock:
            return list(self.active_sessions.values())
    
    def force_cleanup_all(self):
        """Force cleanup of all sessions and resources."""
        self.logger.info("🧹 Force cleanup of all Frida resources...")
        
        try:
            # Cleanup active sessions
            with self.session_lock:
                for session in list(self.active_sessions.values()):
                    try:
                        if session.lock_file:
                            Path(session.lock_file).unlink(missing_ok=True)
                    except Exception:
                        pass
                
                self.active_sessions.clear()
            
            # Cleanup all session directories
            if self.base_temp_dir.exists():
                for session_dir in self.base_temp_dir.glob("session_*"):
                    if session_dir.is_dir():
                        import shutil
                        shutil.rmtree(session_dir, ignore_errors=True)
            
            # Clear registry
            if self.session_registry.exists():
                self.session_registry.write_text('')
            
            # Reset port manager
            with self.port_manager.port_lock:
                self.port_manager.allocated_ports.clear()
            
            self.logger.info("✅ Force cleanup completed")
            
        except Exception as e:
            self.logger.error(f"Force cleanup error: {e}")

# Custom exceptions
class ResourceExhaustionError(Exception):
    """Raised when no resources are available for allocation."""
    pass

class ConcurrentAccessError(Exception):
    """Raised when concurrent access conflicts are detected."""
    pass

# Global instance
_frida_resource_manager = None

def get_frida_resource_manager() -> FridaResourceManager:
    """Get global Frida resource manager instance."""
    global _frida_resource_manager
    if _frida_resource_manager is None:
        _frida_resource_manager = FridaResourceManager()
    return _frida_resource_manager

def cleanup_frida_resources():
    """Cleanup all Frida resources (for shutdown)."""
    global _frida_resource_manager
    if _frida_resource_manager:
        _frida_resource_manager.force_cleanup_all()
        _frida_resource_manager = None
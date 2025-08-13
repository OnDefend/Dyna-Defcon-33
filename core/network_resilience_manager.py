#!/usr/bin/env python3
"""
Network Resilience Manager - Enhanced Network Analysis Edge Cases

This module provides comprehensive network resilience for AODS analysis,
including timeout handling, offline mode fallback, proxy recovery, and
network condition adaptation to improve edge case coverage.
"""

import os
import time
import logging
import threading
import subprocess
import socket
import requests
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from contextlib import contextmanager
import urllib3
from urllib3.exceptions import InsecureRequestWarning

# Suppress SSL warnings for testing environments
urllib3.disable_warnings(InsecureRequestWarning)

@dataclass
class NetworkCondition:
    """Represents current network conditions."""
    connectivity: str  # ONLINE, OFFLINE, LIMITED, UNSTABLE
    latency_ms: float
    bandwidth_mbps: float
    packet_loss_percent: float
    proxy_status: str  # NONE, HTTP, SOCKS, CORPORATE
    dns_resolution: bool
    last_check: float

@dataclass
class NetworkConfiguration:
    """Network configuration for analysis."""
    timeout_connect: int = 10
    timeout_read: int = 30
    max_retries: int = 3
    retry_backoff: float = 1.5
    proxy_url: Optional[str] = None
    offline_mode: bool = False
    adaptive_timeouts: bool = True

class NetworkConnectivityChecker:
    """Checks and monitors network connectivity status."""
    
    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.test_urls = [
            "https://www.google.com",
            "https://1.1.1.1",
            "https://8.8.8.8",
            "http://httpbin.org/get"
        ]
        self.dns_servers = ["8.8.8.8", "1.1.1.1", "208.67.222.222"]
        
    def check_connectivity(self, timeout: int = 5) -> NetworkCondition:
        """Comprehensive network connectivity check."""
        start_time = time.time()
        
        # Initialize condition
        condition = NetworkCondition(
            connectivity="CHECKING",
            latency_ms=0.0,
            bandwidth_mbps=0.0,
            packet_loss_percent=100.0,  # Assume worst case
            proxy_status="NONE",
            dns_resolution=False,
            last_check=start_time
        )
        
        try:
            # Check DNS resolution
            condition.dns_resolution = self._check_dns_resolution()
            
            # Check basic connectivity
            connectivity_results = self._test_connectivity(timeout)
            
            if connectivity_results['success_count'] == 0:
                condition.connectivity = "OFFLINE"
            elif connectivity_results['success_count'] < len(self.test_urls) // 2:
                condition.connectivity = "LIMITED"
            elif connectivity_results['avg_latency'] > 2000:  # 2 seconds
                condition.connectivity = "UNSTABLE"
            else:
                condition.connectivity = "ONLINE"
            
            condition.latency_ms = connectivity_results['avg_latency']
            condition.packet_loss_percent = connectivity_results['packet_loss']
            
            # Check proxy status
            condition.proxy_status = self._detect_proxy()
            
            # Estimate bandwidth (simple test)
            if condition.connectivity in ["ONLINE", "UNSTABLE"]:
                condition.bandwidth_mbps = self._estimate_bandwidth()
            
        except Exception as e:
            self.logger.debug(f"Connectivity check error: {e}")
            condition.connectivity = "OFFLINE"
        
        condition.last_check = time.time()
        
        self.logger.debug(f"🌐 Network condition: {condition.connectivity} "
                         f"(latency: {condition.latency_ms:.1f}ms, "
                         f"loss: {condition.packet_loss_percent:.1f}%)")
        
        return condition
    
    def _check_dns_resolution(self) -> bool:
        """Test DNS resolution capability."""
        try:
            for dns_server in self.dns_servers:
                try:
                    socket.gethostbyname(dns_server)
                    return True
                except socket.gaierror:
                    continue
            return False
        except Exception:
            return False
    
    def _test_connectivity(self, timeout: int) -> Dict[str, Any]:
        """Test connectivity to multiple endpoints."""
        results = {
            'success_count': 0,
            'total_count': len(self.test_urls),
            'latencies': [],
            'avg_latency': 0.0,
            'packet_loss': 100.0
        }
        
        for url in self.test_urls:
            try:
                start_time = time.time()
                response = requests.get(
                    url, 
                    timeout=timeout, 
                    verify=False,
                    headers={'User-Agent': 'AODS-Network-Check/1.0'}
                )
                
                if response.status_code == 200:
                    latency = (time.time() - start_time) * 1000  # Convert to ms
                    results['latencies'].append(latency)
                    results['success_count'] += 1
                    
            except Exception as e:
                self.logger.debug(f"Connectivity test failed for {url}: {e}")
                continue
        
        if results['latencies']:
            results['avg_latency'] = sum(results['latencies']) / len(results['latencies'])
            results['packet_loss'] = ((results['total_count'] - results['success_count']) / results['total_count']) * 100
        
        return results
    
    def _detect_proxy(self) -> str:
        """Detect proxy configuration."""
        try:
            # Check environment variables
            proxy_vars = ['HTTP_PROXY', 'HTTPS_PROXY', 'http_proxy', 'https_proxy']
            for var in proxy_vars:
                if os.environ.get(var):
                    proxy_url = os.environ.get(var)
                    if 'socks' in proxy_url.lower():
                        return "SOCKS"
                    else:
                        return "HTTP"
            
            # Check for corporate proxy indicators
            try:
                # Try to detect corporate proxy by checking for common corporate domains
                response = requests.get('http://httpbin.org/ip', timeout=3, verify=False)
                if response.status_code == 200:
                    ip_info = response.json()
                    # Corporate proxies often have specific IP ranges or hostnames
                    if any(corp in str(ip_info).lower() for corp in ['corporate', 'proxy', 'gateway']):
                        return "CORPORATE"
            except Exception:
                pass
            
            return "NONE"
            
        except Exception:
            return "NONE"
    
    def _estimate_bandwidth(self) -> float:
        """Estimate available bandwidth (simple test)."""
        try:
            # Download a small test file and measure speed
            test_url = "http://httpbin.org/bytes/1024"  # 1KB test
            start_time = time.time()
            
            response = requests.get(test_url, timeout=10, verify=False)
            
            if response.status_code == 200:
                duration = time.time() - start_time
                bytes_downloaded = len(response.content)
                
                # Calculate Mbps
                if duration > 0:
                    mbps = (bytes_downloaded * 8) / (duration * 1_000_000)  # Convert to Mbps
                    return max(mbps, 0.1)  # Minimum 0.1 Mbps
            
            return 1.0  # Default assumption
            
        except Exception:
            return 1.0  # Default assumption

class NetworkResilienceManager:
    """
    Comprehensive network resilience manager for AODS analysis.
    
    Features:
    - Adaptive timeout management based on network conditions
    - Offline mode fallback capabilities
    - Proxy detection and recovery
    - Network condition monitoring
    - Request retry with exponential backoff
    """
    
    def __init__(self, config: Optional[NetworkConfiguration] = None):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.config = config or NetworkConfiguration()
        
        # Network monitoring
        self.connectivity_checker = NetworkConnectivityChecker()
        self.current_condition: Optional[NetworkCondition] = None
        self.condition_lock = threading.Lock()
        
        # Offline cache
        self.offline_cache_dir = Path("/tmp/aods_offline_cache")
        self.offline_cache_dir.mkdir(exist_ok=True)
        
        # Monitoring thread
        self.monitoring_active = True
        self.monitoring_thread = None
        
        # Start network monitoring
        self._start_network_monitoring()
        
        self.logger.info("🌐 Network Resilience Manager initialized")
    
    def get_network_condition(self, force_check: bool = False) -> NetworkCondition:
        """Get current network condition."""
        with self.condition_lock:
            if (self.current_condition is None or 
                force_check or 
                time.time() - self.current_condition.last_check > 30):  # Check every 30 seconds
                
                self.current_condition = self.connectivity_checker.check_connectivity()
            
            return self.current_condition
    
    def get_adaptive_timeouts(self) -> Tuple[int, int]:
        """Get adaptive timeouts based on network conditions."""
        if not self.config.adaptive_timeouts:
            return self.config.timeout_connect, self.config.timeout_read
        
        condition = self.get_network_condition()
        
        # Base timeouts
        connect_timeout = self.config.timeout_connect
        read_timeout = self.config.timeout_read
        
        # Adjust based on network condition
        if condition.connectivity == "OFFLINE":
            return 1, 1  # Fail fast
        elif condition.connectivity == "LIMITED":
            connect_timeout *= 2
            read_timeout *= 2
        elif condition.connectivity == "UNSTABLE":
            connect_timeout = int(connect_timeout * 1.5)
            read_timeout = int(read_timeout * 1.5)
        
        # Adjust based on latency
        if condition.latency_ms > 1000:  # High latency
            connect_timeout = int(connect_timeout * 1.5)
            read_timeout = int(read_timeout * 1.2)
        
        return connect_timeout, read_timeout
    
    @contextmanager
    def resilient_request(self, operation_name: str = "network_operation"):
        """
        Context manager for resilient network operations.
        
        Provides:
        - Adaptive timeouts
        - Retry logic with exponential backoff
        - Offline mode detection
        - Proxy handling
        """
        condition = self.get_network_condition()
        connect_timeout, read_timeout = self.get_adaptive_timeouts()
        
        self.logger.debug(f"🔄 Starting resilient operation: {operation_name} "
                         f"(condition: {condition.connectivity}, "
                         f"timeouts: {connect_timeout}s/{read_timeout}s)")
        
        # Check if we should operate in offline mode
        if condition.connectivity == "OFFLINE" or self.config.offline_mode:
            self.logger.info(f"📴 Operating in offline mode for: {operation_name}")
            yield self._create_offline_session()
            return
        
        # Create resilient session
        session = requests.Session()
        
        # Configure timeouts
        session.timeout = (connect_timeout, read_timeout)
        
        # Configure retries
        from requests.adapters import HTTPAdapter
        from urllib3.util.retry import Retry
        
        retry_strategy = Retry(
            total=self.config.max_retries,
            backoff_factor=self.config.retry_backoff,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS", "POST"]
        )
        
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        # Configure proxy if detected
        if condition.proxy_status != "NONE" and self.config.proxy_url:
            session.proxies = {
                'http': self.config.proxy_url,
                'https': self.config.proxy_url
            }
        
        # Configure headers
        session.headers.update({
            'User-Agent': 'AODS-Security-Scanner/1.0',
            'Accept': 'application/json, text/plain, */*',
            'Connection': 'keep-alive'
        })
        
        try:
            yield session
        except requests.exceptions.RequestException as e:
            self.logger.warning(f"⚠️ Network operation failed: {operation_name} - {e}")
            
            # Check if we should fall back to offline mode
            if self._should_fallback_offline(e):
                self.logger.info(f"📴 Falling back to offline mode for: {operation_name}")
                yield self._create_offline_session()
            else:
                raise
        finally:
            session.close()
    
    def _create_offline_session(self):
        """Create a mock session for offline operations."""
        class OfflineSession:
            def __init__(self, cache_dir: Path):
                self.cache_dir = cache_dir
                self.logger = logging.getLogger("OfflineSession")
            
            def get(self, url, **kwargs):
                self.logger.debug(f"📴 Offline GET request: {url}")
                return self._create_offline_response(url, "GET")
            
            def post(self, url, **kwargs):
                self.logger.debug(f"📴 Offline POST request: {url}")
                return self._create_offline_response(url, "POST")
            
            def _create_offline_response(self, url, method):
                class OfflineResponse:
                    def __init__(self):
                        self.status_code = 200
                        self.headers = {'Content-Type': 'application/json'}
                        self.text = '{"status": "offline_mode", "message": "Operating in offline mode"}'
                    
                    def json(self):
                        return {"status": "offline_mode", "message": "Operating in offline mode"}
                    
                    def raise_for_status(self):
                        """Check if response status indicates an error and raise HTTPError if so."""
                        if self.status_code >= 400:
                            from requests.exceptions import HTTPError
                            raise HTTPError(f"{self.status_code} Client/Server Error for offline mode")
                
                return OfflineResponse()
            
            def close(self):
                """Close the offline session and cleanup resources."""
                # In offline mode, ensure any file handles or resources are cleaned up
                if hasattr(self, '_cache_files'):
                    for cache_file in self._cache_files:
                        try:
                            if cache_file.is_open():
                                cache_file.close()
                        except (AttributeError, OSError):
                            pass
        
        return OfflineSession(self.offline_cache_dir)
    
    def _should_fallback_offline(self, exception: Exception) -> bool:
        """Determine if we should fall back to offline mode."""
        offline_indicators = [
            "Connection refused",
            "Name or service not known",
            "Network is unreachable",
            "Temporary failure in name resolution",
            "Connection timed out"
        ]
        
        exception_str = str(exception).lower()
        return any(indicator.lower() in exception_str for indicator in offline_indicators)
    
    def _start_network_monitoring(self):
        """Start background network monitoring."""
        def monitoring_loop():
            while self.monitoring_active:
                try:
                    # Update network condition
                    with self.condition_lock:
                        self.current_condition = self.connectivity_checker.check_connectivity()
                    
                    # Log significant changes
                    if hasattr(self, '_last_connectivity'):
                        if self._last_connectivity != self.current_condition.connectivity:
                            self.logger.info(f"🔄 Network condition changed: "
                                           f"{self._last_connectivity} → {self.current_condition.connectivity}")
                    
                    self._last_connectivity = self.current_condition.connectivity
                    
                    # Sleep based on network condition
                    if self.current_condition.connectivity == "OFFLINE":
                        time.sleep(10)  # Check more frequently when offline
                    else:
                        time.sleep(30)  # Normal monitoring interval
                        
                except Exception as e:
                    self.logger.debug(f"Network monitoring error: {e}")
                    time.sleep(30)
        
        self.monitoring_thread = threading.Thread(target=monitoring_loop, daemon=True)
        self.monitoring_thread.start()
        self.logger.debug("🔍 Started network monitoring thread")
    
    def enable_offline_mode(self):
        """Enable offline mode."""
        self.config.offline_mode = True
        self.logger.info("📴 Offline mode enabled")
    
    def disable_offline_mode(self):
        """Disable offline mode."""
        self.config.offline_mode = False
        self.logger.info("🌐 Offline mode disabled")
    
    def get_network_stats(self) -> Dict[str, Any]:
        """Get comprehensive network statistics."""
        condition = self.get_network_condition()
        
        return {
            'connectivity': condition.connectivity,
            'latency_ms': condition.latency_ms,
            'bandwidth_mbps': condition.bandwidth_mbps,
            'packet_loss_percent': condition.packet_loss_percent,
            'proxy_status': condition.proxy_status,
            'dns_resolution': condition.dns_resolution,
            'offline_mode': self.config.offline_mode,
            'adaptive_timeouts': self.config.adaptive_timeouts,
            'last_check': condition.last_check
        }
    
    def shutdown(self):
        """Shutdown network monitoring."""
        self.monitoring_active = False
        if self.monitoring_thread and self.monitoring_thread.is_alive():
            self.monitoring_thread.join(timeout=5)
        self.logger.info("🛑 Network Resilience Manager shutdown")

# Global instance
_network_resilience_manager = None

def get_network_resilience_manager() -> NetworkResilienceManager:
    """Get global network resilience manager instance."""
    global _network_resilience_manager
    if _network_resilience_manager is None:
        _network_resilience_manager = NetworkResilienceManager()
    return _network_resilience_manager

def cleanup_network_resources():
    """Cleanup network resources (for shutdown)."""
    global _network_resilience_manager
    if _network_resilience_manager:
        _network_resilience_manager.shutdown()
        _network_resilience_manager = None 
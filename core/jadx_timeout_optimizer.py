#!/usr/bin/env python3
"""
JADX Timeout Optimizer

Provides enhanced timeout management for JADX static analysis to address
the critical timeout failures identified in scan logs.
"""

import os
import logging
import psutil
from typing import Optional

logger = logging.getLogger(__name__)

class JadxTimeoutOptimizer:
    """
    Advanced timeout optimization for JADX decompilation based on 
    APK characteristics and system resources.
    """
    
    def __init__(self):
        self.base_timeout = 180  # 3 minutes (increased from 2 minutes)
        self.max_timeout = 900   # 15 minutes maximum
        self.min_timeout = 90    # 1.5 minutes minimum
    
    def calculate_optimal_timeout(self, apk_path: str, analysis_plugins: list = None) -> int:
        """
        Calculate optimal timeout based on APK characteristics and system resources.
        
        Args:
            apk_path: Path to APK file
            analysis_plugins: List of analysis plugins to run
            
        Returns:
            Optimal timeout in seconds
        """
        try:
            # Get APK size
            if not os.path.exists(apk_path):
                logger.warning(f"APK not found: {apk_path}")
                return self.base_timeout
            
            apk_size_mb = os.path.getsize(apk_path) / (1024 * 1024)
            
            # Calculate size-based multiplier
            size_multiplier = self._get_size_multiplier(apk_size_mb)
            
            # Calculate complexity-based multiplier
            complexity_multiplier = self._get_complexity_multiplier(analysis_plugins or [])
            
            # Calculate resource-based multiplier
            resource_multiplier = self._get_resource_multiplier()
            
            # Calculate final timeout
            timeout = int(self.base_timeout * size_multiplier * complexity_multiplier * resource_multiplier)
            
            # Apply bounds
            timeout = max(self.min_timeout, min(timeout, self.max_timeout))
            
            logger.info(f"JADX timeout optimized: {timeout}s for {apk_size_mb:.1f}MB APK "
                       f"(size: {size_multiplier:.1f}x, complexity: {complexity_multiplier:.1f}x, "
                       f"resources: {resource_multiplier:.1f}x)")
            
            return timeout
            
        except Exception as e:
            logger.warning(f"Error calculating timeout: {e}")
            return self.base_timeout
    
    def _get_size_multiplier(self, apk_size_mb: float) -> float:
        """Calculate timeout multiplier based on APK size."""
        if apk_size_mb < 1:
            return 0.7      # Very small APK: reduce timeout
        elif apk_size_mb < 5:
            return 1.0      # Small APK: standard timeout
        elif apk_size_mb < 20:
            return 1.5      # Medium APK: 1.5x timeout
        elif apk_size_mb < 100:
            return 2.5      # Large APK: 2.5x timeout  
        elif apk_size_mb < 300:
            return 3.5      # Very large APK: 3.5x timeout
        else:
            return 4.0      # Massive APK: 4x timeout
    
    def _get_complexity_multiplier(self, analysis_plugins: list) -> float:
        """Calculate timeout multiplier based on analysis complexity."""
        if not analysis_plugins:
            return 1.0
        
        # Define plugin complexity levels
        high_complexity = {
            "crypto_analysis", "secrets_analysis", "comprehensive_analysis",
            "vulnerability_detection", "advanced_pattern_analysis"
        }
        
        medium_complexity = {
            "insecure_patterns", "code_quality", "manifest_analysis",
            "resource_analysis", "string_analysis"
        }
        
        # Calculate complexity score
        high_count = sum(1 for plugin in analysis_plugins if plugin in high_complexity)
        medium_count = sum(1 for plugin in analysis_plugins if plugin in medium_complexity)
        
        if high_count >= 3:
            return 2.0      # Multiple high-complexity plugins
        elif high_count >= 1:
            return 1.5      # At least one high-complexity plugin
        elif medium_count >= 3:
            return 1.3      # Multiple medium-complexity plugins
        elif medium_count >= 1:
            return 1.1      # At least one medium-complexity plugin
        else:
            return 1.0      # Low complexity
    
    def _get_resource_multiplier(self) -> float:
        """Calculate timeout multiplier based on available system resources."""
        try:
            # Get memory information
            memory = psutil.virtual_memory()
            available_gb = memory.available / (1024**3)
            
            # Get CPU information
            cpu_count = psutil.cpu_count()
            cpu_percent = psutil.cpu_percent(interval=1)
            
            # Calculate resource score
            if available_gb < 2 or cpu_count < 2:
                return 1.8  # Very limited resources
            elif available_gb < 4 or cpu_count < 4:
                return 1.4  # Limited resources
            elif available_gb < 8:
                return 1.1  # Moderate resources
            elif cpu_percent > 80:
                return 1.3  # High CPU usage
            else:
                return 1.0  # Sufficient resources
                
        except Exception as e:
            logger.warning(f"Error checking system resources: {e}")
            return 1.2  # Conservative default
    
    def get_progressive_timeouts(self, base_timeout: int, max_retries: int = 3) -> list:
        """
        Get progressive timeout values for retry attempts.
        
        Args:
            base_timeout: Base timeout value
            max_retries: Number of retry attempts
            
        Returns:
            List of timeout values for each attempt
        """
        timeouts = [base_timeout]
        
        for i in range(1, max_retries + 1):
            # Increase timeout by 50% for each retry
            next_timeout = int(timeouts[-1] * 1.5)
            next_timeout = min(next_timeout, self.max_timeout)
            timeouts.append(next_timeout)
        
        return timeouts
    
    def should_skip_jadx(self, apk_path: str) -> tuple[bool, str]:
        """
        Determine if JADX should be skipped for this APK.
        
        Args:
            apk_path: Path to APK file
            
        Returns:
            Tuple of (should_skip, reason)
        """
        try:
            if not os.path.exists(apk_path):
                return True, "APK file not found"
            
            apk_size_mb = os.path.getsize(apk_path) / (1024 * 1024)
            
            # Skip extremely large APKs in Lightning mode
            if apk_size_mb > 500:
                return True, f"APK too large for JADX analysis ({apk_size_mb:.1f}MB)"
            
            # Check available resources
            try:
                memory = psutil.virtual_memory()
                available_gb = memory.available / (1024**3)
                
                if available_gb < 1:
                    return True, "Insufficient memory for JADX analysis"
                    
            except:
                pass
            
            return False, "JADX analysis feasible"
            
        except Exception as e:
            return True, f"Error assessing APK: {e}"

# Global optimizer instance
_jadx_optimizer = None

def get_jadx_timeout_optimizer() -> JadxTimeoutOptimizer:
    """Get global JADX timeout optimizer instance."""
    global _jadx_optimizer
    if _jadx_optimizer is None:
        _jadx_optimizer = JadxTimeoutOptimizer()
    return _jadx_optimizer

def optimize_jadx_timeout(apk_path: str, analysis_plugins: list = None) -> int:
    """
    Convenience function to get optimized timeout for JADX analysis.
    
    Args:
        apk_path: Path to APK file
        analysis_plugins: List of analysis plugins
        
    Returns:
        Optimized timeout in seconds
    """
    optimizer = get_jadx_timeout_optimizer()
    return optimizer.calculate_optimal_timeout(apk_path, analysis_plugins) 
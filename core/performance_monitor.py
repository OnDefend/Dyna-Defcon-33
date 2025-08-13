#!/usr/bin/env python3
"""
AODS Performance Monitoring Dashboard

Real-time monitoring of AODS scan performance and resource usage.
"""

import time
import psutil
import json
from datetime import datetime
from pathlib import Path

class PerformanceMonitor:
    """Simple performance monitoring for AODS scans."""
    
    def __init__(self):
        self.start_time = time.time()
        self.metrics = {
            'scan_start': datetime.now().isoformat(),
            'files_processed': 0,
            'secrets_found': 0,
            'plugins_executed': 0,
            'memory_usage_mb': 0,
            'cpu_usage_percent': 0,
            'processing_rate_files_per_sec': 0
        }
    
    def update_metrics(self, files_processed=0, secrets_found=0, plugins_executed=0):
        """Update performance metrics."""
        self.metrics['files_processed'] += files_processed
        self.metrics['secrets_found'] += secrets_found
        self.metrics['plugins_executed'] += plugins_executed
        
        # Update system metrics
        process = psutil.Process()
        self.metrics['memory_usage_mb'] = process.memory_info().rss / 1024 / 1024
        self.metrics['cpu_usage_percent'] = process.cpu_percent()
        
        # Calculate processing rate
        elapsed_time = time.time() - self.start_time
        if elapsed_time > 0:
            self.metrics['processing_rate_files_per_sec'] = self.metrics['files_processed'] / elapsed_time
        
        self.metrics['elapsed_time_seconds'] = elapsed_time
    
    def generate_report(self):
        """Generate performance report."""
        self.update_metrics()
        
        report = f"""
        📊 AODS Performance Report
        ========================
        Scan Duration: {self.metrics['elapsed_time_seconds']:.1f} seconds
        Files Processed: {self.metrics['files_processed']}
        Secrets Found: {self.metrics['secrets_found']}
        Plugins Executed: {self.metrics['plugins_executed']}
        Memory Usage: {self.metrics['memory_usage_mb']:.1f} MB
        CPU Usage: {self.metrics['cpu_usage_percent']:.1f}%
        Processing Rate: {self.metrics['processing_rate_files_per_sec']:.1f} files/sec
        """
        
        return report
    
    def save_metrics(self, filepath="performance_metrics.json"):
        """Save metrics to file."""
        with open(filepath, 'w') as f:
            json.dump(self.metrics, f, indent=2)

# Global monitor instance
performance_monitor = PerformanceMonitor()
